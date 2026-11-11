#!/usr/bin/env python3
"""阿里云 DDNS 取证脚本（tools/ddns-aliyun-diagnose.py）的判据测试

为什么要有这个
--------------
这个脚本是**要拿到用户真机上跑**的取证工具，它的作用只有一个：
把「代码判错了」和「公网 IPv4 真的在变」这两种情况分开。

⇒ 它的判据如果不可靠，比没有这个工具更糟：
   判据误报会让排查方向整个跑偏（而用户只有一次机会去现场取这个证）。

本文件钉住四件事：
  1. 地址族判定：A 记录只认 IPv4，IPv6 必须排除出比对
  2. 稳定性判定：必须拿原始采样判断，不能拿「去重后的列表」判断
  3. 快照对比标签：「值变没变 / ID 变没变」必须分得清
  4. **安全底线**：取证脚本自己绝不能有任何写操作

第 4 条是硬红线：用户是把这个脚本拷到自己的 DDNS 设备上跑的。
一个会删 DNS 记录的"取证脚本"等于帮倒忙。
"""

import ast
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT_PATH = os.path.join(ROOT, "tools", "ddns-aliyun-diagnose.py")

PASS = 0
FAIL = 0


# ============================================================
# 只读判据：AST 级 + 运行时级
# ============================================================
#
# 为什么不能只做文本匹配
# ----------------------
# 原来的判据是「源码里有没有 `"Action": "DeleteDomainRecord"`」这种**固定字面量**
# 匹配 ⇒ 下面 4 种恶意改法**全部**能溜过去：
#   ① "Action" : "DeleteDomainRecord"   （多一个空格）
#   ② "Delete" + "DomainRecord"         （拼接）
#   ③ 去掉 _mask，直接把明文 secret 存进快照
#   ④ subprocess.run(["curl", url])       （换个壳发写请求）
# ⇒ 判据改成 AST 级（把常量表达式**求值**再比对），
#   并且每条判据都用「恶意变体」**自证**能拦住。

WRITE_ACTIONS = ("DeleteDomainRecord", "AddDomainRecord", "UpdateDomainRecord",
                 "Delete", "Add", "Update")

# 允许发起外发请求的函数（其余函数里出现 URL 请求就是违规）
ALLOWED_REQUEST_FUNCS = {"probe_public_ip", "aliyun_describe"}

# 能发 HTTP 请求的命令（用 shell 绕出去也算写操作）
HTTP_CAPABLE_CMDS = {"curl", "wget", "http", "httpie", "nc", "ncat", "telnet"}

# 发起 URL 请求的调用名
URL_CALLS = {"urlopen", "urlretrieve", "Request", "HTTPConnection",
             "HTTPSConnection"}


def _const_str(node):
    """把「常量表达式」求成字符串；求不出来返回 None。

    为什么不用 ast.literal_eval：它不支持字符串拼接（BinOp），
    而 `"Delete" + "DomainRecord"` 正是要防的写法之一。
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _const_str(node.left)
        right = _const_str(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append("?")
        return "".join(parts)
    return None


def readonly_violations(src):
    """AST 级只读检查，返回违规原因列表（空 = 通过）。"""
    out = []
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return ["源码无法解析：%s" % e]

    # ① Action 的取值 —— 空格、拼接、f-string 都躲不掉
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "Action":
                s = _const_str(v)
                if s is not None and s in WRITE_ACTIONS:
                    out.append("第 %d 行：Action=%s（写操作）" % (node.lineno, s))

    # ② 外发请求只允许落在两个函数里
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            name = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
            if name in URL_CALLS and fn.name not in ALLOWED_REQUEST_FUNCS:
                out.append("第 %d 行：%s() 在 %s() 里（外发请求只允许在 %s）"
                           % (sub.lineno, name, fn.name,
                              "/".join(sorted(ALLOWED_REQUEST_FUNCS))))

    # ③ shell 出去发 HTTP 请求
    for sub in ast.walk(tree):
        if not isinstance(sub, ast.Call):
            continue
        name = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
        if name not in ("run", "call", "Popen", "check_output", "check_call"):
            continue
        if not sub.args:
            continue
        first = sub.args[0]
        cmds = []
        if isinstance(first, (ast.List, ast.Tuple)):
            for el in first.elts:
                s = _const_str(el)
                if s:
                    cmds.append(s)
        else:
            s = _const_str(first)
            if s:
                cmds.append(s)
        for c in cmds:
            head = c.split()[0].lower() if c.split() else ""
            if head in HTTP_CAPABLE_CMDS:
                out.append("第 %d 行：subprocess 调用了 %s（能发 HTTP 请求）"
                           % (sub.lineno, head))
    return out


def masking_violations(mod, tmpdir):
    """运行时检查：快照里不能出现明文 secret。

    真的跑一遍 probe_config()，喂一个**已知**口令，看返回的快照里是明文还是掩码。
    ⇒ 纯 AST 做不到这件事：「从配置里读 secret」和「从快照里读已遮过的 secret」
    在语法上一模一样，只能靠实跑区分。
    """
    cfg_path = os.path.join(tmpdir, "probe-config.json")
    secret = "SECRETPROBE0123456789"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({
            "domain": "example.com", "region_id": "cn-hangzhou",
            "access_key_id": "AKPROBE", "access_key_secret": secret,
            "records": [],
        }, f)
    old = getattr(mod, "CONFIG_PATH", None)
    try:
        mod.CONFIG_PATH = cfg_path
        snap = mod.probe_config()
    finally:
        if old is not None:
            mod.CONFIG_PATH = old
    dumped = json.dumps(snap, ensure_ascii=False, default=str)
    if secret in dumped:
        return True, "快照里出现了明文 secret（%r）" % snap.get("access_key_secret")
    masked = str(snap.get("access_key_secret", ""))
    if "****" not in masked:
        return True, "快照里的 secret 不是掩码形式（%r）" % masked
    return False, "快照里的 secret 是掩码（%r）" % masked


def evil_variants(src):
    """构造 4 种恶意改写 —— 每种都必须被只读判据拦下。"""
    return [
        ('Action 多一个空格',
         src.replace('"Action": "DescribeDomainRecords",',
                     '"Action" : "DeleteDomainRecord",')),
        ('Action 拼接',
         src.replace('"Action": "DescribeDomainRecords",',
                     '"Action": "Delete" + "DomainRecord",')),
        ('去掉 _mask 直接存明文 secret',
         src.replace('res["access_key_secret"] = _mask(cfg.get("access_key_secret", ""))',
                     'res["access_key_secret"] = cfg.get("access_key_secret", "")')),
        ('用 curl 发写请求',
         src.replace('def aliyun_describe(ak_id, ak_secret, region, domain):',
                     'def aliyun_describe(ak_id, ak_secret, region, domain):\n'
                     '    import subprocess as _sp\n'
                     '    _sp.run(["curl", "-X", "POST", "https://example.invalid/x"])')),
    ]


def check(cond, msg):
    """输出一行断言。行首必须是 [PASS] / [FAIL] —— run_all.sh 按行首锚定计数。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + msg)
    else:
        FAIL += 1
        print("[FAIL] " + msg)


def load_module(path=None):
    spec = importlib.util.spec_from_file_location(
        "ddns_diag", path or SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if not os.path.exists(SCRIPT_PATH):
        print("[FAIL] 取证脚本不存在：%s" % SCRIPT_PATH)
        print("  合计: [PASS] 0   [FAIL] 1")
        return 1
    mod = load_module()
    src = open(SCRIPT_PATH, encoding="utf-8").read()

    # ── 1. 地址族判定 ─────────────────────────────────────────
    print("--- 1. 地址族判定（IPv4 / IPv6 必须分开）---")
    check(mod._is_ipv4("1.2.3.4") is True, "普通 IPv4 被判为 IPv4")
    check(mod._is_ipv4("115.239.126.7") is True, "公网 IPv4 被判为 IPv4")
    check(mod._is_ipv4(" 1.2.3.4 ") is True, "带首尾空白的 IPv4 仍被判为 IPv4")
    check(mod._is_ipv4("240e:390:472b:d180::1") is False,
          "IPv6 地址不被判为 IPv4（否则会得出「多出口」的假结论）")
    check(mod._is_ipv4("::1") is False, "回环 IPv6 不被判为 IPv4")
    check(mod._is_ipv4("not-an-ip") is False, "非 IP 字符串不被判为 IPv4")
    check(mod._is_ipv4("") is False, "空串不被判为 IPv4")

    # ── 2. 稳定性判定 ─────────────────────────────────────────
    print("--- 2. 出口 IPv4 稳定性判定 ---")
    check(mod._judge_stability(["1.2.3.4", "1.2.3.4"], 2) is True,
          "采样 2 次都是同一个 IPv4 ⇒ 稳定")
    check(mod._judge_stability(["1.2.3.4"] * 3, 3) is True,
          "采样 3 次都是同一个 IPv4 ⇒ 稳定")
    check(mod._judge_stability(["1.2.3.4", "5.6.7.8"], 2) is False,
          "采样 2 次得到不同 IPv4 ⇒ 不稳定（出口在漂移）")
    # ↓ 反例：这一条专门钉住「不能拿去重后的列表判断」这个坑。
    #   早先的写法是 len(set(v4)) == 1 and len(v4) == samples，
    #   而 v4 是**去重后**的列表，长度恒为 1 ⇒ samples=2 时恒为 False
    #   ⇒ 「采样 2 次同值」会被误报成「漂移」。
    check(mod._judge_stability(["1.2.3.4", "1.2.3.4"], 3) is False,
          "只采到 2 次却声称采了 3 次 ⇒ 采样不足，判不稳定（不能谎称稳定）")
    check(mod._judge_stability(["1.2.3.4", ""], 2) is False,
          "第二次没取到 ⇒ 采样不完整，判不稳定")
    check(mod._judge_stability(["240e::1", "240e::2"], 2) is None,
          "全是 IPv6 ⇒ 无 IPv4 样本，返回 None（无法判断）而不是 False")
    check(mod._judge_stability(["240e::1", "1.2.3.4"], 2) is False,
          "IPv6 + 1 个 IPv4 ⇒ 只采到 1 个 IPv4，判不稳定")

    # ── 3. 快照对比标签 ───────────────────────────────────────
    print("--- 3. 快照对比：值变没变 / 记录 ID 变没变 ---")
    prev = {"records": [
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "111"},
    ]}
    cur_same_id = {"records": [
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "111"},
    ]}
    cur_diff_id = {"records": [
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "222"},
    ]}
    cur_diff_val = {"records": [
        {"rr": "www", "type": "A", "value": "5.6.7.8", "record_id": "111"},
    ]}
    cur_diff_both = {"records": [
        {"rr": "www", "type": "A", "value": "5.6.7.8", "record_id": "222"},
    ]}
    check(any(l.startswith("[值没变+ID变]") for l in mod.compare(prev, cur_diff_id)),
          "值没变但记录 ID 变了 ⇒ 标成「值没变+ID变」（这是代码 bug 的指纹）")
    check(any(l.startswith("[值变+ID变]") for l in mod.compare(prev, cur_diff_both)),
          "值变了且记录 ID 也变 ⇒ 标成「值变+ID变」")
    check(any(l.startswith("[值变+ID没变]") for l in mod.compare(prev, cur_diff_val)),
          "值变了但记录 ID 没变 ⇒ 标成「值变+ID没变」（原地更新）")
    check(any(l.startswith("[值没变+ID没变]") for l in mod.compare(prev, cur_same_id)),
          "值和 ID 都没变 ⇒ 标成「值没变+ID没变」（本轮 cron 没动它）")
    check(any(l.startswith("[新增]") for l in mod.compare(
        {"records": []}, cur_same_id)), "上次没有、这次有的记录 ⇒ 标成「新增」")
    check(any(l.startswith("[消失]") for l in mod.compare(prev, {"records": []})),
          "上次有、这次没有的记录 ⇒ 标成「消失」")

    # ── 4. 结论区块 ───────────────────────────────────────────
    print("--- 4. 结论区块的判据 ---")
    ip_one = {"icanhazip": {"v4": ["1.2.3.4"], "v6": [], "stable": True, "samples": ["1.2.3.4"]}}
    snap_al = {"records": [
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "111"},
    ]}
    txt = "\n".join(mod.print_conclusion(snap_al, None, ip_one))
    check("本该判定" in txt, "本次算出的 IPv4 == 阿里云现存值 ⇒ 提示「本该跳过」")
    check("决定性" in txt, "结论区块给出「决定性」判据行")

    snap_diff = {"records": [
        {"rr": "www", "type": "A", "value": "9.9.9.9", "record_id": "111"},
    ]}
    txt2 = "\n".join(mod.print_conclusion(snap_diff, None, ip_one))
    check("值是真的变了" in txt2, "本次算出的 IPv4 != 阿里云现存值 ⇒ 提示「值是真的变了」")

    # ↓ 反例：IPv6 差异不得触发「多出口」判定
    ip_v6only_diff = {
        "a": {"v4": ["1.2.3.4"], "v6": ["240e::1"], "stable": True, "samples": ["1.2.3.4"]},
        "b": {"v4": ["1.2.3.4"], "v6": ["240e::2"], "stable": True, "samples": ["1.2.3.4"]},
    }
    txt3 = "\n".join(mod.print_conclusion(snap_al, None, ip_v6only_diff))
    check("多个探测源拿到的公网 IPv4 不一致" not in txt3,
          "只有 IPv6 不同 ⇒ 不得报「IPv4 多出口」（A 记录只认 IPv4）")
    check("IPv6" in txt3, "IPv6 差异以「旁证」形式单独列出")

    ip_v4_diff = {
        "a": {"v4": ["1.2.3.4"], "v6": [], "stable": True, "samples": ["1.2.3.4"]},
        "b": {"v4": ["5.6.7.8"], "v6": [], "stable": True, "samples": ["5.6.7.8"]},
    }
    txt4 = "\n".join(mod.print_conclusion(snap_al, None, ip_v4_diff))
    check("多个探测源拿到的公网 IPv4 不一致" in txt4,
          "两个源返回不同 IPv4 ⇒ 报「多出口」")

    snap_dup = {"records": [
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "111"},
        {"rr": "www", "type": "A", "value": "1.2.3.4", "record_id": "222"},
    ]}
    txt5 = "\n".join(mod.print_conclusion(snap_dup, None, ip_one))
    check("重复记录" in txt5, "同 RR+Type 出现多条 ⇒ 报「重复记录」")

    # ── 5. 安全底线：取证脚本自身不得有任何写操作 ─────────────
    print("--- 5. 安全底线：取证脚本不得有写操作 ---")
    check("def aliyun_describe(" in src, "脚本存在只读查询入口 aliyun_describe")
    check("def _api(" not in src and "def _aliyun_api(" not in src,
          "脚本里不存在通用 API 调用入口（杜绝随手加写操作）")
    check("DescribeDomainRecords" in src, "脚本只调用 DescribeDomainRecords（读）")

    # AST 级只读判据（取代原来的「固定字面量」文本匹配）
    violations = readonly_violations(src)
    check(not violations,
          "AST 级只读判据通过（实际违规：%s）" % (violations or "无"))

    # 运行时级：secret 真的被遮住了吗
    tmpdir = tempfile.mkdtemp(prefix="ddns-diag-judge-")
    leaked, mask_detail = masking_violations(mod, tmpdir)
    check(not leaked, "快照里的 secret 是掩码（%s）" % mask_detail)

    # ↓ 判据自证：4 种恶意改法**每一种**都必须被拦下。
    #   原来的判据在下面 4 种改法下**全部 11/11 通过** ——
    #   也就是说「只读」这条硬红线当时根本没被守住。
    for name, evil in evil_variants(src):
        v_ast = readonly_violations(evil)
        if v_ast:
            check(True, "恶意变体「%s」被 AST 判据拦下（%s）" % (name, v_ast))
            continue
        # AST 没抓到 ⇒ 运行时判据必须抓到（③ 就是这种）
        evil_path = os.path.join(tmpdir, "evil.py")
        with open(evil_path, "w", encoding="utf-8") as f:
            f.write(evil)
        try:
            evil_mod = load_module(evil_path)
            evil_leaked, evil_detail = masking_violations(evil_mod, tmpdir)
        except Exception as e:
            evil_leaked, evil_detail = True, "变体加载失败（也算拦下）：%s" % e
        check(evil_leaked,
              "恶意变体「%s」被运行时判据拦下（%s）" % (name, evil_detail))

    # 用 AST 再核一遍：所有对 alidns 的请求都收在 aliyun_describe 里
    try:
        tree = ast.parse(src)
        # 每个 urlopen 调用点落在哪个函数里
        urlopen_in = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        fn = sub.func
                        name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                        if name == "urlopen":
                            urlopen_in[node.name] = urlopen_in.get(node.name, 0) + 1
        check(set(urlopen_in.keys()) <= {"probe_public_ip", "aliyun_describe"},
              "全部 urlopen 调用只落在 %s 里（实际：%s），没有散落的外发入口"
              % (sorted({"probe_public_ip", "aliyun_describe"}), urlopen_in))
        check(urlopen_in.get("aliyun_describe", 0) == 1,
              "对阿里云的请求只有一处，且是只读查询")
        check(urlopen_in.get("probe_public_ip", 0) == 1,
              "查公网 IP 的请求只有一处")
    except SyntaxError as e:
        check(False, "脚本能被 AST 解析（语法错误：%s）" % e)

    check("_mask(" in src, "AK secret 走 _mask 脱敏")
    check("access_key_secret']" not in src.replace('"access_key_secret"', ''),
          "没有把 access_key_secret 直接拼进输出")

    # ── 6. 加固项：掩码强度 / 快照权限 / 时区 ──────────────────
    #
    # 这三条不是「功能对不对」，而是「这个脚本被拷到用户设备上跑的时候，
    # 会不会顺手泄露或留下隐患」—— 它的输出会被贴进工单、截图、聊天记录。
    print("--- 6. 加固项：掩码强度 / 快照权限 / 时区 ---")

    # 6a. 掩码强度：必须与面板侧 (_mask_password，2+2) 同级。
    #     早先取证脚本是 4+4 ⇒ 一个 30 位的 AK secret 露 8 位，
    #     比面板侧宽一倍 ⇒ 输出传播出去时泄露面大一倍。
    masked_long = mod._mask("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    check(len(masked_long) == 8 and masked_long.count("*") == 4,
          "长 secret 的掩码是 2+2（长度 %d）" % len(masked_long))
    check(masked_long[:2] == "AB" and masked_long[-2:] == "45",
          "长 secret 的掩码只露首 2 尾 2（实际 %r）" % masked_long)
    check(mod._mask("").startswith("(空)"), "空 secret 显示为「(空)」")
    short_masked = mod._mask("abc")
    check("abc" not in short_masked and "已隐藏" in short_masked,
          "短 secret 完全不露（实际 %r）" % short_masked)

    # 6b. 快照文件权限：内容含明文 AccessKeyId 与域名 ⇒ 必须 0600。
    #     实跑一次 save_snapshot，看落在磁盘上的真实权限。
    #
    # ⚠️ 必须把 umask 设成 0：否则「建出来的权限」取决于运行环境的 umask
    #   （本机是 0002，某些 CI 是 0022）⇒ 同一条代码在不同机器上断言结果不同
    #   ⇒ 判据不稳定。umask=0 时「代码要了 0644」就一定是 0644，一眼红。
    snap_dir = tempfile.mkdtemp(prefix="ddns-diag-perm-")
    snap_path = os.path.join(snap_dir, "snap.jsonl")
    old_snap_path = getattr(mod, "SNAPSHOT_PATH", None)
    old_umask = os.umask(0o000)
    try:
        mod.SNAPSHOT_PATH = snap_path
        mod.save_snapshot({"ts": "t", "records": [], "ip": {}})
        mode_new = os.stat(snap_path).st_mode & 0o777
    except Exception as e:
        mode_new = None
        print("  [FAIL] save_snapshot 抛异常：%s" % e)
    finally:
        os.umask(old_umask)
        if old_snap_path is not None:
            mod.SNAPSHOT_PATH = old_snap_path
    check(mode_new == 0o600,
          "新建的快照文件权限就是 0600（实际 %s）"
          % (oct(mode_new) if mode_new is not None else "没建出来"))

    # 6b-2. 已有文件被写宽了（老版本留下的 0644）⇒ 追加时必须收紧。
    #      os.open(O_APPEND) 对**已存在**文件不改权限 ⇒ 只测新建是不够的。
    wide_path = os.path.join(snap_dir, "wide.jsonl")
    with open(wide_path, "w", encoding="utf-8") as f:
        f.write("{}\n")
    os.chmod(wide_path, 0o644)
    old_snap_path = getattr(mod, "SNAPSHOT_PATH", None)
    old_umask = os.umask(0o000)
    try:
        mod.SNAPSHOT_PATH = wide_path
        mod.save_snapshot({"ts": "t2", "records": [], "ip": {}})
        mode_wide = os.stat(wide_path).st_mode & 0o777
    except Exception as e:
        mode_wide = None
        print("  [FAIL] save_snapshot 抛异常：%s" % e)
    finally:
        os.umask(old_umask)
        if old_snap_path is not None:
            mod.SNAPSHOT_PATH = old_snap_path
    check(mode_wide == 0o600,
          "已存在但权限是 0644 的快照文件，追加后被收紧到 0600（实际 %s）"
          % (oct(mode_wide) if mode_wide is not None else "读不到"))

    # 6c. 时间戳：阿里云签名要 UTC，但不能用已弃用的 naive utcnow()。
    #     naive datetime 一旦被当成本地时间做时区换算就会错。
    #
    # ⚠️ 必须查 **AST 调用节点**，不能查源码文本 ——
    #   注释里写着「不要再用 utcnow()」也会被文本匹配命中 ⇒ 假红。
    #   （这正是 M6 定下的规矩：判据要 AST 化。）
    try:
        tree2 = ast.parse(src)
        utcnow_calls = []
        ts_calls = []
        for node in ast.walk(tree2):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            attr = getattr(fn, "attr", None)
            if attr == "utcnow":
                utcnow_calls.append(node.lineno)
            if attr == "now" and node.args:
                ts_calls.append(ast.unparse(node.args[0]))
        check(not utcnow_calls,
              "脚本不再调用已弃用的 datetime.utcnow()（命中行：%s）" % utcnow_calls)
        check(any("timezone" in a for a in ts_calls),
              "取 UTC 时间戳时显式带 timezone（实际参数：%s）" % ts_calls)
    except SyntaxError as e:
        check(False, "脚本能被 AST 解析（语法错误：%s）" % e)

    print("  合计: [PASS] %d   [FAIL] %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
