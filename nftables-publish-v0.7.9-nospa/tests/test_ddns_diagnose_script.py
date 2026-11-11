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
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT_PATH = os.path.join(ROOT, "tools", "ddns-aliyun-diagnose.py")

PASS = 0
FAIL = 0


def check(cond, msg):
    """输出一行断言。行首必须是 [PASS] / [FAIL] —— run_all.sh 按行首锚定计数。"""
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + msg)
    else:
        FAIL += 1
        print("[FAIL] " + msg)


def load_module():
    spec = importlib.util.spec_from_file_location("ddns_diag", SCRIPT_PATH)
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
    for verb in ("DeleteDomainRecord", "AddDomainRecord", "UpdateDomainRecord"):
        hit = ("\"Action\": \"%s\"" % verb) in src or ("'Action': '%s'" % verb) in src
        check(not hit, "脚本没有以 Action=%s 发起写操作" % verb)
    check("DescribeDomainRecords" in src, "脚本只调用 DescribeDomainRecords（读）")

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

    print("  合计: [PASS] %d   [FAIL] %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
