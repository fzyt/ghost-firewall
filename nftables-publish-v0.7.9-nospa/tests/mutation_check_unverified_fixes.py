"""2026-11-21 未核基线条目修复的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_unverified_fixes.py

测什么有效
----------
这一轮修了 18 个独立修复点（基线 88 条里的 19 条，其中 [6]/[35]、
[38]/[52] 各是同一件事）。每条修复都要能被「反向退化」抓住 ——
把修复撤掉，测试必须变红。

只测「源码里有没有那句话」是不够的：那种测试在**语义退化**面前全是绿的。
所以每条变异都往**修复前的真实写法**退，而不是随便改个字。

判定口径
--------
  · 基线（未变异）必须全绿，否则变异验证没有意义。
  · 变异后必须出现 [FAIL] 行才算「被捕获」。
    只有非零退出码、没有 [FAIL] 行 ⇒ **不算捕获** ——
    那说明测试脚本自己崩了，崩不等于抓住。
  · 锚点没命中 ⇒ **算失败**（源码变了、锚点该更新），不静默跳过。

保险丝
------
MutationGuard 在启动时快照全部 git 跟踪的源码文件，
退出时还原 ⇒ 中途被 kill 也不会把变异留在源码里。

⚠️ 运行期间不要改仓库里任何被跟踪的文件：保险丝会把它们**按快照还原**
（2026-11-04 实测踩过：改动被静默覆盖，文件看起来正常，只是少了刚写的几行）。
"""
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
GW_PY = os.path.join(ROOT, 'backend', 'auth_gateway.py')
INIT = os.path.join(ROOT, 'backend', 'nftables-web-auth.init')
TEST = os.path.join(ROOT, 'tests', 'test_unverified_fixes.py')

TARGETS = {APP_PY: None, GW_PY: None, INIT: None}
for _p in TARGETS:
    with open(_p, encoding='utf-8') as _f:
        TARGETS[_p] = _f.read()


def judge_capture(rc, out):
    """这次变异算不算「被捕获」。

    不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」。
    只有输出里真的出现**断言失败**的标记行才算捕获；
    只有崩溃、没有失败行的 ⇒ 算漏网（宁可漏判，不可假捕获）。
    """
    if rc == 0:
        return False, '测试仍然全绿（rc=0）'
    for line in out.splitlines():
        st = line.strip()
        if '[FAIL]' in st and '[PASS]' not in st:
            return True, st
    return False, '测试崩了（rc=%d，但没有 [FAIL] 行）—— 不算捕获' % rc


def apply_edits(src, edits):
    """edits: [(old, new, expect_count)]。

    expect_count 是锚点**必须**出现的次数 —— 不符就抛错。
    这样「锚点没命中」（源码变了）不会被当成「变异没效果」而静默放过。
    """
    for old, new, expect in edits:
        n = src.count(old)
        if n != expect:
            raise ValueError('锚点出现 %d 次（期望 %d 次）: %r' % (n, expect, old[:70]))
        src = src.replace(old, new)
    return src


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1',
                            'PYTHONUNBUFFERED': '1'})
    return r.returncode, (r.stdout + r.stderr)


def restore():
    for path, content in TARGETS.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# ── 变异清单 ──────────────────────────────────────────────────────────
# 每条 = (名字, 目标文件, [(old, new, 期望出现次数)])
MUTATIONS = [
    # ── ①(6/35) 过宽网段守卫 ──────────────────────────────────────
    ('M01  _safe_cidr 去掉 prefixlen<=1 守卫（回退成「只校验是不是合法 CIDR」）',
     APP_PY,
     [("    if net.prefixlen <= 1:\n"
       "        print(f'[WARN] 网段 {s!r} 过宽（/{net.prefixlen}），已回落默认网段 {default!r}',\n"
       "              flush=True)\n"
       "        return default\n",
       "    if False:\n"
       "        pass\n", 1)]),

    # ── ②(20) 中国 IP 名单超网 ───────────────────────────────────
    ('M02  中国IP名单超网改成 continue（静默跳过，不再拒绝整个更新）',
     APP_PY,
     [('    if net.prefixlen <= 1:\n'
       '        die("列表含超网条目 %s：/%d 匹配半个以上地址空间，已拒绝写入"\n'
       '            "（原列表保持不变）" % (net, net.prefixlen))\n',
       '    if net.prefixlen <= 1:\n'
       '        continue\n', 1)]),

    # ── ③(22) isdigit 陷阱 ───────────────────────────────────────
    ('M03  _nonneg_int 退回 isdigit()+int()（去掉 isascii 与 try/except）',
     APP_PY,
     [("    s = str(v if v is not None else '').strip()\n"
       "    if not s or not s.isascii() or not s.isdigit():\n"
       "        return default\n"
       "    try:\n"
       "        n = int(s)\n"
       "    except ValueError:\n"
       "        return default\n"
       "    return n if n >= 0 else default\n",
       "    s = str(v if v is not None else '').strip()\n"
       "    if not s or not s.isdigit():\n"
       "        return default\n"
       "    n = int(s)\n"
       "    return n if n >= 0 else default\n", 1)]),

    ('M04  build_rules 绕过 _nonneg_int 直接 int()（生成阶段炸 500）',
     APP_PY,
     [('    whitelist_timeout = _nonneg_int(config.get("whitelist_timeout", 18000), 18000)',
       '    whitelist_timeout = int(config.get("whitelist_timeout", 18000))', 1)]),

    # ── ④(28) 出厂信任 IP ────────────────────────────────────────
    ('M05  DEFAULT_CONFIG 的 trusted_ip4 又填回具体 IP',
     APP_PY,
     [('    "trusted_ip4": "",\n', '    "trusted_ip4": "192.168.100.1",\n', 1)]),

    ('M06  validate_config 把 trusted_ip4 改回「不能为空」',
     APP_PY,
     [("    for key, ver, optional in (('router_ip4', 4, False), ('trusted_ip4', 4, True),",
       "    for key, ver, optional in (('router_ip4', 4, False), ('trusted_ip4', 4, False),", 1)]),

    ('M07  去掉「access_mode=trusted 必须填 trusted_ip4」这条规则',
     APP_PY,
     [("    if cfg.get('access_mode') == 'trusted':\n"
       "        _t4 = cfg.get('trusted_ip4')\n"
       "        _t4_items = ([str(x).strip() for x in _t4 if str(x).strip()]\n"
       "                      if isinstance(_t4, (list, tuple, set))\n"
       "                      else [str(_t4 or '').strip()])\n"
       "        if not [x for x in _t4_items if x]:\n"
       "            errs.append('access_mode=trusted 时必须指定 trusted_ip4'\n"
       "                        '（否则没有任何来源能免认证访问：模板里的信任放行整块不生成）')\n",
       "", 1)]),

    ('M08  restore_config 恢复时只在生效值非空才补键（空串时键整个缺失）',
     APP_PY,
     [("                restored[_key] = _effective_cfg.get(_key) or ''\n",
       "                _cur_val = _effective_cfg.get(_key)\n"
       "                if _cur_val:\n"
       "                    restored[_key] = _cur_val\n", 1)]),

    # ── ⑤(31) nginx 快照失败 ─────────────────────────────────────
    ('M09  nginx 配置快照失败改成 WARN 后继续（坏配置落盘）',
     APP_PY,
     [("            print(f'[ERROR] 网关配置快照失败: {e}（已中止部署，磁盘未改动）', flush=True)\n"
       '            return False, f"网关配置快照失败：{e}（已中止部署，磁盘未改动）"\n',
       "            print(f'[WARN] 网关配置快照失败: {e}', flush=True)\n"
       "            have_backup = False\n", 1)]),

    # ── ⑥(38/52) 读-改-写加锁 ────────────────────────────────────
    ('M10  save_config 不再复用本线程已持有的锁 fd（update_config 自锁）',
     APP_PY,
     [("    if _lock_depth() > 0:\n"
       "        lock_fd = _CONFIG_LOCK_LOCAL.fd\n"
       "        lock_owned = False\n"
       "    else:\n",
       "    if False:\n"
       "        lock_fd = _CONFIG_LOCK_LOCAL.fd\n"
       "        lock_owned = False\n"
       "    else:\n", 1)]),

    ('M11  update_config 不取排他锁（读-改-写不再互斥）',
     APP_PY,
     [('    try:\n'
       '        fcntl.flock(lock_fd, fcntl.LOCK_EX)\n'
       '    except OSError as e:\n'
       '        os.close(lock_fd)\n'
       '        print(f"[ERROR] update_config 无法锁定配置锁文件（{type(e).__name__}），"\n',
       '    try:\n'
       '        pass\n'
       '    except OSError as e:\n'
       '        os.close(lock_fd)\n'
       '        print(f"[ERROR] update_config 无法锁定配置锁文件（{type(e).__name__}），"\n', 1)]),

    # ── ⑦(69) 请求体类型 ─────────────────────────────────────────
    ('M12  _req_str 去掉 isinstance 判断（非字符串 ip ⇒ 500）',
     APP_PY,
     [("    v = data.get(key)\n"
       "    return v.strip() if isinstance(v, str) else ''\n",
       "    v = data.get(key, '')\n"
       "    return v.strip()\n", 1)]),

    ('M13  名单端点去掉「请求体必须是 JSON 对象」的检查（三处同一句守卫）',
     APP_PY,
     [('    data = request.get_json(silent=True)\n'
       '    if not isinstance(data, dict) or not data:\n'
       '        return jsonify({"success": False, "message": "请求体必须是 JSON 对象"}), 400\n',
       '    data = request.get_json(silent=True)\n'
       '    if not data:\n'
       '        return jsonify({"success": False, "message": "请求体必须是 JSON 对象"}), 400\n', 3)]),

    ('M14  预设端点去掉「非 dict 就当空 dict」的兜底',
     APP_PY,
     [('    data = request.get_json(silent=True)\n'
       '    if not isinstance(data, dict):\n'
       '        data = {}\n',
       '    data = request.get_json(silent=True)\n', 1)]),

    # ── ⑧(77) 私钥缓存头 ─────────────────────────────────────────
    ('M15  私钥下载的 no-store 改回 setdefault（压不过 Werkzeug 的 no-cache）',
     APP_PY,
     [("    resp.headers['Cache-Control'] = 'no-store'\n",
       "    resp.headers.setdefault('Cache-Control', 'no-store')\n", 1)]),

    ('M26  update_config 的锁 os.open 不带 mode（锁文件落盘就是 0644）',
     APP_PY,
     [("    lock_path = CONFIG_PATH + '.lock'\n"
       "    try:\n"
       "        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, _CONFIG_FILE_MODE)\n"
       "    except OSError as e:\n",
       "    lock_path = CONFIG_PATH + '.lock'\n"
       "    try:\n"
       "        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)\n"
       "    except OSError as e:\n", 1)]),

    # ── ⑨(58) 吊销表读锁 ─────────────────────────────────────────
    ('M16  load_revoked 读端不取共享锁（撞上写窗口 ⇒ 令牌复活）',
     GW_PY,
     [("            fcntl.flock(f.fileno(), fcntl.LOCK_SH)\n"
       "            try:\n"
       "                data = json.load(f)\n",
       "            try:\n"
       "                data = json.load(f)\n", 1)]),

    # ── ⑩(67) 免凭据放行留痕 ─────────────────────────────────────
    ('M17  /auth/verify 的免凭据放行不留痕',
     GW_PY,
     [('        audit("lan_bypass_granted")\n', '', 1)]),

    ('M18  /auth/status 的免凭据放行不留痕',
     GW_PY,
     [('        audit("lan_bypass_granted", endpoint="status")\n', '', 1)]),

    ('M19  /auth/portal 的免凭据放行不留痕',
     GW_PY,
     [('        audit("lan_bypass_granted", endpoint="portal")\n', '', 1)]),

    # ── ⑪(84) 孤立代理字符 ───────────────────────────────────────
    ('M20  _verify_password 不再兜 UnicodeEncodeError（500 且跳过限流计数）',
     GW_PY,
     [('        try:\n'
       '            pwd_bytes = password.encode("utf-8")\n'
       '        except UnicodeEncodeError:\n'
       '            pwd_bytes = None\n',
       '        pwd_bytes = password.encode("utf-8")\n', 1)]),

    # ── ⑫(85) 异常状态码 ─────────────────────────────────────────
    ('M21  错误处理器不再夹取状态码（code=None 会落成 200）',
     GW_PY,
     [("        _code = err.code\n"
       "        if not isinstance(_code, int) or not (300 <= _code <= 599):\n"
       "            _code = 500\n",
       "        _code = err.code\n"
       "        if False:\n"
       "            _code = 500\n", 1)]),

    # ── ⑬(88) 静态页缓存头 ───────────────────────────────────────
    ('M22  静态 HTML 页面不再用 no-store（退回 no-cache）',
     GW_PY,
     [('    resp.headers["Cache-Control"] = ("no-store" if filename.endswith(".html")\n'
       '                                      else "no-cache")\n',
       '    resp.headers["Cache-Control"] = "no-cache"\n', 1)]),

    # ── ⑭(59) init：目录自建 ─────────────────────────────────────
    ('M23  prepare_nftweb_files 不再自建目录（chgrp 失败 ⇒ 网关起不来）',
     INIT,
     [('    mkdir -p "$_cfgdir" || return 1\n', '    :\n', 1)]),

    # ── ⑮(76) init：uid/gid=0 ────────────────────────────────────
    ('M24  ensure_nftweb_user 不再拒绝 uid/gid=0（降权等于没降）',
     INIT,
     [('        if [ "$NFTWEB_UID" = "0" ] || [ "$NFTWEB_GID" = "0" ]; then\n'
       '            echo "  ${NFTWEB_USER} 的 uid/gid 是 0（等于 root）—— 降权等于没降，拒绝启动。" >&2\n'
       '            echo "  请先修 /etc/passwd 与 /etc/group 里 ${NFTWEB_USER} 那一行。" >&2\n'
       '            return 1\n'
       '        fi\n',
       '', 1)]),

    # ── ⑯(78) init：僵尸判活 ─────────────────────────────────────
    ('M25  _proc_alive 不再把僵尸当成死进程（网关早死了却报 Started）',
     INIT,
     [('    [ "$_proc_state" = "Z" ] && return 1\n', '', 1)]),
]


def main():
    MutationGuard(ROOT).snapshot()      # 保险丝：中断也会还原源码
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-4000:])
        return 1
    print('  [OK] 基线通过\n')

    caught = missed = 0
    for name, target, edits in MUTATIONS:
        try:
            mutated = apply_edits(TARGETS[target], edits)
        except ValueError as e:
            print('  [FAIL] %s' % name)
            print('      ↓ 锚点没匹配上（源码变了？锚点该更新）: %s' % e)
            missed += 1
            continue
        try:
            with open(target, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            ok, detail = judge_capture(rc, out)
            if ok:
                print('  [OK] %s  —— 被捕获' % name)
                print('      ↓ %s' % detail)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                print('      ↓ %s' % detail)
                missed += 1
        finally:
            restore()

    print()
    print('=' * 60)
    print('结果：捕获 %d / %d' % (caught, caught + missed))
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
