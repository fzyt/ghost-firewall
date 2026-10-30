"""面板侧认证/会话/访问边界批次的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_panel_auth_fixes.py

测什么有效：这类修复最危险的退化不是「写错了」，而是**改回原来的宽松行为**。
那些代码读起来完全正常、成功路径也确实工作 —— 单测很容易全绿，
只有真的把「二次认证」「绝对 TTL」「no-store」这些拆掉，测试才会变红。

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。
"""
import atexit
import os
import shutil
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
TEST_PY = os.path.join(ROOT, 'tests', 'test_panel_auth_fixes.py')
TEST_JS = os.path.join(ROOT, 'tests', 'test_frontend_credential_clear.js')

ORIG_APP = open(APP_PY, encoding='utf-8').read()
ORIG_JS = open(APP_JS, encoding='utf-8').read()
ORIG = {APP_PY: ORIG_APP, APP_JS: ORIG_JS}

# ⚠️ 这里**故意不用** tests/_mutation_guard.py 的 MutationGuard。
#
# 原因（2026-10-30 实测踩到）：MutationGuard 启动时会清理「上次被硬杀的残留快照」，
# 而它还原的是**快照里的所有文件** —— 不只是本脚本改的那两个。
# 同仓库里有别的 agent 在并行改别的文件时，那一次清理会把**别人的改动覆盖掉**
# （实测把并行 agent 正在改的 backend/auth_gateway.py 和
#   backend/nftables-web-auth.init 还原掉了）。
#
# 所以本脚本只备份/还原**自己会动的那两个文件**，一个字节都不碰别的。
# 保险丝（atexit + 信号处理）自己做，最小但够用。


def run_tests():
    """跑本批次的两个测试文件（Python + 前端）。任何一个红就算变异被抓。"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    rc = 0
    out = []
    for t in (TEST_PY, TEST_JS):
        r = subprocess.run([sys.executable if t.endswith('.py') else 'node', t],
                           capture_output=True, text=True, cwd=ROOT,
                           timeout=300, env=env)
        rc = rc or r.returncode
        out.append(r.stdout + r.stderr)
    return rc, '\n'.join(out)


def restore():
    for path, content in ORIG.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# 保险丝：被取消 / 被 kill 时也把变异还原（只还原上面那两个文件）
def _install_fuse():
    def _handler(signum, frame):
        restore()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _handler)
        except Exception:
            pass
    atexit.register(restore)


# (描述, 文件, [(旧串, 新串), ...])
MUTATIONS = [
    ('M1  私钥下载不再要求二次认证（任何面板会话都能导出）',
     APP_PY, [("    confirm = (request.headers.get('X-Confirm-Password') or '').strip()",
               "    confirm = (request.headers.get('X-Confirm-Password') or '') or 'x'")]),

    ('M2  会话不再检查绝对生命周期上限',
     APP_PY, [("        if _session_absolute_expired():",
               "        if False:")]),

    ('M3  登录时不打会话起点戳（绝对 TTL 永远不生效）',
     APP_PY, [("    _mark_session_start()", "    pass")]),

    ('M4  LAN 判断不再拒绝 /1 及更大的网段',
     APP_PY, [("                if net.prefixlen <= 1:\n                    continue\n",
               "")]),

    ('M5  auth_api_port 不再与面板 HTTPS 端口交叉校验',
     APP_PY, [("        if _is_port(api_port) and int(api_port) == int(HTTPS_PORT):",
               "        if False:")]),

    ('M6  面板的 cookie 域退回「自己从证书 SAN 推导」（与网关不一致）',
     APP_PY, [('    bd = ""\n'
               '    if "base_domain" in settings:\n'
               '        try:\n'
               '            bd = _sanitize_rp_host(\n'
               '                str(settings.get("base_domain") or "").strip().lower())\n'
               '        except ValueError:\n'
               '            bd = ""\n',
               '    bd = _rp_base_domain(config)\n')]),

    ('M7  证书 SAN 推出的域名不再净化（非法值直接落盘）',
     APP_PY, [("        try:\n            derived = _sanitize_rp_host(derived)",
               "        try:\n            derived = derived")]),

    ('M8  认证数据响应不再带 Cache-Control: no-store',
     APP_PY, [("        resp.headers.setdefault('Cache-Control', 'no-store')",
               "        pass")]),

    ('M9  预置名单退回「每条查一次内核 set」（查询次数随条数增长）',
     APP_PY, [("        members = _nft_set_members(set_name)\n"
               "        for idx, ip in items:\n"
               "            out[idx] = ip in members",
               "        for idx, ip in items:\n"
               "            out[idx] = ip in _nft_set_members(set_name)")]),

    ('M10 预置名单不再有条数上限',
     APP_PY, [("    if len(presets) >= PRESET_MAX:", "    if False:")]),

    ('M11 登出时不再清空阿里云凭据',
     APP_JS, [("      this.aliyun = {\n"
               "        installed: false,\n"
               "        configured: false,\n"
               "        accessKeyId: '',\n"
               "        accessKeySecret: '',\n"
               "        regionId: 'cn-hangzhou',\n"
               "        domain: '',\n"
               "        records: [],\n"
               "        localRecords: [],\n"
               "        ipv6Sources: [],\n"
               "        loading: false\n"
               "      };",
               "      // 变异：不再清空阿里云凭据")]),

    ('M12 登出时不再清空 DDNS 服务口令',
     APP_JS, [("          s.password = '';\n          s.param_enc = '';",
               "          // 变异：不清空")]),

    ('M13 登出时不再清空 PPPoE 宽带口令',
     APP_JS, [("      this.networkConfig.wan_pppoe_password = '';",
               "      // 变异：不清空")]),

    ('M14 面板不再读 init 写的开机恢复状态（降级了也报「正常」）',
     APP_PY, [("        recovery = _read_recovery_status()",
               "        recovery = None")]),

    ('M15 面板不把非 ok 的恢复状态标成降级',
     APP_PY, [("            \"recovery_degraded\": bool(recovery and recovery.get('state') != 'ok'),",
               "            \"recovery_degraded\": False,")]),
]


def main():
    _install_fuse()
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, path, edits in MUTATIONS:
        src = ORIG[path]
        bad = [old for old, _ in edits if old not in src]
        if bad:
            print(f'  ⚠️  {name}')
            print(f'      ↓ 变异锚点没匹配上（源码变了？），跳过')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '❌' in l), '')
                print(f'  ✅ {name}  —— 被捕获')
                print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  ❌ {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            restore()

    print()
    print(f'════════ 结果：捕获 {caught} / {caught + missed} ════════')
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 ❌ 的测试是假测试')
    else:
        print('源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
