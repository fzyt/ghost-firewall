"""反代上游 Host 头这一批的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_gateway_host_header.py

测什么：把 Host 转发往**各个方向**退化的行为。

为什么这批必须有变异脚本：
    「Host 头带不带端口」这种改动，光看单测全绿**不能证明它在守东西** ——
    只要有人把 `$host:$server_port` 改回 `$host`，功能立刻坏掉
    （上游 401「invalid request origin」，症状是「密码页能开、输完密码进不去」），
    但一个字符串断言放在错误的作用域里（比如盯了门户页那行）就会照样绿。
    变异脚本就是用来证明「这些断言真的会红」。

**不要用 `tests/_mutation_guard.py` 的 `MutationGuard`** ——
它的全快照还原会把**别的 agent 正在改的文件**一起写回去
（实测已造成并行改动丢失两次）。这里只备份/还原自己动的那一个文件。
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
TEST_PY = os.path.join(ROOT, 'tests', 'test_gateway_host_header.py')

ORIG = {APP_PY: open(APP_PY, encoding='utf-8').read()}

HOST_LINE = '    L.append("        proxy_set_header Host $host:$server_port;")'
XFH_LINE = '    L.append("        proxy_set_header X-Forwarded-Host $host:$server_port;")'

MUTATIONS = [
    # M1 —— 本轮修的真问题：端口一丢，上游就 401。
    # 症状不是「打不开」，而是「密码页正常、输完密码进不去主界面」，
    # 极难联想到是 Host 头少了端口 ⇒ 必须有测试钉住。
    ('M1 反代上游的 Host 头丢掉端口（上游 origin 校验会拒绝）',
     APP_PY, [(HOST_LINE,
               '    L.append("        proxy_set_header Host $host;")')]),

    # M2 —— 端口用回客户端可控的 $http_port：
    # 攻击者能把自己的「端口」塞进 Host 头 ⇒ 又是 Host Header Injection。
    ('M2 反代上游的 Host 头端口改用客户端可控的 $http_port',
     APP_PY, [(HOST_LINE,
               '    L.append("        proxy_set_header Host $host:$http_port;")')]),

    # M3 —— 退回 $http_host：整个主机名都变回客户端可控。
    ('M3 反代上游的 Host 头整段退回客户端可控的 $http_host',
     APP_PY, [(HOST_LINE,
               '    L.append("        proxy_set_header Host $http_host:$server_port;")')]),

    # M4 —— 端口写死 8443：网关端口一改（用户很常改）就又对不上了。
    # 这条退化是「功能能跑一阵，换个端口就坏」，最难自己发现。
    ('M4 反代上游的 Host 头端口写死成 8443',
     APP_PY, [(HOST_LINE,
               '    L.append("        proxy_set_header Host $host:8443;")')]),

    # M5 —— 干脆不转发 Host：上游会拿到 nginx 自己的默认 Host
    # （形如 127.0.0.1:6807）⇒ 同样对不上 Origin。
    ('M5 反代上游根本不转发 Host 头',
     APP_PY, [(HOST_LINE, '')]),

    # M6 —— X-Forwarded-Host 丢掉端口：上游拼绝对 URL（回调地址、分享链接）
    # 会指到 443，而网关根本不在 443 上。
    ('M6 X-Forwarded-Host 丢掉端口',
     APP_PY, [(XFH_LINE,
               '    L.append("        proxy_set_header X-Forwarded-Host $host;")')]),

    # M7 —— X-Forwarded-Host 退回 $http_host。
    ('M7 X-Forwarded-Host 退回客户端可控的 $http_host',
     APP_PY, [(XFH_LINE,
               '    L.append("        proxy_set_header X-Forwarded-Host $http_host;")')]),
]


def run_tests():
    r = subprocess.run([sys.executable, TEST_PY], capture_output=True,
                       text=True, cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def restore():
    for path, content in ORIG.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


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
            print('      ↓ 变异锚点没匹配上（源码变了？），跳过')
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
