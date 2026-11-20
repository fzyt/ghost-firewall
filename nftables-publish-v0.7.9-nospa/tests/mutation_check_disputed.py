"""用户拍板的两条争议条目的变异验证（2026-11-05）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_disputed.py

测什么有效
----------
这两条改动都是**安全默认值 / 行为闸门**，最危险的退化恰恰是
「看起来还在、其实已经不生效了」：

  P2-5  auth_lan_bypass 缺省改成 False
        · 缺省改回 True ⇒ 全新安装又天然落进「网关开 + 免登录」
        · 只改 DEFAULT_CONFIG 不改读取处的兜底 ⇒ 配置里没这个键时
          网关状态仍显示 True（界面显示与实际生效对不上）
        · 网关侧兜底改回 True ⇒ 两边又不一致了

  P1-24  POST /api/config 强制要求 config_rev
        · 闸门被摘掉（回到「不带就放行」）⇒ 又能用旧快照覆盖新配置
        · 闸门改成 400 而不是 409 ⇒ 调用方分不清「格式错」和「快照过期」
        · 拒收时**仍然写盘** ⇒ 闸门形同虚设
        · 版本号被剔进 incoming 之前就被 pop 掉 ⇒ 比对的是空串

保险丝：只备份 / 还原**本脚本会动的那几个文件**。
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
GW_PY = os.path.join(ROOT, 'backend', 'auth_gateway.py')
FRONT_JS = os.path.join(ROOT, 'frontend', 'app.js')
TEST = os.path.join(ROOT, 'tests', 'test_disputed_decisions.py')

REL_FILES = [
    os.path.join('backend', 'app.py'),
    os.path.join('backend', 'auth_gateway.py'),
    os.path.join('frontend', 'app.js'),
]
ORIG = {}
for rel in REL_FILES:
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        ORIG[os.path.join(ROOT, rel)] = f.read()


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      （2026-11-11 审查 M8：崩了也被记成「捕获」⇒ 那个捕获是假的）。
    ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获；
      只有崩溃、没有失败行的 ⇒ 算漏网（宁可漏判，不可假捕获）。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        # 失败标记用 Unicode 转义写：源码里不出现符号本身（AGENTS.md 禁 emoji）
        if ('[FAIL]' in s and '[PASS]' not in s) or \
                ('\u274c' in s and '\u2705' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


atexit.register(restore)
for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, lambda *a: (restore(), sys.exit(130)))
    except (ValueError, OSError):
        pass


def run_tests():
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=600, env=env)
    return r.returncode, (r.stdout + r.stderr)


def apply_edits(path, edits):
    src = ORIG[path]
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点在 %s 里出现 %d 次，必须唯一：%r'
                             % (os.path.basename(path), n, old[:70]))
        src = src.replace(old, new, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)


MUTATIONS = [
    ('D-01  P2-5 缺省改回 True（全新安装又天然「网关开 + 免登录」）',
     APP_PY,
     [('    "auth_lan_bypass": False,\n',
       '    "auth_lan_bypass": True,\n')]),

    ('D-02  P2-5 读取处的兜底改回 True（界面显示与实际生效对不上）',
     APP_PY,
     [('            "lan_bypass": bool(config.get("auth_lan_bypass", False)),\n',
       '            "lan_bypass": bool(config.get("auth_lan_bypass", True)),\n')]),

    ('D-03  P2-5 网关侧兜底改回 True（两边又不一致）',
     GW_PY,
     [('    if not cfg.get("auth_lan_bypass", False):\n',
       '    if not cfg.get("auth_lan_bypass", True):\n')]),

    ('D-04  P1-24 版本闸被摘掉（又能用旧快照覆盖新配置）',
     APP_PY,
     [('''        if not sent_rev:
            raise _ConfigRejected(
                'CONFIG_REV_REQUIRED',
                '本次保存缺少配置版本号（config_rev），已拒绝。'
                '请先 GET /api/config 取一份最新快照，'
                '带上 config_rev 再提交。',
                409, {'data': {'config_rev': cur_rev}})
''',
       '''        if False:
            pass
''')]),

    ('D-05  P1-24 拒收时仍继续写盘（闸门形同虚设）',
     APP_PY,
     [('''        if not sent_rev:
            raise _ConfigRejected(
                'CONFIG_REV_REQUIRED',
                '本次保存缺少配置版本号（config_rev），已拒绝。'
                '请先 GET /api/config 取一份最新快照，'
                '带上 config_rev 再提交。',
                409, {'data': {'config_rev': cur_rev}})
        if sent_rev != cur_rev:
            raise _ConfigRejected(
                'CONFIG_STALE',
                '配置在你打开页面之后被改过，本次保存会覆盖掉那些改动，'
                '已拒绝。请刷新页面后重新编辑。',
                409, {'data': {'config_rev': cur_rev}})
''',
       '''        print('[WARN] 缺少 config_rev，仍然放行', flush=True)
''')]),

    ('D-06  P1-24 拒收用 400 而不是 409（调用方分不清「格式错」和「快照过期」）',
     APP_PY,
     [("        if not sent_rev:\n"
       "            raise _ConfigRejected(\n"
       "                'CONFIG_REV_REQUIRED',\n"
       "                '本次保存缺少配置版本号（config_rev），已拒绝。'\n"
       "                '请先 GET /api/config 取一份最新快照，'\n"
       "                '带上 config_rev 再提交。',\n"
       "                409, {'data': {'config_rev': cur_rev}})\n",
       "        if not sent_rev:\n"
       "            raise _ConfigRejected(\n"
       "                'CONFIG_REV_REQUIRED',\n"
       "                '本次保存缺少配置版本号（config_rev），已拒绝。'\n"
       "                '请先 GET /api/config 取一份最新快照，'\n"
       "                '带上 config_rev 再提交。',\n"
       "                400, {'data': {'config_rev': cur_rev}})\n")]),

    ('D-07  P1-24 版本比对被判废（过期快照也能写盘）',
     APP_PY,
     [('        if sent_rev != cur_rev:\n',
       '        if sent_rev != cur_rev and False:\n')]),

    ('D-08  P1-24 拒收时不把当前版本号回给调用方（它没法重试）',
     APP_PY,
     [("        if not sent_rev:\n"
       "            raise _ConfigRejected(\n"
       "                'CONFIG_REV_REQUIRED',\n"
       "                '本次保存缺少配置版本号（config_rev），已拒绝。'\n"
       "                '请先 GET /api/config 取一份最新快照，'\n"
       "                '带上 config_rev 再提交。',\n"
       "                409, {'data': {'config_rev': cur_rev}})\n",
       "        if not sent_rev:\n"
       "            raise _ConfigRejected(\n"
       "                'CONFIG_REV_REQUIRED',\n"
       "                '本次保存缺少配置版本号（config_rev），已拒绝。'\n"
       "                '请先 GET /api/config 取一份最新快照，'\n"
       "                '带上 config_rev 再提交。',\n"
       "                409, {'data': {}})\n")]),

    ('D-09  P2-5 前端不再处理 CONFIG_REV_REQUIRED（用户看不懂为什么被拒）',
     FRONT_JS,
     [("        if (e.code === 'CONFIG_REV_REQUIRED') {\n",
       "        if (false && e.code === 'CONFIG_REV_REQUIRED') {\n")]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if _judge_capture(rc, out):
        print('原始状态下测试就是红的，先修测试再跑变异：')
        print(out[-3000:])
        return 2
    print('原始状态：测试通过（%d 项）' % out.count('[PASS]'))
    print()

    caught, missed = 0, []
    for name, path, edits in MUTATIONS:
        restore()
        try:
            apply_edits(path, edits)
        except ValueError as e:
            print(f'  [脚本错] {name}')
            print(f'      ↓ {e}')
            missed.append(f'{name}（变异脚本自身的错）')
            continue
        rc, out = run_tests()
        if _judge_capture(rc, out):
            caught += 1
            first = ''
            for line in out.splitlines():
                st = line.strip()
                if st.startswith('[FAIL]'):
                    first = st
                    break
            print(f'  [捕获] {name}')
            if first:
                print(f'      ↓ {first[:150]}')
        else:
            missed.append(name)
            print(f'  [漏网] {name}  ← 测试没变红！')

    restore()
    print()
    print('=' * 60)
    print(f'  变异 {len(MUTATIONS)} 条，捕获 {caught} 条，漏网 {len(missed)} 条')
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        return 1
    print('  全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
