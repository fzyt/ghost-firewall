"""「敏感文件落盘即正确」的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_secret_perms.py

测什么有效：权限修复最危险的退化不是「写错了」，而是**又变回「先写、再 chmod」**。
那种代码读起来完全正常、成功路径也确实工作，事后 chmod 一补，**单测很容易全绿**
—— 只有真的把「落盘那一刻就是目标权限」拆掉，测试才会变红。

所以下面每条变异都往「先写后 chmod」这个方向改；抓不住就说明测试是假测试。

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。
"""
import os
import shutil
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_secret_file_perms.py')

ORIG_APP = open(APP_PY, encoding='utf-8').read()


def replace_nth(src, old, new, nth=0):
    """替换 old 的第 nth 次出现（0 起）。找不到就抛异常 —— 别静默跳过。"""
    idx = -1
    for _ in range(nth + 1):
        idx = src.find(old, idx + 1)
        if idx == -1:
            raise ValueError(f'锚点没找到（第 {nth + 1} 次出现）: {old!r}')
    return src[:idx] + new + src[idx + len(old):]


def apply_edits(src, edits):
    """edits: [(old, new, nth, count)]，count 可以是 'all' 表示全部出现。"""
    for old, new, nth, count in edits:
        if count == 'all':
            src = src.replace(old, new)
        else:
            src = replace_nth(src, old, new, nth)
    return src


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def restore():
    with open(APP_PY, 'w', encoding='utf-8') as f:
        f.write(ORIG_APP)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# 每条变异都只改 backend/app.py
MUTATIONS = [
    ('M1  私钥 tmp 不预建权限（回退成「先写后 chmod」）',
     [('        _ensure_file_mode(tmp_k, 0o600)\n', '', 0, 'all')]),

    ('M2  阿里云 AccessKey secret 不预建权限',
     [('    _ensure_file_mode(ALIYUN_DDNS_CONFIG_PATH, 0o600)\n', '', 0, 'all')]),

    ('M3  面板口令文件不预建权限',
     [('    _ensure_file_mode(AUTH_PASSWORD_FILE, 0o640)\n', '', 0, 'all')]),

    ('M4  名单 tmp 不预建权限',
     [('        _ensure_file_mode(tmp, 0o600)\n', '', 0, 'all')]),

    ('M5  规则集 tmp 不预建权限',
     [('    _ensure_file_mode(tmp_path, 0o600)\n', '', 0, 'all')]),

    ('M6  名单锁 os.open 不带 mode（靠后面的 chmod 兜）',
     [('os.open(LISTS_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)',
       'os.open(LISTS_LOCK_PATH, os.O_CREAT | os.O_RDWR)', 0, 'all')]),

    ('M7  save_config 的锁 os.open 不带 mode',
     [('os.open(lock_path, os.O_CREAT | os.O_RDWR, _CONFIG_FILE_MODE)',
       'os.open(lock_path, os.O_CREAT | os.O_RDWR)', 0, 1)]),

    ('M8  restore_config 的锁 os.open 不带 mode（同一个锁文件）',
     [('os.open(lock_path, os.O_CREAT | os.O_RDWR, _CONFIG_FILE_MODE)',
       'os.open(lock_path, os.O_CREAT | os.O_RDWR)', 1, 1)]),

    ('M9  配置 .backup 不预建权限（shutil.copy 按 umask 建 ⇒ 先 0644）',
     [('        _ensure_file_mode(CONFIG_PATH + \'.backup\', _CONFIG_FILE_MODE)\n',
       '', 0, 'all')]),

    ('M10 恢复用的 tmp 不预建权限（shutil.copy 按 umask 建 ⇒ 先 0644）',
     [('        _ensure_file_mode(tmp_path, _CONFIG_FILE_MODE)\n'
       '        shutil.copy(backup_path, tmp_path)',
       '        shutil.copy(backup_path, tmp_path)', 0, 1)]),

    ('M11 _ensure_file_mode 整体退化：不再预建文件（只剩事后 chmod）',
     [('        fd = os.open(path, os.O_CREAT | os.O_WRONLY, mode)\n'
       '        os.close(fd)',
       '        pass', 0, 1)]),
]


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        try:
            mutated = apply_edits(ORIG_APP, edits)
        except ValueError as e:
            print(f'  ⚠️  {name}')
            print(f'      ↓ 变异锚点没匹配上（源码变了？），跳过: {e}')
            missed += 1
            continue
        try:
            with open(APP_PY, 'w', encoding='utf-8') as f:
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
