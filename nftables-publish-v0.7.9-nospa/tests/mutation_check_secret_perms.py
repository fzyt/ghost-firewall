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

    # ⚠️ 锚点缩进必须是源码里的**真实缩进**（12 空格）。
    #   之前写的是 8 空格 —— 那匹配到的是行内子串（前 8 个空格属于 12 空格那一行的
    #   一部分），删除后残留 4 个空格把下一行 `shutil.copy(...)` 撑成 16 空格
    #   ⇒ IndentationError ⇒ app.py 语法错误 ⇒ 测试**崩了**而不是**断言失败**。
    #   崩溃被旧的「rc != 0 即算捕获」口径记成假捕获（2026-11-11 审查 M8）。
    #   ⇒ 缩进写错不是「锚点未命中」，而是**匹配到了一个错误的子串** —— 更隐蔽。
    ('M9  配置 .backup 不预建权限（shutil.copy 按 umask 建 ⇒ 先 0644）',
     [('            _ensure_file_mode(CONFIG_PATH + \'.backup\', _CONFIG_FILE_MODE)\n',
       '', 0, 'all')]),

    # ⚠️ 2026-11-08：这条的锚点跟着 restore_config 的实现改过**两次**。
    #
    # 第一次：原来的锚点是「_ensure_file_mode(tmp_path, ...) 紧跟 shutil.copy(backup_path, tmp_path)」
    # —— 修了「恢复配置回退 auth_token_epoch」之后，restore 路径不再整份拷贝 backup，
    # 改成「读 JSON → 改世代号 → 写 tmp」，两行锚点就失配了，
    # 变异被**静默跳过**（扫描器报「锚点未命中」，当失败处理才没被当成通过）。
    #
    # 第二次（2026-11-08 C3）：锚点换成了「_ensure_file_mode 紧跟 epoch 赋值」那一整块，
    # 结果 C3 又往这两行**中间插了一段**（缺失字段继承当前生效值）⇒ 又失配 ⇒
    # 变异又被静默跳过 ⇒ 脚本自报 10/11，扫描器把这一份标成 [BAD]。
    #
    # ⇒ 教训：**锚点要钉在「这段代码独有的语义」上，不要钉在
    #    「A 和 B 恰好挨在一起」上** —— 往中间插一行就全废。
    #    现在用的是**纯代码**三行（`json.dump(restored, ...)` 只有 restore_config 有），
    #    不含任何注释 ⇒ 改注释、插代码都不会再把它打散。
    #
    # 这条变异本身**依然有意义**：restore 路径用
    # 「_ensure_file_mode 先建好 tmp(0640) → open('w') 只截断不改权限」落盘，
    # 去掉 _ensure_file_mode 就会按 umask 建出 0644 的 tmp ⇒ 落盘有可读窗口。
    ('M10 恢复用的 tmp 不预建权限（open 按 umask 建 ⇒ 先 0644）',
     [('        _ensure_file_mode(tmp_path, _CONFIG_FILE_MODE)\n'
       '        with open(tmp_path, \'w\') as f:\n'
       '            json.dump(restored, f, indent=2, ensure_ascii=False)\n',
       '        with open(tmp_path, \'w\') as f:\n'
       '            json.dump(restored, f, indent=2, ensure_ascii=False)\n', 0, 1)]),

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
            if _judge_capture(rc, out):
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
