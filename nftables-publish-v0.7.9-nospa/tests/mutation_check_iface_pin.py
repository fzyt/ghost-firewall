#!/usr/bin/env python3
"""变异验证：接口名钉定（iface-pin）。

覆盖两个脚本：
  setup/iface-pin.sh       —— 开机时按 MAC 把网卡改名成固定名字
  setup/iface-pin-map.sh   —— 生成/刷新「MAC → 固定名」映射表

为什么必须有这个
----------------
tests/test_iface_pin.py 有 45 条断言，但它们自己「会不会在缺陷重现时失败」
从来没被证明过 —— 于是「测试全绿」可能只是「判据根本没测到点上」。

每条变异对应一个**已经在真机上踩过、或者设计上明确禁止**的行为：
  · 2026-11-15 .232 实测事故：对有成员口的 bridge 改名 ⇒ 内核挂死 ⇒ 整机失联
  · 2026-11-15 .232 实测事故：运行期改名 ⇒ 桥变空桥 ⇒ 桥上 IP 掉 ⇒ 面板 000
  · 2026-11-15 .232 实测事故：目标名被占用就跳过 ⇒ 互占时两块卡都纠正不回来

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_iface_pin.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {
    'pin': os.path.join(ROOT, 'setup', 'iface-pin.sh'),
    'map': os.path.join(ROOT, 'setup', 'iface-pin-map.sh'),
}
TEST = os.path.join(ROOT, 'tests', 'test_iface_pin.py')

# (描述, 文件键, 旧文本, 新文本, 期望出现次数)
MUTATIONS = [
    # ── 钉名脚本：三条硬约束 ───────────────────────────────
    ('PIN-1 去掉「虚拟设备不改名」的检查（bridge/vlan 会被改名）', 'pin',
     '    # ⚠️ 硬约束 2：bridge / 虚拟设备一律不碰\n'
     '    if ! is_physical "$cur"; then\n'
     '        log "$mac 当前叫 $cur，是虚拟设备（bridge/vlan/dummy），不改名"\n'
     '        continue\n'
     '    fi',
     '    # 变异：去掉虚拟设备检查', 1),

    ('PIN-2 去掉「系统里有桥就整体跳过」的安全窗口（运行期也改名）', 'pin',
     'if has_bridge; then\n'
     '    log "检测到系统里已有桥（netifd 已在运行）—— 此时改名会拆桥，跳过。"\n'
     '    log "接口名钉定只在开机时执行（init 脚本 START=15），下次重启生效。"\n'
     '    exit 0\n'
     'fi',
     'if has_bridge; then\n'
     '    log "检测到系统里已有桥（netifd 已在运行）—— 此时改名会拆桥，跳过。"\n'
     '    log "接口名钉定只在开机时执行（init 脚本 START=15），下次重启生效。"\n'
     'fi', 1),

    ('PIN-3 改名失败时中断整体（后面的口全不处理）', 'pin',
     '        # ⚠️ 硬约束 3：失败只跳过这一个，不能中断整体\n'
     '        log "$mac: $cur -> $want 改名失败，继续处理下一个"\n'
     '    fi',
     '        # 变异：失败就整体退出\n'
     '        log "$mac: $cur -> $want 改名失败，继续处理下一个"\n'
     '        exit 1\n'
     '    fi', 1),

    ('PIN-4 目标名被占用时直接跳过（不腾位）⇒ 互占时纠正不回来', 'pin',
     '    if [ -e "$SYSFS/$want" ]; then\n'
     '        other_mac=$(cat "$SYSFS/$want/address" 2>/dev/null)\n'
     '        if [ "$other_mac" != "$mac" ]; then\n'
     '            # 占位的那个口也得是物理口才能挪（虚拟设备挪了会出事）\n'
     '            if ! is_physical "$want"; then',
     '    if [ -e "$SYSFS/$want" ]; then\n'
     '        other_mac=$(cat "$SYSFS/$want/address" 2>/dev/null)\n'
     '        if [ "$other_mac" != "$mac" ]; then\n'
     '            log "$mac 想改成 $want，但 $want 已被占用，跳过"\n'
     '            continue\n'
     '            # 占位的那个口也得是物理口才能挪（虚拟设备挪了会出事）\n'
     '            if ! is_physical "$want"; then', 1),

    ('PIN-5 按 MAC 找口时不物理口优先（同 MAC 的虚拟设备会抢走固定名）', 'pin',
     '        # 物理口优先\n'
     '        if is_physical "$_n"; then\n'
     '            echo "$_n"\n'
     '            return 0\n'
     '        fi',
     '        # 变异：不物理口优先', 1),

    # ── 执行痕迹 ────────────────────────────────────────────
    # 2026-11-15 真机踩到的坑：脚本「无事可做」时是零日志的，
    # 而「压根没跑」也是零日志 —— 两者在 logread 里长得一模一样。
    # 实测就栽在这：源文件 100644 ⇒ 设备上不可执行 ⇒ S15 钩子 rc=126
    # ⇒ 钉名保护静默失效，日志里一个字都没有。
    ('PIN-6 去掉「开始」日志（保护静默失效时没人察觉）', 'pin',
     'log "接口名钉定开始：映射表 $MAP_FILE，共 $map_count 条"',
     '# 变异：去掉开始日志', 1),

    ('PIN-7 去掉「执行完毕」收尾日志（跑没跑过都看不出来）', 'pin',
     'log "接口名钉定执行完毕：映射 $map_count 条"',
     '# 变异：去掉收尾日志', 1),

    # ── 映射表生成器 ────────────────────────────────────────
    ('MAP-1 把 bridge 也收进映射表（等于给 bridge 钉名）', 'map',
     '        try:\n'
     '            if os.path.realpath(dev) == os.path.realpath(os.path.join(NETDIR, name)):\n'
     '                continue\n'
     '        except OSError:\n'
     '            continue',
     '        try:\n'
     '            pass\n'
     '        except OSError:\n'
     '            continue', 1),

    ('MAP-2 旧表里的固定名被当前名覆盖（漂移已发生时会把错名固化成"正确名"）', 'map',
     '    for mac, name in old.items():\n'
     '        if mac in present_macs and name not in claimed:\n'
     '            data[mac] = name\n'
     '            claimed.add(name)',
     '    for mac, name in old.items():\n'
     '        if False:\n'
     '            data[mac] = name\n'
     '            claimed.add(name)', 1),

    ('MAP-3 腾位留下的临时名也被钉成固定名', 'map',
     '        if TMP_MARK in name:\n'
     '            # 腾位留下的临时名，不是稳定名 ⇒ 不钉\n'
     '            continue',
     '        if False:\n'
     '            # 变异：临时名也钉进去\n'
     '            continue', 1),

    ('MAP-4 映射表不原子写入（断电时留下半截表 ⇒ 钉名静默失效）', 'map',
     '    tmp = MAP_PATH + \'.tmp\'\n'
     '    with open(tmp, \'w\', encoding=\'utf-8\') as f:\n'
     '        json.dump(data, f, indent=2, sort_keys=True)\n'
     '        f.write(\'\\n\')\n'
     '    os.replace(tmp, MAP_PATH)',
     '    with open(MAP_PATH, \'w\', encoding=\'utf-8\') as f:\n'
     '        json.dump(data, f, indent=2, sort_keys=True)\n'
     '        f.write(\'\\n\')', 1),
]

# ── 「文件状态」类变异 ──────────────────────────────────────
# 2026-11-15 真机发现的缺陷：setup/iface-pin.sh 在 git 索引里是 100644
#   ⇒ 部署用 `tar -x` 传输、**保留权限** ⇒ 设备上也是 0644
#   ⇒ S15 init 钩子开机时 Permission denied (rc=126) ⇒ 钉名保护**静默失效**
#     （只有手动跑过 setup.sh 才会被 chmod 755 救回来）
#
# 这类变异改的是**文件状态**（mode）而不是源码文本，所以单列一批。
# ⚠ 保险丝 MutationGuard 还原时只比对**内容**，mode 变了它看不出来 ⇒
#   这里必须自己还原（见 _mode_mutate 里的 finally）。
#
# kind='disk'  ⇒ 改工作区文件的权限位（git 索引不动）
# kind='index' ⇒ 改 git 索引里的 mode（工作区文件不动）

# (描述, 文件键, kind)
MODE_MUTATIONS = [
    ('MODE-1 setup/iface-pin.sh 在工作区去掉可执行位（设备上 init 钩子 Permission denied）', 'pin', 'disk'),
    ('MODE-2 setup/iface-pin-map.sh 在工作区去掉可执行位（设备上刷不出映射表）', 'map', 'disk'),
    ('MODE-3 setup/iface-pin.sh 在 git 索引里变成 100644（部署时权限被带成不可执行）', 'pin', 'index'),
    ('MODE-4 setup/iface-pin-map.sh 在 git 索引里变成 100644（部署时权限被带成不可执行）', 'map', 'index'),
]


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      （崩了也被记成「捕获」⇒ 那个捕获是假的）。
    ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        if '[FAIL]' in s and '[PASS]' not in s:
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def run_tests():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       timeout=300, env=env)
    return r.returncode, r.stdout


def _git_index_chmod(path, plus):
    """把 git 索引里某个文件的 mode 设成 +x / -x。返回原 mode，失败返回 None。"""
    try:
        cur = subprocess.run(['git', '-C', ROOT, 'ls-files', '-s', '--',
                              os.path.relpath(path, ROOT)],
                             capture_output=True, text=True, timeout=30)
        if cur.returncode != 0 or not cur.stdout.strip():
            return None
        old_mode = cur.stdout.split()[0]
        subprocess.run(['git', '-C', ROOT, 'update-index',
                        '--chmod=%s' % ('+x' if plus else '-x'),
                        os.path.relpath(path, ROOT)],
                       capture_output=True, text=True, timeout=30, check=True)
        return old_mode
    except (OSError, subprocess.SubprocessError):
        return None


def _mode_mutate(path, kind):
    """做一次「文件状态变异」，返回 (变异前状态, 是否成功)。调用方负责还原。"""
    if kind == 'disk':
        old = os.stat(path).st_mode & 0o777
        os.chmod(path, 0o644)
        return old, True
    # kind == 'index'：索引里的 mode 改成 100644
    old_mode = _git_index_chmod(path, plus=False)
    return old_mode, old_mode is not None


def _mode_restore(path, kind, old_state):
    """还原「文件状态变异」。"""
    if kind == 'disk':
        os.chmod(path, old_state)
        return
    # 索引：按变异前的 mode 还原（不假定它一定是 100755）
    _git_index_chmod(path, plus=(old_state == '100755'))


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    backup = tempfile.mkdtemp()
    for key, path in FILES.items():
        shutil.copy(path, os.path.join(backup, key))
    originals = {key: open(path, encoding='utf-8').read() for key, path in FILES.items()}

    def restore():
        for key, path in FILES.items():
            shutil.copy(os.path.join(backup, key), path)

    print('=== 变异验证：接口名钉定 ===')
    rc, _ = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不是全绿，先修好再谈变异')
        restore()
        shutil.rmtree(backup, ignore_errors=True)
        return 1

    caught = missed = skipped = 0
    missed_list = []
    for desc, key, old, new, expect in MUTATIONS:
        src = originals[key]
        n = src.count(old)
        if n != expect:
            print(f'  [WARN] {desc} —— 锚点出现 {n} 次（期望 {expect}），跳过')
            skipped += 1
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src.replace(old, new))
        rc, out = run_tests()
        fails = out.count('[FAIL]')
        if _judge_capture(rc, out):
            print(f'  [PASS] {desc} —— 被捕获（{fails} 条断言失败）')
            caught += 1
        else:
            print(f'  [FAIL] {desc} —— 测试仍然全绿（无效变异！）')
            missed += 1
            missed_list.append(desc)
        restore()

    # ── 文件状态类变异（mode）─────────────────────────────────
    for desc, key, kind in MODE_MUTATIONS:
        path = FILES[key]
        old_state, ok = _mode_mutate(path, kind)
        if not ok:
            print(f'  [WARN] {desc} —— 无法施加变异（git 不可用或文件未入索引），跳过')
            skipped += 1
            continue
        try:
            rc, out = run_tests()
            fails = out.count('[FAIL]')
            if _judge_capture(rc, out):
                print(f'  [PASS] {desc} —— 被捕获（{fails} 条断言失败）')
                caught += 1
            else:
                print(f'  [FAIL] {desc} —— 测试仍然全绿（无效变异！）')
                missed += 1
                missed_list.append(desc)
        finally:
            _mode_restore(path, kind, old_state)

    total = caught + missed + skipped
    print(f'\n=== 结果：捕获 {caught} / {total}'
          + (f'（跳过 {skipped}）' if skipped else '') + ' ===')
    for m in missed_list:
        print('  未捕获: ' + m)
    restore()
    shutil.rmtree(backup, ignore_errors=True)
    return 0 if missed == 0 and skipped == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
