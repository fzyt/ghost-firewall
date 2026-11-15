#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变异验证：LAN 桥成员口（多 LAN 口）。

覆盖：backend/app.py 里的 LAN 成员口读写链路。

为什么必须有这个
----------------
tests/test_lan_members.py 有 54 条断言，但它们自己「会不会在缺陷重现时失败」
从来没被证明过 —— 于是「测试全绿」可能只是「判据根本没测到点上」。

这块功能的失败模式是**整机失联**（不是「配置不对」）：
  · 把 WAN 口划进 LAN 桥 ⇒ WAN 没口了 ⇒ 断网；
  · 把 LAN 桥的成员清空 ⇒ 桥没 IP ⇒ 管理口失联，路由器变砖。

⇒ 每条变异都对着这些「会让设备失联」的行为。

关于「等价变异」
--------------
实现里有**两道**各自完整的空列表拦截：
  (a) `if not isinstance(raw, list) or not raw:` —— 请求体层
  (b) `if not members:`                   —— 清洗后层
两条**各自单独就足够**，同时存在属于纵深防御。
所以把其中一条拿掉，可观测行为完全不变（另一条兜住）⇒ 那是等价变异，
不是测试有洞。真正会退化的，是**两条同时拿掉** —— 那条单列在 MUTATIONS 里。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_lan_members.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {'app': os.path.join(ROOT, 'backend', 'app.py')}
TEST = os.path.join(ROOT, 'tests', 'test_lan_members.py')

# (描述, 文件键, [(旧文本, 新文本), ...])
MUTATIONS = [
    ('LAN-1 空列表的两道拦截同时放开（清空 LAN 桥 = 失联）', 'app', [
        ('    if not isinstance(raw, list) or not raw:\n',
         '    if not isinstance(raw, list):\n'),
        ('    if not members:\n',
         '    if False:\n'),
    ]),

    ('LAN-2 不拦「已被 WAN/其它接口占用的口」（把 WAN 划进 LAN = 断网）', 'app', [
        ('        if m in reserved:\n',
         '        if False:\n'),
    ]),

    ('LAN-3 不拦「不是物理网卡的接口」（桥/VLAN 混进成员口）', 'app', [
        ('        if not _is_physical_iface(m):\n',
         '        if False:\n'),
    ]),

    ('LAN-4 不拦「本机不存在的口」', 'app', [
        ('        if not os.path.exists(os.path.join(SYSFS_NET_ROOT, m)):\n',
         '        if False:\n'),
    ]),

    ('LAN-5 改写桥段时旧 ports 行不删（追加而不是替换）', 'app', [
        ("    kept = [l for l in body if not _UCI_PORTS_RE.match(l.strip())]\n",
         "    kept = list(body)\n"),
    ]),

    ('LAN-7 写完不回读校验（内容写错了也照样报成功）', 'app', [
        ('    if sorted(got) != sorted(members):\n',
         '    if False:\n'),
    ]),

    ('LAN-8 写之前不备份（出事没法回滚）', 'app', [
        ("    _ensure_file_mode(path + '.backup', _network_config_mode(path))\n"
         "    shutil.copy(path, path + '.backup')\n"
         "    try:\n"
         "        os.chmod(path + '.backup', _network_config_mode(path))\n"
         "    except OSError:\n"
         "        pass\n"
         "\n"
         "    try:\n"
         "        _atomic_write_network_config(path, new)\n",
         "    try:\n"
         "        _atomic_write_network_config(path, new)\n"),
    ]),

    ('LAN-9 写完不刷新接口名钉定映射表（新口下次重启照样会漂）', 'app', [
        ('    _refresh_iface_pin_map()\n',
         '    pass  # 变异：不刷新映射表\n'),
    ]),

    ('LAN-10 不把「默认路由走的口」算进被占用名单（WAN 自动挑的机器会断网）', 'app', [
        ('    route_dev = _default_route_dev()\n'
         '    if route_dev and route_dev != bridge and _is_physical_iface(route_dev):\n'
         '        out.add(route_dev)\n',
         '    route_dev = _default_route_dev()\n'
         '    if False and route_dev:\n'
         '        out.add(route_dev)\n'),
    ]),
]

# 等价变异：改掉之后**可观测行为完全不变**，不是测试有洞。
# 理由写在每一条后面。
EQUIVALENT = {
    'LAN-E1 只放开请求体层的空列表拦截':
        '等价变异 —— 清洗后的 `if not members:` 仍会兜住空列表，'
        '两条同时放开才会退化（那条已单列在 MUTATIONS 里）',
    'LAN-E2 只放开清洗后的空列表拦截':
        '等价变异 —— 请求体层的 `or not raw` 仍会兜住空列表',
    'LAN-E3 ports 行插到段尾空行之后':
        '等价变异 —— UCI 的段由**下一个 config 行**结束，空行只是空行，'
        'ports 放在空行前还是后对 uci 解析没有区别（实测：改写结果完全一致）',
}


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」。
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
                       timeout=600, env=env, cwd=ROOT)
    return r.returncode, r.stdout


def main():
    MutationGuard(ROOT).snapshot()
    backup = tempfile.mkdtemp()
    for key, path in FILES.items():
        shutil.copy(path, os.path.join(backup, key))
    originals = {key: open(path, encoding='utf-8').read()
                 for key, path in FILES.items()}

    def restore():
        for key, path in FILES.items():
            shutil.copy(os.path.join(backup, key), path)

    print('=== 变异验证：LAN 桥成员口（多 LAN 口） ===')
    rc, _ = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不是全绿，先修好再谈变异')
        restore()
        shutil.rmtree(backup, ignore_errors=True)
        return 1

    # 等价变异：先单独跑，确认「拿掉一条仍然全绿」确实成立。
    equiv_ok = []
    for desc, key, pairs in [
        ('LAN-E1 只放开请求体层的空列表拦截', 'app', [
            ('    if not isinstance(raw, list) or not raw:\n',
             '    if not isinstance(raw, list):\n'),
        ]),
        ('LAN-E2 只放开清洗后的空列表拦截', 'app', [
            ('    if not members:\n',
             '    if False:\n'),
        ]),
        ('LAN-E3 ports 行插到段尾空行之后', 'app', [
            ("    out = lines[:start + 1] + kept + new_ports + tail + lines[end:]\n",
             "    out = lines[:start + 1] + kept + tail + new_ports + lines[end:]\n"),
        ]),
    ]:
        src = originals[key]
        bad = False
        for old, new in pairs:
            if src.count(old) != 1:
                print(f'  [WARN] {desc} —— 锚点出现 {src.count(old)} 次（期望 1）')
                bad = True
                break
            src = src.replace(old, new, 1)
        if bad:
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src)
        rc, _ = run_tests()
        restore()
        if rc == 0:
            equiv_ok.append(desc)
            print(f'  [等价] {desc} —— {EQUIVALENT[desc]}')
        else:
            print(f'  [注意] {desc} 竟然被抓住了 —— 它不是等价变异，'
                  f'请把它挪进 MUTATIONS')

    caught = missed = skipped = 0
    missed_list = []
    for desc, key, pairs in MUTATIONS:
        src = originals[key]
        ok = True
        for old, new in pairs:
            n = src.count(old)
            if n != 1:
                print(f'  [WARN] {desc} —— 锚点出现 {n} 次（期望 1），跳过')
                ok = False
                break
            src = src.replace(old, new, 1)
        if not ok:
            skipped += 1
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src)
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

    total = caught + missed + skipped
    print(f'\n=== 结果：捕获 {caught} / {total}'
          + (f'（跳过 {skipped}）' if skipped else '')
          + f'；等价变异 {len(equiv_ok)} 条 ===')
    for m in missed_list:
        print('  未捕获: ' + m)
    restore()
    shutil.rmtree(backup, ignore_errors=True)
    return 0 if missed == 0 and skipped == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
