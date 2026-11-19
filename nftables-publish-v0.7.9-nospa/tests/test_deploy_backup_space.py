#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署备份轮转与空间预检（2026-11-19）

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_deploy_backup_space.py

背景
----
给 .193 部署「访问日志封顶」时踩到：

    cp: can't create '.../etc-nftables/backup/dhcp...': No space left on device
    cp: write error: No space left on device
    ❌ 回滚脚本生成失败
    ❌ 正在回滚：/root/nftables-web-backups/20261119-104634/restore.sh

设备的 /overlay 总共只有 86MB，而**每份部署备份 3.6MB**（backend+frontend 的代码）。
备份目录当时堆了 7 份 ⇒ 25MB ⇒ 磁盘 100% 满 ⇒ 备份阶段直接炸。

更要命的是这个坑会**自我加深**
--------------------------------
备份轮转原本只在部署**成功后**跑（phase_summary 之后的 prune_backups）。
部署失败 ⇒ 轮转没跑 ⇒ 这次失败的备份目录**又留在设备上**
⇒ 设备更满 ⇒ 下一次部署连备份都做不完 ⇒ 越失败越没空间。

所以修两处
----------
  ① 备份**之前**先轮转（给新备份腾位置）
  ② 备份前做可用空间预检：不够就**提前说人话**，
     而不是让 cp 报 "No space left on device"、报错还指向 cp，
     根本看不出真因是「磁盘满了」

沙箱
----
轮转逻辑是**真的删除命令**，所以这里在本地临时目录里跑它
（把设备上的备份根换成沙箱目录），**绝不碰真设备**。
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, 'tools', 'deploy.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def extract_func(src, name):
    m = re.search(r'^' + re.escape(name) + r'\(\) \{', src, re.M)
    if not m:
        return ''
    end = src.find('\n}\n', m.start())
    if end < 0:
        return ''
    return src[m.start():end + 3]


HARNESS = r'''#!/bin/bash
set -euo pipefail
BACKUP_ROOT="__SANDBOX__"
SANDBOX="__SANDBOX__"
rssh() {
    # 把命令里的设备备份根换成本地沙箱目录，再原样执行
    local cmd="$1"
    cmd="${cmd//$BACKUP_ROOT/$SANDBOX}"
    eval "$cmd" >/dev/null 2>&1 || true
}
__FUNC__
prune_backups_keep "$1"
ls -1d "$SANDBOX"/*/ 2>/dev/null | sed 's|.*/\([^/]*\)/|\1|' | sort
'''


def run_rotate(func_src, tmpdir, keep):
    """在沙箱里跑一次真实的轮转，返回剩下的目录名列表。"""
    sandbox = os.path.join(tmpdir, 'backups')
    os.makedirs(sandbox, exist_ok=True)
    # 造 5 份备份，mtime 递增（ls -1dt 按时间倒序）
    for i in range(5):
        d = os.path.join(sandbox, '202611%02d-00000%d' % (10 + i, i))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'payload'), 'w', encoding='utf-8') as f:
            f.write('x' * 100)
        os.utime(d, (1700000000 + i * 100, 1700000000 + i * 100))
    harness = os.path.join(tmpdir, 'harness.sh')
    with open(harness, 'w', encoding='utf-8') as f:
        f.write(HARNESS.replace('__SANDBOX__', sandbox).replace('__FUNC__', func_src))
    r = subprocess.run(['bash', harness, str(keep)], capture_output=True,
                       text=True, timeout=30)
    left = sorted(x.strip() for x in r.stdout.splitlines() if x.strip())
    return left, r.stderr


def main():
    src = open(DEPLOY, encoding='utf-8').read()

    sec('一、源码层面的改动')
    check('deploy.sh 语法正确',
          subprocess.run(['bash', '-n', DEPLOY], capture_output=True).returncode == 0)
    check('有 prune_backups_keep 函数（可复用）',
          'prune_backups_keep()' in src)
    check('备份之前就轮转（不是只在成功后轮转）',
          re.search(r'阶段 3/10　备份.*?prune_backups_keep', src, re.S) is not None)
    check('轮转时给新备份腾位置（保留 KEEP-1 份）',
          'prune_backups_keep "$((KEEP_BACKUPS - 1))"' in src)
    check('有可用空间预检（df -k）',
          'df -k' in src)
    check('空间不足时直接中止（不是硬着头皮往下跑）',
          re.search(r'avail_kb.*?-lt 10240.*?die ', src, re.S) is not None)
    check('空间读不到时跳过预检（不能因预检本身卡死部署）',
          '*[!0-9]*)' in src)

    func_src = extract_func(src, 'prune_backups_keep')
    if not func_src:
        print('\n  [FAIL] 抽不出 prune_backups_keep，后面行为判据没法跑')
        print('\n  合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
        return 1

    sec('二、轮转真的只留最近 N 份（本地沙箱实跑）')
    tmpdir = tempfile.mkdtemp(prefix='prunetest-')
    try:
        left, errout = run_rotate(func_src, tmpdir, 2)
        check('保留 2 份时只剩 2 个目录', len(left) == 2, str(left))
        check('留下的是最近的两份',
              left == ['20261113-000003', '20261114-000004'], str(left))
        check('旧的三份被删掉了',
              not any(x.startswith('2026111') and x <= '20261112-000002' for x in left),
              str(left))

        left, _ = run_rotate(func_src, tmpdir, 5)
        check('保留 5 份时一份都不删', len(left) == 5, str(left))

        left, _ = run_rotate(func_src, tmpdir, 1)
        check('保留 1 份时只剩最新的那份', len(left) == 1, str(left))
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()
    print('  合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项:')
        for name in FAIL:
            print('    - ' + name)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
