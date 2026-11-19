#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""部署自检的 crontab 完整性判据（2026-11-19）

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_deploy_crontab_check.py

背景
----
2026-11-19 部署「访问日志封顶」到 .193 时踩到：

    ❌ crontab 条数未变 —— 期望 3，实际 4
    ❌ 自检 1 项不通过
    ❌ 正在回滚：/root/nftables-web-backups/20261119-103949/restore.sh

**部署其实一点问题都没有。** 那多出来的一条是面板启动时自己装的
（访问日志封顶脚本的 cron）—— 部署本来就要重启面板。

更要命的是回滚只还原代码、不还原 crontab ⇒ 设备留在混合状态：
代码是旧的，cron 条目和封顶脚本却是新的。

为什么这条判据本来就太粗
------------------------
「crontab 条数未变」想守的是 P0-10 那类事故：
读 crontab 失败被当成「本来是空的」，接着用「只有自己那一条」覆盖整张表
⇒ acme 续期和证书续期双双消失。

所以不变式的本意是**不许丢条目**，不是「不许加条目」。
「条数」这个量纲恰好把两件事混在了一起：
丢一条又加一条，条数照样不变 —— 真正的漏网反而看不见了。

现在判的是三条
--------------
  ① 原有条目一条都没丢、也没被改（逐行精确比对）—— 不变式的本意
  ② 同一条目没有被多装一遍
  ③ 新增的条目只允许指向面板自己管的脚本目录（/opt/nftables-web/），
     且那个脚本必须可执行

本判据守的是**判据本身**：这三条各自都得能判红，也都不能误判红。

沙箱
----
deploy.sh 底部会直接 `main "$@"`，**不能 source**。
所以这里把函数原文抽出来，塞进一个打桩的沙箱脚本里跑
（ok/err/warn/rssh 全是假的，绝不碰真设备、真 crontab）。
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
    """从 shell 源码里抽出 `name() { ... }` 的完整定义。

    结束位置用「行首的 }」判定 —— deploy.sh 里所有函数都是这个写法
    （函数体内的 } 都带缩进）。
    """
    m = re.search(r'^' + re.escape(name) + r'\(\) \{', src, re.M)
    if not m:
        return ''
    end = src.find('\n}\n', m.start())
    if end < 0:
        return ''
    return src[m.start():end + 3]


HARNESS = r'''#!/bin/bash
# ⚠ 必须复刻 deploy.sh 的 shell 选项（第 27 行 set -euo pipefail）：
# 判据是在**这个环境**里跑的，选项不一样就等于测了个假的。
set -euo pipefail
FAILED_CHECKS=0
CHECK_FAILURES=()
ok() { :; }
err() { :; }
warn() { :; }
CRON_BEFORE="$1"
FAKE_CRON="$2"
FAKE_EXEC="$3"
rssh() {
    case "$1" in
        "crontab -l 2>/dev/null")
            printf '%s\n' "$FAKE_CRON"
            return 0
            ;;
        "test -x "*)
            p="${1#test -x }"
            p="${p%\'}"; p="${p#\'}"
            case ",$FAKE_EXEC," in
                *,"$p",*) return 0 ;;
            esac
            return 1
            ;;
    esac
    return 0
}
__FUNC__
check_crontab_intact
echo "FAILED_CHECKS=$FAILED_CHECKS"
if [ ${#CHECK_FAILURES[@]} -gt 0 ]; then
    printf 'FAILURES=%s\n' "${CHECK_FAILURES[@]}"
fi
'''


def run_case(tmpdir, func_src, cron_before, cron_after, exec_list):
    """跑一次判据，返回 (失败条数, 失败原因列表)。"""
    harness = os.path.join(tmpdir, 'harness.sh')
    with open(harness, 'w', encoding='utf-8') as f:
        f.write(HARNESS.replace('__FUNC__', func_src))
    r = subprocess.run(['bash', harness, cron_before, cron_after, exec_list],
                       capture_output=True, text=True, timeout=30)
    out = r.stdout
    m = re.search(r'FAILED_CHECKS=(\d+)', out)
    n = int(m.group(1)) if m else -1
    reasons = []
    for line in out.splitlines():
        if line.startswith('FAILURES='):
            reasons = [x for x in line[len('FAILURES='):].split('\t') if x]
    return n, reasons, r.stderr


def main():
    src = open(DEPLOY, encoding='utf-8').read()
    func_src = extract_func(src, 'check_crontab_intact')

    sec('一、判据在 deploy.sh 里存在且写法正确')
    check('deploy.sh 里有 check_crontab_intact 函数', bool(func_src))
    check('函数体不是空的', len(func_src) > 200, '%d 字节' % len(func_src))
    check('deploy.sh 语法正确',
          subprocess.run(['bash', '-n', DEPLOY], capture_output=True).returncode == 0)
    check('自检不再用「条数未变」当判据',
          'check_eq "crontab 条数未变"' not in src)
    check('回滚脚本会还原 crontab',
          'crontab "$BK/crontab.txt"' in src)
    check('回滚还原 crontab 前判了文件非空（空文件会清空整张表）',
          '[ -s "$BK/crontab.txt" ]' in src)

    if not func_src:
        print('\n  [FAIL] 抽不出函数体，后面的行为判据没法跑')
        print('\n  合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
        return 1

    tmpdir = tempfile.mkdtemp(prefix='croncheck-')
    try:
        base = ('0 0 * * * /etc/init.d/acme renew\n'
                '*/10 * * * * /opt/nftables-web/update-ipv6.sh\n'
                '*/30 * * * * /opt/nftables-web/renew-certs.sh')
        exec_list = ('/opt/nftables-web/truncate-gateway-log.sh,'
                     '/opt/nftables-web/update-ipv6.sh,'
                     '/opt/nftables-web/renew-certs.sh')

        sec('二、正向场景：面板装了一条自己的 cron')
        after = base + '\n*/5 * * * * /opt/nftables-web/truncate-gateway-log.sh'
        n, reasons, errout = run_case(tmpdir, func_src, base, after, exec_list)
        check('新增一条面板自己装的脚本 ⇒ 不判失败', n == 0,
              '失败 %s 条 %s' % (n, reasons))

        sec('三、负向场景：每种坏法都得判红')
        n, reasons, _ = run_case(tmpdir, func_src, base,
                                  '0 0 * * * /etc/init.d/acme renew\n'
                                  '*/10 * * * * /opt/nftables-web/update-ipv6.sh', exec_list)
        check('原有条目丢了一条 ⇒ 判失败', n > 0, '失败 %s 条 %s' % (n, reasons))
        check('失败原因说的是「原有条目丢了」',
              any('原有条目丢了' in r for r in reasons), str(reasons))

        n, reasons, _ = run_case(tmpdir, func_src, base,
                                  base + '\n*/5 * * * * /opt/nftables-web/truncate-gateway-log.sh\n'
                                  '*/5 * * * * /opt/nftables-web/truncate-gateway-log.sh', exec_list)
        check('同一条目被装了两遍 ⇒ 判失败', n > 0, '失败 %s 条 %s' % (n, reasons))

        n, reasons, _ = run_case(tmpdir, func_src, base,
                                  base + '\n*/5 * * * * /usr/bin/evil.sh', exec_list)
        check('新增条目指向面板管不到的目录 ⇒ 判失败', n > 0,
              '失败 %s 条 %s' % (n, reasons))

        n, reasons, _ = run_case(tmpdir, func_src, base,
                                  base + '\n*/5 * * * * /opt/nftables-web/truncate-gateway-log.sh',
                                  '/opt/nftables-web/update-ipv6.sh')
        check('新增条目指向的脚本不可执行 ⇒ 判失败', n > 0,
              '失败 %s 条 %s' % (n, reasons))

        n, reasons, _ = run_case(tmpdir, func_src, base,
                                  '*/5 * * * * /etc/init.d/acme renew\n'
                                  '*/10 * * * * /opt/nftables-web/update-ipv6.sh\n'
                                  '*/30 * * * * /opt/nftables-web/renew-certs.sh\n'
                                  '0 0 * * * /etc/init.d/acme renew', exec_list)
        check('原有条目被改了内容（少了 renew-certs 多了别的）⇒ 判失败', n > 0,
              '失败 %s 条 %s' % (n, reasons))

        sec('四、基线读不到时跳过（不能误判红）')
        n, reasons, _ = run_case(tmpdir, func_src, '',
                                  '0 0 * * * /etc/init.d/acme renew', exec_list)
        check('基线为空时跳过检查、不判失败', n == 0, '失败 %s 条 %s' % (n, reasons))
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
