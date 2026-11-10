#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.sh「遗留备份归位」这一步的行为级测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_setup_initd_cleanup.py

测什么有效
----------
2026-11-10 在 .232 真机的 /etc/init.d/ 里发现一个
`nftables-web.bak.1793432750` —— 旧版 init 脚本的副本，
躺在**系统目录**里。本轮在 setup.sh 里加了一步把它挪到
项目自己的 ${CONFIG_DIR}/backup/。

这一步的风险全在「动错东西」上：
  · 把正常的服务脚本当备份挪走 ⇒ 服务起不来；
  · 把软链或目录挪走 ⇒ 直接把机器弄坏；
  · `set -e` 下某条命令返回非 0 ⇒ 整个安装中断。

所以这里**真跑那个 shell 函数**（不是文本匹配）：
把 setup.sh 拷进沙箱、去掉末尾的 main 调用、把 /etc/init.d 与
CONFIG_DIR 换成临时目录，然后真的执行它，看目录里最后剩了什么。

⚠️ 为什么用「拷一份再改路径」而不是给生产代码加环境变量开关：
   给 setup.sh 加测试专用开关会让生产脚本多出一条分支；
   而这里改的只是**路径常量**，被测的函数体一个字节都没动。
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def run_cleanup(entries):
    """在沙箱里跑 relocate_initd_backups。

    entries: {文件名: ('file'|'dir'|'link', 内容或链接目标)}

    返回 (沙箱根, init.d 路径, CONFIG_DIR 路径, 脚本输出, 返回码)
    """
    d = tempfile.mkdtemp()
    fake_initd = os.path.join(d, 'init.d')
    os.makedirs(fake_initd)
    for name, (kind, content) in entries.items():
        p = os.path.join(fake_initd, name)
        if kind == 'file':
            with open(p, 'w') as f:
                f.write(content)
        elif kind == 'dir':
            os.makedirs(p)
        elif kind == 'link':
            os.symlink(content, p)
        elif kind == 'linkrel':
            # 目标相对于 init.d 目录本身 —— 指向沙箱里**真实存在**的文件。
            # ⚠️ 不能用悬空软链当样本：`[ -f "$f" ]` 对悬空软链为**假**，
            #    它会被第一道判据（不是普通文件）挡下，
            #    根本走不到「是不是软链」那一步 ⇒ 测不出第二道判据。
            os.symlink(os.path.join(fake_initd, content), p)

    fake_cfg = os.path.join(d, 'nftables')

    src = open(SETUP, encoding='utf-8').read()
    # 去掉末尾的 main 调用（否则会真的跑整个安装流程）
    src = src.replace('\nmain "$@"\n', '\n')
    # 把路径常量换成沙箱路径 —— 被测的函数体一个字节都没动
    src = src.replace('/etc/init.d', fake_initd)
    src = src.replace('CONFIG_DIR="/etc/nftables"',
                      'CONFIG_DIR="%s"' % fake_cfg)
    # 末尾直接调用那个函数
    src += '\nrelocate_initd_backups\n'

    script = os.path.join(d, 'setup.sh')
    with open(script, 'w', encoding='utf-8') as f:
        f.write(src)

    r = subprocess.run(['sh', script], capture_output=True, text=True, timeout=60)
    return d, fake_initd, fake_cfg, (r.stdout + r.stderr), r.returncode


sec('第 1 组：备份被挪走，正常服务脚本不受影响')

d, initd, cfg, out, rc = run_cleanup({
    'nftables-web': ('file', '#!/bin/sh /etc/rc.common\n'),
    'nftables-web-auth': ('file', '#!/bin/sh /etc/rc.common\n'),
    'nftables-web.bak.1793432750': ('file', '#!/bin/sh /etc/rc.common\nOLD\n'),
})

check('脚本执行成功（rc=0）', rc == 0, out[-400:])
check('备份文件被挪走了',
      not os.path.exists(os.path.join(initd, 'nftables-web.bak.1793432750')))
check('备份文件在 %s/backup/ 里' % cfg,
      os.path.exists(os.path.join(cfg, 'backup', 'nftables-web.bak.1793432750')),
      str(os.listdir(os.path.join(cfg, 'backup')) if os.path.isdir(os.path.join(cfg, 'backup')) else '目录不存在'))
check('正常的服务脚本**没有**被挪走',
      os.path.exists(os.path.join(initd, 'nftables-web')))
check('认证服务的 init 脚本也没被挪走',
      os.path.exists(os.path.join(initd, 'nftables-web-auth')))
check('输出里说明了挪到了哪', 'backup' in out, out[-200:])


sec('第 2 组：软链和目录一律不动')

d2, initd2, cfg2, out2, rc2 = run_cleanup({
    'nftables-web': ('file', '#!/bin/sh /etc/rc.common\n'),
    # ⚠️ 软链样本的**名字必须像备份**（`*.bak*`）：
    #    函数第一步就是 `for f in /etc/init.d/*.bak*` ——
    #    名字不匹配的软链压根不会被看到，改什么代码都动不到它，
    #    用它当样本会让人以为「软链判据验过了」（实际是空转）。
    #
    #    也不能用**悬空**软链：`[ -f "$f" ]` 对悬空软链为**假**，
    #    它会被「不是普通文件」那道判据挡下，同样走不到软链那一道。
    #    ⇒ 指向**真实存在**的文件的软链，才真的能测到「是不是软链」这层。
    'nftables-web.bak.link': ('linkrel', 'nftables-web'),
    'adirectory.bak.123': ('dir', ''),
    'nftables-web.bak.999': ('file', 'X\n'),
})

check('脚本执行成功（rc=0）', rc2 == 0, out2[-400:])
check('软链**没有**被挪走（挪了会直接把服务弄坏）',
      os.path.islink(os.path.join(initd2, 'nftables-web.bak.link')))
check('软链指向的目标也没被动',
      os.path.exists(os.path.join(initd2, 'nftables-web')))
check('目录**没有**被挪走',
      os.path.isdir(os.path.join(initd2, 'adirectory.bak.123')))
check('普通文件的备份还是被挪走了',
      not os.path.exists(os.path.join(initd2, 'nftables-web.bak.999')))


sec('第 3 组：没有备份时是空操作，且不报错')

d3, initd3, cfg3, out3, rc3 = run_cleanup({
    'nftables-web': ('file', '#!/bin/sh /etc/rc.common\n'),
})

check('脚本执行成功（rc=0）', rc3 == 0, out3[-400:])
check('输出里说明没有遗留备份', '没有遗留' in out3, out3[-200:])
check('服务脚本还在原处', os.path.exists(os.path.join(initd3, 'nftables-web')))


sec('第 4 组：重复跑是幂等的')

d4, initd4, cfg4, out4, rc4 = run_cleanup({
    'nftables-web.bak.111': ('file', 'X\n'),
})
# 再造一个同样的场景跑第二遍
d4b, initd4b, cfg4b, out4b, rc4b = run_cleanup({
    'nftables-web.bak.111': ('file', 'X\n'),
})
check('第二次跑也成功（rc=0）', rc4b == 0, out4b[-300:])
check('第二次跑之后 backup 目录里只有一份',
      len(os.listdir(os.path.join(cfg4b, 'backup'))) == 1,
      str(os.listdir(os.path.join(cfg4b, 'backup'))))


sec('第 5 组：源码里这一步确实被调用了')

src = open(SETUP, encoding='utf-8').read()
check('setup.sh 里定义了 relocate_initd_backups',
      'relocate_initd_backups()' in src)
check('main 流程里调用了它', 'relocate_initd_backups\n' in src)
check('挪到的目录是项目自己的 ${CONFIG_DIR}/backup',
      '"${CONFIG_DIR}/backup/"' in src)

print('\n' + '=' * 60)
print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
if FAIL:
    print('  失败项: %s' % FAIL)
print('=' * 60)
sys.exit(1 if FAIL else 0)
