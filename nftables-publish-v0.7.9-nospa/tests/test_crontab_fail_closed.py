#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
「凡是读 crontab 再写回的地方，读失败必须 fail-closed」的不变式测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_crontab_fail_closed.py

背景
----
P0-10（2026-10-29 Shannon 复核坐实）：`crontab -l` 读取失败时，代码把
「读不到」当成「crontab 本来就是空的」，接着 `crontab -` 用「只有我这一条」
的内容**覆盖整个 root crontab** —— `/etc/init.d/acme renew` 与
`/opt/nftables-web/renew-certs.sh` 双双被抹，而接口照样返回 200。

P0-10 当年修了 `_upsert_cron_for()` 与 `install_china_ips()` 两处，
**漏了 `_manage_ddns_cron()`**（阿里云 DDNS 的 cron 条目管理）。
2026-11-08 的面板侧 53 条静态判定对账把它挖了出来：
三处里只有它用双引号写 `["crontab", "-l"]`，另外两处是单引号
`['crontab', '-l']` 且带 returncode 检查 —— 引号风格的差异正好标出了
它没跟上 P0-10。

为什么写成「不变式」而不是「再补一个点」
----------------------------------------
只测 `_manage_ddns_cron` 一个函数的话，将来再加第四个 crontab 写入口
又会漏一次同样的错。所以这个文件先**扫源码**找出所有读 crontab 的函数，
再对**每一个**断言 fail-closed —— 新增写入口若没带闸门，本文件会直接红。

测什么有效
----------
「读失败」有三种**形态**，每一种都必须单独盖住 —— 只测一种的话，
另外两种的退化就是隐形的：

  rc_nonzero     crontab 二进制在，但 spool 读不出来（P0-10 实测的形态）
  raise_missing  crontab 二进制被删 / 被 shadow（FileNotFoundError）
  raise_timeout  spool 所在磁盘卡住（TimeoutExpired）

而且「失败」必须是**明确的失败返回**，不能是：
  · 抛异常         —— 会变成 Flask 500，而不是「已中止（未做任何修改）」的提示
  · 返回成功        —— 面板说「配置已保存」，运维以为 cron 已配好
  · 继续写 crontab —— 这就是 P0-10 本身（把别人的条目抹掉）

沙箱：只 import 模块并打补丁；`crontab -` 要么抛异常、要么被 mock 拦下，
**绝不动本机 crontab**。
"""
import importlib
import os
import re
import subprocess
import sys
import tempfile

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def strip_comments(src):
    """去掉 Python 注释（保留字符串字面量里的 #）。

    修复时为了说明「原来怎么错的」，注释里**引用了旧代码原文**。
    源码级断言直接搜原文会把注释当成代码 ⇒ 误判。
    断言「旧写法已经不在代码里」必须只看真正的代码。
    """
    out = []
    for line in src.splitlines():
        buf = []
        quote = None
        i = 0
        while i < len(line):
            c = line[i]
            if quote:
                buf.append(c)
                if c == '\\' and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in ('"', "'"):
                quote = c
                buf.append(c)
                i += 1
                continue
            if c == '#':
                break
            buf.append(c)
            i += 1
        out.append(''.join(buf))
    return '\n'.join(out)


def func_body(src, name):
    """取出 `def name(...)` 的函数体（到下一个顶层 def/@ 之前），已去注释。"""
    m = re.search(r'^def\s+' + re.escape(name) + r'\s*\(', src, re.M)
    if not m:
        return ''
    rest = src[m.end():]
    nxt = re.search(r'^(?:@|def\s|class\s)', rest, re.M)
    body = rest[:nxt.start()] if nxt else rest
    return strip_comments(body)


def functions_using(src, pattern):
    """源码里匹配 pattern 的所有顶层函数，返回 [(函数名, 函数体)]。

    做法：找每个匹配点，往上找最近的顶层 `def`。
    """
    found = []
    for m in re.finditer(pattern, src):
        pos = m.start()
        owner = None
        for d in re.finditer(r'^def\s+(\w+)\s*\(', src[:pos], re.M):
            owner = d.group(1)
        if owner is None:
            continue
        if owner not in [n for n, _ in found]:
            found.append((owner, func_body(src, owner)))
    return found


def fresh_app():
    """加载一个面板模块副本，配置路径指向临时目录。"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


SRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
SRC_CODE = strip_comments(SRC)

# crontab -l 的调用点（单引号 / 双引号都算）
READ_PAT = r"""['"]crontab['"]\s*,\s*['"]-l['"]"""
# crontab - 的调用点（写回）
WRITE_PAT = r"""['"]crontab['"]\s*,\s*['"]-['"]"""


class _WriteAttempted(Exception):
    """被测代码在读失败后仍然尝试执行 `crontab -`。"""


# ── 读失败的四种形态 ───────────────────────────────────────
#
# 前三种是「读失败」，期望：明确的失败返回 + 绝不写 crontab。
# 第四种是「读成功但写失败」，期望：明确的失败返回（不能报「已更新」）。
#
# 每一项：(键, 说明, 期望是否允许出现 `crontab -` 调用)
FAIL_MODES = [
    ('rc_nonzero', 'crontab -l 返回非 0（spool 读不出来）', False),
    ('raise_missing', 'crontab -l 抛 FileNotFoundError（二进制被删）', False),
    ('raise_timeout', 'crontab -l 抛 TimeoutExpired（磁盘卡住）', False),
    ('write_fails', 'crontab - 写入失败（返回码非 0）', True),
]


def _make_fake_run(mode, calls):
    """按形态造一个假的 subprocess.run。

    写回类调用（`crontab -`）**绝不**放行到真 crontab：
      · 读失败形态下 → 抛 _WriteAttempted（说明代码硬要写）
      · write_fails 形态下 → 返回返回码 1（模拟写失败）
    """
    real_run = subprocess.run

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        if isinstance(cmd, (list, tuple)) and 'crontab' in cmd:
            if '-l' in cmd:
                if mode == 'rc_nonzero':
                    class _R:
                        returncode = 1
                        stdout = ''
                        stderr = "crontab: can't open 'root': No such file or directory"
                    return _R()
                if mode == 'raise_missing':
                    raise FileNotFoundError(2, 'No such file or directory: crontab')
                if mode == 'raise_timeout':
                    raise subprocess.TimeoutExpired(cmd, 10)
                # write_fails：读是成功的
                class _ROK:
                    returncode = 0
                    stdout = '0 3 * * 1 /opt/nftables-web/renew-certs.sh\n'
                    stderr = ''
                return _ROK()
            # 写回类调用
            if mode == 'write_fails':
                class _W:
                    returncode = 1
                    stdout = ''
                    stderr = 'crontab: installing new crontab: disk full'
                return _W()
            raise _WriteAttempted('测试不允许真正写 crontab：%r' % (cmd,))
        return real_run(cmd, *a, **kw)

    return fake_run


def run_scenario(fn, args, mode):
    """跑一个形态，返回 (结果分类, 详情, 是否调用过 `crontab -`)。

    结果分类：
      failed_ok   明确的失败返回（正确）
      succeeded   返回成功（错误：面板会报「已保存」）
      raised      抛异常（错误：变成 500，不是「已中止」的提示）
      wrote       读失败却仍然写 crontab（错误：P0-10 本身）
    """
    calls = []
    fake_run = _make_fake_run(mode, calls)
    real_run = subprocess.run
    subprocess.run = fake_run
    try:
        res = fn(*args)
    except _WriteAttempted as e:
        kind, detail = 'wrote', str(e)
    except Exception as e:
        kind, detail = 'raised', f'{type(e).__name__}: {e}'
    else:
        ok = bool(res[0]) if isinstance(res, tuple) else bool(res)
        kind = 'failed_ok' if not ok else 'succeeded'
        detail = str(res[1] if isinstance(res, tuple) else res)[:160]
    finally:
        subprocess.run = real_run
    wrote = any(isinstance(c, (list, tuple)) and 'crontab' in c and '-l' not in c
                for c in calls)
    return kind, detail, wrote


def main():
    readers = functions_using(SRC_CODE, READ_PAT)
    writers = functions_using(SRC_CODE, WRITE_PAT)

    sec('第 1 组：不变式 —— 每个读 crontab 的函数都必须有 fail-closed 闸门')
    check('源码里能找到读 crontab 的函数', len(readers) >= 3,
          '找到 %d 个: %s' % (len(readers), [n for n, _ in readers]))
    check('源码里能找到写 crontab 的函数', len(writers) >= 3,
          '找到 %d 个: %s' % (len(writers), [n for n, _ in writers]))

    for name, body in readers:
        # 读取点与写回点之间必须有 returncode 闸门
        i_read = body.find("'crontab', '-l'")
        if i_read < 0:
            i_read = body.find('"crontab", "-l"')
        i_write = body.find("'crontab', '-'")
        if i_write < 0:
            i_write = body.find('"crontab", "-"')
        gate = body[i_read:i_write] if (i_read >= 0 and i_write > i_read) else ''
        check('%s：crontab -l 读取点与写回点之间有 returncode 闸门' % name,
              'returncode != 0' in gate,
              '闸门段=%r' % gate[:160])
        # 闸门必须真的中止（return False / return jsonify），不能只是记个警告
        check('%s：读失败时中止（return），不是拿空列表继续' % name,
              re.search(r'return\s+(False|jsonify)', gate) is not None,
              '闸门段=%r' % gate[:160])
        # 闸门必须落在**读取点之后、写回点之前** —— 放到写回之后就等于没有闸门：
        # crontab 已经被覆盖完了，再报错也来不及。
        #
        # 这里刻意找 **`result.returncode != 0` 这个条件的位置**，而不是笼统地
        # 找「有没有 return」。因为 except 分支里那句 `return False` 一直都在，
        # 用它当判据的话，「把 returncode 闸门挪到写回之后」这种退化照样能过。
        i_gate = body.find('returncode != 0')
        check('%s：returncode 闸门在写回点之前（不是写完再检查）' % name,
              i_gate >= 0 and i_read <= i_gate < i_write,
              '读点=%d 闸门点=%d 写点=%d' % (i_read, i_gate, i_write))

    sec('第 2 组：行为级 —— 读失败的各种形态都必须中止，且绝不写 crontab')
    app = fresh_app()

    # 只对**纯函数**做行为级验证。
    #
    # install_china_ips 是 Flask 路由，调用它会写 /opt/... 的脚本文件
    # （本机没权限）⇒ 它的行为级验证留给既有的 test_p0_security_fixes.py
    # （那边把建目录/写脚本/chmod 都 mock 掉了）。本文件对它只做源码层不变式断言。
    BEHAVIOR_TARGETS = {
        '_upsert_cron_for': ('/opt/x/update.sh', '* * * * * /opt/x/update.sh'),
        '_manage_ddns_cron': ({'records': [{'enabled': True}]},),
    }

    for name, _body in readers:
        fn = getattr(app, name, None)
        if fn is None:
            check('%s：函数存在' % name, False, 'app.py 里找不到')
            continue
        if name not in BEHAVIOR_TARGETS:
            check('%s：跳过行为级（不是纯函数，副作用由别的测试覆盖）' % name, True)
            continue
        args = BEHAVIOR_TARGETS[name]
        for mode, desc, allow_write in FAIL_MODES:
            kind, detail, wrote = run_scenario(fn, args, mode)
            check('%s：%s → 明确的失败返回' % (name, desc),
                  kind == 'failed_ok',
                  '结果=%s 详情=%s' % (kind, detail))
            if not allow_write:
                check('%s：%s → 没有执行 `crontab -`' % (name, desc),
                      not wrote and kind != 'wrote',
                      '结果=%s 详情=%s' % (kind, detail))

    sec('第 3 组：_manage_ddns_cron 的正常路径不能被这次修复弄坏')
    # 正常读取时：保留其它条目、只替换 DDNS 那一条
    calls = []
    payload = {}
    real_run = subprocess.run

    def ok_run2(cmd, *a, **kw):
        calls.append(cmd)
        if isinstance(cmd, (list, tuple)) and 'crontab' in cmd:
            if '-l' in cmd:
                class _R:
                    returncode = 0
                    stdout = ("0 3 * * 1 /opt/nftables-web/renew-certs.sh\n"
                              "*/10 * * * * /opt/nftables-web-v2/aliyun-ddns-update.py\n"
                              "@reboot /etc/init.d/acme renew\n")
                    stderr = ''
                return _R()
            # 写回类调用：只把内容记下来，绝不放行到真 crontab
            payload['written'] = kw.get('input')
            class _W:
                returncode = 0
                stdout = ''
                stderr = ''
            return _W()
        return real_run(cmd, *a, **kw)

    subprocess.run = ok_run2
    try:
        ok, msg = app._manage_ddns_cron({'records': [{'enabled': True}]})
    finally:
        subprocess.run = real_run
    check('正常路径：返回成功', ok, str(msg)[:120])
    written = payload.get('written') or ''
    check('正常路径：保留了证书续期条目', 'renew-certs.sh' in written,
          '写入内容=%r' % written)
    check('正常路径：保留了 acme renew 条目', 'acme renew' in written,
          '写入内容=%r' % written)
    check('正常路径：DDNS 条目只有一条（旧的被替换不重复）',
          written.count('aliyun-ddns-update.py') == 1,
          '写入内容=%r' % written)

    print('\n' + '=' * 60)
    print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项: %s' % FAIL)
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
