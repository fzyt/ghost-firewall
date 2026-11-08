#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破坏性操作安全闸（tests/precheck_generated_rules.py）的行为级测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_precheck_generated_rules.py

为什么要有这个测试
------------------
这个安全闸的唯一职责是回答「生成的规则会不会把管理通道（SSH 22 / 面板 5443）
一起关掉」。在**没有带外通道**的机器上，它误判 PASS 的后果不是「测试没测到」，
而是**跑完 applyRules 就再也连不上设备**。

所以它必须满足两条：

  · 好的规则 ⇒ 判「有保障」
  · 任何一种「放行看着在、实际不生效」的坏规则 ⇒ **必须**判「没保障」

第二条才是关键。只查「规则文本里出现过 22 / 5443」是不够的 ——
放行规则写错了链、写在丢弃规则后面、网卡名对不上，都会**看着有、实际没有**。

测法
----
先用项目自己的 build_rules 生成一份基准规则，然后按各种方式把它改坏，
逐个喂给安全闸，看它是不是都判 FAIL。
安全闸自己被改坏（检查项被摘掉、结论恒为 PASS）时，本文件会失败 ——
这正是它要防的事。
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, 'backend')
GATE = os.path.join(HERE, 'precheck_generated_rules.py')
FIXTURE = os.path.join(HERE, 'fixtures', 'lan232-config.json')

PASS = []
FAIL = []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print('  [%s] %s%s' % ('PASS' if ok else 'FAIL', name,
                            ('  — %s' % detail) if detail else ''))


def sec(title):
    print('\n=== %s ===' % title)


def load_app(tmpdir):
    """加载 app.py 并把落盘路径指到临时目录。"""
    env = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmpdir, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmpdir, 'aliyun.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmpdir, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmpdir, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmpdir, 'nginx-conf'),
    }
    os.environ.update(env)
    sys.path.insert(0, BACKEND)
    spec = importlib.util.spec_from_file_location(
        'app_precheck_test', os.path.join(BACKEND, 'app.py'))
    mod = importlib.util.module_from_spec(spec)
    sys.modules['app_precheck_test'] = mod
    spec.loader.exec_module(mod)
    return mod


def run_gate(rules_text, tmpdir, lan_if='br-lan'):
    """把规则文本喂给安全闸，返回 (退出码, 输出)。"""
    path = os.path.join(tmpdir, 'case.nft')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(rules_text)
    r = subprocess.run(
        [sys.executable, GATE, '--rules-file', path, '--lan-if', lan_if],
        capture_output=True, text=True, cwd=ROOT, timeout=180,
        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def move_allow_after_drop(text):
    """把管理端口放行行挪到 meta nfproto ipv4 drop 之后 —— 看着有，实际被丢弃。"""
    lines = text.splitlines()
    allow = [l for l in lines if 'tcp dport { 22, 5443 } accept' in l]
    if not allow:
        return None
    drop = [i for i, l in enumerate(lines)
            if l.strip() == 'meta nfproto ipv4 drop']
    if not drop:
        return None
    out = []
    for l in lines:
        if l in allow:
            continue
        if l.strip() == 'meta nfproto ipv4 drop':
            out.append(l)
            out.extend(allow)
            continue
        out.append(l)
    return '\n'.join(out) + '\n'


def main():
    tmpdir = tempfile.mkdtemp(prefix='nft-gate-test-')

    with open(FIXTURE, encoding='utf-8') as f:
        cfg = json.load(f)
    cfg.pop('_comment', None)
    app = load_app(tmpdir)
    base = app.build_rules(cfg)

    sec('第 1 组：基准规则必须判「有保障」')
    rc, out = run_gate(base, tmpdir)
    check('正常生成的规则判有保障（退出码 0）', rc == 0,
          '退出码 %d' % rc)
    check('输出里有 4 项检查全部通过', out.count('[PASS]') >= 4,
          'PASS 计数 %d' % out.count('[PASS]'))
    check('输出里没有 [FAIL]', '[FAIL]' not in out)

    sec('第 2 组：放行「看着在、实际不生效」的各种坏规则必须判没保障')
    # 负例 1：input 链不跳到 input_lan —— 放行规则永远不执行
    bad = base.replace('iifname $LAN_IF jump input_lan', '# jump 被删掉了')
    check('input 链不跳 LAN 链 ⇒ 判没保障', bad != base and run_gate(bad, tmpdir)[0] != 0)

    # 负例 2：放行规则挪到丢弃规则之后
    bad = move_allow_after_drop(base)
    check('放行排在丢弃规则之后 ⇒ 判没保障',
          bad is not None and run_gate(bad, tmpdir)[0] != 0)

    # 负例 3：放行规则整行删掉
    bad = re.sub(r'^.*tcp dport \{ 22, 5443 \} accept.*$', '', base, flags=re.M)
    check('放行规则被删掉 ⇒ 判没保障', bad != base and run_gate(bad, tmpdir)[0] != 0)

    # 负例 4：端口换成别的（22 / 5443 都不在里面）
    bad = base.replace('tcp dport { 22, 5443 } accept',
                       'tcp dport { 8080, 9090 } accept')
    check('放行端口被换成 8080/9090 ⇒ 判没保障',
          bad != base and run_gate(bad, tmpdir)[0] != 0)

    # 负例 5：网卡名对不上（设备上是 eth0，规则里写的是 br-lan）
    rc, out = run_gate(base, tmpdir, lan_if='eth0')
    check('define LAN_IF 与设备网卡名不符 ⇒ 判没保障', rc != 0,
          '退出码 %d' % rc)

    # 负例 6：只有 22 没有 5443 —— 面板进不去，机器上排障也瞎
    bad = base.replace('tcp dport { 22, 5443 } accept', 'tcp dport { 22 } accept')
    check('只放行 22 没放行 5443 ⇒ 判没保障',
          bad != base and run_gate(bad, tmpdir)[0] != 0)

    # 负例 7：端口多写一位尾零（{ 220, 54430 }）
    # 这一条专门盯「端口用子串匹配」那种退化：220 里含 22、54430 里含 5443，
    # 按子串匹配会以为两个端口都放行了 ⇒ 误判 PASS。
    bad = base.replace('tcp dport { 22, 5443 } accept',
                       'tcp dport { 220, 54430 } accept')
    check('端口写成 { 220, 54430 }（各多一位）⇒ 判没保障',
          bad != base and run_gate(bad, tmpdir)[0] != 0)

    # 负例 8：整个 input_lan 链改名 —— jump 到的链不存在
    bad = base.replace('chain input_lan {', 'chain input_lan_renamed {')
    check('input_lan 链被改名 ⇒ 判没保障',
          bad != base and run_gate(bad, tmpdir)[0] != 0)

    sec('第 3 组：脚本自身健壮性')
    rc, out = run_gate('', tmpdir)
    check('空规则文件 ⇒ 判没保障（不是崩掉）', rc == 1, '退出码 %d' % rc)
    r = subprocess.run([sys.executable, GATE, '--rules-file',
                        os.path.join(tmpdir, '不存在.nft')],
                       capture_output=True, text=True, cwd=ROOT, timeout=60)
    check('规则文件不存在 ⇒ 退出码 2（区别于「判没保障」的 1）',
          r.returncode == 2, '退出码 %d' % r.returncode)

    print('\n' + '=' * 60)
    print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项: %s' % FAIL)
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
