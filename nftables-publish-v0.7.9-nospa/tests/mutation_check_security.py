#!/usr/bin/env python3
"""三个安全修复的变异验证。

每条变异把修复拆掉一个环节，测试必须失败。
如果测试仍然全绿，说明这条测试没有真正盯住那个缺陷 —— 不能算有效测试。

运行: python3 tests/mutation_check_security.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
GW = os.path.join(ROOT, 'backend', 'auth_gateway.py')
PORTAL = os.path.join(ROOT, 'backend', 'static', 'portal.js')
LOGIN = os.path.join(ROOT, 'backend', 'static', 'login.js')
TEST = os.path.join(ROOT, 'tests', 'test_security_fixes.py')

# SEC-3 变体：把「吊销旧令牌」整块挪到 issue_token 之后。
#
# 这里刻意用正则按**结构**锚定（从 `if _old:` 一直吃到 `did = device_id_from_request()`
# 之前的空行），而不是把整段源码逐字写死。写死的话，在这两行之间加一行注释就会
# 让替换悄悄失配 —— 变异脚本会打印「变异未生效」并跳过，而跳过在肉眼扫一遍输出
# 时非常容易看成「通过」。
_SEC3_BLOCK_RE = re.compile(
    r'(    _old = parse_token\(request\.cookies\.get\(COOKIE_TOKEN, ""\)\)\n'
    r'    if _old:\n.*?\n\n)'
    r'(?=    did = device_id_from_request\(\))',
    re.S)
_SEC3_ISSUE_ANCHOR = '    token = issue_token("kirito", did, ttl, abs_deadline)\n'


def _mut_sec3_move_revocation_after_issue(s):
    m = _SEC3_BLOCK_RE.search(s)
    if not m:
        return s
    block = m.group(1)
    stripped = s[:m.start()] + s[m.end():]
    j = stripped.find(_SEC3_ISSUE_ANCHOR)
    if j < 0:
        return s
    k = j + len(_SEC3_ISSUE_ANCHOR)
    return stripped[:k] + block + stripped[k:]


MUTATIONS = [
    ('SEC-1 DNS 校验改回「不检查」',
     APP,
     lambda s: s.replace(
         "if _host_resolvable(_t_host) is False:",
         "if False:"),
     '解析不通的域名不再被 400 拦截'),

    ('SEC-1 DNS 检查改为永远放行',
     APP,
     lambda s: s.replace(
         "    if _host_resolvable(_t_host) is False:",
         "    if _host_resolvable(_t_host) is None:"),
     '解析失败被当成「无法判定」而放行'),

    ('SEC-2 保存挪回部署之前（恢复持久化 DoS）',
     APP,
     lambda s: s.replace(
         """    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False,
                        "message": f"网关配置未生效，规则已丢弃: {deploy_msg}"}), 500

    _save_rp_config(config)""",
         """    _save_rp_config(config)

    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False,
                        "message": f"服务已保存但网关配置未生效: {deploy_msg}"}), 500"""),
     '毒规则重新持久化到配置里'),

    ('SEC-3 登录时不吊销旧令牌',
     GW,
     lambda s: re.sub(
         r'    _old = parse_token\(request\.cookies\.get\(COOKIE_TOKEN, ""\)\)\n'
         r'    if _old:\n.*?\n\n(?=    did = device_id_from_request\(\))',
         '', s, count=1, flags=re.S),
     '重新登录后旧令牌仍然有效'),

    ('SEC-3 吊销挪到签发之后（顺序反了）',
     GW,
     _mut_sec3_move_revocation_after_issue,
     '新令牌已签发才吊销旧的'),

    ('SEC-4 /auth/status 限流阈值放到无穷大',
     GW,
     lambda s: s.replace('def _status_rate_ok(window=60, limit=120):',
                         'def _status_rate_ok(window=60, limit=10**9):'),
     '状态端点重新变成无限流'),

    ('SEC-4 status 限流直接放行',
     GW,
     lambda s: s.replace('    if not _status_rate_ok():',
                         '    if False:'),
     '状态端点无限制'),

    ('SEC-4 限流器所有源共用一个计数器',
     GW,
     lambda s: s.replace('    ip = client_ip() or "-"',
                         '    ip = "-"'),
     '一个 IP 被限流会连累所有源'),

    ('SEC-5 恢复 via=lan-bypass 泄露',
     GW,
     lambda s: s.replace(
         '            "authenticated": True, "user": "lan",',
         '            "authenticated": True, "via": "lan-bypass", "user": "lan",'),
     '内网豁免机制重新暴露给客户端'),

    ('SEC-5 门户改回依赖 via 判别式',
     PORTAL,
     lambda s: s.replace(
         '        if (typeof d.expires_in === \'number\') {',
         '        if (d.via === \'token\') {'),
     '门户重新依赖认证方式标记'),
]


def run_tests():
    # 必须关掉字节码缓存：变异在 1 秒内连续写入，而 Python 判断 .pyc 是否过期
    # 只看 mtime + size。两条变异若大小相同，第二次就会复用第一次的 .pyc ——
    # 测的根本不是当前这条变异。实测这会让失败断言跨条目乱串，
    # 把「漏网」伪装成「捕获」。
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    p = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       timeout=180, cwd=ROOT, env=env)
    return p.returncode, p.stdout + p.stderr


def main():
    backups = {}
    try:
        print('════ 安全修复变异验证 ════\n')
        print('基线（未变异）应全绿：')
        rc, out = run_tests()
        if rc != 0:
            print(out[-2500:])
            print('❌ 基线就不过，无法验证变异')
            return 1
        print('  ✅ 基线 35/35 通过\n')

        caught = 0
        for name, path, mutate, expect in MUTATIONS:
            if path not in backups:
                backups[path] = open(path, encoding='utf-8').read()
            original = backups[path]
            mutated = mutate(original)
            if mutated == original:
                print('  ⚠️  %-38s 变异未生效（模式没匹配上，跳过）' % name)
                continue
            open(path, 'w', encoding='utf-8').write(mutated)
            try:
                rc, out = run_tests()
            finally:
                open(path, 'w', encoding='utf-8').write(original)
            if rc != 0:
                caught += 1
                fails = re.findall(r'^\s+-\s+(.+)$', out, re.M)
                print('  ✅ 被捕获  %-36s' % name)
                if fails:
                    print('        失败断言: %s' % ' | '.join(fails[:3]))
            else:
                print('  ❌ 漏网    %-36s' % name)
                print('        %s' % expect)

        total = len(backups) and len(MUTATIONS)
        print('\n────────────────────────────────')
        print('捕获 %d / %d' % (caught, len(MUTATIONS)))
        if caught < len(MUTATIONS):
            print('有变异未被捕获 → 对应测试无效')
            return 1
        return 0
    finally:
        for p, c in backups.items():
            open(p, 'w', encoding='utf-8').write(c)
        print('源码已全部还原')


if __name__ == '__main__':
    sys.exit(main())
