#!/usr/bin/env python3
"""变异验证：把功能性审查的 7 组修复逐条改回旧行为，确认 tests/test_functional_fixes.py 会变红。

全绿的测试套件不能证明它在测东西 —— 必须在缺陷重现时失败。
每条变异对应「这个修复如果没做，会退化出什么行为」，不是随便改改看能不能被抓。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_functional.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {
    'app': os.path.join(ROOT, 'backend', 'app.py'),
    'auth': os.path.join(ROOT, 'backend', 'auth_gateway.py'),
    'fe': os.path.join(ROOT, 'frontend', 'index.html'),
}
TEST = os.path.join(ROOT, 'tests', 'test_functional_fixes.py')

# (描述, 文件键, 旧文本, 新文本, 期望出现次数)
MUTATIONS = [
    # ── FIX-1  ACME 路径漏掉私钥权限加固 ────────────────────────────
    ('FIX-1 _acme_issue 不补权限（nginx worker 读不到 acme.sh 写的私钥）', 'app',
     '    _harden_key_for_nginx_worker(keyfile)',
     '    pass  # 变异：还原成不加固', 1),

    ('FIX-1 _acme_renew 不补权限（续期会重写 privkey.pem）', 'app',
     '    _harden_key_for_nginx_worker(os.path.join(cert_dir, "privkey.pem"))',
     '    pass  # 变异：还原成不加固', 1),

    ('FIX-1 docstring 谎报成「三条」', 'app',
     '写入私钥的路径一共五条', '写入私钥的路径一共三条', 1),

    # ── FIX-2  前后端 source 取值不一致 ────────────────────────────
    ('FIX-2 前端改回判 acme（后端写的是 auto → 续期按钮永不显示）', 'fe',
     "cert.source === 'auto'", "cert.source === 'acme'", 3),

    # ── FIX-3  /auth/static/ 的 HTML 缺 CSP ─────────────────────────
    ('FIX-3 static_files 不给 HTML 加 CSP', 'auth',
     '    if filename.endswith(".html"):\n'
     '        resp.headers["Content-Security-Policy"] = (\n'
     '            CSP_PORTAL_HTML if filename == "portal.html" else CSP_LOGIN_HTML)\n'
     '    return resp',
     '    return resp', 1),

    ('FIX-3 CSP 不区分登录页与门户页（form-action 放宽成任意来源）', 'auth',
     '            CSP_PORTAL_HTML if filename == "portal.html" else CSP_LOGIN_HTML)',
     '            CSP_PORTAL_HTML)', 1),

    # ── FIX-4  网关配置先落盘后部署 ────────────────────────────────
    ('FIX-4 改回「先 save_config 后部署」（部署失败时磁盘已是新配置）', 'app',
     '    deploy_ok, deploy_msg = _deploy_gateway_nginx(new_cfg)\n'
     '    if not deploy_ok:\n'
     '        return jsonify({"success": False,\n'
     '                        "message": f"网关部署失败，配置未保存：{deploy_msg}"}), 500\n'
     '\n'
     '    save_config(new_cfg)',
     '    save_config(new_cfg)\n'
     '    deploy_ok, deploy_msg = _deploy_gateway_nginx(new_cfg)\n'
     '    if not deploy_ok:\n'
     '        return jsonify({"success": False,\n'
     '                        "message": f"配置已保存但网关部署失败：{deploy_msg}"}), 500', 1),

    # ── FIX-5  反代 CRUD 漏交叉校验（免认证 DNAT 直达） ──────────────
    ('FIX-5 rp_create_rule 不做交叉校验', 'app',
     '    conflicts = _rp_forward_conflicts(config)\n'
     '    if conflicts:\n'
     '        rp["rules"].pop()',
     '    conflicts = []\n'
     '    if conflicts:\n'
     '        rp["rules"].pop()', 1),

    ('FIX-5 rp_create_rule 冲突时不撤销 append', 'app',
     '        rp["rules"].pop()\n', '        pass  # 变异：脏规则留在内存里\n', 1),

    ('FIX-5 rp_update_rule 不做交叉校验', 'app',
     '    conflicts = _rp_forward_conflicts(config)\n'
     '    if conflicts:\n'
     '        rule.clear()\n'
     '        rule.update(original)',
     '    conflicts = []\n'
     '    if conflicts:\n'
     '        rule.clear()\n'
     '        rule.update(original)', 1),

    ('FIX-5 rp_update_rule 冲突时不还原被改的规则', 'app',
     '        rule.update(original)\n', '        pass  # 变异：改动不还原\n', 1),

    ('FIX-5 validate_config 不再调交叉校验（两份逻辑分叉）', 'app',
     '    errs.extend(_rp_forward_conflicts(cfg))',
     '    pass  # 变异：内联逻辑被删掉', 1),

    # ── FIX-6  手动更新 IPv6 不写 DDNS 中转文件 ─────────────────────
    ('FIX-6 手动更新 IPv6 不写 /tmp/ddns-ipv6-0', 'app',
     '            with open("/tmp/ddns-ipv6-0", "w") as f:\n'
     '                f.write(f"{prefix}::1")',
     '            pass  # 变异：DDNS 读不到本机地址', 1),

    ('FIX-6 手动更新 IPv6 不写 /tmp/ddns-ipv6-{idx}', 'app',
     '                with open(f"/tmp/ddns-ipv6-{idx}", "w") as f:\n'
     '                    f.write(full_ipv6)',
     '                pass  # 变异：DDNS 读不到转发地址', 1),

    ('FIX-6 写中转文件失败时改成抛异常（一个 IO 错误让整个接口 500）', 'app',
     '        except OSError as e:\n'
     '            print(f"[WARN] 写 /tmp/ddns-ipv6-0 失败: {e}", flush=True)',
     '        except ValueError as e:\n'
     '            print(f"[WARN] 写 /tmp/ddns-ipv6-0 失败: {e}", flush=True)', 1),

    # ── FIX-7  上传/重传不校验配对 ──────────────────────────────────
    ('FIX-7 公钥取出来却不比较（校验形同虚设，正是原来的 bug）', 'app',
     '    if pub_c != pub_k:',
     '    if False:  # 变异：不比较', 1),

    ('FIX-7 配对不通过也判通过', 'app',
     '        return False, "证书与私钥不配对（两个文件的公钥不一致）"',
     '        return True, "证书与私钥不配对（两个文件的公钥不一致）"', 1),

    ('FIX-7 openssl 不可用时改成拦截（环境问题被当成校验失败）', 'app',
     '        return True, f"无法校验（{type(e).__name__}），已跳过"',
     '        return False, f"无法校验（{type(e).__name__}），已跳过"', 1),

    ('FIX-7 垃圾文件当合法证书放行', 'app',
     '        return False, "证书文件无法解析（可能不是 PEM 格式的 x509 证书）"',
     '        return True, "证书文件无法解析（可能不是 PEM 格式的 x509 证书）"', 1),

    ('FIX-7 用 rsa 读私钥（ECDSA 证书被误拒）', 'app',
     '["openssl", "pkey"', '["openssl", "rsa"', 1),

    ('FIX-7 upload/reupload 都跳过配对校验', 'app',
     '        ok, why = _cert_key_pair_ok(tmp_c, tmp_k)',
     '        ok, why = True, ""  # 变异：不校验', 2),

    ('FIX-7 upload 改回直写正式文件（传错私钥会冲掉原证书）', 'app',
     '    tmp_c = fullchain_path + ".upload.tmp"\n'
     '    tmp_k = key_path + ".upload.tmp"',
     '    tmp_c = fullchain_path\n'
     '    tmp_k = key_path', 1),

    ('FIX-7 reupload 改回直写正式文件', 'app',
     '        tmp_c = cert_path + ".reupload.tmp"\n'
     '        tmp_k = key_path + ".reupload.tmp"',
     '        tmp_c = cert_path\n'
     '        tmp_k = key_path', 1),

    # ── FIX-8  /api/rules/save 是条绕过全部安全机制的旁路 ────────────
    ('FIX-8 /api/rules/save 改回自己写盘（绕过损坏守卫/锁/校验/回滚）', 'app',
     '    return apply_rules()\n',
     '    config = load_config()\n'
     '    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)\n'
     '    with open(RULES_PATH, "w") as f:\n'
     '        f.write(build_rules(config))\n'
     '    return jsonify({"success": True, "message": "规则已保存",\n'
     '                    "path": RULES_PATH})\n', 1),

    ('FIX-8 apply_rules 去掉配置损坏守卫（save 转发过来也跟着失效）', 'app',
     '    refused = _config_corrupted_response()\n'
     '    if refused is not None:\n'
     '        return refused',
     '    refused = None', 1),
]


def run_tests():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       timeout=300, env=env)
    return r.returncode, r.stdout


def main():
    backup = tempfile.mkdtemp()
    for key, path in FILES.items():
        shutil.copy(path, os.path.join(backup, key))
    originals = {key: open(path, encoding='utf-8').read() for key, path in FILES.items()}

    def restore():
        for key, path in FILES.items():
            shutil.copy(os.path.join(backup, key), path)

    print('=== 变异验证：功能性审查修复 ===')
    rc, _ = run_tests()
    if rc != 0:
        print('❌ 基线就不是全绿，先修好再谈变异')
        restore()
        return 2
    print('  基线全绿，开始注入变异\n')

    caught = missed = skipped = 0
    missed_list = []
    for desc, key, old, new, expect in MUTATIONS:
        src = originals[key]
        n = src.count(old)
        if n != expect:
            print(f'  ⚠️  {desc} —— 锚点出现 {n} 次（期望 {expect}），跳过')
            skipped += 1
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src.replace(old, new))
        rc, out = run_tests()
        fails = out.count('❌')
        if rc != 0:
            print(f'  ✅ {desc} —— 被捕获（{fails} 条断言失败）')
            caught += 1
        else:
            print(f'  ❌ {desc} —— 测试仍然全绿（无效变异！）')
            missed += 1
            missed_list.append(desc)
        restore()

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