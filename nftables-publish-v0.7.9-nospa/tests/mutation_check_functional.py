#!/usr/bin/env python3
"""变异验证：把功能性审查的 10 组修复逐条改回旧行为，确认 tests/test_functional_fixes.py 会变红。

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
    'js': os.path.join(ROOT, 'frontend', 'app.js'),
    'tool': os.path.join(ROOT, 'tools', 'check-api-coverage.py'),
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

    # 锚点缩进跟着 FIX-12 的改动一起挪了位置（写中转文件移进了成功分支），
    # 变异脚本必须跟着代码走 —— 锚点对不上就跳过，不改就是让变异名存实亡。
    ('FIX-6 手动更新 IPv6 不写 /tmp/ddns-ipv6-{idx}', 'app',
     '                    with open(f"/tmp/ddns-ipv6-{idx}", "w") as f:\n'
     '                        f.write(full_ipv6)',
     '                    pass  # 变异：DDNS 读不到转发地址', 1),

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

    # ── FIX-9  守卫只挂 1 个端点 / 只挡下发不挡落盘 ──────────────────
    ('FIX-9 _apply_ruleset 里的守卫去掉（下发旁路重新打开）', 'app',
     '    bad, err = _config_corrupted()\n'
     '    if bad:\n'
     "        print(f'[ERROR] 配置损坏（{err}），拒绝按默认配置下发 nft 规则', flush=True)\n"
     '        return False, _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH)\n',
     '    pass\n', 1),

    ('FIX-9 save_config 的守卫去掉（损坏被固化成永久配置）', 'app',
     '    if not _force:\n'
     '        bad, err = _config_corrupted()\n'
     '        if bad:\n'
     '            raise ConfigCorruptedError(_CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH))\n',
     '    if False:\n        pass\n', 1),

    ('FIX-9 save_config 的守卫挪到备份之后（唯一完好的恢复材料被覆盖）', 'app',
     '    if not _force:\n'
     '        bad, err = _config_corrupted()\n'
     '        if bad:\n'
     '            raise ConfigCorruptedError(_CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH))\n'
     '    # 自动备份当前配置\n'
     "    if os.path.exists(CONFIG_PATH):\n"
     "        shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')\n",
     '    # 自动备份当前配置\n'
     "    if os.path.exists(CONFIG_PATH):\n"
     "        shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')\n"
     '    if not _force:\n'
     '        bad, err = _config_corrupted()\n'
     '        if bad:\n'
     '            raise ConfigCorruptedError(_CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH))\n', 1),

    ('FIX-9 restart_network 改回自己写盘自己跑 nft -f', 'app',
     '        ok, message = _apply_ruleset(config)\n'
     '        if not ok:\n'
     '            return jsonify({"success": False, "message":\n'
     '                            f"网络已重启，但防火墙规则未生效，{message}"}), 500\n',
     '        rules = build_rules(config)\n'
     '        os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)\n'
     "        with open(RULES_PATH, 'w') as f:\n"
     '            f.write(rules)\n'
     "        res = subprocess.run(['nft', '-f', RULES_PATH], capture_output=True, text=True, timeout=30)\n"
     '        if res.returncode != 0:\n'
     '            return jsonify({"success": False, "message": "规则加载失败"}), 500\n', 1),

    ('FIX-9 restart_network 的守卫挪到重启网络之后（网络已断才发现装不回规则）', 'app',
     '        bad, err = _config_corrupted()\n'
     '        if bad:\n'
     '            return jsonify({"success": False, "code": "CONFIG_CORRUPTED",\n'
     '                            "message": _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH)}), 500\n'
     "        subprocess.run(['/etc/init.d/network', 'restart'],\n"
     '                       capture_output=True, text=True, timeout=30)\n',
     "        subprocess.run(['/etc/init.d/network', 'restart'],\n"
     '                       capture_output=True, text=True, timeout=30)\n'
     '        bad, err = _config_corrupted()\n'
     '        if bad:\n'
     '            return jsonify({"success": False, "code": "CONFIG_CORRUPTED",\n'
     '                            "message": _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH)}), 500\n', 1),

    ('FIX-9 errorhandler 去掉（save_config 抛出的异常变成裸 500）', 'app',
     '@app.errorhandler(ConfigCorruptedError)\n'
     'def _handle_config_corrupted(e):\n'
     '    """save_config 在配置损坏时抛的异常统一在这里变成 500 响应。\n'
     '\n'
     '    为什么要单独一个 handler：save_config 有 8 个调用点（保存配置、网络配置、\n'
     '    名单预设增删改、名单历史清理、反代配置落盘…）。在每个调用点手写 try/except\n'
     '    迟早会漏一个，而漏掉的那个就是「静默把出厂配置写回磁盘」的那条路。\n'
     '    统一抛 + 统一格式化，改一处就全覆盖。\n'
     '    """\n'
     "    return jsonify({'success': False,\n"
     "                    'code': 'CONFIG_CORRUPTED',\n"
     "                    'message': str(e)}), 500\n\n\n",
     '', 1),

    # ── FIX-10  0 服务时 $auth_user 无定义 / 缺 reverse_proxy 段崩溃 ──
    ('FIX-10 去掉 $auth_user 默认值（0 服务时 nginx unknown variable）', 'app',
     '    L.append(\'    set $auth_user "";\')\n'
     '    L.append(\'    set $auth_device "";\')',
     '    pass  # 变异：还原成不定义', 1),

    ('FIX-10 $auth_device 漏掉默认定义', 'app',
     '    L.append(\'    set $auth_device "";\')',
     '    pass  # 变异：只补了 user', 1),

    ('FIX-10b 去掉 reverse_proxy 的 dict 兜底（全新安装即 AttributeError）', 'app',
     '    rp = config.get("reverse_proxy")\n'
     '    if not isinstance(rp, dict):\n'
     '        rp = {}\n'
     '    if isinstance(rp.get("settings"), dict):\n'
     '        settings = rp["settings"]',
     '    rp = config.get("reverse_proxy")\n'
     '    if isinstance(rp, dict) and isinstance(rp.get("settings"), dict):\n'
     '        settings = rp["settings"]', 1),

    ('FIX-10b 兜底挪到 settings 之后（证书读取先炸，兜底形同虚设）', 'app',
     '    rp = config.get("reverse_proxy")\n'
     '    if not isinstance(rp, dict):\n'
     '        rp = {}\n'
     '    if isinstance(rp.get("settings"), dict):\n'
     '        settings = rp["settings"]\n'
     '\n'
     '    cert_id = str(settings.get("default_cert_id", "") or "")\n'
     '    certs = {c.get("id"): c for c in (rp.get("certificates") or [])',
     '    rp = config.get("reverse_proxy")\n'
     '    if isinstance(rp, dict) and isinstance(rp.get("settings"), dict):\n'
     '        settings = rp["settings"]\n'
     '\n'
     '    cert_id = str(settings.get("default_cert_id", "") or "")\n'
     '    certs = {c.get("id"): c for c in ((rp or {}).get("certificates") or [])', 1),

    # ── FIX-11  名单增量操作不持锁 ────────────────────────────────
    ('FIX-11 _nft_set_write 不持锁（又与看门狗 nft -f 交叉执行）', 'app',
     '    with _FW_APPLY_LOCK:\n'
     "        return subprocess.run(['nft'] + list(args), capture_output=True,\n"
     '                              text=True, timeout=timeout)',
     '    return subprocess.run([\'nft\'] + list(args), capture_output=True,\n'
     '                          text=True, timeout=timeout)', 1),

    ('FIX-11 list_add 退回裸 subprocess.run（绕过统一入口 = 绕过锁）', 'app',
     "        result = _nft_set_write(['add', 'element', 'inet', 'fw4', set_name, '{', ip, '}'])",
     "        result = subprocess.run(\n"
     "            ['nft', 'add', 'element', 'inet', 'fw4', set_name, '{', ip, '}'],\n"
     '            capture_output=True, text=True, timeout=10\n'
     '        )', 1),

    ('FIX-11 list_flush 退回裸 subprocess.run', 'app',
     "        result = _nft_set_write(['flush', 'set', 'inet', 'fw4', set_name])",
     "        result = subprocess.run(\n"
     "            ['nft', 'flush', 'set', 'inet', 'fw4', set_name],\n"
     '            capture_output=True, text=True, timeout=10\n'
     '        )', 1),

    ('FIX-11 list_delete 退回裸 subprocess.run', 'app',
     "        result = _nft_set_write(['delete', 'element', 'inet', 'fw4', set_name, '{', ip, '}'])",
     "        result = subprocess.run(\n"
     "            ['nft', 'delete', 'element', 'inet', 'fw4', set_name, '{', ip, '}'],\n"
     '            capture_output=True, text=True, timeout=10\n'
     '        )', 1),

    ('FIX-11 presets/apply 退回裸 subprocess.run', 'app',
     '        result = _nft_set_write(cmd[1:])',
     '        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)', 1),

    ('FIX-11 update_ipv6 的批量事务不持锁', 'app',
     "                with _FW_APPLY_LOCK:\n"
     "                    result = subprocess.run(['nft', '-f', '-'], input=batch,\n"
     '                                            capture_output=True, text=True,\n'
     '                                            timeout=10)',
     "                result = subprocess.run(['nft', '-f', '-'], input=batch,\n"
     '                                        capture_output=True, text=True,\n'
     '                                        timeout=10)', 1),

    # ── FIX-12  update_ipv6 部分失败被掩盖 ─────────────────────────
    ('FIX-12 flush 与 add 拆回两条命令（add 失败时旧地址被清空）', 'app',
     "            batch = (f\"flush set inet fw4 {set_name}\\n\"\n"
     '                     f"add element inet fw4 {set_name} {{ {full_ipv6} }}\\n")',
     '            batch = f"add element inet fw4 {set_name} {{ {full_ipv6} }}\\n"\n'
     '            _nft_set_write([\'flush\', \'set\', \'inet\', \'fw4\', set_name])', 1),

    ('FIX-12 顶层 success 无条件 True（部分失败也报成功）', 'app',
     '            "success": not failed,',
     '            "success": True,', 1),

    ('FIX-12 message 数的是尝试数不是成功数', 'app',
     '            message = (f"成功 {len(updated)} 条，失败 {len(failed)} 条："',
     '            message = (f"已更新 {len(updated)} 条，失败 {len(failed)} 条："', 1),

    ('FIX-12 部分失败仍返回 200（前端封装按 success 判，这里是双保险）', 'app',
     '        }), (200 if not failed else 500)',
     '        })', 1),

    ('FIX-12 前端不再读 failed 明细（后端算好了但界面看不见）', 'js',
     '        const failed = e.data && e.data.failed;\n'
     '        if (failed && failed.length) {',
     '        const failed = null;\n'
     '        if (failed && failed.length) {', 1),

    # ── FIX-14  回环白名单 ────────────────────────────────────────
    ('FIX-14 只放行 IPv6 回环（IPv4 本机访问被 deny all 挡成 403）', 'app',
     '            L.append("        allow 127.0.0.1;")\n'
     '            L.append("        allow ::1;")',
     '            L.append("        allow ::1;")', 1),

    ('FIX-14 把 ::1 换成 127.0.0.1（等于把 IPv6 回环堵回去）', 'app',
     '            L.append("        allow 127.0.0.1;")\n'
     '            L.append("        allow ::1;")',
     '            L.append("        allow 127.0.0.1;")', 1),

    ('FIX-14 回环白名单排在 deny all 之后（写了也不生效）', 'app',
     '            L.append("        allow 127.0.0.1;")\n'
     '            L.append("        allow ::1;")\n'
     '            L.append("        deny all;")',
     '            L.append("        deny all;")\n'
     '            L.append("        allow 127.0.0.1;")\n'
     '            L.append("        allow ::1;")', 1),

    # ── FIX-13  界面没接上（等于死接口还在） ───────────────────────
    ('FIX-13 侧边栏去掉改密码入口（功能又变成只有 curl 能用）', 'fe',
     '          修改密码\n', '\n', 1),

    ('FIX-13 证书重传按钮改成对所有证书显示（ACME 证书会被误导向重传）', 'fe',
     'x-show="cert.source !== \'auto\'"\n'
     '                        @click="pickRpReupload(cert, \'cert\')"',
     '@click="pickRpReupload(cert, \'cert\')"', 1),

    ('FIX-13 阿里云测试不再传 ipv6_source（IPv6 来源文件为空这个静默失效又测不到了）',
     'js',
     "          ipv6_source: isAaaa ? (src || '') : '',",
     "          ipv6_source: '',", 1),

    ('FIX-13 工具把「刻意不做界面」的清单删掉（5 条误报又回来了）', 'tool',
     "    '/api/knock-info': '供 LAN 内客户端脚本读敲门端口，刻意无面板入口',",
     "    # '/api/knock-info': 误报登记被删", 1),

    # ── FIX-15  x-show 与组件根位置（真实浏览器实测逮到的） ────────
    ('FIX-15 看门狗区退回 x-show（watchdog 为 null 时刷 TypeError）', 'fe',
     '<template x-if="rulesHealth.watchdog">',
     '<div x-show="rulesHealth.watchdog"', 1),

    ('FIX-15 阿里云结果行退回 x-show（result 为 null 时刷 TypeError）', 'fe',
     '<template x-if="aliyunTest.result && aliyunTest.index === index">',
     '<p x-show="aliyunTest.result && aliyunTest.index === index"', 1),

    ('FIX-15 弹窗被挪出 x-data 组件根（遮罩挡住整页，按钮全点不动）', 'fe',
     '    </main>\n',
     '    </main>\n  </div>\n', 1),
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