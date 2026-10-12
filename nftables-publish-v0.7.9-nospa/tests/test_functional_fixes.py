"""功能性审查发现的 7 个缺陷的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_functional_fixes.py

  FIX-1  ACME 申请/续期后必须补私钥权限（nginx worker 已降权，读不到会握手失败）
  FIX-2  证书 source 取值前后端一致（不一致会让续期按钮永远不显示）
  FIX-3  /auth/static/ 下的 HTML 必须带 CSP（真机实测过它可达且无该头）
  FIX-4  网关配置必须先部署后落盘（原来反过来，失败时磁盘已是新配置）
  FIX-5  反代 CRUD 必须做与端口转发的交叉校验（防免认证 DNAT 直达）
  FIX-6  手动更新 IPv6 必须写 /tmp/ddns-ipv6-*（只有 cron 脚本写 → IPv6 DDNS 静默失效）
  FIX-7  上传/重传必须校验证书与私钥配对，且校验失败不覆盖原文件
  FIX-8  /api/rules/save 不再绕过 /api/rules/apply 的安全路径（自己写盘）
  FIX-9  配置损坏时守卫覆盖全部下发与落盘路径（原来只挂 1 个端点）

每条测试都写成「旧代码必然失败」的形式。沙箱运行：不碰真实路径、
不执行 openssl / nft / nginx（需要外部命令的分支一律打桩）。
"""
import io
import os
import re
import sys
import contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


APP_SRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
AUTH_SRC = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
FE_HTML = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()


def fn_src(src, name):
    """取函数体（含下一行 def 之前的内容）。"""
    m = re.search(rf'^def {re.escape(name)}\(.*?(?=\n@app\.route|\ndef |\nclass |\n# ═)',
                  src, re.S | re.M)
    return m.group(0) if m else ''


def strip_comments(text):
    """去掉 # 注释行。

    不剥注释会踩同一个坑踩第二次：解释「为什么原来顺序反了」的注释里
    写着 save_config()，做位置判断时就把它当成了真正的调用点。
    """
    return '\n'.join(l for l in text.splitlines()
                     if not l.lstrip().startswith('#'))


def fn_code(src, name):
    """取函数体并剥掉 docstring 与 # 注释 —— 只剩可执行代码。

    为什么 docstring 也必须剥：这轮已经因为它踩了两次。
    修 restart_network 时我在 docstring 里写「原实现是 open(RULES_PATH,'w')」
    来解释改了什么，位置断言立刻匹配到 docstring 而非真实代码，测试误报；
    守卫前置那条同样栽在「shutil.copy(CONFIG_PATH, ...)」这句解释上。
    注释会骗人，解释修复原因的 docstring 一样会骗人。
    """
    body = fn_src(src, name)
    # 去掉紧跟 def 的第一个三引号块（函数 docstring）
    body = re.sub(r'(?s)^(def\s+\w+\([^)]*\)[^\n]*:\n)\s*("""|\'\'\')(?:(?!""").)*?\2\n',
                  r'\1', body, count=1)
    return strip_comments(body)


# ─────────────────────────────────────────────────────────────
sec('FIX-1  ACME 申请/续期后补私钥权限')

_issue = fn_src(APP_SRC, '_acme_issue')
_renew = fn_src(APP_SRC, '_acme_renew')
check('_acme_issue 内有 _harden_key_for_nginx_worker',
      '_harden_key_for_nginx_worker' in _issue,
      'acme.sh 以 root 写出 privkey.pem600，worker(nobody) 读不到 → 握手失败')
check('_acme_renew 内有 _harden_key_for_nginx_worker',
      '_harden_key_for_nginx_worker' in _renew,
      '续期会重写 privkey.pem，同样要补')
check('加固调用在 --install-cert 之后（不是之前）',
      _issue.find('_harden_key_for_nginx_worker') > _issue.find('--install-cert'),
      '写在 install-cert 之前等于加固了一个还不存在的文件')
check('续期里加固的是 privkey.pem 而不是 fullchain',
      'privkey.pem' in _renew)

# 五条私钥写入路径，三条 chmod + 两条 ACME，全都要覆盖
_sec_m = re.search(r'def _harden_key_for_nginx_worker.*?(?=\ndef |\n@app\.route|\n# ═)',
                   APP_SRC, re.S)
_fn_src = _sec_m.group(0) if _sec_m else ''
check('docstring 如实列出五条写入路径',
      '五条' in _fn_src and 'ACME' in _fn_src,
      '上一版 docstring 写「三处（上传/ACME续期/自签）」但第三处其实是 reupload，'
      '注释自己撒谎恰好掩盖了 ACME 的缺口')

# ─────────────────────────────────────────────────────────────
sec('FIX-2  证书 source 取值前后端一致')

_src_vals = set(re.findall(r'"source":\s*"(\w+)"', APP_SRC))
check('后端写入的 source 取值', bool(_src_vals), str(sorted(_src_vals)))
check('后端用的是 auto/manual', _src_vals == {'auto', 'manual'}, str(sorted(_src_vals)))

_fe_src_vals = set(re.findall(r"cert\.source === '(\w+)'", FE_HTML))
check('前端判断的 source 取值', bool(_fe_src_vals), str(sorted(_fe_src_vals)))
# 注意是「前端用到的值必须都在后端集合内」，不是两边集合完全相等 ——
# 前端只关心它要判的那一个值，没理由把另一个也写进模板里。
check('前端用到的取值后端确实会写（否则续期按钮永不显示）',
      _fe_src_vals and _fe_src_vals <= _src_vals,
      f'前端 {sorted(_fe_src_vals)} 必须是后端 {sorted(_src_vals)} 的子集')
check("前端不再残留 'acme' 判断", 'acme' not in _fe_src_vals)
check('后端 /renew 的守卫与前端一致（只接受 auto）',
      re.search(r'cert\.get\("source"\) != "auto"', APP_SRC) is not None)

# ─────────────────────────────────────────────────────────────
sec('FIX-3  /auth/static/ 下的 HTML 带 CSP')

_static = fn_src(AUTH_SRC, 'static_files')
check('static_files 里设了 CSP',
      'Content-Security-Policy' in _static,
      '真机实测：/auth/static/login.html 返回 200 且无该响应头')
check('CSP 只对 HTML 加（CSS/JS 加了也无害但没必要）',
      re.search(r'endswith\("\.html"\)|endswith\(\'\.html\'\)', _static) is not None)
check('CSP 值来自常量而不是就地再抄一份',
      'CSP_PORTAL_HTML' in _static and 'CSP_LOGIN_HTML' in _static,
      '就地再抄一份迟早分叉')
check('login.html 与 portal.html 用的是不同 CSP（form-action 不同）',
      'CSP_PORTAL_HTML if filename == "portal.html" else CSP_LOGIN_HTML' in _static)
check('两个常量都已定义',
      'CSP_LOGIN_HTML = (' in AUTH_SRC and 'CSP_PORTAL_HTML = (' in AUTH_SRC)
check('门户页与登录页改用常量（不再内联第二份）',
      _static.count('Content-Security-Policy') == 1
      and fn_src(AUTH_SRC, 'portal_page').count('Content-Security-Policy') == 1
      and fn_src(AUTH_SRC, 'auth_login_page').count('Content-Security-Policy') == 1)

# ─────────────────────────────────────────────────────────────
sec('FIX-4  网关配置先部署后落盘')

_gw = fn_src(APP_SRC, 'gateway_set_config')
if not _gw:
    # 函数名可能不同，从路由装饰器兜底
    m = re.search(r'@app\.route\(\s*[\'"]/api/gateway/config[\'"].*?(?=\n@app\.route)',
                  APP_SRC, re.S)
    _gw = m.group(0) if m else ''
check('找到网关配置保存路由', bool(_gw), '' if _gw else '未找到 /api/gateway/config')

# 顺序判断必须剥注释：解释「为什么原来顺序反了」的注释里就写着 save_config()，
# 而且那句注释的字节位置恰好落在真正调用之前，不剥就会读出「顺序反了」的假象。
_gw_code = strip_comments(_gw)
_i_save = _gw_code.find('save_config(')
_i_deploy = _gw_code.find('_deploy_gateway_nginx(')
check('先部署、后落盘',
      _i_deploy != -1 and _i_save != -1 and _i_deploy < _i_save,
      f'deploy@{_i_deploy} save@{_i_save}'
      + ('' if (_i_deploy != -1 and _i_save != -1 and _i_deploy < _i_save) else ' —— 顺序反了'))
# 同样剥注释：那条「配置已保存但网关部署失败」是旧文案，当前只该出现在解释它的注释里
check('部署失败的提示不再声称「已保存」',
      '配置已保存但网关部署失败' not in _gw_code,
      '落盘在前时说「已保存」是实话，但下一次改别的字段会基于这份落盘配置重新生成')
check('部署失败时明确告知配置未保存',
      '配置未保存' in _gw_code)

# ─────────────────────────────────────────────────────────────
sec('FIX-5  反代 CRUD 做与端口转发的交叉校验')

_conf = fn_src(APP_SRC, '_rp_forward_conflicts')
check('_rp_forward_conflicts 已抽成独立函数', bool(_conf))
check('validate_config 调用它（不再内联一份）',
      '_rp_forward_conflicts(cfg)' in fn_src(APP_SRC, 'validate_config'))
check('validate_config 内不再残留 rp_targets 内联逻辑',
      'rp_targets = set()' not in fn_src(APP_SRC, 'validate_config'),
      '两份逻辑迟早分叉 —— 反代的 PUT 就是这么漏的')

for fn in ('rp_create_rule', 'rp_update_rule'):
    body = fn_src(APP_SRC, fn)
    check(f'{fn} 调用了交叉校验',
          '_rp_forward_conflicts(' in body,
          '不调用就能构造免登录入口：先建转发、再建指向同一后端的反代')
    check(f'{fn} 校验在部署之前',
          body.find('_rp_forward_conflicts(') != -1
          and body.find('_rp_forward_conflicts(') < body.find('_deploy_all_rules('))
    check(f'{fn} 冲突时撤销了内存里的改动',
          re.search(r'rp\["rules"\]\.pop\(\)|rule\.update\(original\)', body) is not None)

# ─────────────────────────────────────────────────────────────
sec('FIX-6  手动更新 IPv6 写中转文件')

_ipv6 = fn_src(APP_SRC, 'update_ipv6')
# 断言必须盯 open() 调用本身。只找 '/tmp/ddns-ipv6-0' 这个字面量的话，
# 旁边 print("[WARN] 写 /tmp/ddns-ipv6-0 失败") 里也有同样的串 —— 变异把
# 真正的写入删掉、把警告留着，测试照样全绿。这已经是第三次被注释/旁证字面量骗了。
_writes = re.findall(r'with open\((f?)"/tmp/ddns-ipv6-(0|\{idx\})",\s*"w"\)', _ipv6)
check('update_ipv6 写 /tmp/ddns-ipv6-0（路由器本机地址）',
      ('', '0') in _writes,
      'DDNS 的 ip_script 读的就是这个文件；已匹配到 ' + str(_writes))
check('update_ipv6 写 /tmp/ddns-ipv6-{idx}（各条转发）',
      ('f', '{idx}') in _writes,
      '已匹配到 ' + str(_writes))
check('两处写入都在（不是只写本机地址）', len(_writes) == 2, str(_writes))

# 每处写入都必须被 try/except OSError 包住：写不进去是环境问题，
# 让整个接口 500 反而把「DDNS 输入缺失」变成一个看不出原因的故障。
_guards = re.findall(r'try:\s*\n(?:[^\n]*\n)*?[^\n]*with open\([^\n]*ddns-ipv6[^\n]*\n(?:[^\n]*\n)*?\s*except OSError[^\n]*:\s*\n\s*print\(',
                     strip_comments(_ipv6))
check('两处写入都包了 try/except OSError（IO 失败不阻断主流程）',
      len(_guards) == 2,
      f'匹配到 {len(_guards)} 处 —— 保护数与写入数不等就说明有裸写的')

# ─────────────────────────────────────────────────────────────
sec('FIX-7  上传/重传校验证书与私钥配对')

_pair = fn_src(APP_SRC, '_cert_key_pair_ok')
check('_cert_key_pair_ok 函数存在', bool(_pair))
check('比较的是两边的公钥（不是比字符串）',
      'x509' in _pair and '-pubkey' in _pair and 'pkey' in _pair and '-pubout' in _pair)
check('用 pkey 而不是 rsa（ECDSA 私钥也能过）',
      '["openssl", "pkey"' in _pair)
check('公钥不一致时判定为不配对（整个校验的核心）',
      re.search(r'if pub_c != pub_k:\s*\n\s*return False',
                strip_comments(_pair)) is not None,
      '只把两边公钥都取出来却从不比较 = 校验形同虚设，恰好还是原来那个 bug')
# 剥注释：except 与 return True 之间夹着解释「为什么放行」的一行注释
check('openssl 不可用时放行，不拦用户存证书',
      re.search(r'except Exception[^\n]*:\s*\n\s*return True',
                strip_comments(_pair)) is not None,
      '校验不了 ≠ 校验失败，环境缺 openssl 不该拦住用户存证书')

for fn, tmp_c, tmp_k in (('rp_upload_cert', '.upload.tmp', '.upload.tmp'),
                         ('rp_reupload_cert', '.reupload.tmp', '.reupload.tmp')):
    body = fn_src(APP_SRC, fn)
    check(f'{fn} 调用了配对校验',
          '_cert_key_pair_ok(' in body)
    check(f'{fn} 先写临时文件再校验',
          f'{tmp_c}' in body and f'{tmp_k}' in body,
          '直接 save 到正式路径的话，传错私钥已经把原来能用的证书冲掉了')
    check(f'{fn} 校验失败时删除临时文件并返回 400',
          re.search(r'if not ok:.*?_unlink_quiet.*?400', body, re.S) is not None)
    check(f'{fn} 校验通过才 os.replace 覆盖正式文件',
          'os.replace(' in body)

check('垃圾文件（非 x509）会被拒绝而不是入库',
      'return False, "证书文件无法解析' in _pair)

# ─────────────────────────────────────────────────────────────
sec('FIX-8  /api/rules/save 不绕过 apply 的安全路径')

_save = fn_src(APP_SRC, 'save_rules')
check('/api/rules/save 转发给 apply_rules',
      re.search(r'\n\s*return apply_rules\(\)', strip_comments(_save)) is not None,
      '自己 build_rules + 写盘会同时绕过配置损坏守卫、_FW_APPLY_LOCK、'
      '语法校验与失败回滚这四样')
check('不再直接往 RULES_PATH 写盘',
      not re.search(r'open\(RULES_PATH,\s*[\'"]w[\'"]\)', _save))
check('apply_rules 侧的配置损坏守卫还在（save 现在共用它）',
      '_config_corrupted_response()' in fn_src(APP_SRC, 'apply_rules'))
check('apply_rules 走加锁下发（save 现在共用它）',
      '_apply_ruleset(config)' in fn_src(APP_SRC, 'apply_rules'))

# ─────────────────────────────────────────────────────────────
sec('FIX-9  配置损坏守卫覆盖全部下发与落盘路径')

_apply = fn_code(APP_SRC, '_apply_ruleset')
check('_apply_ruleset 内部查 _config_corrupted()',
      '_config_corrupted()' in _apply,
      '守卫原来只挂在 /api/rules/apply 一个端点上，其余 5 个端点全绕过')
check('守卫在取锁之前判断（纯内存检查没理由占锁）',
      _apply.find('_config_corrupted()') < _apply.find('_FW_APPLY_LOCK.acquire()'))
check('守卫命中时返回 (False, 拒绝文案) 而不是抛异常',
      re.search(r'if bad:\s*\n(?:[^\n]*\n){0,3}?\s*return False,', _apply) is not None,
      '返回 False 让调用方按自己的话术报错，抛异常会让 5 个端点各不相同')

_save = fn_code(APP_SRC, 'save_config')
# 锚点必须带缩进：docstring 里也出现了同一行文字来解释「为什么守卫要前置」，
# 只按裸字符串找会先匹配到 docstring，把顺序判断读反（同一个坑第三次）。
_i_backup = _save.find("    shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')")
check('save_config 也查 _config_corrupted()（阻断持久化）',
      '_config_corrupted()' in _save,
      '守卫只挡下发不挡落盘 = 一次瞬时损坏被固化成永久配置')
check('守卫在「把当前文件复制成 .backup」之前',
      _i_backup != -1 and _save.find('_config_corrupted()') < _i_backup,
      f'守卫@{_save.find("_config_corrupted()")} / 备份@{_i_backup}。'
      'load_config 检出损坏时会把原件移走，这时 .backup 是唯一完好的恢复材料，'
      '先复制等于用损坏文件覆盖它')
check('命中时抛 ConfigCorruptedError', 'raise ConfigCorruptedError' in _save)
check('_force 旁路存在且默认关闭',
      re.search(r'def save_config\(config,\s*_force=False\)', APP_SRC) is not None)
check('ConfigCorruptedError 有统一的 errorhandler（8 个调用点不用各写一遍）',
      '@app.errorhandler(ConfigCorruptedError)' in APP_SRC)
# {path} 漏填会直接 KeyError —— 这个坑我真踩了一次，所以单列一条
_refusal_re = r"_CORRUPT_REFUSAL\.format\([^)]*err=err[^)]*path=CONFIG_PATH\)"
check('_CORRUPT_REFUSAL 的 {err} 与 {path} 两个占位符都填了',
      len(re.findall(_refusal_re, APP_SRC)) >= 2,
      f'实际 {len(re.findall(_refusal_re, APP_SRC))} 处（save_config 与 _apply_ruleset 各一处）')

_rn = fn_code(APP_SRC, 'restart_network')
check('restart_network 改走 _apply_ruleset（拿到原子写/预检/备份/锁）',
      '_apply_ruleset(config)' in _rn)
check('restart_network 不再自己 open(RULES_PATH) 写盘',
      not re.search(r'open\(RULES_PATH,\s*[\'"]w[\'"]\)', _rn))
check('restart_network 不再自己跑 nft -f',
      not re.search(r"subprocess\.run\(\['nft',\s*'-f'", _rn))
_i_guard = _rn.find('_config_corrupted()')
_i_restart = _rn.find('/etc/init.d/network')
check('守卫在重启网络之前（否则网络已断才发现装不回规则）',
      _i_guard != -1 and _i_restart != -1 and _i_guard < _i_restart,
      f'守卫@{_i_guard} / 重启@{_i_restart}')
check('重启在下发之前（重启会重载 fw4 冲掉规则）',
      _i_restart < _rn.find('_apply_ruleset(config)'))

# 守卫下沉不能误伤看门狗自愈 —— 它自己会查并退到 .backup / lockdown
check('看门狗有自己的损坏检查（守卫下沉不会误伤自愈）',
      '_config_corrupted()' in fn_src(APP_SRC, '_auto_recover_ruleset_if_empty'))

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')