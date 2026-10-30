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
  FIX-10 网关 0 服务时 nginx 配置必须能加载（$auth_user 未定义会让整份配置被拒）
  FIX-10b 配置缺 reverse_proxy 段时不能 AttributeError（全新安装即命中）
  FIX-11 名单增量 nft 操作持 _FW_APPLY_LOCK（原来与看门狗 nft -f 交叉执行）
  FIX-12 update_ipv6 部分失败不再被掩盖（原子事务 + 如实汇总 + 前端显示明细）

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
_relay = fn_src(APP_SRC, '_write_ddns_relay')

# ⚠️ FIX-6 在 P2-14 之后**行为翻转了**，断言必须跟着翻。
#
# 原来查的是 `open("/tmp/ddns-ipv6-N", "w")` 裸写 + 「两处都包了
# try/except OSError（IO 失败不阻断主流程）」。
#
# 两个问题：
#   1. 裸写会**跟随软链** —— /tmp 是 1777 sticky 共享目录，别的本地用户
#      可以提前建好同名软链，面板是 root ⇒ open(path,'w') 跟着软链把目标
#      截断重写 = root 权限的任意文件写（P2-14）。
#   2. 「IO 失败不阻断主流程」这条**本身就是缺陷**：写不进去 = DDNS
#      继续发布**上一个旧地址**，用户以为地址更新了。静默跳过 = 谎报成功。
#
# 现在：中转文件走 _write_ddns_relay（随机名 tmp + O_EXCL|O_NOFOLLOW +
# 0600 + os.replace 原子换名），写失败**如实上报**、不阻断也不谎报成功。

check('update_ipv6 不再有裸 open("/tmp/ddns-ipv6-N", "w") 写入',
      re.search(r'with open\([^)]*ddns-ipv6[^)]*["\']w["\']', _ipv6) is None,
      '仍有裸写（会跟随软链）')

_relay_calls = re.findall(r'_write_ddns_relay\(', _ipv6)
check('update_ipv6 通过 _write_ddns_relay 写中转文件（本机地址 + 各条转发）',
      len(_relay_calls) >= 2, f'匹配到 {len(_relay_calls)} 处')

check('_write_ddns_relay 用 O_NOFOLLOW（不跟随软链）',
      'O_NOFOLLOW' in _relay)
check('_write_ddns_relay 用 O_EXCL（不覆盖任何已存在的东西）',
      'O_EXCL' in _relay)
check('_write_ddns_relay 建文件即 0600（落盘那一刻就不可读）',
      '0o600' in _relay)
check('_write_ddns_relay 用 os.replace 原子换名（不跟随软链）',
      'os.replace' in _relay)
check('_write_ddns_relay 用随机 tmp 名（别的用户猜不到）',
      'secrets.token_hex' in _relay)

# ⚠️ 这条要盯**写失败时的返回形态**。
# 「写失败时抛异常」和「写失败时返回 (False, err)」在 update_ipv6 那侧
# 表现一样（都进错误列表），所以只看调用方是分不出来的 ——
# 必须盯被调函数自己：它必须**返回**失败，不能 raise。
# 抛出去的后果：update_ipv6 整个 500，把「中转文件写不进去」变成一个
# 看不出原因的接口错误（用户看到 500，实际是磁盘/权限问题）。
check('_write_ddns_relay 写失败时返回 (False, err) 而不是抛异常',
      re.search(r'except OSError as e:.*?return False,', _relay, re.S) is not None
      and 'raise' not in _relay,
      '写失败会抛出去（一个 IO 错误让整个接口 500）')

# 写失败必须**如实上报**，不能静默跳过（静默 = DDNS 继续发布旧地址）
check('写失败进错误列表（不是静默跳过）',
      'relay_errors' in _ipv6 or 'failed' in _ipv6,
      '写失败没有进错误列表')
check('写失败会打 ERROR 级日志',
      re.search(r'print\(f?["\']\[ERROR\]', _ipv6) is not None,
      '写失败没有 ERROR 日志')

# 过期的中转文件要有人清（P2-13）
check('过期的中转文件会被清理（P2-13）',
      '_cleanup_orphan_ddns_relays' in _ipv6,
      '没有清理过期中转文件的调用')

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

# ── FIX-10 ────────────────────────────────────────────────────────
# 网关开着 + 0 个反代服务时生成的 nginx 配置必须能加载。
# 旧代码在这里产出 [emerg] unknown "auth_user" variable（.224 真机实测），
# 后果不是少个功能，是整份配置拒绝加载 → 整个网关连 portal/登录页一起没了。
sec('FIX-10 网关 0 服务时 nginx 配置仍可加载（$auth_user 必须有定义）')
# 2026-10-28 host 分发改造把网关配置的生成拆成了三个函数：
#   _generate_gateway_nginx_conf（组装）/ _nginx_server_preamble（server 前言）/
#   _nginx_service_location（单个服务的 location）
# $auth_user 的默认值在前言里、回环白名单在 service location 里 —— 只看主函数
# 会把它们当成「消失了」。这里是**搬走**，不是删除，所以断言要覆盖整条链路。
_gen = (fn_src(APP_SRC, '_nginx_server_preamble')
        + fn_src(APP_SRC, '_nginx_service_location')
        + fn_src(APP_SRC, '_generate_gateway_nginx_conf'))

# 只看剥掉注释后的代码 —— 解释这个 bug 的注释里就写着 auth_request_set，
# 做位置判断时会被当成真的赋值语句（同一个坑已经踩过三次）。
_gen_code = strip_comments(_gen)

# 匹配「独立的 set 指令」而不是任何含 set 的子串。
# auth_request_set $auth_device 本身就包含 "set $auth_device" ——
# 用普通 in / find 的话，把 auth_request_set 删掉测试照样全绿（已踩到）。
_SET_RE = r'(?<![A-Za-z0-9_])set\s+\$(\w+)'
# log_format 里用到的 nginx 内置变量：这些不需要（也不允许）用 set 定义。
_NGINX_BUILTIN_VARS = {
    'time_iso8601', 'remote_addr', 'request_method', 'status',
    'body_bytes_sent', 'request_time', 'host', 'uri',
    'http_user_agent', 'http_referer',
}
_i_set_user = _gen_code.find('set $auth_user')
# 循环元组 2026-10-28 起是 6 元（多了 rp_host），这里只匹配前缀，
# 免得每加一个字段就要改一次锚点。
_i_loop = _gen_code.find('for rule, prefix, protocol, host, tport')
check('$auth_user 在服务端级别有 set 默认值（不依赖服务循环）',
      _i_set_user != -1 and (_i_loop == -1 or _i_set_user < _i_loop),
      f'set@{_i_set_user} / 循环@{_i_loop}')
_gen_vars = set(re.findall(_SET_RE, _gen_code))
check('$auth_device 同样有 set 默认值（不能被 auth_request_set 顶替）',
      'auth_device' in _gen_vars,
      f'独立 set 的变量: {sorted(_gen_vars)}')
check('$auth_user 同样是独立 set（不能被 auth_request_set 顶替）',
      'auth_user' in _gen_vars)

# 行为断言：真的调一次生成函数，0 服务时两个变量都必须在 server 块里被定义。
try:
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location('_nftapp_zero', os.path.join(BACKEND, 'app.py'))
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _cfg = _mod.load_config()
    _cfg['gateway_enabled'] = True
    _rp = _cfg.get('reverse_proxy')
    if isinstance(_rp, dict):
        _rp['rules'] = []
    _conf = _mod._generate_gateway_nginx_conf(_cfg)
    _zero_ok = isinstance(_conf, str) and 'set $auth_user' in _conf
    check('0 服务生成物里确实定义了 $auth_user（行为验证）', _zero_ok,
          f'{len(_conf) if isinstance(_conf, str) else 0} 字符')
    # 反向断言：log_format 里引用的变量都必须真的被 set 定义过。
    # log_format 是**多行续行**的，只扫含 'log_format' 关键字的那一行会漏掉
    # 最后那行 'auth_user="$auth_user" auth_dev="$auth_device"'; —— 正是它。
    if isinstance(_conf, str):
        _fm = _conf.find('log_format')
        _block = _conf[_fm:_conf.find(';', _fm)] if _fm != -1 else ''
        _defs = set(re.findall(_SET_RE, _conf))
        _uses = set(re.findall(r'\$(\w+)', _block))
        # nginx 自带变量不需要 set；自定义变量（auth_user / auth_device）必须有。
        _missing = _uses - _defs - _NGINX_BUILTIN_VARS
        check('log_format 引用的自定义变量全部有独立 set 定义',
              not _missing and {'auth_user', 'auth_device'} <= _uses,
              f'缺失: {sorted(_missing)}' if _missing
              else f'自定义变量 {sorted(_uses & {"auth_user", "auth_device"})} 已定义')
    # 有服务时仍然要保留 auth_request_set 的真实赋值（别被默认值盖掉）
    _cfg2 = _mod.load_config()
    _cfg2['gateway_enabled'] = True
    _rules = (_cfg2.get('reverse_proxy') or {}).get('rules') or []
    if _rules:
        _c2 = _mod._generate_gateway_nginx_conf(_cfg2)
        check('有服务时 auth_request_set 仍负责赋真实值',
              'auth_request_set $auth_user' in _c2)
except Exception as _e:   # noqa: BLE001
    check('0 服务生成物里确实定义了 $auth_user（行为验证）', False, repr(_e))

# FIX-10b：配置里没有 reverse_proxy 段时不能崩。
# DEFAULT_CONFIG 压根不含这个键，全新安装时 rp 是 None，
# 旧代码直接 rp.get("certificates") → AttributeError（.224 真机复现）。
_gen2 = strip_comments(fn_src(APP_SRC, '_generate_gateway_nginx_conf'))
_i_rp = _gen2.find('rp = config.get("reverse_proxy")')
_i_rpchk = _gen2.find('if not isinstance(rp, dict)')
_i_certs = _gen2.find('rp.get("certificates")')
check('reverse_proxy 非 dict 时兜底为空 dict',
      _i_rp != -1 and _i_rpchk != -1 and _i_rp < _i_rpchk < _i_certs,
      f'取值@{_i_rp} / 兜底@{_i_rpchk} / 用证书@{_i_certs}')
check('兜底不能只包住 settings（证书读取在它之后，会先炸）',
      'if isinstance(rp.get("settings"), dict)' in _gen2)

try:
    _fresh = dict(_mod.load_config())
    _fresh.pop('reverse_proxy', None)          # 模拟全新安装
    _fresh['gateway_enabled'] = True
    _c_fresh = _mod._generate_gateway_nginx_conf(_fresh)
    check('配置完全没有 reverse_proxy 段时也能生成（不 AttributeError）',
          isinstance(_c_fresh, str) and 'set $auth_user' in _c_fresh)
except Exception as _e:   # noqa: BLE001
    check('配置完全没有 reverse_proxy 段时也能生成（不 AttributeError）',
          False, repr(_e))

# ── FIX-11 ───────────────────────────────────────────────────────
# 名单的增量 nft 操作必须持 _FW_APPLY_LOCK。
# 这个锁当初引入就是为了防「增量操作与看门狗 nft -f 交叉执行」，
# 但只有 _apply_ruleset / _recover_ruleset_if_unhealthy 两处真拿了，
# 名单 add/delete/flush/apply 全在锁外裸跑。
sec('FIX-11 名单增量操作持 _FW_APPLY_LOCK（防与看门狗 nft -f 交叉执行）')
_hold = fn_src(APP_SRC, '_nft_set_write')
check('_nft_set_write 存在（统一入口，新增名单操作不会再漏加锁）',
      'def _nft_set_write' in APP_SRC)
check('_nft_set_write 内部持锁',
      '_FW_APPLY_LOCK' in _hold and 'with _FW_APPLY_LOCK' in _hold)

# 五个运行期写 set 的调用点必须全部走这个入口，不能还有裸 subprocess.run
WRITE_RE = (r"subprocess\.run\(\s*\[\s*'nft',\s*'(?:add|delete|flush)',"
            r"\s*'(?:element|set)',\s*'inet',\s*'fw4'")
_bare = re.findall(WRITE_RE, APP_SRC)
check('没有任何「裸 subprocess.run 直接改内核 set」', not _bare,
      f'仍有 {len(_bare)} 处' if _bare else '5 处写操作全部走 _nft_set_write')

for _fn, _label in (('list_add', 'add'), ('list_delete', 'delete'),
                    ('list_flush', 'flush')):
    _s = strip_comments(fn_src(APP_SRC, _fn))
    check(f'{_label} 走 _nft_set_write', '_nft_set_write(' in _s)
_s_apply = strip_comments(fn_src(APP_SRC, 'list_apply_preset'))
check('presets/apply 走 _nft_set_write', '_nft_set_write(' in _s_apply)
check('update_ipv6 的批量事务也持锁（同样是写内核 set）',
      '_FW_APPLY_LOCK' in strip_comments(fn_src(APP_SRC, 'update_ipv6')))

# ── FIX-12  update_ipv6 的失败必须报出来 ─────────────────────────
sec('FIX-12 update_ipv6 部分失败不再被掩盖')
_u6 = strip_comments(fn_src(APP_SRC, 'update_ipv6'))
check('flush 与 add 放进同一个 nft 事务（add 失败时旧地址不丢）',
      "'nft', '-f', '-'" in _u6 and 'flush set inet fw4' in _u6,
      '原来先 flush 再 add 是两条命令，add 失败 set 就空了')
check('不再有独立的 flush 命令后跟 add 命令的非原子写法',
      not re.search(r"'flush',\s*'set'.*?\n.*?'add',\s*'element'", _u6, re.S))
check('顶层 success 由失败数决定，不是无条件 True',
      '"success": not failed' in _u6)
check('message 里的条数是成功数不是尝试数',
      '成功 {len(updated)} 条，失败 {len(failed)} 条' in _u6)
check('失败项单独返回且带错误原因',
      '"failed": failed' in _u6 and '"error": err' in _u6)
check('部分失败时返回非 2xx',
      re.search(r"\),\s*\(200 if not failed else 500\)", _u6) is not None)
check('失败项写进了服务端日志（不是只有前端能看见）',
      '[ERROR]' in _u6 and '更新失败' in _u6)

# 前端必须真的读逐条失败 —— 后端算好了但没人看，等于没修
_fe_js = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
_ui6 = _fe_js[_fe_js.find('async updateIpv6'):_fe_js.find('async updateChinaIps')]
_ui6_nc = '\n'.join(l for l in _ui6.splitlines()
                    if not l.strip().startswith('//') and not l.strip().startswith('*'))
# 必须盯**绑定本身**，不能只判「函数里出现过 e.data」——
# 模板串 `${e.data.succeeded_count}` 里也有 e.data，把它改成 null 断言照样通过。
# 这个坑今天已经踩到第四次了（注释、子串、多行续行、模板串）。
check('前端 updateIpv6 把 e.data.failed 绑给了 failed',
      re.search(r'const\s+failed\s*=\s*e\.data\s*&&\s*e\.data\.failed', _ui6_nc)
      is not None)
check('前端失败时弹的是 error 提示而不是 success',
      re.search(r'failed\.length.*?\'error\'', _ui6_nc, re.S) is not None)
check('前端失败提示里带上了具体是哪些 set 失败',
      'f.set_name' in _ui6_nc and 'failed.map' in _ui6_nc)

# ── FIX-13  死接口补界面 ─────────────────────────────────────────
# tools/check-api-coverage.py 报出 12 条「后端有、前端不调」。逐条看过之后
# 只有 7 条是真缺界面，其余 5 条本来就该没有（脚本下载端点、给外部脚本用的、
# 已废弃保留的、静态文件路由）。这里断言 7 条都真的接上了。
sec('FIX-13 7 条死接口补上界面，其余 5 条在工具里显式说明原因')
_FE_HTML = FE_HTML
_JS = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()

_UI_PAIRED = [
    ('/api/auth/change-password', '改密码表单'),
    ('/api/rules/health', '规则集健康卡'),
    ('/api/reverse-proxy/certificates/', '证书重新上传按钮'),
    ('/api/network/wan-ipv6', 'WAN 公网 IPv6 展示'),
    ('/api/network/install-ipv6-cron', '安装 IPv6 定时更新'),
    ('/api/aliyun-ddns/test', '阿里云记录连通性测试'),
    ('/api/reverse-proxy/nginx/preview/', '反代 nginx 配置预览'),
]
for _ep, _label in _UI_PAIRED:
    check(f'{_label} 在 app.js 里调了 {_ep}', _ep in _JS)

_FOOT = _FE_HTML[_FE_HTML.find('<div class="nf-sidebar__foot">'):
                   _FE_HTML.find('</aside>')]
check('改密码入口在侧边栏页脚（不是塞进某个功能页）',
      # 必须限定在侧边栏范围内找：页面里还有一处「修改密码」在 HTML 注释里
      # （弹窗那段的分隔注释），只看全文的话把真正的按钮删掉测试照样通过。
      'openPasswordModal()' in _FOOT and '修改密码' in _FOOT)
check('改密码要求输入两次新密码',
      'confirm_password' in _JS and '两次输入的新密码不一致' in _JS)
check('健康卡展示看门狗的上次自检结果',
      'watchdog.last_result' in _FE_HTML and 'watchdog.actions' in _FE_HTML)
check('健康卡区分「规则集可用」与「内核里有表」',
      'ruleset_functional' in _FE_HTML and 'ruleset_loaded' in _FE_HTML)
check('证书重传只对手动证书显示（ACME 走续期）',
      "cert.source !== 'auto'" in _FE_HTML)
check('证书重传先选证书再选私钥，两次都走同一个端点',
      'pickRpReupload' in _JS and 'submitRpReupload' in _JS
      and '/reupload' in _JS)
check('nginx 预览读的是 config_content 字段',
      'config_content' in _JS)
check('阿里云测试按行取记录自身的 RR/Type/Value',
      'rec.RR || rec.rr' in _JS and 'rec.Type || rec.type' in _JS)
check('阿里云 AAAA 测试传 ipv6_source 不传 value（让后端读 /tmp/ddns-ipv6-N）',
      'ipv6_source: isAaaa' in _JS and "value: isAaaa ? ''" in _JS)
check('阿里云表格补了表头（加了一列就得分表头跟着改）',
      '>IPv6 来源<' in _FE_HTML)

# 弹窗必须落在 x-data="app()" 组件根内部。
#
# 这条是被真实浏览器逮到的：x-show 依赖 Alpine 求值，元素在组件根之外时
# nginxPreview 是 undefined，指令根本不生效，遮罩层保持默认的 display:block
# —— 于是它盖住整页，所有按钮都点不动。静态测试（curl 打接口）完全测不出来，
# 只有真去点按钮才会暴露。已加进 e2e 的回归路径。
_HTML_LINES = _FE_HTML.split('\n')
_depth = 0
_depth_at = {}
for _i, _ln in enumerate(_HTML_LINES, 1):
    if 'x-data="app()"' in _ln:
        _depth_at['__root__'] = (_i, _depth)
    _s = re.sub(r'<!--.*?-->', '', _ln)
    _depth += _s.count('<div') - _s.count('</div>')
    if 'x-data="app()"' in _ln:
        _depth_at['__root__'] = (_i, _depth + _s.count('<div') - _s.count('</div>'))

# 重新算一次，记录每个标记所在行的深度
_depth = 0
_marks = {}
for _i, _ln in enumerate(_HTML_LINES, 1):
    _s = re.sub(r'<!--.*?-->', '', _ln)
    _depth += _s.count('<div') - _s.count('</div>')
    for _k in ('diffModal.show', 'pwModal.show', 'nginxPreview.show',
               'rp-reupload-cert', 'rp-reupload-key'):
        if _k in _ln and _k not in _marks:
            _marks[_k] = (_i, _depth)

# 组件根从开启到闭合之间，根外的元素深度恒为 0；
# 根内的弹窗深度 ≥ 1（外面还包着 <main> 或直接就是根的子级）。
for _k, (_i, _d) in _marks.items():
    check(f'{_k} 在 x-data 组件根内（放根外会让 x-show 失效、遮罩挡住整页）',
          _d >= 1, f'行 {_i} depth={_d}')
check('HTML 的 div 标签配平（搬移弹窗时最容易破的地方）', _depth == 0,
      f'末尾 depth={_depth}')

# x-show 不阻止求值 —— 里面解引用可能为 null 的对象会刷 TypeError。
#
# 和「弹窗放到组件根外」是同一类根因：Alpine 指令的语义被想当然地理解了。
# 真实浏览器实测逮到：watchdog 初始 null，x-show 只是把 display 设成 none，
# 内层 x-text 照样跑，页面刷出 270 次 "Cannot read properties of null"。
# curl 打接口完全测不出来 —— /api/rules/health 返回正常，
# 坏的是「数据还没到时模板已经渲染」这一段。
# 反模式：同一个元素上既有 x-show 又直接解引用可能为 null 的对象。
# x-show 只改 display，指令表达式照样求值 —— 这是 Alpine 最容易被想当然的地方。
def _xshow_deref_conflicts(html, prefix):
    """找出「带 x-show 的元素同时又解引用 prefix」的开标签。"""
    obj = prefix.rstrip('.')
    bad = []
    for m in re.finditer(r'<[a-zA-Z][^>]*>', html, re.S):
        tag = m.group(0)
        if 'x-show=' not in tag:
            continue
        if re.search(re.escape(prefix), tag):
            bad.append(tag[:110].replace('\n', ' '))
    return bad


for _label, _prefix in (('watchdog（健康卡的看门狗区）', 'rulesHealth.watchdog.'),
                        ('aliyunTest.result（阿里云测试结果行）', 'aliyunTest.result.')):
    _conf = _xshow_deref_conflicts(_FE_HTML, _prefix)
    check(f'{_label}：没有「x-show 与解引用同一元素」的反模式', not _conf,
          f'{len(_conf)} 处: {_conf[:1]}')

check('看门狗区用的是 x-if 而不是 x-show',
      '<template x-if="rulesHealth.watchdog">' in _FE_HTML)
check('阿里云结果行用的是 x-if 而不是 x-show',
      '<template x-if="aliyunTest.result && aliyunTest.index === index">' in _FE_HTML)

# ── FIX-14  网关 allow 127.0.0.1 ──────────────────────────────────
sec('FIX-14 仅内网服务同时放行 IPv4 与 IPv6 回环')
# 回环白名单搬进了 _nginx_service_location —— 同上，看整条链路。
_gen2b = (fn_src(APP_SRC, '_nginx_service_location')
          + fn_src(APP_SRC, '_generate_gateway_nginx_conf'))
_gen2b_c = strip_comments(_gen2b)
check('生成物里有 allow 127.0.0.1', 'allow 127.0.0.1;' in _gen2b_c)
check('生成物里仍保留 allow ::1（IPv6 回环没被这个改动挤掉）',
      'allow ::1;' in _gen2b_c)
check('两个回环都在 allow {lan_cidr} 之后、deny all 之前',
      # lan_cidr 是生成函数里的局部变量，测试里拿不到它的值 ——
      # 只能按源码里的模板字面量 'allow {lan_cidr}' 来定位顺序。
      _gen2b_c.find('allow 127.0.0.1;') > _gen2b_c.find('allow {lan_cidr}')
      and _gen2b_c.find('allow 127.0.0.1;') < _gen2b_c.find('deny all;'))
check('不是把 ::1 改成 127.0.0.1（那是把 IPv6 回环堵回去）',
      _gen2b_c.count('allow ::1;') == 1 and _gen2b_c.count('allow 127.0.0.1;') == 1)

# 工具不再把这 5 类误报成「缺界面」
_TOOL = open(os.path.join(ROOT, 'tools', 'check-api-coverage.py'), encoding='utf-8').read()
# 必须剥掉 Python 注释再找：把登记项注释掉，字符串本身还在文件里，
# 不剥注释的话断言照样通过（这个坑今天已经踩到第五次了）。
_TOOL_CODE = strip_comments(_TOOL)
for _ep in ('/api/knock-info', '/api/scripts/update-ipv6.sh',
            '/api/firewall/china-ips-script', '/api/rules/save', '/:file'):
    check(f'工具把 {_ep} 归入「刻意不做界面」', repr(_ep) in _TOOL_CODE)
check('工具有独立的 D 类输出（解释为什么不报）', '【D】' in _TOOL_CODE)
check('工具的 D 类清单不是摆设：B 类判定里真的排除了它们',
      'INTENTIONAL_NO_UI' in _TOOL_CODE
      and re.search(r'if p in INTENTIONAL_NO_UI:.*?continue', _TOOL_CODE, re.S)
      is not None)

# ---------------------------------------------------------------- FIX-16
sec('FIX-16 敲门限流 burst 必须容得下一整轮序列')
# 2026-10-13 .224 真机实测：knock_wan_v4 四步序列 0 次成功，第 1 步就把
# @knock_rate4 里该源地址的限流桶用光，第 2~4 步全部超限不匹配，
# 只剩链尾 [KNOCK-WAN4-UNMATCHED] 兜底丢弃。根因：限流挂在 set 元素上，
# 四个步骤写的是同一个集合，桶跨规则共享。
_TPL = open(os.path.join(BACKEND, 'templates', 'nftables.conf'), encoding='utf-8').read()


def nft_live_code(text):
    """剥掉 nft 注释，并把反斜杠续行拼成**逻辑语句**。

    为什么不能只剥整行注释：nft 的一条规则是好几行用 `\\` 续起来的，
    只把首行注释掉，后面几行还躺在文件里，断言照样数得到限流表达式 ——
    「文本在但规则已经死了」正是这套断言最典型的假绿。

    关键在 orphan（孤儿续行）这一支：某条语句的续行被注释掉之后，
    后面那些以 `\\` 结尾的物理行其实已经是无主的碎片，拼起来会伪装成
    一条完整规则。所以要记住「上一条语句被截断了」，把直到第一个不带
    `\\` 的行为止的碎片整段丢掉。

    模板里字符串内不含 `#`（已核对：只有 define 行有行尾注释，# 在引号外），
    所以按 # 截断是安全的。
    """
    lines = []
    orphan = False          # 上一条语句的续行被注释掉了
    for raw in text.splitlines():
        line = re.sub(r'#.*$', '', raw).rstrip()
        if not line:
            # 判断依据必须是**物理行原文**是否以 \ 结尾：剥完注释这行是空的，
            # 但正是这条物理行承载着续行符 —— 它被注释掉，语句就断在这里。
            # （早先写成看 lines[-1]，那是它前面那条正常行，永远不带 \，形同虚设。）
            if raw.rstrip().endswith('\\'):
                orphan = True
            continue
        if orphan:
            if line.endswith('\\'):
                continue    # 仍是孤儿碎片
            orphan = False
            continue        # 这一行是孤儿语句的收尾，同样丢掉
        lines.append(line)
    joined, buf = [], ''
    for line in lines:
        if line.endswith('\\'):
            buf += line[:-1].rstrip() + ' '
        else:
            joined.append(buf + line)
            buf = ''
    if buf:
        joined.append(buf)
    return '\n'.join(joined)


_TPL_CODE = nft_live_code(_TPL)

# 序列长度由 KNOCK1..KNOCK4 决定，burst 必须 >= 它
_KNOCK_STEPS = 4
_limits = re.findall(
    r'add @knock_rate[46] \{ ip6? saddr limit rate (\S+) burst (\d+) packets \}', _TPL_CODE)
check('v4+v6 共 8 处敲门限流都在（4 步 × 2 条链）',
      len(_limits) == 8, '实际匹配 %d 处' % len(_limits))
check('每处 burst 都容得下一整轮 %d 步序列' % _KNOCK_STEPS,
      bool(_limits) and all(int(b) >= _KNOCK_STEPS for _, b in _limits),
      'burst=%s' % sorted({b for _, b in _limits}))
check('限流窗口不是 1/minute（配 4 步序列需秒级窗口）',
      bool(_limits) and all(rate != '1/minute' for rate, _ in _limits),
      'rate=%s' % sorted({r for r, _ in _limits}))
for _fam, _chain in (('4', 'knock_wan_v4'), ('6', 'knock_wan_v6')):
    _body = re.search(r'chain %s \{(.*?)\n    \}' % _chain, _TPL_CODE, re.S)
    _in_chain = len(re.findall(r'add @knock_rate%s \{ ip6? saddr limit rate' % _fam,
                               _body.group(1))) if _body else -1
    check('chain %s 内正好 4 步各带一次限流' % _chain, _in_chain == _KNOCK_STEPS,
          '实际 %d 处' % _in_chain)
check('没有残留 burst 1 的敲门限流（那正是本缺陷本身）',
      'limit rate 1/minute burst 1 packets' not in _TPL_CODE)

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')