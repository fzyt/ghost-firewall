#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第 8 批开工前的两处修复（N1 + 供应链条目 8）的行为级测试。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch8_fixes.py

测两件
------
N1   内网分支（public_access=false）的身份标记必须**真的生效**
     —— 原来写的是 `auth_request_set`，而该指令在没有 `auth_request` 时
        永不赋值（nginx 语义）⇒ 变量恒空 ⇒ 日志里的 auth_dev 与上游收到的
        X-Auth-Device 两个通道全是空的（.193 实测 974 行日志零命中）。

8    GitHub 安装包必须做 sha256 校验（fail-closed）
     —— 原来下载完直接 `tar -xzf` 以 root 落盘，全程无任何完整性校验。

为什么必须是行为级判据
----------------------
N1：只看源码里的字符串，`auth_request_set` 和 `set` 都能被 grep 到，
    测不出「哪条指令真的会给变量赋值」⇒ 必须**真的生成一份 nginx 配置**
    再看生成物里到底是什么。
8 ：必须**真的跑一遍 setup.sh 的部署流程**（沙箱里用假 curl 冒充下载），
    只看源码里出现了 sha256 字样，证明不了「包坏了真的停下来」。

⚠ 沙箱怎么模拟下载：用一个**假 curl**（PATH 注入），**不改被测源码一个字节**。
  早先的写法是改 setup.sh 里的 URL 常量来注入 —— 那种注入**与被测源码耦合**：
  变异脚本改的往往就是同一行（例如把 sum_url 置空），于是变异被测试的注入
  抵消掉、测试全绿、变异就漏网了。假 curl 没有这个问题。

本文件只读仓库里的源码、只在临时目录里写东西：
不碰 /opt/nftables-web-v2，不碰 /etc/nftables，不动 crontab。
"""
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ============================================================
# N1：内网身份标记
# ============================================================

# nginx 变量指令：只认**独立**的 set。
# auth_request_set $auth_device 本身就包含 "set $auth_device" ——
# 用普通 in / find 的话，把 auth_request_set 删掉测试照样全绿（已踩过）。
_SET_RE = r'(?<![A-Za-z0-9_])set\s+\$(\w+)'
# log_format 里用到的 nginx 内置变量：这些不需要（也不允许）用 set 定义。
_NGINX_BUILTIN_VARS = {
    'time_iso8601', 'remote_addr', 'request_method', 'status',
    'body_bytes_sent', 'request_time', 'host', 'uri',
    'http_user_agent', 'http_referer',
}


def location_block(conf, service_name):
    """从生成的 nginx 配置里取出某个服务的 location 块。

    ⚠ 不能按名字全文 find —— 同一服务可能同时有路径入口和 host 入口，
    两个块长得一样。必须用「# ---- 名字 ----」标记定位到**第一个**块，
    且测试里只配 path_prefix（不配 host）⇒ 全文只有一个该名字的块。
    """
    marker = f'# ---- {service_name} ----'
    i = conf.find(marker)
    if i == -1:
        return ''
    j = conf.find('\n    location', i)
    if j == -1:
        return ''
    k = conf.find('\n    }', j)
    return conf[j:k] if k != -1 else conf[j:]


def load_app_module():
    # app.py 会 import 同目录的 template_engine ⇒ backend/ 必须在 sys.path 上。
    # 用 importlib 从文件路径加载时不会自动带上，所以这里显式补。
    if BACKEND not in sys.path:
        sys.path.insert(0, BACKEND)
    spec = importlib.util.spec_from_file_location(
        '_nftapp_batch8', os.path.join(BACKEND, 'app.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_conf_with_two_services(mod):
    """造一份配置：一个内网服务 + 一个公网服务。"""
    cfg = mod.load_config()
    cfg['gateway_enabled'] = True
    rp = cfg.get('reverse_proxy')
    if not isinstance(rp, dict):
        rp = {}
    rp['rules'] = [
        {'name': '内网服务', 'path_prefix': '/lan',
         'target_address': '192.168.100.10:8080', 'target_protocol': 'http',
         'enabled': True, 'public_access': False},
        {'name': '公网服务', 'path_prefix': '/wan',
         'target_address': '192.168.100.11:8080', 'target_protocol': 'http',
         'enabled': True, 'public_access': True},
    ]
    if not isinstance(rp.get('settings'), dict):
        rp['settings'] = {}
    if not isinstance(rp.get('certificates'), list):
        rp['certificates'] = []
    cfg['reverse_proxy'] = rp
    return cfg


sec('N1：内网分支的身份标记必须真的生效')

try:
    _mod = load_app_module()
    _conf = _mod._generate_gateway_nginx_conf(
        build_conf_with_two_services(_mod))
    _conf = _conf if isinstance(_conf, str) else ''
except Exception as _e:  # 生成失败也要报出来，不能静默跳过
    _conf = ''
    print(f'  [FAIL] 生成 nginx 配置时抛异常 — {type(_e).__name__}: {_e}')

_lan = location_block(_conf, '内网服务')
_wan = location_block(_conf, '公网服务')

check('真的生成出了内网服务的 location 块', bool(_lan), f'{len(_lan)} 字符')
check('真的生成出了公网服务的 location 块', bool(_wan), f'{len(_wan)} 字符')

# ── 核心判据：内网块必须是真正会赋值的 set ──────────────────────
# ⚠ 负向断言必须**同时要求对象非空**：块没生成出来时，「块里没有 X」是
#   天然的假通过 ⇒ 变异脚本会把「测不出」误判成「抓住了」。
check('内网块用 set $auth_user "lan"（服务端常量，不可伪造）',
      'set $auth_user "lan";' in _lan, _lan[-260:] if _lan else '无块')
check('内网块**不含** auth_request_set（没有 auth_request 时它永不赋值）',
      bool(_lan) and 'auth_request_set' not in _lan,
      '出现了: ' + repr([l for l in _lan.splitlines() if 'auth_request_set' in l]))
check('内网块**不含** $cookie_gw_device（客户端自称的未签名 cookie，可伪造）',
      bool(_lan) and 'cookie_gw_device' not in _lan)
check('内网块仍保留来源白名单（allow/deny 没有被顺手删掉）',
      bool(_lan) and 'deny all;' in _lan)

# ── 反向判据：公网分支的认证语义一点没动 ────────────────────────
check('公网块仍走 auth_request /_auth;（公网必须无条件认证）',
      bool(_wan) and 'auth_request /_auth;' in _wan)
check('公网块仍从认证服务回的头取身份',
      bool(_wan)
      and 'auth_request_set $auth_user $upstream_http_x_auth_user;' in _wan
      and 'auth_request_set $auth_device $upstream_http_x_auth_device;' in _wan)

# ── 整份配置层面 ────────────────────────────────────────────────
check('整份配置里已彻底移除 $cookie_gw_device（可伪造身份源）',
      bool(_conf) and 'cookie_gw_device' not in _conf)

_set_vars = set(re.findall(_SET_RE, _conf))
check('$auth_user 有独立 set 定义（否则 nginx 报 unknown variable，整份配置被拒）',
      'auth_user' in _set_vars, f'独立 set 的变量: {sorted(_set_vars)}')
check('$auth_device 有独立 set 定义（同上）',
      'auth_device' in _set_vars)

if _conf:
    _fm = _conf.find('log_format')
    _fblock = _conf[_fm:_conf.find(';', _fm)] if _fm != -1 else ''
    _uses = set(re.findall(r'\$(\w+)', _fblock))
    _missing = _uses - _set_vars - _NGINX_BUILTIN_VARS
    check('log_format 引用的自定义变量全部有独立 set 定义',
          not _missing, f'缺失: {sorted(_missing)}' if _missing else '全部已定义')


# ============================================================
# 条目 8：GitHub 安装包的 sha256 校验
# ============================================================

# 沙箱里的假 curl —— 只实现 deploy_project 用到的那两种下载。
# 不碰被测源码一个字节（原因见文件头）。
_FAKE_CURL = r'''#!/bin/sh
url=""
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --connect-timeout|--max-time|--retry|--retry-delay) shift 2 ;;
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  *sha256sums.txt)
      if [ "$FAKE_CURL_FAIL_SUMS" = "1" ]; then
          echo "curl: (37) Couldn't open file" >&2
          exit 37
      fi
      cp "$FAKE_CURL_SUMS" "$out"
      ;;
  *.tar.gz)
      cp "$FAKE_CURL_TARBALL" "$out"
      ;;
  *)
      echo "curl: (37) Couldn't open file $url" >&2
      exit 37
      ;;
esac
exit 0
'''


def make_sandbox():
    """搭一个「设备安装目录」沙箱。

    返回 (沙箱根, INSTALL_DIR, INITD 路径, fakebin 目录)
    """
    d = tempfile.mkdtemp(prefix='batch8-')
    inst = os.path.join(d, 'opt-nftables-web-v2')
    os.makedirs(inst)
    initd = os.path.join(d, 'init.d', 'nftables-web')
    os.makedirs(os.path.dirname(initd))
    # 假 init 脚本：把被调用的参数记到标记文件里
    marker = os.path.join(d, 'restart-marker.txt')
    with open(initd, 'w', encoding='utf-8') as f:
        f.write('#!/bin/sh\necho "called: $@" >> "%s"\nexit 0\n' % marker)
    os.chmod(initd, 0o755)
    # 假 curl
    fakebin = os.path.join(d, 'fakebin')
    os.makedirs(fakebin)
    curl_path = os.path.join(fakebin, 'curl')
    with open(curl_path, 'w', encoding='utf-8') as f:
        f.write(_FAKE_CURL)
    os.chmod(curl_path, 0o755)
    return d, inst, initd, fakebin


def make_setup_script(inst, initd, extra=''):
    """把 setup.sh 拷进沙箱并改掉**路径常量**，末尾调用 deploy_project。

    ⚠ 只改路径常量，被测的函数体一个字节都没动
      （不给生产脚本加测试专用开关 —— 那会让生产代码多出一条分支）。
    """
    src = open(SETUP, encoding='utf-8').read()
    src = src.replace('\nmain "$@"\n', '\n')
    for old, new in (
            ('INSTALL_DIR="/opt/nftables-web-v2"', 'INSTALL_DIR="%s"' % inst),
            ('INITD_SCRIPT="/etc/init.d/nftables-web"', 'INITD_SCRIPT="%s"' % initd)):
        assert src.count(old) == 1, \
            '常量行不唯一（出现 %d 次）: %r' % (src.count(old), old)
        src = src.replace(old, new)
    src += extra
    src += '\ndeploy_project\n'
    path = os.path.join(os.path.dirname(inst), 'setup.sh')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    return path


def run_sh(script, fakebin, tarball=None, sums=None, fail_sums=False, timeout=300):
    """跑沙箱 setup.sh。

    ⚠ stdin 给 DEVNULL ⇒ `[ -t 0 ]` 为假 ⇒ 走非交互分支，
      不会卡在「是否覆盖？」的交互提问上。
    """
    env = {
        **os.environ,
        'PYTHONDONTWRITEBYTECODE': '1',
        'PATH': fakebin + os.pathsep + os.environ.get('PATH', ''),
        'FAKE_CURL_TARBALL': tarball or '',
        'FAKE_CURL_SUMS': sums or '',
        'FAKE_CURL_FAIL_SUMS': '1' if fail_sums else '0',
    }
    r = subprocess.run(['sh', script], capture_output=True, text=True,
                       timeout=timeout, stdin=subprocess.DEVNULL, env=env)
    return r.returncode, (r.stdout + r.stderr)


def make_tarball(d):
    """造一个可解包的 tarball，解开后是 ghost-firewall-main/。

    ⚠ 目录名固定用 ghost-firewall-main —— setup.sh 的候选列表里
      `ghost-firewall-main` 排在第三位，前两个是按 tag 拼的。
    """
    tarroot = os.path.join(d, 'tarroot')
    os.makedirs(os.path.join(tarroot, 'ghost-firewall-main', 'backend'))
    os.makedirs(os.path.join(tarroot, 'ghost-firewall-main', 'frontend'))
    with open(os.path.join(tarroot, 'ghost-firewall-main', 'backend', 'app.py'),
              'w', encoding='utf-8') as f:
        f.write('# 沙箱里的假 app.py\n')
    with open(os.path.join(tarroot, 'ghost-firewall-main', 'frontend', 'index.html'),
              'w', encoding='utf-8') as f:
        f.write('<!doctype html>\n')
    tarball = os.path.join(d, 'archive.tar.gz')
    rc = subprocess.run(['tar', '-czf', tarball, '-C', tarroot, 'ghost-firewall-main'],
                        capture_output=True, text=True)
    assert rc.returncode == 0, '沙箱 tar 制作失败: ' + rc.stderr
    return tarball


def write_sums(path, tarball, entry_name='ghost-firewall-main.tar.gz', wrong=False):
    """写一份 sha256 清单（标准 sha256sum 格式）。"""
    digest = subprocess.run(['sha256sum', tarball], capture_output=True,
                            text=True).stdout.split()[0]
    if wrong:
        digest = '0' * 64
    with open(path, 'w', encoding='utf-8') as f:
        f.write('%s  %s\n' % (digest, entry_name))
    return path


def deployed(inst):
    """安装目录里到底有没有装上代码。"""
    return os.path.isfile(os.path.join(inst, 'backend', 'app.py'))


sec('条目 8：清单正确时，tag 安装应当成功')

d1, inst1, initd1, fb1 = make_sandbox()
tar1 = make_tarball(d1)
sums1 = write_sums(os.path.join(d1, 'sha256sums.txt'), tar1)
script1 = make_setup_script(inst1, initd1, extra='ARG_VERSION="v1.2.3"\n')
rc1, out1 = run_sh(script1, fb1, tarball=tar1, sums=sums1)
check('退出码为 0', rc1 == 0, out1[-700:])
check('代码确实装进了安装目录', deployed(inst1))
check('输出里有「sha256 校验通过」', 'sha256 校验通过' in out1, out1[-400:])

sec('条目 8：清单对不上时，必须中止且**不许装任何东西**')

d2, inst2, initd2, fb2 = make_sandbox()
tar2 = make_tarball(d2)
sums2 = write_sums(os.path.join(d2, 'sha256sums.txt'), tar2, wrong=True)
script2 = make_setup_script(inst2, initd2, extra='ARG_VERSION="v1.2.3"\n')
rc2, out2 = run_sh(script2, fb2, tarball=tar2, sums=sums2)
check('退出码非 0（fail-closed，不能继续装）', rc2 != 0, f'rc={rc2}')
check('安装目录里**没有**代码（坏包绝不能落盘）', not deployed(inst2))
check('输出里明确说了 sha256 校验失败', 'sha256 校验失败' in out2, out2[-500:])

sec('条目 8：取不到清单时，同样必须中止')

d3, inst3, initd3, fb3 = make_sandbox()
tar3 = make_tarball(d3)
script3 = make_setup_script(inst3, initd3, extra='ARG_VERSION="v1.2.3"\n')
rc3, out3 = run_sh(script3, fb3, tarball=tar3,
                   sums=os.path.join(d3, 'no-such-sums.txt'), fail_sums=True)
check('退出码非 0', rc3 != 0, f'rc={rc3}')
check('安装目录里**没有**代码', not deployed(inst3))
check('输出里明确说了取不到清单', '取不到 sha256 清单' in out3, out3[-500:])

sec('条目 8：清单里没有 .tar.gz 条目时，也必须中止（不能当成通过）')

d4, inst4, initd4, fb4 = make_sandbox()
tar4 = make_tarball(d4)
sums4 = write_sums(os.path.join(d4, 'sha256sums.txt'), tar4,
                    entry_name='not-a-tarball.txt')
script4 = make_setup_script(inst4, initd4, extra='ARG_VERSION="v1.2.3"\n')
rc4, out4 = run_sh(script4, fb4, tarball=tar4, sums=sums4)
check('退出码非 0', rc4 != 0, f'rc={rc4}')
check('安装目录里**没有**代码', not deployed(inst4))
check('输出里说明了清单里没有 .tar.gz 条目',
      '清单里没有 .tar.gz 条目' in out4, out4[-500:])

sec('条目 8：main 是开发分支，没有清单可校验 —— 明确警告但不阻断')

d5, inst5, initd5, fb5 = make_sandbox()
tar5 = make_tarball(d5)
script5 = make_setup_script(inst5, initd5)
rc5, out5 = run_sh(script5, fb5, tarball=tar5)
check('退出码为 0（开发分支的正常路径没被堵死）', rc5 == 0, out5[-700:])
check('代码确实装进了安装目录', deployed(inst5))
check('输出里明确警告了没有清单可校验',
      '没有 sha256 清单可校验' in out5, out5[-400:])


# ============================================================
print('\n' + '=' * 60)
print(f'通过 {len(PASS)} 条，失败 {len(FAIL)} 条')
if FAIL:
    for _f in FAIL:
        print('  [FAIL] ' + _f)
    sys.exit(1)
print('[OK] 全部通过')
sys.exit(0)
