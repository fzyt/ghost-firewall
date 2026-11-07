"""打包清理批（CB-1~CB-4，2026-11-04 第十四/十五轮）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_c_batch.py

测什么有效
----------
这一批改的是**机制**，不是界面：配置自愈、密钥缓存、降级告警、装机兜底。
机制最危险的退化不是「写错了」，而是**看起来还在、其实已经不生效了**：

  · 启动时不再同步 router_ip4 ⇒ 机器换 IP 后证书 CN 停在旧 IP
  · 同步挪到生成证书**之后** ⇒ 顺序反了，证书还是旧 IP
  · 同步顺手调了 apply_rules ⇒ 启动阶段重下发，可能把网络打断
  · 密钥不再缓存 ⇒ 每次调用都是新随机密钥，刚签的令牌立刻验不过
  · 读不到密钥时**覆盖**原文件 ⇒ 唯一那份密钥被毁掉
  · 读不到密钥时一声不吭 ⇒ 管理员不知道自己登不上
  · 网关自己写密钥文件 ⇒ 属主/权限语义被弄乱
  · 降级原因不记 / 不清 ⇒ 界面上的告警条要么永远不出现，要么永远出现
  · apk add 不带 --timeout ⇒ 卡住就是死等（实测 4 分钟零字节）
  · apk_file_looks_valid 认了 HTML 错误页 ⇒ 镜像问题被伪装成签名问题
  · apk_rotate_mirror 不换源 ⇒ 同一个包反复失败

分四组
------
  C  router_ip4 自愈（backend/app.py）
  D  网关令牌密钥（backend/auth_gateway.py）
  E  访问边界降级告警（backend/app.py + frontend/*）
  F  setup.sh 的三个 apk 缺陷（setup/setup.sh）

⚠️ 断言「不该出现 / 该出现」的那几条必须基于**去注释后的源码**
   （strip_py_comments / strip_sh_comments）——
   setup.sh 和 app.py 里到处是解释性注释，而注释**正好包含**
   `--timeout`、`[WARNING]`、`switch_apk_mirror` 这些关键字：
   把代码删了、注释留着，朴素文本断言照样全绿。

保险丝：只备份 / 还原**本脚本会动的那几个文件**，不碰仓库里其他文件。
"""
import atexit
import os
import shutil
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
GW_PY = os.path.join(ROOT, 'backend', 'auth_gateway.py')
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
FRONT_JS = os.path.join(ROOT, 'frontend', 'app.js')
FRONT_HTML = os.path.join(ROOT, 'frontend', 'index.html')
FRONT_CSS = os.path.join(ROOT, 'frontend', 'styles.css')

TEST_C = os.path.join(ROOT, 'tests', 'test_c_batch.py')
TEST_APK = os.path.join(ROOT, 'tests', 'test_setup_apk_fallback.py')

# 本脚本会动的文件（只这些）
REL_FILES = [
    os.path.join('backend', 'app.py'),
    os.path.join('backend', 'auth_gateway.py'),
    os.path.join('setup', 'setup.sh'),
    os.path.join('frontend', 'app.js'),
    os.path.join('frontend', 'index.html'),
    os.path.join('frontend', 'styles.css'),
]
ORIG = {}
for rel in REL_FILES:
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        ORIG[os.path.join(ROOT, rel)] = f.read()


def restore():
    """把文件还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


atexit.register(restore)
for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, lambda *a: (restore(), sys.exit(130)))
    except (ValueError, OSError):
        pass


def run_tests(which):
    """跑指定的测试文件。which: 'c' | 'apk' | 'both'"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    targets = []
    if which in ('c', 'both'):
        targets.append(TEST_C)
    if which in ('apk', 'both'):
        targets.append(TEST_APK)
    out = ''
    for t in targets:
        r = subprocess.run([sys.executable, t], capture_output=True, text=True,
                           cwd=ROOT, timeout=900, env=env)
        out += r.stdout + r.stderr
        if r.returncode != 0:
            return r.returncode, out
    return 0, out


def apply_edits(path, edits):
    """edits: [(old, new)]，每条都必须**唯一**匹配 —— 匹配不上就报错。

    为什么必须唯一：变异脚本按「第一个匹配」替换；
    old 片段不唯一 ⇒ 改到哪一处全看运气 ⇒ 「漏网」被伪装成「捕获」。
    """
    src = ORIG[path]
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError(f'锚点在 {os.path.basename(path)} 里出现 {n} 次，必须唯一：{old[:70]!r}')
        src = src.replace(old, new, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)


# ─────────────────────────────────────────────────────────────
# C 组：router_ip4 自愈（backend/app.py）
# ─────────────────────────────────────────────────────────────
C_MUTATIONS = [
    ('C-01  启动时不再同步 router_ip4（机器换 IP 后证书 CN 停在旧 IP）',
     APP_PY,
     [('        _sync_msg = _sync_router_ip4(_bind)\n',
       '        _sync_msg = ""\n')],
     'c'),

    ('C-02  同步挪到生成证书之后（顺序反了，证书还是旧 IP）',
     APP_PY,
     [('        _sync_msg = _sync_router_ip4(_bind)\n'
       '        if _sync_msg:\n'
       '            print(f\'[INFO] {_sync_msg}\', flush=True)\n'
       '    except Exception as e:\n'
       '        print(f\'[WARN] 同步 router_ip4 失败（不影响启动）: \'\n'
       '              f\'{type(e).__name__}: {e}\', flush=True)\n'
       '\n'
       '    cert_files = _ensure_https_cert()\n',
       '    cert_files = _ensure_https_cert()\n'
       '\n'
       '    try:\n'
       '        _sync_msg = _sync_router_ip4(_bind)\n'
       '        if _sync_msg:\n'
       '            print(f\'[INFO] {_sync_msg}\', flush=True)\n'
       '    except Exception as e:\n'
       '        print(f\'[WARN] 同步 router_ip4 失败（不影响启动）: \'\n'
       '              f\'{type(e).__name__}: {e}\', flush=True)\n')],
     'c'),

    ('C-03  同步时顺手重下发防火墙（启动阶段重下发可能打断网络）',
     APP_PY,
     [('    cfg[\'router_ip4\'] = str(detected).strip()\n'
       '    try:\n'
       '        save_config(cfg)\n',
       '    cfg[\'router_ip4\'] = str(detected).strip()\n'
       '    try:\n'
       '        save_config(cfg)\n'
       '        apply_rules()\n')],
     'c'),

    ('C-04  非法地址不再校验（把垃圾写进配置，证书 CN 也跟着废掉）',
     APP_PY,
     [('    try:\n'
       '        ipaddress.ip_address(str(detected).strip())\n'
       '    except ValueError:\n'
       '        return \'\'\n',
       '    try:\n'
       '        ipaddress.ip_address(str(detected).strip())\n'
       '    except ValueError:\n'
       '        pass\n')],
     'c'),

    ('C-05  地址一致时也写盘（每次启动都无谓地改配置）',
     APP_PY,
     [('    old = str(cfg.get(\'router_ip4\') or \'\').strip()\n'
       '    if old == str(detected).strip():\n'
       '        return \'\'\n',
       '    old = str(cfg.get(\'router_ip4\') or \'\').strip()\n')],
     'c'),

    ('C-06  同步失败会抛异常（阻断启动，管理员连面板都开不了）',
     APP_PY,
     [('    except Exception as e:          # noqa: BLE001\n'
       '        return (f\'router_ip4 同步失败（不影响启动）: {type(e).__name__}: {e}\')\n',
       '    except Exception as e:          # noqa: BLE001\n'
       '        raise RuntimeError(f\'router_ip4 同步失败: {type(e).__name__}: {e}\')\n')],
     'c'),
]

# ─────────────────────────────────────────────────────────────
# D 组：网关令牌密钥（backend/auth_gateway.py）
# ─────────────────────────────────────────────────────────────
D_MUTATIONS = [
    ('D-01  密钥不再缓存（每次调用都是新随机密钥，刚签的令牌立刻验不过）',
     GW_PY,
     [('    if _SECRET_CACHE["key"] is not None:\n'
       '        return _SECRET_CACHE["key"]\n'
       '\n',
       '    _SECRET_CACHE["key"] = None\n'
       '\n')],
     'c'),

    ('D-02  读盘失败时覆盖原文件（唯一那份密钥被毁掉）',
     GW_PY,
     [('            print(f"[WARNING] 读取网关令牌密钥 {SECRET_FILE} 失败: {e}"\n'
       '                  "（本次进程使用临时密钥；已签发的令牌将无法验证，"\n'
       '                  "修复文件权限后重启即可恢复）", flush=True)\n'
       '            _SECRET_CACHE["key"] = secrets.token_hex(32).encode()\n',
       '            print(f"[WARNING] 读取网关令牌密钥 {SECRET_FILE} 失败: {e}"\n'
       '                  "（本次进程使用临时密钥；已签发的令牌将无法验证，"\n'
       '                  "修复文件权限后重启即可恢复）", flush=True)\n'
       '            with open(SECRET_FILE, "w") as _f:\n'
       '                _f.write(secrets.token_hex(32))\n'
       '            _SECRET_CACHE["key"] = secrets.token_hex(32).encode()\n')],
     'c'),

    ('D-03  读盘失败时一声不吭（管理员不知道自己为什么登不上）',
     GW_PY,
     [('            print(f"[WARNING] 读取网关令牌密钥 {SECRET_FILE} 失败: {e}"\n'
       '                  "（本次进程使用临时密钥；已签发的令牌将无法验证，"\n'
       '                  "修复文件权限后重启即可恢复）", flush=True)\n',
       '            pass\n')],
     'c'),

    ('D-04  文件缺失时一声不吭（init 没播种也没人知道）',
     GW_PY,
     [('    print(f"[WARNING] 网关令牌密钥文件 {SECRET_FILE} 不存在"\n'
       '          "（init 脚本本应播种它）—— 本次进程使用临时密钥，"\n'
       '          "重启后所有已签发的令牌都会失效", flush=True)\n',
       '    pass\n')],
     'c'),

    ('D-05  网关自己写令牌密钥文件（属主/权限语义被弄乱）',
     GW_PY,
     [('    _SECRET_CACHE["key"] = secrets.token_hex(32).encode()\n'
       '    return _SECRET_CACHE["key"]\n',
       '    with open(SECRET_FILE, "w") as _f:\n'
       '        _f.write(secrets.token_hex(32))\n'
       '    _SECRET_CACHE["key"] = secrets.token_hex(32).encode()\n'
       '    return _SECRET_CACHE["key"]\n')],
     'c'),

    ('D-06  缓存键名改了（缓存形同虚设）',
     GW_PY,
     [('_SECRET_CACHE = {"key": None}\n',
       '_SECRET_CACHE = {"key2": None}\n')],
     'c'),
]

# ─────────────────────────────────────────────────────────────
# E 组：访问边界降级告警（backend/app.py + frontend/*）
# ─────────────────────────────────────────────────────────────
E_MUTATIONS = [
    ('E-01  /api/auth/status 不再带 access_boundary_warning（界面永远看不到告警）',
     APP_PY,
     [('            \'access_boundary_warning\': access_boundary_warning(),\n',
       '            \'access_boundary_warning\': \'\',\n')],
     'c'),

    ('E-02  降级原因不再记录（告警条永远不出现）',
     APP_PY,
     [('        _set_access_boundary_degraded(\n'
       '            f\'配置文件 {CONFIG_PATH} 不存在 —— 面板当前**已拒绝所有来源访问**\'\n'
       '            \'（访问边界降级）。请 SSH 到本机重建该配置后重启面板服务。\')\n',
       '        pass\n')],
     'c'),

    ('E-03  配置恢复后不清降级原因（告警变成「狼来了」，真告警没人看）',
     APP_PY,
     [('        if not degraded:\n'
       '            _set_access_boundary_degraded(\'\')\n',
       '        if not degraded:\n'
       '            pass\n')],
     'c'),

    ('E-04  前端不再读告警字段（告警条永远不显示）',
     FRONT_JS,
     [('        this.auth.accessWarning = d.access_boundary_warning || \'\';\n',
       '        this.auth.accessWarning = \'\';\n')],
     'c'),

    ('E-05  页面里没有告警条',
     FRONT_HTML,
     [('x-show="auth.accessWarning"',
       'x-show="false"')],
     'c'),

    ('E-06  告警条 z-index 低于登录遮罩（登录页看不见）',
     FRONT_CSS,
     [('  z-index: 110;\n',
       '  z-index: 95;\n')],
     'c'),

    ('E-07  降级原因里不写清后果与修复步骤（管理员不知道面板已拒绝所有来源、不知道怎么修）',
     APP_PY,
     [('            f\'配置文件 {CONFIG_PATH} 不存在 —— 面板当前**已拒绝所有来源访问**\'\n'
       '            \'（访问边界降级）。请 SSH 到本机重建该配置后重启面板服务。\')\n',
       '            f\'配置文件 {CONFIG_PATH} 不存在\')\n')],
     'c'),

    # ── fail-closed 三条降级路径（2026-11-08 用户拍板改 fail-closed）──
    # 每条降级路径各一条：任何一条被改回「不限制来源」，
    # 都必须被测试逮住 —— 否则 fail-closed 会被悄悄退化掉，
    # 而退化后的表现（面板谁都能进）恰恰是没人会主动报的问题。
    ('E-08  配置损坏时改回 fail-open（谁都能连面板端口）',
     APP_PY,
     [('                nets = list(_DENY_ALL_NETS)\n            else:',
       '                nets = []\n            else:')],
     'c'),

    ('E-09  配置读取抛异常时改回 fail-open',
     APP_PY,
     [('            nets = list(_DENY_ALL_NETS)\n    if nets:',
       '            nets = []\n    if nets:')],
     'c'),

    ('E-10  配置不存在时改回 fail-open（谁都能连面板端口）',
     APP_PY,
     [('        nets = list(_DENY_ALL_NETS)\n    else:',
       '        nets = []\n    else:')],
     'c'),

    # ── 下面这条钉住 2026-11-08 改 fail-closed 时挖出来的坑 ──
    ('E-11  降级时也清降级状态（告警被自己抹掉，降级了就没人看得见）',
     APP_PY,
     [('        if not degraded:\n'
       '            _set_access_boundary_degraded(\'\')\n',
       '        if True:\n'
       '            _set_access_boundary_degraded(\'\')\n')],
     'c'),
]
# ⚠️ 曾试过一条「缓存命中判断漏掉 is not None」的变异（E-12），**它是无效变异**：
#    缓存判断位于 os.stat 成功的 else 分支内，配置缺失路径根本走不到 ⇒
#    去掉那个条件不改变任何行为 ⇒ 测试当然不红。
#    留着它是**双保险**（防以后把判断挪出 else），但不能算作变异条目。
#    （这轮踩到的另一个教训：注释里写「必须」却写错了推理，
#      差点把一段误导性的说明留在代码里。）

# ─────────────────────────────────────────────────────────────
# F 组：setup.sh 的三个 apk 缺陷
# ─────────────────────────────────────────────────────────────
F_MUTATIONS = [
    ('F-01  apk add 不带 --timeout（卡住就是死等，实测 4 分钟零字节）',
     SETUP,
     [('        apk_supports_timeout && apk_opts="${apk_opts} --timeout ${APK_NET_TIMEOUT}"\n',
       '        apk_supports_timeout && apk_opts="${apk_opts}"\n')],
     'apk'),

    ('F-02  --timeout 不再探测（apk 2.x 直接报 unknown option）',
     SETUP,
     [('apk_supports_timeout() {\n'
       '    if [ -z "$APK_HAS_TIMEOUT" ]; then\n'
       '        if apk add --help 2>&1 | grep -q -- \'--timeout\'; then\n'
       '            APK_HAS_TIMEOUT=1\n'
       '        else\n'
       '            APK_HAS_TIMEOUT=0\n'
       '        fi\n'
       '    fi\n'
       '    [ "$APK_HAS_TIMEOUT" = "1" ]\n'
       '}\n',
       'apk_supports_timeout() {\n'
       '    APK_HAS_TIMEOUT=1\n'
       '    [ "$APK_HAS_TIMEOUT" = "1" ]\n'
       '}\n')],
     'apk'),

    ('F-03  APK_NET_TIMEOUT 默认值失效（默认 0 = 不超时）',
     SETUP,
     [('APK_NET_TIMEOUT="${APK_NET_TIMEOUT:-30}"\n',
       'APK_NET_TIMEOUT="${APK_NET_TIMEOUT:-0}"\n')],
     'apk'),

    ('F-04  apk_file_looks_valid 不再校验包头（HTML 错误页被当成包）',
     SETUP,
     [('    apk_file_has_apk_magic "$f"\n',
       '    return 0\n')],
     'apk'),

    ('F-05  apk_file_looks_valid 不再校验体积（截断的半截文件被当成包）',
     SETUP,
     [('    sz="$(wc -c < "$f" 2>/dev/null | tr -d \' \')"\n'
       '    [ -n "$sz" ] && [ "$sz" -ge 64 ] || return 1\n',
       '    sz="$(wc -c < "$f" 2>/dev/null | tr -d \' \')"\n'
       '    [ -n "$sz" ] || return 1\n')],
     'apk'),

    ('F-06  apk_rotate_mirror 不再轮换（同一个包反复失败）',
     SETUP,
     [('            apk_rotate_mirror || true\n',
       '            true\n')],
     'apk'),

    ('F-07  apk_rotate_mirror 不跳过当前源（换回自己，等于没换）',
     SETUP,
     [('        [ "$host" = "$cur" ] && continue\n',
       '        :\n')],
     'apk'),

    ('F-08  兜底安装前不再校验文件是不是真的包',
     SETUP,
     [('    if ! apk_file_looks_valid "$f"; then\n'
       '        warn "  下载到的不是有效的 apk 包（当前镜像缺包体：$(basename "$f")，$(wc -c < "$f" 2>/dev/null | tr -d \' \') 字节）"\n'
       '        rm -rf "$work"\n'
       '        return 1\n'
       '    fi\n',
       '    :\n')],
     'apk'),

    ('F-09  apk add 不再走外层 run_with_timeout（apk 自己卡死就死等）',
     SETUP,
     [('        if run_with_timeout "${APK_INSTALL_TIMEOUT:-600}" apk add ${apk_opts} "$pkg"; then\n',
       '        if apk add ${apk_opts} "$pkg"; then\n')],
     'apk'),

    ('F-10  不认 ADB v3 包头（25.12 上所有合法包都被拒）',
     SETUP,
     [('        magic="$(od -An -tx1 -N3 "$f" 2>/dev/null | tr -d \' \\n\')"\n'
       '        if [ -n "$magic" ]; then\n'
       '            case "$magic" in\n'
       '                414442*|1f8b*) return 0 ;;\n'
       '            esac\n'
       '            return 1\n'
       '        fi\n',
       '        magic="$(od -An -tx1 -N3 "$f" 2>/dev/null | tr -d \' \\n\')"\n'
       '        if [ -n "$magic" ]; then\n'
       '            case "$magic" in\n'
       '                1f8b*) return 0 ;;\n'
       '            esac\n'
       '            return 1\n'
       '        fi\n'),
      ('        magic="$(hexdump -v -n 3 -e \'1/1 "%02x"\' "$f" 2>/dev/null | tr -d \' \\n\')"\n'
       '        if [ -n "$magic" ]; then\n'
       '            case "$magic" in\n'
       '                414442*|1f8b*) return 0 ;;\n'
       '            esac\n'
       '            return 1\n'
       '        fi\n',
       '        magic="$(hexdump -v -n 3 -e \'1/1 "%02x"\' "$f" 2>/dev/null | tr -d \' \\n\')"\n'
       '        if [ -n "$magic" ]; then\n'
       '            case "$magic" in\n'
       '                1f8b*) return 0 ;;\n'
       '            esac\n'
       '            return 1\n'
       '        fi\n')],
     'apk'),

    ('F-11  去掉 hexdump 降级层（OpenWrt 上没有 od 时读不到包头）',
     SETUP,
     [('    # ② hexdump（busybox applet，OpenWrt 一定有）\n'
       '    if command -v hexdump >/dev/null 2>&1; then\n'
       '        magic="$(hexdump -v -n 3 -e \'1/1 "%02x"\' "$f" 2>/dev/null | tr -d \' \\n\')"\n'
       '        if [ -n "$magic" ]; then\n'
       '            case "$magic" in\n'
       '                414442*|1f8b*) return 0 ;;\n'
       '            esac\n'
       '            return 1\n'
       '        fi\n'
       '    fi\n',
       '    # ② hexdump 层被删掉了\n')],
     'apk'),

    ('F-12  去掉 shell 内建兜底层（连 hexdump 都没有的机器上读不到包头）',
     SETUP,
     [('    b=""\n'
       '    IFS= read -r -n 3 b < "$f" 2>/dev/null\n'
       '    [ "$b" = "ADB" ] && return 0\n'
       '    b=""\n'
       '    IFS= read -r -n 2 b < "$f" 2>/dev/null\n'
       '    [ "$b" = "$(printf \'\\037\\213\')" ] && return 0\n'
       '    return 1\n',
       '    return 1\n')],
     'apk'),
]

ALL = ([('C', m) for m in C_MUTATIONS]
       + [('D', m) for m in D_MUTATIONS]
       + [('E', m) for m in E_MUTATIONS]
       + [('F', m) for m in F_MUTATIONS])


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests('both')
    if rc != 0:
        print('原始状态下测试就是红的，先修测试再跑变异：')
        print(out[-3000:])
        return 2
    print('原始状态：测试通过（C 批 %d 项 + apk 批 %d 项）'
          % (out.count('[PASS]'), out.count('✅')))
    print()

    caught, missed = 0, []
    for grp, (name, path, edits, which) in ALL:
        restore()
        try:
            apply_edits(path, edits)
        except ValueError as e:
            print(f'  [脚本错] {name}')
            print(f'      ↓ {e}')
            missed.append(f'{name}（变异脚本自身的错）')
            continue
        rc, out = run_tests(which)
        if rc != 0:
            caught += 1
            first = ''
            for line in out.splitlines():
                st = line.strip()
                if st.startswith('[FAIL]') or st.startswith('❌'):
                    first = st
                    break
            print(f'  [捕获] {grp} {name}')
            if first:
                print(f'      ↓ {first[:150]}')
        else:
            missed.append(f'{grp} {name}')
            print(f'  [漏网] {grp} {name}  ← 测试没变红！')

    restore()

    print()
    print('=' * 60)
    print(f'  变异 {len(ALL)} 条，捕获 {caught} 条，漏网 {len(missed)} 条')
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        return 1
    print('  全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
