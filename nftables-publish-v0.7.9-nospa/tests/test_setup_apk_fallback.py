"""setup.sh 的三个 apk 缺陷的回归测试（真跑 shell 函数）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_setup_apk_fallback.py

背景
----
2026-10-30 在 `.238`（全新 OpenWrt 25.12.5）上跑全新安装路径时暴露了
**三个** apk 相关缺陷：

1. **`apk add` 没有超时保护** ——
   `apk update` 有 `run_with_timeout`，install 是**裸调** ⇒ 卡住就是死等
   （实测 4 分钟零字节，界面完全没反应）。
   修法：`apk add --timeout N`（apk-tools 3.x 的全局选项，语义是
   「连接没有进展就超时」）+ 外层 `run_with_timeout` 兜底。
   ⚠️ apk 2.x 没有 `--timeout` ⇒ 必须**先探测再用**。

2. **failover 换到的镜像可能「索引全、包体缺」** ——
   实测 ustc 上 nginx-full / wget-ssl / python3-pip / acme-acmesh 都是
   404（索引里有名字，包体没有）。
   而这种源 `apk update` 是**成功**的 ⇒ 只靠 `apk_update_with_failover`
   永远不会换源 ⇒ 同一个包反复失败，最后报一个毫无线索的
   "file format is invalid or inconsistent"（.232 真机实测的原文；
   镜像问题被伪装成包格式问题，排查方向整个偏掉）。
   修法：装包失败时**主动轮换**镜像 + 校验下载到的文件**是不是真的包**。

3. **`apk_install_via_local_file()` 的兜底在 25.12 上不成立** ——
   它的注释写着「apk fetch 用的是 apk 自带的下载器（不走外部 wget）」，
   实测 apk-tools 3.0.5 下载索引和包体**都会外调外部下载器**
   （.232 上抓到的调用参数是 `-q -T 60 <url> -O -`）。
   ⇒ 这条兜底并不比正常路径可靠；它真正的价值是「文件可以单独校验」。

这个文件把三条都固化成断言，并且**真把 shell 函数抽出来跑** ——
静态文本断言钉不住「校验函数到底认不认 HTML 错误页」。

2026-11-05 真机复检（`.232`，OpenWrt 25.12.5 / apk-tools 3.0.5）
----------------------------------------------------------------
在 `.232` 上真跑这三个缺陷时，发现 **v0.19.1 的修复本身有两个真 bug** ——
它们在开发机上**永远测不出来**，因为开发机有 `od`、而包也不是 ADB 格式：

  ① 包头判据写成了 gzip 魔数 `1f8b`。但 apk-tools 3.x 的包是 **ADB v3**
     格式，头 3 字节是 "ADB"（`41 44 42`，完整 4 字节 "ADBd"）；
     连索引文件 `APKINDEX.*.tar.gz` 都是 ADB 格式（文件名带 .tar.gz，
     内容根本不是 gzip，实测 `gzip -t` 报 "invalid magic"）。
     ⇒ 原判据在 25.12 上**永远为假**，合法包全被当成无效
       ⇒ `apk_install_via_local_file` 恒失败 ⇒ 兜底路径等于死代码。
     apk-tools 2.x（24.10）的包才是 tar.gz ⇒ **两种魔数都得认**。

  ② 读字节用的是 `od`。而 **OpenWrt 25.12.5 上根本没有 od**
     （busybox 也不带这个 applet），实测 `od -An -tx1` 报 "od: not found"
     ⇒ 魔数读出来是空串 ⇒ 判定恒为假 ⇒ 同上，兜底路径在真机上等于死代码。
     可用的替代：busybox 自带 `hexdump`（实测 `/usr/bin/hexdump -> busybox`），
     以及 shell 内建 `read -n`（busybox ash 实测能读二进制字节）。

所以第 4 节专门加了一组**「模拟 OpenWrt 上没有 od」**的行为断言：
把 PATH 削到只剩 `wc`/`tr`，让 `od`/`hexdump`/`read -n` 之外的路径失效，
再跑一遍同样的文件判定 —— 这次能挡住上面那两个 bug。

沙箱运行：只抽函数、桩掉外部命令，不碰真实路径、不联网。
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


SETUP_SRC = open(SETUP, encoding='utf-8').read()


def sh_func(name):
    """从 setup.sh 里抽出某个 shell 函数的完整定义。"""
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{', SETUP_SRC, re.M)
    if not m:
        return ''
    start = m.start()
    depth = 0
    i = m.end() - 1          # 指向 '{'
    while i < len(SETUP_SRC):
        if SETUP_SRC[i] == '{':
            depth += 1
        elif SETUP_SRC[i] == '}':
            depth -= 1
            if depth == 0:
                return SETUP_SRC[start:i + 1]
        i += 1
    return ''


def strip_sh_comments(src):
    """剥掉 shell 注释（# 开头 / 行内 #），保留引号内的内容。

    为什么需要：setup.sh 里到处是解释性注释，而这些注释**正好包含**
    被断言的关键字 —— 比如 pkg_install_apk 的注释里写着 `--timeout`，
    于是「函数体里有 --timeout」这个断言即使把**代码**删了也照样通过。
    ⇒ 断言「这个东西该出现」必须基于去注释后的源码。
    """
    out = []
    for line in src.splitlines():
        st = line.lstrip()
        if st.startswith('#'):
            continue
        in_s = in_d = False
        cut = None
        for idx, ch in enumerate(line):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == '#' and not in_s and not in_d:
                if idx == 0 or line[idx - 1] in ' \t':
                    cut = idx
                    break
        out.append(line if cut is None else line[:cut])
    return '\n'.join(out)


def run_sh(script, name='t', path=None, shell='sh'):
    """在临时目录里跑一段 shell，返回 (rc, stdout+stderr)。

    ⚠️ shell 必须用**绝对路径**启动：沙箱场景下 env['PATH'] 被削得很干净，
       再用 'sh' 这种裸名字，subprocess 会按新 PATH 去找 → 找不到就报错。
    """
    shell_bin = shutil.which(shell) or shell
    d = tempfile.mkdtemp(prefix='apkchk-')
    try:
        p = os.path.join(d, name + '.sh')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(script)
        env = dict(os.environ, PATH=path or '/usr/bin:/bin:/usr/local/bin')
        r = subprocess.run([shell_bin, p], capture_output=True, text=True,
                           cwd=d, env=env, timeout=60)
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    finally:
        shutil.rmtree(d, ignore_errors=True)


def sandbox_path(tools):
    """造一个只含指定工具的 PATH 目录（模拟 OpenWrt 上缺 od 的环境）。

    为什么需要：开发机（Ubuntu）**有 od** ⇒ 直接跑函数永远走第一层降级，
    测不到「目标设备没有 od」这条真实路径。
    """
    d = tempfile.mkdtemp(prefix='apksbx-')
    for t in tools:
        src = shutil.which(t)
        if src:
            os.symlink(src, os.path.join(d, t))
    return d


# ─────────────────────────────────────────────────────────────
sec('1  apk add 的超时保护（缺陷一）')

check('setup.sh 里 apk_supports_timeout 存在',
      bool(sh_func('apk_supports_timeout')))
# ⚠️ 默认值必须是**正数**：0 在 apk 里等于「不超时」，
#   写成 :-0 会让「有超时保护」这件事完全失效 —— 而 \d+ 照样匹配 0。
_m_to = re.search(r'APK_NET_TIMEOUT="\$\{APK_NET_TIMEOUT:-(\d+)\}"', SETUP_SRC)
check('setup.sh 里 APK_NET_TIMEOUT 有默认值',
      _m_to is not None,
      _m_to.group(0) if _m_to else '没找到 APK_NET_TIMEOUT 的默认值')
check('APK_NET_TIMEOUT 的默认值大于 0（0 = 不超时，等于没有保护）',
      _m_to is not None and int(_m_to.group(1)) > 0,
      '默认值=%s' % (_m_to.group(1) if _m_to else '?'))

_apk_fn = sh_func('pkg_install_apk')
_apk_code = strip_sh_comments(_apk_fn)
check('pkg_install_apk 里 apk add 带了 --timeout',
      '--timeout' in _apk_code,
      '没有超时保护 ⇒ 卡住就是死等（实测 4 分钟零字节）')
check('pkg_install_apk 里 apk add 走 run_with_timeout（外层兜底）',
      re.search(r'run_with_timeout[^\n]*apk add', _apk_code) is not None)
check('--timeout 是**探测后**才拼的（apk 2.x 没有这个选项）',
      'apk_supports_timeout &&' in _apk_code,
      '写死 --timeout 会让 apk 2.x 直接报 unknown option')
check('不再有裸调 apk add（没有超时的写法已经消失）',
      re.search(r'^\s*if apk add --no-cache "\$pkg"; then', _apk_code, re.M) is None)
# ⚠️ 同理：'--timeout' 在**注释**里也写着 ⇒ 只看原始文本会被骗过。
#   这条断言把注释剥掉后再查 —— 防止「代码删了、注释留着」蒙混过关。
check('--timeout 是真的在**代码**里（不是只在注释里写着）',
      '--timeout' in _apk_code,
      '去注释后找不到 --timeout ⇒ 超时保护其实已经没了')

# 真跑 apk_supports_timeout 的探测（静态断言钉不住「它到底会不会去问 apk」）
#
# ⚠️ 2026-11-05：这两段断言一度被误删 ⇒ C 批的 F-02 变异（把探测改成写死
#    「支持」）立刻变成漏网。**行为级断言不能省**，静态文本检查抓不到它。
probe = r'''
%s

# 桩：模拟 apk 2.x（没有 --timeout）与 apk 3.x（有 --timeout）
apk() {
    if [ "$1" = "add" ] && [ "$2" = "--help" ]; then
        if [ "$FAKE_APK_VER" = "3" ]; then
            echo "  --timeout TIME   Timeout network connections if no progress is made"
        else
            echo "  --no-cache        Do not use any local cache path"
        fi
        return 0
    fi
    return 0
}
FAKE_APK_VER=2
if apk_supports_timeout; then echo "HAS_TIMEOUT 2"; else echo "NO_TIMEOUT 2"; fi
''' % sh_func('apk_supports_timeout')

rc, out = run_sh(probe, 'probe')
check('apk 2.x（没有 --timeout）被正确识别为不支持',
      'NO_TIMEOUT 2' in out, out.strip()[:200])

probe3 = r'''
%s
apk() {
    if [ "$1" = "add" ] && [ "$2" = "--help" ]; then
        echo "  --timeout TIME   Timeout network connections if no progress is made"
        return 0
    fi
    return 0
}
if apk_supports_timeout; then echo "HAS_TIMEOUT 3"; else echo "NO_TIMEOUT 3"; fi
''' % sh_func('apk_supports_timeout')
rc, out = run_sh(probe3, 'probe3')
check('apk 3.x（支持 --timeout）被正确识别为支持',
      'HAS_TIMEOUT 3' in out, out.strip()[:200])

# ─────────────────────────────────────────────────────────────
sec('2  镜像「索引全、包体缺」的识别与轮换（缺陷二）')

check('setup.sh 里 apk_rotate_mirror 存在', bool(sh_func('apk_rotate_mirror')))
check('装包失败后会主动轮换镜像（apk_update_with_failover 不够：'
      '那种源 apk update 是成功的）',
      'apk_rotate_mirror' in _apk_code,
      '只刷索引不换源 ⇒ 同一个包反复失败')
check('轮换会跳过当前源（否则换回自己，等于没换）',
      'continue' in strip_sh_comments(sh_func('apk_rotate_mirror')))
# ⚠️ 轮换必须真的**换**（调 switch_apk_mirror），不能只是走个过场。
check('轮换真的会切到新源（调了 switch_apk_mirror）',
      'switch_apk_mirror' in strip_sh_comments(sh_func('apk_rotate_mirror')))
check('轮换后会把索引也拉一遍（索引与包体必须来自同一个源）',
      'apk_update_once' in strip_sh_comments(sh_func('apk_rotate_mirror')))
check('setup.sh 里 apk_file_looks_valid 存在', bool(sh_func('apk_file_looks_valid')))

# ─────────────────────────────────────────────────────────────
sec('3  兜底路径的注释与校验（缺陷三）')

check('兜底函数 apk_install_via_local_file 存在',
      bool(sh_func('apk_install_via_local_file')))
_fb = sh_func('apk_install_via_local_file')
# ⚠️ 说明性注释写在函数**外面**（函数上方）⇒ 得连注释一起看，
#    只抽函数体会把「关于下载器的更正说明」漏掉。
_fb_idx = SETUP_SRC.index('apk_install_via_local_file()')
_fb_ctx = SETUP_SRC[max(0, _fb_idx - 1600):_fb_idx] + _fb
check('兜底安装前会校验文件是不是真的包',
      # ⚠️ 必须查**去注释版**（2026-11-05 加固）：
      #    断言是在问「代码里有没有调用这个校验」，
      #    而 _fb 是带注释的函数体 —— 将来谁在这个函数里写一句
      #    「这里要调 apk_file_looks_valid」之类的说明，
      #    断言就会被注释顶住（setup_resume 的 M20 就是这么漏网的）。
      'apk_file_looks_valid' in strip_sh_comments(_fb),
      '不校验 ⇒ 镜像缺包体时装上一张 HTML 错误页，报包格式不对')
check('兜底失败时给出「镜像缺包体」的可读原因（不是让人去查签名）',
      '缺包体' in _fb or '不是有效的 apk 包' in _fb)
check('关于「apk fetch 走自带下载器」的过时说法已被更正',
      '自带下载器' not in _fb_ctx,
      '25.12 上 apk fetch 同样外调下载器，注释与事实不符会误导排查')
check('注释里写明了 25.12 的实测事实',
      '25.12' in _fb_ctx and 'wget' in _fb_ctx)

# ⚠️ 2026-11-05 真机复检新增：注释里给出的**报错原文**必须是真的。
#   .232 实测：拿一张 HTML 错误页当 .apk 装，apk 报的是
#   "file format is invalid or inconsistent"，
#   原来注释写的 "ADB integrity error" 是「包体被截断」时才出现的话。
check('注释里的缺包体报错原文与真机一致（file format is invalid or inconsistent）',
      'file format is invalid or inconsistent' in _fb_ctx,
      '报错原文写错 ⇒ 排查时会照着错误信息去找错方向')

# ─────────────────────────────────────────────────────────────
sec('4  真机口径的包头判定（.232 实测修正的两条判据）')

_magic_fn = sh_func('apk_file_has_apk_magic')
check('setup.sh 里 apk_file_has_apk_magic 存在（专门负责取包头字节）',
      bool(_magic_fn))
_magic_code = strip_sh_comments(_magic_fn) if _magic_fn else ''

check('认得 apk-tools 3.x 的 ADB v3 包头（414442 = "ADB"）',
      '414442' in _magic_code,
      'ADB v3 才是 25.12 上真实的包格式；只认 gzip 会把合法包全拒掉')
check('仍认 apk-tools 2.x 的 gzip 包头（1f8b）',
      '1f8b' in _magic_code,
      '24.10 上的包是 tar.gz，不能只认 ADB')
check('od 只是**第一层**降级，不是唯一手段',
      'od' in _magic_code and 'hexdump' in _magic_code,
      'OpenWrt 上没有 od，必须有别的读字节的办法')
check('有 hexdump 降级层（busybox applet，OpenWrt 一定有）',
      'hexdump' in _magic_code)
check('有 shell 内建兜底层（read -n，不依赖任何外部命令）',
      re.search(r'read\s+-r\s+-n', _magic_code) is not None)
check('体积下限仍然在（0 字节 / 几十字节的半截文件要挡掉）',
      re.search(r'-ge\s+64', strip_sh_comments(sh_func('apk_file_looks_valid')))
      is not None)

# ---- 真跑：三种 PATH 环境下的文件判定 ----
#
# 造五种文件：
#   adb.apk   —— apk-tools 3.x 的真包（头 "ADB"，.232 实测的真实格式）
#   gzip.apk  —— apk-tools 2.x 的真包（头 1f 8b）
#   page.apk  —— 镜像缺包体 ⇒ 下载器存下来的 HTML 错误页
#   empty.apk —— 0 字节
#   tiny.apk  —— 头对但不足 64 字节
_CASES_BODY = r'''
%s
%s

# adb.apk：apk-tools 3.x 的真包 —— 头 3 字节 "ADB"（.232 实测的真实格式）
printf 'ADB' > adb.apk
dd if=/dev/zero bs=1 count=200 >> adb.apk 2>/dev/null
# gzip.apk：apk-tools 2.x 的真包 —— 头 1f 8b
printf '\037\213\010\000\000\000\000\000\000\003' > gzip.apk
dd if=/dev/zero bs=1 count=200 >> gzip.apk 2>/dev/null
# page.apk：镜像缺包体 ⇒ 下载器存下来的 HTML 错误页
printf '<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head></html>\n' > page.apk
: > empty.apk
printf 'ADB' > tiny.apk
dd if=/dev/zero bs=1 count=10 >> tiny.apk 2>/dev/null

for f in adb.apk gzip.apk page.apk empty.apk tiny.apk; do
    if apk_file_looks_valid "$f"; then echo "VALID $f"; else echo "INVALID $f"; fi
done
''' % (sh_func('apk_file_looks_valid'), _magic_fn)

_EXPECT = {
    'adb.apk': 'VALID',       # ADB v3 真包 —— 25.12 上最常见的形态
    'gzip.apk': 'VALID',      # apk-tools 2.x 的 tar.gz 真包
    'page.apk': 'INVALID',    # HTML 错误页 —— 缺陷二的核心
    'empty.apk': 'INVALID',   # 空文件
    'tiny.apk': 'INVALID',    # 半截文件
}


def _verdict(lines, f):
    return lines.get(f, '(没输出)')


def judge(out):
    return {ln.split()[1]: ln.split()[0]
            for ln in out.splitlines() if ln.startswith(('VALID', 'INVALID'))}


# ① 开发机环境（od / hexdump 都在）
rc, out = run_sh(_CASES_BODY, 'case_full')
_lines = judge(out)
for _f, _want in _EXPECT.items():
    check(f'[有 od/hexdump] {_f} 判为 {_want}', _lines.get(_f) == _want,
          '实际=%s' % _verdict(_lines, _f))

# ② 模拟 OpenWrt：**没有 od**（.232 真机就是这样）
#    ⚠️ 沙箱里必须留 dd —— 造测试文件要用它。
rc, out = run_sh(_CASES_BODY, 'case_nood',
                 path=sandbox_path(['wc', 'tr', 'dd', 'hexdump']))
_lines = judge(out)
for _f, _want in _EXPECT.items():
    check(f'[没有 od] {_f} 判为 {_want}', _lines.get(_f) == _want,
          '实际=%s' % _verdict(_lines, _f))

# ③ 最恶劣：**既没有 od 也没有 hexdump**，只剩 shell 内建 read -n
#    ⚠️ dash 的 read 不支持 -n（POSIX 没这选项）⇒ 这一档用 bash 跑；
#    目标设备上是 busybox ash（实测支持 read -n 读二进制字节）。
_probe = subprocess.run(
    ['bash', '-c', "IFS= read -r -n 3 v < /etc/hostname; echo ${#v}"],
    capture_output=True, text=True)
if _probe.returncode == 0 and _probe.stdout.strip() == '3':
    rc, out = run_sh(_CASES_BODY, 'case_bare',
                     path=sandbox_path(['wc', 'tr', 'dd']), shell='bash')
    _lines = judge(out)
    for _f, _want in _EXPECT.items():
        check(f'[没有 od 也没有 hexdump] {_f} 判为 {_want}',
              _lines.get(_f) == _want,
              '实际=%s' % _verdict(_lines, _f))
else:
    print('  [跳过] 本机 bash 的 read -n 不可用 ⇒ 无法验证 shell 内建兜底层')

# ─────────────────────────────────────────────────────────────
sec('5  镜像路径前缀（2026-11-15 在 .120 实测踩到）')

# 现象：.120（OpenWrt 25.12.5）全新安装卡在【依赖安装】阶段，
#   所有镜像源都报 "unexpected end of file"，最后 nginx 装不上。
#
# 根因：**国内镜像的 OpenWrt 仓库挂在 /openwrt/ 下面，比官方源多一层**。
#   官方源：https://downloads.openwrt.org/releases/25.12.5/...
#   国内源：https://mirrors.ustc.edu.cn/openwrt/releases/25.12.5/...
# 而 switch_apk_mirror 原来只换主机、路径原样保留 ⇒ 切过去的 URL 变成
#   https://mirrors.ustc.edu.cn/releases/25.12.5/...
# 三个国内镜像上**全是 404**（实测 curl 逐个验过）：
#   404  https://mirrors.ustc.edu.cn/releases/25.12.5/packages/x86_64/base/packages.adb
#   200  https://mirrors.ustc.edu.cn/openwrt/releases/25.12.5/packages/x86_64/base/packages.adb
#
# 为什么这个 bug 特别难查：**症状和「官方源被截断」一模一样**。
# setup.sh 的注释里写着「官方源在国内网络大文件会截断」，所以看到
# "unexpected end of file" 会自然地往截断方向想 ⇒ 而真实原因是 404，
# 404 的响应体不是索引文件，apk 也报成 end of file。排查方向整个被带偏。
#
# 而且它是**救急动作本身把能用的源弄坏了**：官方源本来是好的
# （.120 上首次 apk update 成功，11258 个包），切镜像之后反而全挂。

_mirror_fn = sh_func('switch_apk_mirror')
check('setup.sh 里 switch_apk_mirror 存在', bool(_mirror_fn))

# ---- 真跑：抽函数出来，实际切一次源，检查产物路径形态 ----
#
# 为什么必须真跑：静态文本断言只能证明「代码里写了 openwrt」，
# 钉不住「切出来的 URL 到底长什么样」——
# 而这个 bug 恰恰是「代码看着对、产物全 404」。
#
# 沙箱里造一份假的 distfeeds.list（内容与 .120 真机一致），
# 跑真函数，然后检查每一行是不是 <host>/openwrt/releases/ 形态。
_MIRROR_CASE = r'''
%s

# 桩：apk_repo_file 返回沙箱里的假清单
apk_repo_file() { echo "$REPO"; }

REPO=%s
switch_apk_mirror "%s" || echo "SWITCH_FAILED"
cat "$REPO"
''' % (_mirror_fn, '$REPO', '${HOST}')

# 用真实的 .120 distfeeds 内容做输入
_120_DISTFEEDS = """https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/packages/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/base/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/kmods/6.12.94-1-a7bc15f451f9652701ba04af9cfb0b95/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/luci/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/packages/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/routing/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/telephony/packages.adb
https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/video/packages.adb
"""

# 沙箱版：apk_repo_file 桩成固定路径，函数体照抄
_mirror_sandbox = _MIRROR_CASE.replace('"$REPO"', '"$SANDBOX_REPO"')
_mirror_sandbox = _mirror_sandbox.replace('REPO=$REPO', 'REPO=$SANDBOX_REPO')
_mirror_sandbox = _mirror_sandbox.replace('switch_apk_mirror "%s"' % '${HOST}',
                                          'switch_apk_mirror "$TEST_HOST"')
_mirror_sandbox = _mirror_sandbox.replace("'%s'" % '${HOST}', '"$TEST_HOST"')


def shlex_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _run_mirror(host, feeds=_120_DISTFEEDS):
    """在沙箱里真跑一次 switch_apk_mirror，返回切完之后的清单内容。"""
    d = tempfile.mkdtemp(prefix='apkmirror-')
    try:
        repo = os.path.join(d, 'distfeeds.list')
        with open(repo, 'w', encoding='utf-8') as f:
            f.write(feeds)
        script = ('SANDBOX_REPO=%s\nTEST_HOST=%s\n%s\n'
                  % (shlex_quote(repo), shlex_quote(host), _mirror_sandbox))
        rc, out = run_sh(script, 'mirror')
        return rc, out
    finally:
        shutil.rmtree(d, ignore_errors=True)


rc, out = _run_mirror('mirrors.ustc.edu.cn')
_lines = [ln for ln in out.splitlines() if ln.startswith('http')]
check('切镜像后清单非空（switch_apk_mirror 真的干了活）',
      len(_lines) > 0, '输出=%s' % out.strip()[:200])

if _lines:
    # 核心断言：每行都得是 <host>/openwrt/releases/ 形态
    # （少了 openwrt/ 这一层就是 .120 上踩的那个坑 ⇒ 必然 404）
    _bad = [ln for ln in _lines
            if not re.match(r'^https://mirrors\.ustc\.edu\.cn/openwrt/releases/', ln)]
    check('切到国内镜像后路径带 openwrt/ 这一层（.120 上少了就是全 404）',
          not _bad,
          '不合格的行: %s' % (_bad[:2] if _bad else '无'))

    _no_layer = [ln for ln in _lines if '/openwrt/' not in ln]
    check('没有漏掉 openwrt/ 层的行',
          not _no_layer,
          '漏掉的行: %s' % (_no_layer[:2] if _no_layer else '无'))

    _double = [ln for ln in _lines if 'openwrt/openwrt' in ln]
    check('没有出现 openwrt/openwrt/ 双层（重复切源时的坑）',
          not _double,
          '双层的行: %s' % (_double[:2] if _double else '无'))

    # 幂等：连切两次，路径形态必须不变
    rc2, out2 = _run_mirror('mirror.nju.edu.cn', feeds='\n'.join(_lines) + '\n')
    _lines2 = [ln for ln in out2.splitlines() if ln.startswith('http')]
    _bad2 = [ln for ln in _lines2
             if not re.match(r'^https://mirror\.nju\.edu\.cn/openwrt/releases/', ln)]
    check('连切两次后路径形态仍然正确（幂等）',
          bool(_lines2) and not _bad2,
          '不合格的行: %s' % (_bad2[:2] if _bad2 else '无'))

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'✅ 通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
