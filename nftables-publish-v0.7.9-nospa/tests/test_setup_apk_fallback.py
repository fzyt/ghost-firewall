"""setup.sh 的三个 apk 缺陷的回归测试（真跑 shell 函数）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_setup_apk_fallback.py

背景
----
2026-10-30 在 `.238`（全新 OpenWrt 25.12.5）上跑全新安装路径时暴露了
**三个** apk 相关缺陷，一直挂到今天才修：

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
   永远不会换源 ⇒ 同一个包反复失败，最后报一个
   "ADB integrity error"（镜像问题被伪装成签名问题，排查方向整个偏掉）。
   修法：装包失败时**主动轮换**镜像 + 校验下载到的文件**是不是真的包**。

3. **`apk_install_via_local_file()` 的兜底在 25.12 上不成立** ——
   它的注释写着「apk fetch 用的是 apk 自带的下载器（不走外部 wget）」，
   实测 apk-tools 3.0.5 的包体下载**同样外调 wget**（设备的 /usr/bin/wget
   是 busybox 的 uclient-fetch 软链），大包照样断流。
   ⇒ 这条兜底并不比正常路径可靠；它真正的价值是「文件可以单独校验」。

这个文件把三条都固化成断言，并且**真把 shell 函数抽出来跑** ——
静态文本断言钉不住「校验函数到底认不认 HTML 错误页」。

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


def run_sh(script, name='t'):
    """在临时目录里跑一段 shell，返回 (rc, stdout+stderr)。"""
    d = tempfile.mkdtemp(prefix='apkchk-')
    try:
        p = os.path.join(d, name + '.sh')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(script)
        env = dict(os.environ, PATH='/usr/bin:/bin:/usr/local/bin')
        r = subprocess.run(['sh', p], capture_output=True, text=True,
                           cwd=d, env=env, timeout=60)
        return r.returncode, (r.stdout or '') + (r.stderr or '')
    finally:
        shutil.rmtree(d, ignore_errors=True)


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

# 真跑：apk_file_looks_valid 到底认不认 HTML 错误页
_val = sh_func('apk_file_looks_valid')
check('setup.sh 里 apk_file_looks_valid 存在', bool(_val))

body = r'''
%s

# 造四种文件：
#   1) 真包（gzip 流，头 1f 8b，够大）
#   2) 镜像缺包体 ⇒ wget 存下来的 HTML 错误页
#   3) 空文件
#   4) 截断的半截文件（魔数对但太小）
printf '\037\213\010\000\000\000\000\000\000\003' > real.apk
dd if=/dev/zero bs=1 count=200 >> real.apk 2>/dev/null
printf '<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head></html>\n' > page.apk
: > empty.apk
printf '\037\213\010\000\000\000\000\000\000\003' > tiny.apk

for f in real.apk page.apk empty.apk tiny.apk; do
    if apk_file_looks_valid "$f"; then echo "VALID $f"; else echo "INVALID $f"; fi
done
''' % _val

rc, out = run_sh(body, 'valid')
lines = {ln.split()[1]: ln.split()[0] for ln in out.splitlines() if ln.startswith(('VALID', 'INVALID'))}
check('真 apk 包被判为有效', lines.get('real.apk') == 'VALID', out.strip()[:200])
check('HTML 错误页被判为无效（这是缺陷二的核心）',
      lines.get('page.apk') == 'INVALID', out.strip()[:200])
check('空文件被判为无效', lines.get('empty.apk') == 'INVALID', out.strip()[:200])
check('截断的半截文件被判为无效', lines.get('tiny.apk') == 'INVALID', out.strip()[:200])

# 真跑：apk_supports_timeout 的探测
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
FAKE_APK_VER=3
# 清掉缓存再探（同一个进程里缓存了结果，这里换个进程语义：用新 shell）
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
sec('3  兜底路径的注释与校验（缺陷三）')

check('兜底函数 apk_install_via_local_file 存在',
      bool(sh_func('apk_install_via_local_file')))
_fb = sh_func('apk_install_via_local_file')
# ⚠️ 说明性注释写在函数**外面**（函数上方）⇒ 得连注释一起看，
#    只抽函数体会把「关于下载器的更正说明」漏掉。
_fb_idx = SETUP_SRC.index('apk_install_via_local_file()')
_fb_ctx = SETUP_SRC[max(0, _fb_idx - 1600):_fb_idx] + _fb
check('兜底安装前会校验文件是不是真的包',
      'apk_file_looks_valid' in _fb,
      '不校验 ⇒ 镜像缺包体时装上一张 HTML 错误页，报 ADB integrity error')
check('兜底失败时给出「镜像缺包体」的可读原因（不是让人去查签名）',
      '缺包体' in _fb or '不是有效的 apk 包' in _fb)
check('关于「apk fetch 走自带下载器」的过时说法已被更正',
      '自带下载器' not in _fb_ctx,
      '25.12 上 apk fetch 同样外调 wget，注释与事实不符会误导排查')
check('注释里写明了 25.12 的实测事实',
      '25.12' in _fb_ctx and 'wget' in _fb_ctx)

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'✅ 通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
