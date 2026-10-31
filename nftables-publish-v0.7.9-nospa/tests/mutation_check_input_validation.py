"""输入校验与注入批次的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_input_validation.py

**不要用 `tests/_mutation_guard.py` 的 `MutationGuard`** ——
它的全快照还原会把**别的 agent 正在改的文件**一起写回去
（实测已造成并行改动丢失两次）。这里只备份/还原自己动的那两个文件。

测什么有效：这一批全是「把校验改回去」的退化方向。
注入类修复最危险的地方是**改回去之后功能照样正常** ——
单测很容易全绿，只有真的把校验拆掉，测试才会变红。
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
KNOCK = os.path.join(ROOT, 'setup', 'knock-lan.sh')
TEST_PY = os.path.join(ROOT, 'tests', 'test_input_validation_fixes.py')

ORIG = {APP_PY: open(APP_PY, encoding='utf-8').read(),
        KNOCK: open(KNOCK, encoding='utf-8').read()}


def run_tests():
    r = subprocess.run([sys.executable, TEST_PY], capture_output=True,
                       text=True, cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def restore():
    for path, content in ORIG.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


def _install_fuse():
    def _handler(signum, frame):
        restore()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _handler)
        except Exception:
            pass
    atexit.register(restore)


# (描述, 文件, [(旧串, 新串), ...])
MUTATIONS = [
    ('M1  knock-lan.sh 退回用 eval 解析配置',
     KNOCK, [('        HOST=$(printf \'%s\\n\' "$CONFIG_VALS" | sed -n \'1p\')',
              '        eval "HOST=\\"$(printf \'%s\\n\' "$CONFIG_VALS" | sed -n \'1p\')\\""')]),

    ('M2  knock-lan.sh 退回把 host 插进 bash -c 的命令串',
     KNOCK, [('timeout 3 bash -c \'exec 3<>/dev/udp/"$1"/"$2" && printf "k" >&3\' _ "$host" "$port"',
              'timeout 3 bash -c "exec 3<>/dev/udp/${host}/${port} && printf \'k\' >&3"')]),

    ('M3  knock-lan.sh 去掉 host 白名单校验',
     KNOCK, [('    case "$1" in\n        *[!0-9A-Za-z.:_-]*) return 1 ;;\n    esac\n    return 0',
              '    return 0')]),

    ('M4  router_ip6 又原样进 nftables 规则',
     APP_PY, [('    router_ip6 = _safe_ip(config.get("router_ip6"), 6, "")',
               '    router_ip6 = (config.get("router_ip6") or "").strip()')]),

    ('M5  证书路径不再限制在 SSL 目录内（nginx 配置注入）',
     APP_PY, [('    if real != base and not real.startswith(base.rstrip(\'/\') + \'/\'):\n        return default\n',
               '')]),

    ('M6  冲突检测退回裸字符串比较（漏报冲突）',
     APP_PY, [('            key = _normalize_target_host(host)\n            if key:\n                rp_targets.add((key, int(port)))',
               '            if host:\n                rp_targets.add((host.strip(), int(port)))')]),

    ('M7  detect-* 不再限制目标必须在 LAN 网段内（SSRF oracle）',
     APP_PY, [('    if not _detect_target_allowed(host):\n'
               '        return jsonify({"success": False,\n'
               '                        "message": "target_address 必须是 LAN 网段内的内网 IP:端口"}), 400\n'
               '    prefixes, err = _detect_upstream_api_prefixes(host, port, proto)',
               '    prefixes, err = _detect_upstream_api_prefixes(host, port, proto)')]),

    ('M8  探测失败时错误信息又回显 URL（oracle）',
     APP_PY, [('        return [], "探测失败：目标无响应，或不是提供 openapi.json 的服务"',
               '        return [], f"读取 {url} 失败：{type(e).__name__}: {e}"')]),

    ('M9  兜底防火墙的 lan_if 又原样插进 nftables',
     APP_PY, [('    lan_if = _safe_iface(config.get("lan_if"), "br-lan")',
               '    lan_if = str(config.get("lan_if", "") or "").strip() or "br-lan"')]),

    ('M10 名单元素读出来时不再校验（二次注入）',
     APP_PY, [('            if not _valid_ip(ip, ver):\n'
               '                print(f\'[WARN] 名单 {name} 里有非法元素，已丢弃: {ip!r}\', flush=True)\n'
               '                continue\n',
               '')]),

    ('M11 生成器对非法目标主机恢复静默丢弃',
     APP_PY, [('        if not _valid_upstream_host(host):',
               '        if False:')]),

    ('M12 规则校验不再检查生成器会不会丢弃这条规则',
     APP_PY, [('    if not _valid_upstream_host(_t_host):\n'
               '        return None, (f"目标地址 {_t_host!r} 不是有效的内网 IP 或接口名"\n'
               '                      "（生成网关配置时会被直接丢弃）")\n',
               '')]),

    # ⚠️ M13 是 M12 的「反面」：M12 删掉**校验侧**的检查，M13 让**生成侧**
    # 收窄到只认 IPv6。M13 制造的是**有害方向**的分叉 ——
    # 校验侧放行 IPv4 目标、生成器却把它丢掉 ⇒ 正是 P2-16 描述的
    # 「API 报成功但规则没生效」。
    #
    # 为什么必须有这条：M12 删掉校验侧的检查后，含空格的怪目标只是
    # 「换个文案被拒」（仍然是拒），**行为没变** —— 只守 M12 的话，
    # 那种「校验放行、生成器丢弃」的有害分叉就没人守了。
    ('M13 生成侧的判定收窄（校验放行的目标被生成器静默丢弃 = 规则没生效）',
     APP_PY, [('        if not _valid_upstream_host(host):\n'
               '            # 静默丢弃是「API 报成功但规则没生效」的来源（P2-16）。',
               '        if not _valid_ip(host, 6):\n'
               '            # 静默丢弃是「API 报成功但规则没生效」的来源（P2-16）。')]),

    # ⚠️ 锚点必须精确落在 **_nginx_service_location**（反代上游那行）上。
    # 之前锚的是 `proxy_set_header Host $host;` —— 那串字面量在文件里出现三次
    # （认证端点 ×2 + 门户页 ×1），真正要守的「反代上游」那行反而**打不到**：
    # 变异打在了不相干的地方，测试是靠门户行变红才捕获的 —— 属于「碰巧捕获」，
    # 哪天门户那行改了写法，这条变异就会变成「打空枪」（锚点失配 = 没人守）。
    ('M14 上游又收到客户端可控的 Host 头',
     APP_PY, [('    L.append("        proxy_set_header Host $host:$server_port;")',
               '    L.append("        proxy_set_header Host $http_host:$server_port;")')]),

    # M14b 反代上游的 Host 头丢掉端口 —— 这是本轮修的真问题：
    # 上游（思源）拿 Origin 头和 Host 头逐字节比对，端口不一致就
    # 401「invalid request origin」⇒ 密码页能开、输完密码进不去主界面。
    ('M14b 反代上游的 Host 头丢掉端口（上游 origin 校验会拒绝）',
     APP_PY, [('    L.append("        proxy_set_header Host $host:$server_port;")',
               '    L.append("        proxy_set_header Host $host;")')]),

    # M14c X-Forwarded-Host 丢掉端口 —— 上游拼绝对 URL（回调地址、分享链接）
    # 会指到 443，而网关根本不在 443 上。
    ('M14c X-Forwarded-Host 丢掉端口',
     APP_PY, [('    L.append("        proxy_set_header X-Forwarded-Host $host:$server_port;")',
               '    L.append("        proxy_set_header X-Forwarded-Host $host;")')]),

    # M14d 门户页转发改用客户端可控的 Host 头 —— 同样是 Host Header Injection。
    ('M14d 门户页转发改用客户端可控的 Host 头',
     APP_PY, [('    L.append("        proxy_set_header Host $host;")',
               '    L.append("        proxy_set_header Host $http_host;")')]),
]


def main():
    _install_fuse()
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, path, edits in MUTATIONS:
        src = ORIG[path]
        bad = [old for old, _ in edits if old not in src]
        if bad:
            print(f'  ⚠️  {name}')
            print(f'      ↓ 变异锚点没匹配上（源码变了？），跳过')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '❌' in l), '')
                print(f'  ✅ {name}  —— 被捕获')
                print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  ❌ {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            restore()

    print()
    print(f'════════ 结果：捕获 {caught} / {caught + missed} ════════')
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 ❌ 的测试是假测试')
    else:
        print('源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
