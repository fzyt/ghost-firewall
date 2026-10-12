"""权限降级的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_privilege.py

测什么有效：降权代码最危险的退化不是「写错了」，而是**降权失败还继续跑**。
那种代码读起来完全正常、成功路径也确实工作，单测很容易全绿 ——
只有真的把 fail-closed 拆掉，测试才会变红。所以下面每条变异都往
「静默失败」这个方向改；抓不住就说明测试是假测试。

关于「只拆一层」
----------------
降权代码有两道**互相独立**的防线：
  ① except 里 raise SystemExit(1)
  ② 降权后复核 geteuid / getuid / getgid 是否真的变成目标身份

只拆①，②仍然独立拦住，缺陷并不重现 —— 此时测试保持绿色是**正确的**，
不是盲区。真正要验的是两道同时失效（M1），那才是真的 fail-open。
这个区别不写清楚，很容易把「变异太弱」误判成「测试没用」。

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入
时 Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。
"""
import os
import shutil
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GW = os.path.join(ROOT, 'backend', 'auth_gateway.py')
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
INIT = os.path.join(ROOT, 'backend', 'nftables-web-auth.init')
TEST = os.path.join(ROOT, 'tests', 'test_privilege_drop.py')

ORIG_GW = open(GW, encoding='utf-8').read()
ORIG_APP = open(APP_PY, encoding='utf-8').read()
ORIG_INIT = open(INIT, encoding='utf-8').read()
ORIG_SH = open(os.path.join(ROOT, 'tools', 'nginx-priv-drop.sh'), encoding='utf-8').read()


def _orig_of(path):
    return {GW: ORIG_GW, APP_PY: ORIG_APP,
            INIT: ORIG_INIT}.get(path, ORIG_SH)


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=180,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def restore():
    for path, content in ((GW, ORIG_GW), (APP_PY, ORIG_APP),
                          (INIT, ORIG_INIT),
                          (os.path.join(ROOT, 'tools', 'nginx-priv-drop.sh'), ORIG_SH)):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


_EXCEPT_OLD = '''    except (OSError, PermissionError, LookupError) as e:
        # 权限错误是 OSError 的子类，单独列出只为让日志一眼看出是权限问题
        print(f"[FATAL] 降权到 {user}({uid}:{gid}) 失败: "
              f"{type(e).__name__}: {e} —— 拒绝以 root 继续运行。", flush=True)
        raise SystemExit(1)'''

_EXCEPT_NEW = '''    except (OSError, PermissionError, LookupError) as e:
        print(f"[WARN] 降权到 {user}({uid}:{gid}) 失败: "
              f"{type(e).__name__}: {e} —— 继续以 root 运行。", flush=True)'''

_VERIFY_OLD = '    if os.geteuid() != uid or os.getuid() != uid or os.getgid() != gid:'
_VERIFY_NEW = '    if False:'

# ─────────────────────────────────────────────────────────────
# 每条：(名称, 目标文件, [(原串, 替换串), ...])
# 原串匹配不上会当场报错，不会静默跳过（那比漏网更糟）。
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('M1  两道防线同时失效：except 不退出 + 复核被跳过（真 fail-open）',
     GW, [(_EXCEPT_OLD, _EXCEPT_NEW), (_VERIFY_OLD, _VERIFY_NEW)]),

    ('M2  只拆复核：setuid 无异常但 uid 没变时不再拦',
     GW, [(_VERIFY_OLD, _VERIFY_NEW)]),

    ('M3  顺序反了：先 setuid 再 setgid',
     GW, [('''        os.initgroups(user, gid)
        os.setgid(gid)
        os.setuid(uid)''',
           '''        os.initgroups(user, gid)
        os.setuid(uid)
        os.setgid(gid)''')]),

    ('M4  去掉 initgroups（只 setuid，组权限残留 = 假降权）',
     GW, [('''        os.initgroups(user, gid)
        os.setgid(gid)''',
           '''        os.setgid(gid)''')]),

    ('M5  允许 AUTH_DROP_UID=0（等于没降权也放行）',
     GW, [('''    if uid == 0:
        print("[FATAL] AUTH_DROP_UID=0 —— 那等于没有降权。拒绝启动。", flush=True)
        raise SystemExit(1)''',
           '''    if uid == 0:
        print("[WARN] AUTH_DROP_UID=0 —— 没有降权。", flush=True)''')]),

    ('M6  缺 AUTH_DROP_USER 时不再拒绝（initgroups 会被跳过）',
     GW, [('''    if not user:
        print("[FATAL] 缺少 AUTH_DROP_USER：没有用户名就无法清 supplementary "
              "groups，这样的降权是假的。拒绝启动。", flush=True)
        raise SystemExit(1)''',
           '''    if not user:
        user = "root"''')]),

    ('M7  init 脚本不再注入 AUTH_DROP_*（降权静默失效）',
     INIT, [('        AUTH_DROP_UID="$NFTWEB_UID" AUTH_DROP_GID="$NFTWEB_GID" '
             'AUTH_DROP_USER="$NFTWEB_USER" \\\n', '')]),

    ('M8  init 去掉启动后的 uid 复核（最后一道闸被拆）',
     INIT, [('''        if [ "$real_uid" = "0" ]; then
            echo "nftables-web-auth: 进程起来了但 uid 仍是 0，降权未生效 —— 停掉它" >&2
            kill "$(cat "$PID_FILE")" 2>/dev/null
            rm -f "$PID_FILE"
            return 1
        fi''',
             '''        if [ "$real_uid" = "0" ]; then
            echo "nftables-web-auth: 警告：uid 仍是 0" >&2
        fi''')]),

    ('M9  /etc/nftables 不再 setgid（root 重建文件后网关读不到）',
     INIT, [('    chmod g+s "$_cfgdir" || return 1', '    :')]),
]


# ─────────────────────────────────────────────────────────────
# nginx worker 降权：重点是那两个「假绿灯」陷阱
#   N1  校验用回裸 nginx -t → 验的不是服务实际加载的那份配置
#   N2  只查用户不查组   → OpenWrt 缺 nobody 组时 nginx 直接拒启动
# ─────────────────────────────────────────────────────────────

NGINX_SH = os.path.join(ROOT, 'tools', 'nginx-priv-drop.sh')

MUTATIONS += [
    ('N1  校验退回裸 nginx -t（验错配置文件的假绿灯）',
     NGINX_SH, [('nginx_check() { nginx -t -c "$CONF" "$@"; }',
                 'nginx_check() { nginx -t; }')]),

    ('N2  不再检查 /etc/group 里的 worker 组（OpenWrt 缺组直接起不来）',
     NGINX_SH, [('''if ! grep -q "^${WORKER_USER}:" /etc/group; then
    echo "  /etc/group 里没有组 $WORKER_USER —— nginx 的 getgrnam() 会失败"
    echo "${WORKER_USER}:x:${WORKER_GID}:" >> /etc/group
    say "已补建组 ${WORKER_USER} (gid=${WORKER_GID})"
fi''', 'if false; then :; fi')]),

    ('N3  指令变更时改用 reload（worker 身份不会变）',
     NGINX_SH, [('''    /etc/init.d/nginx stop 2>/dev/null || true
    sleep 1
    /etc/init.d/nginx start''', '''    nginx -s reload 2>/dev/null || true
    sleep 1
    :''')]),

    ('N4  去掉 worker 数量下限（服务没起来也会报「完成」）',
     NGINX_SH, [('''if [ "$NMASTER" -eq 0 ]; then
    echo "nginx 一个进程都没有 —— 服务没起来" >&2; BAD=1
elif [ "$NWORKER" -eq 0 ]; then
    echo "没有 worker 进程" >&2; BAD=1
fi''', ':')]),

    ('N5  worker 校验放宽成「只要非 0 就算过」',
     NGINX_SH, [('''            elif [ "$U" != "$WORKER_UID" ]; then
                echo "worker pid=$p uid=$U，与期望 $WORKER_UID 不符" >&2; BAD=1
''', '')]),

    ('N6  少一处私钥补权限（下次换证书就 TLS 握手失败）',
     APP_PY, [('    os.chmod(key_path, 0o600)\n    _harden_key_for_nginx_worker(key_path)',
               '    os.chmod(key_path, 0o600)')]),

    ('N7  补权限改成会抛异常（加固反过来搞挂证书流程）',
     APP_PY, [('''    except OSError:
        return False''', '''    except OSError:
        raise''')]),

    # N8/N9 针对 P0-2 本身。旧版断言按参数名统计，这两条路径传的不是 key_path，
    # 从来没进过计数 —— 也就是说没有任何变异能打中「ACME 漏加固」这个缺陷。
    ('N8  _acme_issue 少一处补权限（acme.sh 写的 privkey worker 读不到）',
     APP_PY, [('    _harden_key_for_nginx_worker(keyfile)', '    pass')]),

    ('N9  _acme_renew 少一处补权限（续期重写 privkey 后又是 600 root）',
     APP_PY, [('    _harden_key_for_nginx_worker(os.path.join(cert_dir, "privkey.pem"))',
               '    pass')]),

    ('N10 chmod 之后紧跟的补权限被挪到 chmod 之前（顺序反了等于没加固）',
     APP_PY, [('    os.chmod(key_path, 0o600)\n    _harden_key_for_nginx_worker(key_path)',
               '    _harden_key_for_nginx_worker(key_path)\n    os.chmod(key_path, 0o600)')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-2000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, path, edits in MUTATIONS:
        src = _orig_of(path)
        bad = [old for old, _ in edits if old not in src]
        if bad:
            print(f'  ⚠️  {name}')
            print(f'      ↓ 变异锚点没匹配上（源码变了？），跳过')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
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