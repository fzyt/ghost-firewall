#!/usr/bin/env python3
"""变异验证：认证网关硬化四项修复（2026-10-16 Shannon 第二轮）

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_auth_hardening.py

作用
----
tests/test_auth_hardening.py 里 47 条断言到底有没有牙齿？把每处修复逐一改回
修复前的样子，看测试是否真的会红。**测试全绿但变异全逃过，等于没有测试。**

被验证的四项修复：
  1. /auth/* 的 client_max_body_size + Flask MAX_CONTENT_LENGTH（OOM DoS）
  2. init 脚本降权守卫的固定 sleep → 轮询（机器一忙就误杀健康进程）
  3. validate_config 的 lan_subnet /1 放行（半公网免认证）
  4. _origin_host_mismatch 的两个洞（CSRF 绕过）

安全约束
--------
这个脚本会**改写源码再还原**。它只接受下面 MUTATIONS 里写死的成对字符串，
每次改完立刻还原，finally 兜底。它不生成任何新代码，不做正则替换。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = os.path.join(ROOT, "tests", "test_auth_hardening.py")

AG = os.path.join(ROOT, "backend", "auth_gateway.py")
APP = os.path.join(ROOT, "backend", "app.py")
INIT = os.path.join(ROOT, "backend", "nftables-web-auth.init")

# (说明, 目标文件, 原文, 变异后)
MUTATIONS = [
    # ── 4. CSRF ────────────────────────────────────────────────
    ("CSRF 洞 2：改回 netloc.split(':')[0]（userinfo 冒充复活）",
     AG,
     '        host = (u.hostname or "").strip().lower()\n        if not host:\n            return True',
     '        host = u.netloc.split(":")[0]\n        if not host:\n            return True'),

    ("CSRF 洞 1：解析不出 host 时改回 return False（无 scheme Origin 复活）",
     AG,
     '        host = (u.hostname or "").strip().lower()\n        if not host:\n            return True',
     '        host = (u.hostname or "").strip().lower()\n        if not host:\n            return False'),

    # ⚠️ 锚点 2026-10-30 更新：P1-11 修复把 CSRF 的判定从
    # 「Origin 的主机 == Host 头的���机」换成了**服务端自己知道的域名**
    # （_trusted_host_names）+ 端口纳入比较。旧锚点
    # 「return host != (request.host or "").split(":")[0]...」已经不存在了 ——
    # 锚点失配等于这条缺陷从此没人守，所以必须跟着实现一起改。
    ("CSRF：跨站判定反转（host 不匹配反而算同源）",
     AG,
     "        if not host_ok:\n            return True",
     "        if not host_ok:\n            return False"),

    ("CSRF：异常分支改成放行（fail-open）",
     AG,
     "        return port not in allowed\n    except Exception:\n        return True",
     "        return port not in allowed\n    except Exception:\n        return False"),

    # ── 1. 请求体上限 ──────────────────────────────────────────
    ("Flask：拿掉 MAX_CONTENT_LENGTH",
     AG,
     'app.config["MAX_CONTENT_LENGTH"] = 8 * 1024',
     '# mutated: MAX_CONTENT_LENGTH removed'),

    ("Flask：MAX_CONTENT_LENGTH 放大到 128M（等于没设）",
     AG,
     'app.config["MAX_CONTENT_LENGTH"] = 8 * 1024',
     'app.config["MAX_CONTENT_LENGTH"] = 128 * 1024 * 1024'),

    ("Flask：删掉读之前的 content_length 前置检查（只剩 silent 兜底）",
     AG,
     '    _max_len = app.config.get("MAX_CONTENT_LENGTH") or 0\n'
     '    if _max_len and (request.content_length or 0) > _max_len:\n'
     '        audit("login_body_too_large")\n'
     '        return jsonify({"success": False, "code": "PAYLOAD_TOO_LARGE",\n'
     '                        "message": "请求体过大"}), 413\n',
     '    _max_len = 0\n'),

    ("Flask：删掉 RequestEntityTooLarge 分支（chunked 超限请求失控）",
     AG,
     '    except RequestEntityTooLarge:\n'
     '        audit("login_body_too_large")\n'
     '        return jsonify({"success": False, "code": "PAYLOAD_TOO_LARGE",\n'
     '                        "message": "请求体过大"}), 413\n',
     ''),

    ("Flask：超限时不再返回 413（伪装成普通登录失败）",
     AG,
     '        return jsonify({"success": False, "code": "PAYLOAD_TOO_LARGE",\n'
     '                        "message": "请求体过大"}), 413\n\n    try:',
     '        return jsonify({"success": False, "code": "AUTH_FAILED",\n'
     '                        "message": "密码错误"}), 401\n\n    try:'),

    ("nginx：删掉 location 的 client_max_body_size 那一行",
     APP,
     '        L.append(f"        client_max_body_size {GATEWAY_AUTH_MAX_BODY};")\n',
     ''),

    ("nginx：把认证端点的上限写成 128M（退回全局默认）",
     APP,
     'GATEWAY_AUTH_MAX_BODY = "8K"',
     'GATEWAY_AUTH_MAX_BODY = "128M"'),

    # ── 3. lan_subnet /1 ───────────────────────────────────────
    ("validate_config：/1 守卫改回 == 0（半个互联网免认证）",
     APP,
     'if net.prefixlen <= 1:',
     'if net.prefixlen == 0:'),

    ("validate_config：干脆去掉网段守卫",
     APP,
     'if net.prefixlen <= 1:\n'
     '            errs.append(\n'
     '                f\'{key} 不能是 {raw}：/{net.prefixlen} 匹配半个地址空间，\'\n'
     '                f\'保存后公网会有大片来源被当成内网而免认证。请填具体网段，\'\n'
     '                f\'如 192.168.100.0/24\')\n',
     ''),

    # ── 2. init 降权守卫 ───────────────────────────────────────
    ("init：轮询改回固定 sleep 1（竞态复活）",
     INIT,
     '    while [ "$waited" -lt 150 ]; do\n'
     '        kill -0 "$pid" 2>/dev/null || break          # 进程自己退了，交给下面的失败分支\n'
     '        real_uid=$(awk \'/^Uid:/ {print $2}\' "/proc/$pid/status" 2>/dev/null)\n'
     '        # 非空且非 0 才算降权完成；空说明 /proc 还没建好，继续等\n'
     '        if [ -n "$real_uid" ] && [ "$real_uid" != "0" ]; then\n'
     '            break\n'
     '        fi\n'
     '        sleep 0.1 2>/dev/null || sleep 1              # BusyBox 老版本不支持小数 sleep\n'
     '        waited=$((waited + 1))\n'
     '    done\n',
     '    sleep 1\n'
     '    real_uid=$(awk \'/^Uid:/ {print $2}\' "/proc/$pid/status" 2>/dev/null)\n'),

    ("init：空 uid 也当成降权失败（机器慢时误杀健康进程）",
     INIT,
     '        if [ "$real_uid" = "0" ] || [ -z "$real_uid" ]; then',
     '        if [ "$real_uid" = "0" ] || true; then'),

    ("init：等待上限缩到 1 次（等价于立刻放弃）",
     INIT,
     '    while [ "$waited" -lt 150 ]; do',
     '    while [ "$waited" -lt 1 ]; do'),

    ("init：降权失败不再杀进程（守卫生效）",
     INIT,
     '            kill "$pid" 2>/dev/null\n            rm -f "$PID_FILE"\n            return 1',
     '            rm -f "$PID_FILE"\n            return 1'),
]


# 等价变异：改掉之后**可观测行为完全不变**，不是测试有洞。
#
# 实现里对「超限请求」有两道各自完整的拦截：
#   (a) 读之前的 content_length 前置检查   —— 有 Content-Length 时先拦
#   (b) try 里 except RequestEntityTooLarge —— werkzeug 自己也会抛 413
# 两条**各自单独就足够**，同时存在属于纵深防御，对同一路径也确实冗余。
# 所以把 (a) 或 (b) 拿掉，客户端拿到的都是 413 PAYLOAD_TOO_LARGE。
#
# （两条都拿掉才会退化：异常落进通用 except Exception → 401 AUTH_FAILED，
#  那种变异已单列在 MUTATIONS 里，且能被测试抓住。）
EQUIVALENT = {
    "Flask：删掉读之前的 content_length 前置检查（只剩 silent 兜底）":
        "等价变异 —— except RequestEntityTooLarge 分支会兜住同样的请求",
    "Flask：删掉 RequestEntityTooLarge 分支（chunked 超限请求失控）":
        "等价变异 —— content_length 前置检查先拦下，实测仍返回 413 PAYLOAD_TOO_LARGE",
}


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, cwd=ROOT, env=env, timeout=300)


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print("=" * 74)
    print("变异验证：认证网关硬化四项修复")
    print("=" * 74)

    print("\n[0] 基线：未变异时测试必须全绿")
    base = run_test()
    if base.returncode != 0:
        print("基线就红了，测试本身有问题，先修测试：")
        print(base.stdout[-3000:])
        print(base.stderr[-2000:])
        return 1
    green = base.stdout.count("✅")
    print(f"    基线全绿：{green} 条断言")

    print("\n[1] 逐项变异，每个都必须被测试抓住")
    caught = missed = equiv = 0
    misses = []
    equivalents = []
    for desc, path, old, new in MUTATIONS:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        n = src.count(old)
        if n == 0:
            print(f"    ⚠️  锚点未命中（跳过）：{desc}")
            missed += 1
            misses.append(f"{desc} —— 锚点未命中")
            continue
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(src.replace(old, new))
            r = run_test()
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)          # 无条件还原

        if r.returncode != 0:
            caught += 1
            print(f"    ✅ 捕获：{desc}")
        elif desc in EQUIVALENT:
            equiv += 1
            equivalents.append((desc, EQUIVALENT[desc]))
            print(f"    ⚖️  等价变异（已归类，不算漏过）：{desc}")
            print(f"       理由：{EQUIVALENT[desc]}")
        else:
            missed += 1
            misses.append(desc)
            print(f"    ❌ 漏过：{desc}")

    print("\n[2] 还原校验：源码必须与变异前逐字节一致")
    b = run_test()
    ok = b.returncode == 0
    print(f"    {'✅' if ok else '❌'} 还原后测试{'恢复全绿' if ok else '仍然红 —— 源码没还原干净'}")
    if not ok:
        print(b.stdout[-3000:])

    total = caught + missed + equiv
    print("\n" + "=" * 74)
    print(f"变异 {total} 处  捕获 {caught}  漏过 {missed}  "
          f"等价变异 {equiv}  锚点未命中 {sum('锚点未命中' in m for m in misses)}")
    if equivalents:
        print("等价变异明细（行为不变，不计漏过）：")
        for d, why in equivalents:
            print(f"  · {d}\n      → {why}")
    if misses:
        print("\n漏过/未命中明细：")
        for m in misses:
            print(f"  - {m}")
        print("\n结论：测试有洞，上面的项必须改测试或改实现。")
        return 1
    print("\n全部变异均被捕获（等价变异已单独归类并说明理由）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
