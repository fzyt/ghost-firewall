"""变异检查：把本批次的修复逐条改回原样，测试必须变红。

运行:  python3 tests/mutation_check_gateway_auth_fixes.py

─── 保险丝（刻意**不用** tests/_mutation_guard.py）────────────────────────
并行批次也在跑变异脚本，而 MutationGuard 启动时会做「上次被硬杀的残留快照」
清理 —— 它会把**整个快照里的所有文件**从快照写回去，包括别的批次正在改的
文件（backend/app.py）。本次就差点被冲掉，所以这里只做**单文件**备份还原：

  · 启动时把 backend/auth_gateway.py 原文读进内存（ORIG）
  · 每条变异前写变异版 → 跑测试 → **无条件**写回 ORIG
  · atexit + SIGTERM/SIGINT 兜底：被打断也一定还原

只碰 backend/auth_gateway.py 这一个文件：不扫描 /tmp/mutguard-*，
不还原任何快照目录，不动别的仓库文件。

─── 变异锚点 ───────────────────────────────────────────────────────────
用**成对的精确字符串**（旧串 → 新串），旧串必须在源码里**唯一**。
锚点失配（找不到 / 找到多处）一律**报错并跳过**，不静默跳过 ——
一个「因为锚点没匹配上所以没测」的变异等于没测。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "backend", "auth_gateway.py")
TEST = os.path.join(ROOT, "tests", "test_gateway_auth_fixes.py")
PY = "/tmp/nftvenv/bin/python3" if os.path.exists("/tmp/nftvenv/bin/python3") else sys.executable

with open(TARGET, "r", encoding="utf-8") as f:
    ORIG = f.read()

_state = {"restored": True}


def _restore():
    if _state["restored"]:
        return
    try:
        with open(TARGET, "w", encoding="utf-8") as f:
            f.write(ORIG)
        _state["restored"] = True
        print("    ↩ 已还原 backend/auth_gateway.py")
    except OSError as e:
        print(f"    ✗ 还原失败：{e}")


def _write_src(text):
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(text)
    _state["restored"] = False


def _on_signal(signum, _frame):
    _restore()
    sys.exit(1)


atexit.register(_restore)
signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT, _on_signal)


def run_tests():
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PATH"] = os.path.dirname(PY) + os.pathsep + env.get("PATH", "")
    p = subprocess.run([PY, TEST], env=env, cwd=ROOT,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, timeout=900)
    return p.returncode, p.stdout or ""


# (编号, 说明, 旧串, 新串)
MUTATIONS = [
    ("P1-1", "重新登录要吊销 Bearer 客户端的旧令牌",
     "    _old = parse_token(_extract_token())",
     '    _old = parse_token(request.cookies.get(COOKIE_TOKEN, ""))'),

    ("P1-3", "吊销表写盘后立刻刷新 last-known-good",
     "    _REVOKED_LKG = dict(data)",
     "    pass  # 变异：写后不刷新 LKG"),

    ("P1-5", "/auth/portal 要执行绝对 TTL",
     "    # 绝对上限：签发时间起算，超时强制重登（与 _verify_or_deny 同一判据）\n"
     "    abs_to = _absolute_ttl(cfg)\n"
     "    if abs_to:\n"
     "        now = int(time.time())\n"
     "        if now - int(payload.get(\"iat\", now)) > abs_to:\n"
     "            return False\n"
     "    return True",
     "    # 变异：/auth/portal 不查绝对 TTL\n"
     "    return True"),

    ("P1-6", "续期后旧令牌必须作废（吊销表写不进去时也要）",
     '        _mark_superseded(payload.get("jti", ""), exp)',
     "        pass  # 变异：旧 jti 不进进程内作废名单"),

    ("P1-7", "降权前把审计日志属主改成 root:网关gid",
     "        if os.geteuid() == 0 and gid > 0:",
     "        if False and gid > 0:  # 变异：不做属主/权限摆正"),

    ("P1-8", "审计日志权限 0640（轮转后不退化成 0644）",
     "AUDIT_LOG_MODE = 0o640",
     "AUDIT_LOG_MODE = 0o644  # 变异：world-readable"),

    ("P1-11", "CSRF origin 锚点：按服务端自己知道的域名",
     "        trusted = _trusted_host_names(cfg)",
     "        trusted = set()  # 变异：退回和客户端可控的 Host 头比较"),

    ("P1-11", "CSRF origin 锚点：端口纳入比较",
     "        return port not in allowed",
     "        return False  # 变异：不比端口"),

    ("P1-12", "绑环回断言要看真实监听套接字",
     "    if not ip.is_loopback:",
     "    if False:  # 变异：不查真实套接字"),

    ("P1-13", "门户页也要发 HSTS",
     '    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")',
     "    pass  # 变异：不发 HSTS"),

    ("P1-14", "令牌 cookie 的 Max-Age 以令牌 exp 为准",
     "    return max(0, exp - int(time.time()))",
     "    return ttl  # 变异：用会话 TTL 当 cookie 寿命"),

    ("P1-15", "lan_subnet4 配成 /1 也不能当内网",
     "        if net.prefixlen <= 1:",
     "        if net.prefixlen == 0:  # 变异：漏掉 /1"),

    ("P1-16", "回环不再隐式当可信 LAN",
     '    if addr.is_loopback:\n        return bool(cfg.get("auth_lan_bypass_loopback", False))',
     '    if addr.is_loopback:\n        return True  # 变异：回环一律当内网'),

    ("P2-1", "限流表要有 IP 数量上限",
     "                if len(data) > RATELIMIT_MAX_IPS:",
     "                if False:  # 变异：不限流表容量"),

    ("P2-2", "成功登录要把内存兜底表的键删掉",
     "        _RATE_FALLBACK.pop(ip, None)",
     "        _RATE_FALLBACK[ip] = {}  # 变异：只置空、键还在"),

    ("P2-3", "吊销表要有容量上限",
     "                if len(data) > REVOKED_MAX_ENTRIES:",
     "                if False:  # 变异：不限吊销表容量"),

    ("P1-45", "审计写入要限流",
     "        if event in _AUDIT_FLOODABLE and event not in _AUDIT_ALWAYS:",
     "        if False:  # 变异：审计写入不限流"),
]


def main():
    print("=== 变异检查：把修复改回原样，测试必须变红 ===\n")
    print(f"目标文件: {TARGET}")
    print(f"测试文件: {TEST}\n")

    rc, out = run_tests()
    if rc != 0:
        print("❌ 基线不绿（未变异时测试就失败）—— 先修测试，别做变异：")
        print(out[-4000:])
        return 2
    print("✅ 基线绿：未变异时全部通过\n")

    caught, missed, skipped = [], [], []
    for tag, desc, old, new in MUTATIONS:
        n = ORIG.count(old)
        if n != 1:
            print(f"⚠️  锚点失配（命中 {n} 处，必须恰好 1 处）—— 跳过：{tag} {desc}")
            skipped.append((tag, desc, f"锚点命中 {n} 处"))
            continue
        mutated = ORIG.replace(old, new, 1)
        if mutated == ORIG:
            print(f"⚠️  变异无效（替换后源码没变）—— 跳过：{tag} {desc}")
            skipped.append((tag, desc, "替换后源码没变"))
            continue
        try:
            _write_src(mutated)
            rc, out = run_tests()
        finally:
            _restore()
        if rc != 0:
            caught.append((tag, desc))
            print(f"✅ 被捕获  {tag}  {desc}")
        else:
            missed.append((tag, desc))
            print(f"❌ 没抓到  {tag}  {desc}   ← 测试仍然是绿的，这条变异没被覆盖")
            tail = [ln for ln in out.splitlines() if "❌" in ln]
            for ln in tail[:8]:
                print(f"      {ln.strip()}")

    # 收尾：确认源码回到原样
    _restore()
    with open(TARGET, "r", encoding="utf-8") as f:
        now = f.read()
    same = hashlib.sha256(now.encode()).hexdigest() == hashlib.sha256(ORIG.encode()).hexdigest()
    print(f"\n{'=' * 60}")
    print(f"  变异总数 : {len(MUTATIONS)}")
    print(f"  捕获     : {len(caught)}")
    print(f"  未捕获   : {len(missed)}")
    print(f"  跳过     : {len(skipped)}")
    print(f"  源码已还原: {'是' if same else '否 —— 手动检查！'}")
    if missed:
        print("\n  未捕获的变异：")
        for tag, desc in missed:
            print(f"    - {tag} {desc}")
    if skipped:
        print("\n  跳过的变异：")
        for tag, desc, why in skipped:
            print(f"    - {tag} {desc}（{why}）")
    if missed or skipped or not same:
        return 1
    print("  全部捕获")
    return 0


if __name__ == "__main__":
    sys.exit(main())
