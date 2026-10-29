#!/usr/bin/env python3
"""变异验证：认证侧两个边界（会话绝对上限 / 审计日志体积）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_auth_bounds.py

作用
----
tests/test_auth_policy_bounds.py 的断言到底有没有牙齿？把每处修复逐一改回
修复前的样子，看测试是否真的会红。**测试全绿但变异全逃过，等于没有测试。**

被验证的两项（Shannon 第二轮剩下的两条 P2）：
  AUTH-VULN-03  绝对上限的默认值与执行点
  AUTH-VULN-05  审计日志体积上限与轮转

安全约束
--------
本脚本会**改写源码再还原**。只接受下面 MUTATIONS 里写死的成对字符串，
每次改完立刻还原，finally 兜底。不生成新代码，不做正则替换。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = os.path.join(ROOT, "tests", "test_auth_policy_bounds.py")
AG = os.path.join(ROOT, "backend", "auth_gateway.py")
APP = os.path.join(ROOT, "backend", "app.py")

MUTATIONS = [
    # ── AUTH-VULN-03 绝对上限 ───────────────────────────────────────
    ("默认值退回 0（出厂即不启用，滑动续期可永不过期）",
     AG,
     'TOKEN_ABS_TTL_DEFAULT = 43200',
     'TOKEN_ABS_TTL_DEFAULT = 0'),

    ("执行点退回「取不到就关闭」（存量 0 直接关掉绝对上限）",
     AG,
     '    ttl = _int(cfg.get("auth_absolute_timeout"), TOKEN_ABS_TTL_DEFAULT)\n'
     '    return ttl if 0 < ttl <= 604800 else TOKEN_ABS_TTL_DEFAULT',
     '    ttl = _int(cfg.get("auth_absolute_timeout"), TOKEN_ABS_TTL_DEFAULT)\n'
     '    return ttl if 0 < ttl <= 604800 else 0'),

    ("面板默认值退回 0",
     APP,
     '    "auth_absolute_timeout": 43200,',
     '    "auth_absolute_timeout": 0,'),

    ("迁移不再执行（存量配置里的 0 原地保留）",
     APP,
     "    if config.get('auth_absolute_timeout') != 0:\n"
     "        return config",
     "    if True:\n"
     "        return config"),

    ("迁移把已经配好的正数也覆盖掉",
     APP,
     "    if config.get('auth_absolute_timeout') != 0:\n"
     "        return config",
     "    if config.get('auth_absolute_timeout') is None:\n"
     "        return config"),

    ("迁移从 load_config 里被摘掉（helper 还在，永远没人调）",
     APP,
     "        result = _migrate_auth_absolute_timeout(result)\n",
     ""),

    ("启动时的落盘迁移被摘掉（内存改了，网关读盘仍看到 0）",
     APP,
     "            save_config(load_config())\n"
     "            print('[MIGRATE] auth_absolute_timeout 新默认值已落盘', flush=True)",
     "            pass"),

    # ── AUTH-VULN-05 审计日志体积 ───────────────────────────────────
    ("审计日志不再轮转（回到无上限）",
     AG,
     "        _audit_maybe_rotate(AUDIT_LOG, len(line.encode(\"utf-8\")))\n",
     ""),

    ("轮转判据退回「只看当前大小」（会溢出整整一行，上限不再是硬边界）",
     AG,
     "        if os.path.getsize(path) + incoming <= AUDIT_LOG_MAX_BYTES:",
     "        if os.path.getsize(path) < AUDIT_LOG_MAX_BYTES:"),

    ("轮转失败时不再就地截断（文件继续无限长吃 RAM）",
     AG,
     "        # 轮转不成（目录只读、跨设备等）就地截断：宁可丢历史，\n"
     "        # 也不能让文件继续无限长把 RAM 吃光。\n"
     "        try:\n"
     "            open(path, \"w\").close()\n"
     "        except OSError:\n"
     "            pass",
     "        pass"),

    ("轮转用 rename 代替 replace（.1 可能残留旧内容，总占用翻倍）",
     AG,
     "        os.replace(path, path + \".1\")",
     "        os.rename(path, path + \".1\")"),

    # ── 限流表不可用时不得把登录搞挂（.224 实测的真 bug）────────────
    #
    # 这组是「一张表被删 = 所有人永久登不进」的自伤式拒绝服务。
    # /etc/nftables 是 drwxr-sr-x root:nftweb（组只有 r-x），
    # 网关降权后以 uid 1000 根本建不出这张表 —— 移走它之后没有任何自愈路径。

    ("限流表：打不开时直接抛（回到 .224 实测的 500 登录失败）",
     AG,
     "    except Exception as e:  # noqa: BLE001\n"
     "        _ratelimit_degrade(e)\n"
     "        return _ratelimit_fallback_mutate(ip, on_fail)\n"
     "    try:\n"
     "        with os.fdopen(fd, \"r+\") as f:",
     "    try:\n"
     "        with os.fdopen(fd, \"r+\") as f:"),

    # 下面三条锚点指向 `_ratelimit_fallback_mutate` / `_is_locked`。
    # 2026-10-29：这两处被 Shannon P0-5 修复改写过（锁定时不再清空 fails、
    # 降级路径返回真实 locked 标志、读端补 flock(LOCK_SH)），旧锚点
    # 匹配不上 → 「锚点未命中（跳过）」。跳过 = 这三条变异**根本没跑过**，
    # 等于静默失去覆盖。锚点必须跟着源码一起更新。
    #
    # 锚点刻意避开注释块：注释里引用了修复前的代码原文，
    # 拿它当锚点会在下次改注释时再次失效。

    ("限流表：降级后放行但不计数（暴力破解防护被悄悄关掉）",
     AG,
     "        fails.append(now)\n"
     "        if len(fails) >= RATE_LIMIT_MAX_FAILS:\n",
     "        # 变异：降级后放行但不计数\n"
     "        if len(fails) >= RATE_LIMIT_MAX_FAILS:\n"),

    ("限流表：降级后永不上锁",
     AG,
     "            rec = {\"locked_until\": now + RATE_LIMIT_LOCKOUT, \"fails\": fails}\n",
     "            rec = {\"locked_until\": 0, \"fails\": fails}\n"),

    ("限流表：降级时不置告警标志（线上无从判断限流已失效）",
     AG,
     "    if not _RATELIMIT_DEGRADED[\"warned\"]:\n"
     "        _RATELIMIT_DEGRADED[\"warned\"] = True",
     "    if False:\n"
     "        _RATELIMIT_DEGRADED[\"warned\"] = True"),

    ("限流表：上锁判定退回只读文件（降级期间暴力破解防护被悄悄关掉）",
     AG,
     "    return _ratelimit_fallback_is_locked(ip)\n"
     "\n"
     "\n"
     "def _origin_host_mismatch",
     "    return False\n"
     "\n"
     "\n"
     "def _origin_host_mismatch"),
]

# 等价变异：行为不变，不计漏过。
EQUIVALENT = {
    "轮转用 rename 代替 replace（.1 可能残留旧内容，总占用翻倍）":
        "真等价 —— POSIX 的 rename(2) 对已存在的目标本身就是原子替换，"
        "语义与 replace 一致。replace 的优势只在 Windows 上存在，而目标平台"
        "是 OpenWrt/Linux。这条当初是按「replace 才原子」的印象写的，印象是错的。",
}


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, cwd=ROOT, env=env, timeout=600)


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print("=" * 74)
    print("变异验证：认证边界两项（绝对上限 / 审计日志体积）")
    print("=" * 74)

    print("\n[0] 基线：未变异时测试必须全绿")
    base = run_test()
    if base.returncode != 0:
        print("基线就红了，测试本身有问题，先修测试：")
        print(base.stdout[-3000:])
        print(base.stderr[-2000:])
        return 1
    print(f"    基线全绿：{base.stdout.count('✅')} 条断言")

    print("\n[1] 逐项变异，每个都必须被测试抓住")
    caught = missed = equiv = 0
    misses, equivalents = [], []
    for desc, path, old, new in MUTATIONS:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if src.count(old) == 0:
            print(f"    ⚠️  锚点未命中（跳过）：{desc}")
            missed += 1
            misses.append(f"{desc} —— 锚点未命中")
            continue
        if src.count(old) > 1:
            print(f"    ⚠️  锚点不唯一（{src.count(old)} 处）：{desc} —— 需要更精确的锚点")
            missed += 1
            misses.append(f"{desc} —— 锚点不唯一")
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(src.replace(old, new))
        try:
            r = run_test()
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)

        if desc in EQUIVALENT:
            equiv += 1
            equivalents.append(f"{desc} —— {EQUIVALENT[desc]}")
            if r.returncode != 0:
                print(f"    ⚠️  {desc} 被判为等价，却让测试变红了；"
                      f"说明判定过时")
            continue
        if r.returncode != 0:
            caught += 1
            import re
            fails = re.findall(r"^\s+- (.+)$", r.stdout, re.M)
            print(f"    ✅ 被捕获  {desc}")
            if fails:
                print(f"        失败断言: {' | '.join(fails[:3])}")
        else:
            missed += 1
            misses.append(desc)
            print(f"    ❌ 漏网    {desc}")

    print("\n[2] 还原校验：源码必须与变异前逐字节一致")
    import hashlib
    for p in (AG, APP):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]
        print(f"    {os.path.relpath(p, ROOT)}  sha256={h}")
    final = run_test()
    if final.returncode != 0:
        print("    ❌ 还原后测试仍不绿，源码可能没还原干净")
        return 1
    print("    ✅ 还原后测试恢复全绿")

    total = len(MUTATIONS) - len(EQUIVALENT)
    print("\n" + "=" * 74)
    print(f"变异 {len(MUTATIONS)} 处  捕获 {caught}  漏过 {missed} "
          f"等价变异 {equiv}  （应捕获 {total}）")
    if equivalents:
        print("等价变异明细（行为不变，不计漏过）：")
        for e in equivalents:
            print(f"  - {e}")
    if missed:
        print("漏过的变异 → 对应测试无效：")
        for m in misses:
            print(f"  - {m}")
        return 1
    print("\n全部变异均被捕获（等价变异已单独归类并说明理由）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
