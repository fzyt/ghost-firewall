#!/usr/bin/env python3
"""变异验证：Shannon 渗透测试 P0 修复（v0.8.7）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_p0_fixes.py

作用
----
tests/test_p0_security_fixes.py 与 tests/test_linux_gateway_preamble.py 的
断言到底有没有牙齿？把每处 P0 修复逐一改回**修复前的样子**，看测试是否
真的会红。

**测试全绿但变异全逃过，等于没有测试。**

2026-10-29 第一轮全量回归的价值就在这里：它没有停在「跑过了」，
而是抓出了 4 处「测试写死了修复前的契约 / 根本没有断言拦着」——
  · test_auth_gateway.py 的 11.3 断言的还是「续期发生在 /auth/verify」
  · test_gateway_entry_guard.py 一刀切断言「只读键一律不落盘」
  · mutation_check_auth_bounds.py 的 3 条锚点匹配不上 ⇒ 那 3 条变异
    **根本没跑过**（跳过 ≠ 通过）
  · mutation_check_privilege.py 的 M13 没有任何断言拦它 ⇒ 漏网

覆盖
----
  P0-4   auth_token_epoch 不能经通用 POST /api/config 落盘
  P0-5   触发锁定的那次登录返 429 且 remaining=0；读端持共享锁
  P0-6   PBKDF2 dummy 路径不慢于真实路径（计时 oracle）
  P0-7   共享配置不能是 world-readable
  P0-8   linux_gateway 前导块：先建表再 flush / 只 delete 自己的两条链
  P0-9   DDNS ipv6_source 白名单；预校验必须在删除现有 service 之前
  P0-10  crontab -l 失败必须 fail-closed
  P0-11  反代 test 端点：错误归一化 + 时间归一化 + 记审计

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
APP = os.path.join(ROOT, "backend", "app.py")
AG = os.path.join(ROOT, "backend", "auth_gateway.py")
TE = os.path.join(ROOT, "backend", "template_engine.py")

# 每个测试文件对应一批变异。变异只要让其中**任意一个**测试文件变红，
# 就算被抓住。
TESTS = [
    os.path.join(ROOT, "tests", "test_p0_security_fixes.py"),
    os.path.join(ROOT, "tests", "test_linux_gateway_preamble.py"),
]

MUTATIONS = [
    # ══════════════════════════════════════════════════════════════════
    # P0-4  auth_token_epoch 不能经通用 POST /api/config 落盘
    # ══════════════════════════════════════════════════════════════════
    ("P0-4  auth_token_epoch 从只读名单里被摘掉（通用路径能改世代号）",
     APP,
     "    'auth_token_epoch',\n",
     "    # 变异：auth_token_epoch 不再是只读\n"),

    ("P0-4  /api/config 不再剔除只读键（世代号能被通用路径改）",
     APP,
     "    readonly_hits = sorted(k for k in incoming if k in READONLY_CONFIG_KEYS)\n"
     "    for k in READONLY_CONFIG_KEYS:\n"
     "        incoming.pop(k, None)\n",
     "    readonly_hits = sorted(k for k in incoming if k in READONLY_CONFIG_KEYS)\n"
     "    # 变异：不再剔除\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-5  触发锁定的那次登录必须返 429 且 remaining=0
    # ══════════════════════════════════════════════════════════════════
    ("P0-5  锁定时清空 fails（remaining 被算成 5，且返 401 而不是 429）",
     AG,
     "                    if len(fails) >= RATE_LIMIT_MAX_FAILS:\n"
     "                        rec[\"locked_until\"] = now + RATE_LIMIT_LOCKOUT\n",
     "                    if len(fails) >= RATE_LIMIT_MAX_FAILS:\n"
     "                        rec[\"locked_until\"] = now + RATE_LIMIT_LOCKOUT\n"
     "                        rec[\"fails\"] = []\n"),

    ("P0-5  降级路径同样清空 fails",
     AG,
     "            rec = {\"locked_until\": now + RATE_LIMIT_LOCKOUT, \"fails\": fails}\n",
     "            rec = {\"locked_until\": now + RATE_LIMIT_LOCKOUT, \"fails\": []}\n"),

    ("P0-5  auth_login 不认 locked 标志（触发锁定那次返 401 而不是 429）",
     AG,
     "        locked, fails = _mutate_ratelimit(ip, on_fail=True)\n",
     "        locked, fails = False, _mutate_ratelimit(ip, on_fail=True)[1]\n"),

    ("P0-5  限流表读端不拿共享锁（可能读到半截 JSON → 当作未锁定放行）",
     AG,
     "            fcntl.flock(f, fcntl.LOCK_SH)\n",
     "            # 变异：读端不拿共享锁\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-6  PBKDF2 dummy 路径必须不慢于真实路径
    # ══════════════════════════════════════════════════════════════════
    ("P0-6  dummy 路径退回用最小迭代数（94.9ms vs 48.6ms 的计时 oracle 回来）",
     AG,
     "            dummy_iters = max(iters, PBKDF2_ITERATIONS_MIN, PBKDF2_ITERATIONS_DUMMY)\n",
     "            dummy_iters = PBKDF2_ITERATIONS_MIN\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-7  共享配置不能是 world-readable
    # ══════════════════════════════════════════════════════════════════
    ("P0-7  共享配置权限退回 0644（本地任意账号可读第三方服务商凭据）",
     APP,
     "_CONFIG_FILE_MODE = 0o640\n",
     "_CONFIG_FILE_MODE = 0o644\n"),

    # ⚠️ 2026-10-30 改造过 —— 原写法变成了**等价变异**。
    #
    # 原变异是「save_config 不再 chmod」。但配置 tmp 现在**落盘那一刻**
    # 就是 0640（`save_config` 里的 `_ensure_file_mode`）⇒ 那次 chmod
    # 变成**冗余**，去掉它权限也不变 ⇒ 测不到东西（全量回归实测漏网）。
    #
    # 改成**双重退化**：预建和事后 chmod 一起去掉 ⇒ 真的写出 umask 默认的 0644。
    # 这才是这条变异要测的退化方向。
    ("P0-7  save_config 既不预建权限也不 chmod（写出来就是 umask 默认的 0644）",
     APP,
     "            _ensure_file_mode(tmp_path, _CONFIG_FILE_MODE)\n"
     "            with open(tmp_path, 'w') as f:\n"
     "                json.dump(config, f, indent=2, ensure_ascii=False)\n"
     "                f.flush()\n"
     "                os.fsync(f.fileno())\n"
     "            os.chmod(tmp_path, _CONFIG_FILE_MODE)\n"
     "            os.replace(tmp_path, CONFIG_PATH)\n",
     "            with open(tmp_path, 'w') as f:\n"
     "                json.dump(config, f, indent=2, ensure_ascii=False)\n"
     "                f.flush()\n"
     "                os.fsync(f.fileno())\n"
     "            os.replace(tmp_path, CONFIG_PATH)\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-8  linux_gateway 前导块（规则集残留 / 首次部署失败）
    # ══════════════════════════════════════════════════════════════════
    ("P0-8  前导块不再先建空表（首次部署整个规则集加载失败）",
     TE,
     '            "table inet fw4 { }\\n"\n',
     ""),

    ("P0-8  前导块不再 flush table inet fw4（fw4 里的旧规则永久残留）",
     TE,
     '            "flush table inet fw4\\n"\n',
     ""),

    ("P0-8  前导块不再 delete prerouting 链（已撤销的转发规则继续生效）",
     TE,
     '            "delete chain ip nat prerouting\\n"\n',
     ""),

    ("P0-8  前导块不再 delete postrouting 链（masquerade 每 apply 叠加一份）",
     TE,
     '            "delete chain ip nat postrouting"',
     ""),

    ("P0-8  前导块改用 flush table ip nat（会清掉宿主机 Docker 的规则）",
     TE,
     '            "delete chain ip nat prerouting\\n"\n'
     '            "delete chain ip nat postrouting"',
     '            "flush table ip nat"'),

    ("P0-8  delete 挪到建链脚手架之前（nft 按文件顺序求值 → 报错）",
     TE,
     '            "table ip nat {\\n"\n'
     '            "    chain prerouting {\\n"\n'
     '            "        type nat hook prerouting priority dstnat;\\n"\n'
     '            "    }\\n"\n'
     '            "    chain postrouting {\\n"\n'
     '            "        type nat hook postrouting priority srcnat;\\n"\n'
     '            "    }\\n"\n'
     '            "}\\n"\n'
     '            "delete chain ip nat prerouting\\n"\n'
     '            "delete chain ip nat postrouting"',
     '            "delete chain ip nat prerouting\\n"\n'
     '            "delete chain ip nat postrouting\\n"\n'
     '            "table ip nat {\\n"\n'
     '            "    chain prerouting {\\n"\n'
     '            "        type nat hook prerouting priority dstnat;\\n"\n'
     '            "    }\\n"\n'
     '            "    chain postrouting {\\n"\n'
     '            "        type nat hook postrouting priority srcnat;\\n"\n'
     '            "    }\\n"\n'
     '            "}"'),

    ("P0-8  前导块里 prerouting 的 hook 与模板不一致（两处不同步）",
     TE,
     '            "        type nat hook prerouting priority dstnat;\\n"\n',
     '            "        type nat hook prerouting priority srcnat;\\n"\n'),

    # ══════════════════════════════════════════════════════════════════
    # P0-9  DDNS ipv6_source 白名单（路径穿越 + 命令注入）
    # ══════════════════════════════════════════════════════════════════
    ("P0-9  ipv6_source 白名单失效（../../etc/hostname、x;id 都能过）",
     APP,
     "        if _src and _src != 'router' and not _re.fullmatch(r'rule_\\d+', _src):\n",
     "        if False:\n"),

    ("P0-9  idx 改回裸 replace 拼接（路径穿越 + 命令注入回来）",
     APP,
     "                        idx = _m.group(1)\n",
     "                        idx = _src.replace('rule_', '')\n"),

    ("P0-9  预校验挪到「删除现有 service」之后（非法值留下半成品配置）",
     APP,
     "        ok, msg = _validate_ddns_services(services)\n"
     "        if not ok:\n"
     "            return jsonify({\"success\": False, \"message\": msg}), 400\n"
     "        # 1. 先获取现有的 service 名称和密码缓存\n"
     "        existing = _parse_ddns_config()\n",
     "        # 1. 先获取现有的 service 名称和密码缓存\n"
     "        existing = _parse_ddns_config()\n"
     "        ok, msg = _validate_ddns_services(services)\n"
     "        if not ok:\n"
     "            return jsonify({\"success\": False, \"message\": msg}), 400\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-10  crontab -l 失败必须 fail-closed
    # ══════════════════════════════════════════════════════════════════
    ("P0-10 _upsert_cron_for 读到 crontab 失败时继续往下走（覆盖整个 crontab）",
     APP,
     "        if result.returncode != 0:\n"
     "            return False, (f\"读取 crontab 失败，已中止（未做任何修改）: \"\n",
     "        if False:\n"
     "            return False, (f\"读取 crontab 失败，已中止（未做任何修改）: \"\n"),

    ("P0-10 install_china_ips 读到 crontab 失败时不中止（覆盖整个 crontab）",
     APP,
     "        if result.returncode != 0:\n"
     "            return jsonify({\"success\": False,\n"
     "                            \"message\": f\"crontab 读取失败，已中止（未做任何修改）: \"\n",
     "        if False:\n"
     "            return jsonify({\"success\": False,\n"
     "                            \"message\": f\"crontab 读取失败，已中止（未做任何修改）: \"\n"),

    # ══════════════════════════════════════════════════════════════════
    # P0-11  反代 test 端点的内网端口扫描 oracle
    # ══════════════════════════════════════════════════════════════════
    ("P0-11 回显原始异常文本（refused / 超时 / DNS 失败三者可区分）",
     APP,
     "        message = \"连接失败：目标不可达\"\n",
     "        message = f\"连接失败: {str(e)}\"\n"),

    ("P0-11 不可达时不再等满最小时间（时间侧信道回来）",
     APP,
     "        _wait = _RP_TEST_MIN_WAIT_MS - elapsed_ms\n"
     "        if _wait > 0:\n"
     "            time.sleep(_wait / 1000.0)\n",
     "        _wait = 0\n"),

    ("P0-11 不可达时 ssl_valid 也报 true（仍可区分状态）",
     APP,
     "        \"ssl_valid\": reachable,\n",
     "        \"ssl_valid\": True,\n"),

    ("P0-11 反代 test 不记审计（口令泄露后扫内网无痕）",
     APP,
     "    print(f'[AUDIT] rp_test_rule rule={rule_id} target={host}:{port} '\n",
     "    # 变异：不记审计\n"),
]


def run_tests():
    """跑全部测试文件。返回 (是否有文件失败, 合并输出)。"""
    failed = False
    chunks = []
    for t in TESTS:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, t], capture_output=True,
                           text=True, cwd=ROOT, env=env, timeout=600)
        chunks.append(f"── {os.path.basename(t)} ──\n{r.stdout}{r.stderr}")
        if r.returncode != 0:
            failed = True
    return failed, "\n".join(chunks)


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print("=" * 74)
    print("变异验证：Shannon 渗透测试 P0 修复（v0.8.7）")
    print("=" * 74)

    print("\n[0] 基线：未变异时测试必须全绿")
    failed, out = run_tests()
    if failed:
        print("基线就红了，测试本身有问题，先修测试：")
        print(out[-4000:])
        return 1
    print("    基线全绿")

    print("\n[1] 逐项变异，每个都必须被测试抓住")
    caught = missed = 0
    misses = []
    for desc, path, old, new in MUTATIONS:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if src.count(old) == 0:
            print(f"    ⚠️  锚点未命中（跳过）：{desc}")
            missed += 1
            misses.append(f"{desc} —— 锚点未命中（这条变异根本没跑过）")
            continue
        if src.count(old) > 1:
            print(f"    ⚠️  锚点不唯一（{src.count(old)} 处）：{desc}")
            missed += 1
            misses.append(f"{desc} —— 锚点不唯一")
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(src.replace(old, new))
        try:
            failed, out = run_tests()
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(src)

        if not failed:
            missed += 1
            misses.append(desc)
            print(f"    ❌ 漏网    {desc}")
            continue
        # 测试「变红」和测试「崩了」是两回事：
        # 只有断言真的红（输出里有 ❌）才算被抓住。崩了说明这条变异
        # 把代码改到连跑都跑不起来 —— 那种红是假的，不能算数。
        if "❌" not in out:
            missed += 1
            misses.append(f"{desc} —— 测试崩了而不是变红（没有断言覆盖它）")
            print(f"    ❌ 崩了    {desc}（测试没红，只是跑不起来）")
            continue
        caught += 1
        import re
        fails = re.findall(r"^\s*(?:❌\s*)?-?\s*(.+?)\s*(?:—.*)?$",
                           "\n".join(l for l in out.splitlines() if "❌" in l),
                           re.M)
        print(f"    ✅ 被捕获  {desc}")
        if fails:
            print(f"        失败断言: {' | '.join(fails[:3])}")

    print("\n[2] 还原校验：源码必须与变异前逐字节一致")
    import hashlib
    for p in (APP, AG, TE):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]
        print(f"    {os.path.relpath(p, ROOT)}  sha256={h}")
    failed, out = run_tests()
    if failed:
        print("    ❌ 还原后测试仍不绿，源码可能没还原干净")
        return 1
    print("    ✅ 还原后测试恢复全绿")

    print("\n" + "=" * 74)
    print(f"变异 {len(MUTATIONS)} 处  捕获 {caught}  漏过 {missed}  （应捕获 {len(MUTATIONS)}）")
    if misses:
        print("漏过的变异 → 对应测试无效：")
        for m in misses:
            print(f"  - {m}")
        return 1
    print("\n全部变异均被捕获")
    return 0


if __name__ == "__main__":
    sys.exit(main())
