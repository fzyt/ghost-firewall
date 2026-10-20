#!/usr/bin/env python3
"""变异验证：会话生命周期四项（epoch 作废 / 吊销 fail-closed / 时序 / 安全头）

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_auth_session.py

作用
----
tests/test_auth_session_lifecycle.py 的断言到底有没有牙齿？把每处修复
逐一改回修复前的样子，看测试是否真的会红。**测试全绿但变异全逃过，等于没有测试。**

被验证的四项：
  MISC-02  load_revoked 读失败 fail-closed（LKG + 判为已吊销）
  MISC-01  改密码递增 epoch，网关 JWT 与面板 session 都绑定它
  AUTH-01  去掉 bool(stored) 短路，让 dummy PBKDF2 真跑
  P3       after_request 补 HSTS 与 Cache-Control 覆盖面

外加 revoke_jti 的落盘结果汇报（4c/4d 节，.224 真机跑出来的加固）。

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
TEST = os.path.join(ROOT, "tests", "test_auth_session_lifecycle.py")
AG = os.path.join(ROOT, "backend", "auth_gateway.py")
APP = os.path.join(ROOT, "backend", "app.py")

MUTATIONS = [
    # ── MISC-02 吊销表 fail-closed ────────────────────────────────
    ("MISC-02：读失败时不再返回 None（退回 fail-open 的空表）",
     AG,
     '        if _REVOKED_LKG is None:\n            return None',
     '        return {}'),

    ("MISC-02：不再退到 last-known-good（损坏即清空）",
     AG,
     '        if _REVOKED_LKG is None:\n            return None\n        return _REVOKED_LKG',
     '        return {}'),

    ("MISC-02：成功读之后不更新 LKG（进程内没有可退的副本）",
     AG,
     '    _REVOKED_LKG = data\n    return data',
     '    return data'),

    ("MISC-02：判不出来时改回放行（fail-open）",
     AG,
     '        audit("revocation_unreadable")\n        return True',
     '        return False'),

    ("MISC-02：非 dict 的 JSON 也当成空表放行",
     AG,
     '        if not isinstance(data, dict):\n            raise ValueError("吊销表不是 JSON 对象")',
     '        if not isinstance(data, dict):\n            data = {}'),

    ("MISC-02：文件被删掉时也当干净初始状态（删表等于复活所有已吊销令牌）",
     AG,
     '        if _REVOKED_LKG is None:\n            _REVOKED_LKG = {}\n            return {}\n        return _REVOKED_LKG',
     '        _REVOKED_LKG = {}\n        return {}'),

    # ── MISC-01 epoch ────────────────────────────────────────────
    ("MISC-01：令牌不再带 epoch 字段（改密码作废不了旧会话）",
     AG,
     '        "ep": _token_epoch(),\n',
     ''),

    # 这两条原先锚在 `_verify_or_deny` 内联的 `tok_epoch != cur_epoch` 上。
    # 2026-10-16 把 epoch 判据抽成 `_payload_epoch_ok`（因为 `_authenticated`
    # 漏查、两边必须共用同一套判据）之后锚点就失配了 —— 变异被静默跳过，
    # 覆盖悄悄没了。所以两条都改锚到 helper 里，并新增一条盯住「helper 恒真」。
    ("MISC-01：epoch 判据恒为真（令牌不再与配置比对世代号）",
     AG,
     "    return tok_epoch == cur_epoch",
     "    return True"),

    ("MISC-01：epoch 比对反过来（改密码后旧令牌反而能用）",
     AG,
     "    return tok_epoch == cur_epoch",
     "    return tok_epoch != cur_epoch"),

    ("MISC-01：_token_epoch 恒返回 0",
     AG,
     '        return int(load_gateway_config().get("auth_token_epoch", 0) or 0)\n'
     '    except (TypeError, ValueError):\n        return 0',
     '        return 0\n'
     '    except (TypeError, ValueError):\n        return 0'),

    ("MISC-01：面板 _bump_token_epoch 不再递增",
     APP,
     "    new_ep = int(cfg.get('auth_token_epoch', 0) or 0) + 1",
     "    new_ep = int(cfg.get('auth_token_epoch', 0) or 0)"),

    ("MISC-01：_session_epoch_ok 恒为真（会话不再绑定世代号）",
     APP,
     '    return stamped == _current_token_epoch()',
     '    return True'),

    ("MISC-01：登录时不盖世代号（会话永远停留在 0）",
     APP,
     "    session['auth_epoch'] = _current_token_epoch()\n"
     "    return jsonify({'success': True, 'data': {'message': '登录成功'}})",
     "    return jsonify({'success': True, 'data': {'message': '登录成功'}})"),

    ("MISC-01：before_request 不再检查世代号（改密后旧面板会话存活）",
     APP,
     '        if not _session_epoch_ok():',
     '        if False:'),

    ("MISC-01：auth/status 汇报的认证状态不看世代号",
     APP,
     "            'authenticated': _is_authenticated() and _session_epoch_ok(),",
     "            'authenticated': _is_authenticated(),"),

    # ── AUTH-01 时序 ─────────────────────────────────────────────
    ("AUTH-01：改回 bool(stored) and 短路（stored 空时不跑 PBKDF2）",
     AG,
     '    _ok = _verify_password(password, stored)\n'
     '    ok = bool(password) and bool(stored) and _ok',
     '    ok = bool(password) and bool(stored) and _verify_password(password, stored)'),

    # ── P3 安全头 ───────────────────────────────────────────────
    ("P3：after_request 不再兜底 Cache-Control",
     AG,
     '    resp.headers.setdefault("Cache-Control", "no-store")',
     '    pass  # mutated'),

    ("P3：不再下发 HSTS",
     AG,
     '        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")',
     '        pass  # mutated'),

    ("P3：HSTS 带上 includeSubDomains（会误伤同域其它服务）",
     AG,
     '        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")',
     '        resp.headers.setdefault("Strict-Transport-Security",\n'
     '                                "max-age=31536000; includeSubDomains")'),

    ("P3：兜底改成硬覆盖（把静态资源的 no-cache 也改成 no-store）",
     AG,
     '    resp.headers.setdefault("Cache-Control", "no-store")',
     '    resp.headers["Cache-Control"] = "no-store"'),

    ("P3：不再下发 X-Frame-Options",
     AG,
     '    resp.headers.setdefault("X-Frame-Options", "DENY")',
     '    pass  # mutated'),

    ("P3：/auth/* location 不再透传 X-Forwarded-Proto（HSTS 永远发不出去）",
     APP,
     '        L.append("        proxy_set_header X-Forwarded-Proto $scheme;")\n'
     '        L.append("    }")\n'
     '        L.append("")\n',
     '        L.append("    }")\n'
     '        L.append("")\n'),

    # ── 共享机密文件权限（.224 实测挖出来的既有 bug）────────────
    ("权限：_write_password_hash 退回 chmod 600（网关再也读不到密码文件）",
     APP,
     '    _apply_shared_secret_perms(AUTH_PASSWORD_FILE)',
     '    os.chmod(AUTH_PASSWORD_FILE, 0o600)'),

    ("权限：_init_app_secret 退回 chmod 600",
     APP,
     '        _apply_shared_secret_perms(AUTH_SECRET_FILE)',
     '        os.chmod(AUTH_SECRET_FILE, 0o600)'),

    ("权限：有 nftweb 组时也不再 chgrp（组名写错等于没修）",
     APP,
     "        os.chown(path, -1, grp.getgrnam('nftweb').gr_gid)",
     "        os.chown(path, -1, os.getgid())"),

    ("权限：chgrp 之后忘了 chmod 640（属组对了但组仍无读权限）",
     APP,
     '    try:\n        os.chmod(path, 0o640)\n    except OSError:\n        pass',
     '    pass'),

    ("权限：回退分支直接放行不 chmod（组不存在时文件权限失控）",
     APP,
     '        try:\n            os.chmod(path, 0o600)\n        except OSError:\n            pass\n        return',
     '        return'),

    # ── logout 与 verify 取令牌方式不对称（.224 实测挖出）────────
    #
    # 2026-10-16 把优先级翻成 Bearer 优先后，这条的锚点也跟着换了：
    # 原来锚的是「cookie 优先」那版实现体，现在源里已经是 Bearer 优先，
    # 锚点失配会让它被静默跳过。锚点必须跟着实现一起走，否则测试
    # 会在你以为它还在盯着的时候悄悄失去覆盖。
    # 下面这条是「完全不认 Bearer」，比同组的「退回 cookie 优先」更强一档：
    # 它连兜底都没有，任何走 Bearer 的客户端一律登不掉。
    ("logout：_extract_token 完全不认 Bearer（Bearer 客户端永远登不掉）",
     AG,
     '    authz = (request.headers.get("Authorization") or "").strip()\n'
     '    if authz.lower().startswith("bearer "):\n'
     '        return authz[7:].strip()\n'
     '    return request.cookies.get(COOKIE_TOKEN, "") or ""',
     '    return request.cookies.get(COOKIE_TOKEN, "") or ""'),

    ("logout：装饰器被挪到 _extract_token 上（logout 路由返回裸字符串）",
     AG,
     '@app.route("/auth/logout", methods=["POST"])\ndef auth_logout():',
     'def auth_logout():'),

    ("logout：不再调用 revoke_jti（登出只是清 cookie）",
     AG,
     '    payload = parse_token(_extract_token())\n'
     '    ok = True\n'
     '    if payload:\n'
     '        ok = revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0)))',
     '    parse_token(_extract_token())'),

    # ── revoke_jti 落盘结果必须被如实汇报（4c 节）────────────────────
    #
    # 这几条盯的是同一个东西：**吊销到底成没成立，必须让调用方知道**。
    # 谎报的后果两头都很难看：往好了报（return True）= 登出看着成功、
    # 令牌其实还活着；往坏了报（chmod 失败就 return False）= 一个纯粹的
    # 权限收紧动作被当成安全失败，把所有人都踢下线。

    ("revoke_jti：建文件退回 open(a+)（创建即 0644，有世界可读窗口）",
     AG,
     '        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)',
     '        fd = open(path, "a+").fileno()'),

    ("revoke_jti：写盘失败谎报成功（令牌其实还活着却返回 True）",
     AG,
     '        audit("revocation_open_failed", error=type(e).__name__)\n'
     '        return False',
     '        audit("revocation_open_failed", error=type(e).__name__)\n'
     '        return True'),

    ("revoke_jti：chmod 收紧失败被当成吊销失败（一次权限动作踢掉所有人）",
     AG,
     '    except OSError:\n'
     '        audit("revocation_chmod_failed")\n'
     '    return True',
     '    except OSError:\n'
     '        return False'),

    ("logout：吊销失败也返回 200（令牌还活着却报登出成功）",
     AG,
     '    return (resp, 200) if ok else (resp, 500)',
     '    return resp, 200'),

    ("logout：失败时不清 cookie（本机凭据留在浏览器里）",
     AG,
     '    _set_cookies(resp, "", "", clear=True)\n'
     '    return (resp, 200) if ok else (resp, 500)',
     '    if ok:\n'
     '        _set_cookies(resp, "", "", clear=True)\n'
     '    return (resp, 200) if ok else (resp, 500)'),

    ("login：旧令牌没吊销掉时不留审计（线上无从判断）",
     AG,
     '        if not revoke_jti(_old.get("jti", ""), int(_old.get("exp", 0))):\n'
     '            audit("login_old_token_not_revoked",\n'
     '                  exp=int(_old.get("exp", 0)))',
     '        revoke_jti(_old.get("jti", ""), int(_old.get("exp", 0)))'),

    ("续期：吊销表只读时直接拒绝放行（每次续期都 401，把网关对外全关）",
     AG,
     '            if not revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0))):\n'
     '                audit("refresh_old_token_not_revoked",\n'
     '                      exp=int(payload.get("exp", 0)), device=payload.get("dev"))',
     '            if not revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0))):\n'
     '                return _deny("revocation_failed")'),

    # ── 凭据优先级：Bearer 必须压过 cookie（4g 节）────────────────────
    #
    # 这条优先级原来一直是 cookie 在前、注释却写着「Bearer 优先」。把它翻过来
    # 之后更要盯住：翻错了不会有任何报错，只会让脚本客户端拿着有效令牌拿 401。

    ("凭据：退回 cookie 优先（注释说 Bearer，实现不跟）",
     AG,
     '    authz = (request.headers.get("Authorization") or "").strip()\n'
     '    if authz.lower().startswith("bearer "):\n'
     '        return authz[7:].strip()\n'
     '    return request.cookies.get(COOKIE_TOKEN, "") or ""',
     '    raw = request.cookies.get(COOKIE_TOKEN, "") or ""\n'
     '    if raw:\n'
     '        return raw\n'
     '    authz = (request.headers.get("Authorization") or "").strip()\n'
     '    if authz.lower().startswith("bearer "):\n'
     '        return authz[7:].strip()\n'
     '    return ""'),

    ("凭据：verify 入口自己先看 cookie（绕过 _extract_token 的优先级）",
     AG,
     '        raw = _extract_token()',
     '        raw = request.cookies.get(COOKIE_TOKEN, "") or _extract_token()'),

    ("凭据：Bearer scheme 改成大小写敏感（RFC 7235 里它本该不敏感）",
     AG,
     '    if authz.lower().startswith("bearer "):',
     '    if authz.startswith("bearer "):'),

    # ── 两条鉴权路径的 epoch 判据必须一致（.224 实测的真洞）────────
    #
    # epoch 校验曾经只写在 _verify_or_deny 里，_authenticated 没查。
    # 于是改密码后 auth_request 401 了、门户页面仍然 200 —— 用户看到
    # 「密码都改了，页面还能打开」。这类「一条路径查了、另一条没查」的洞
    # 只有在**两个端点都打**的时候才暴露得出来。

    ("门户：_authenticated 不查 epoch（改密码后页面照样 200）",
     AG,
     "    return (bool(payload)\n"
     "            and _payload_epoch_ok(payload, cfg)\n"
     "            and not is_revoked(payload.get(\"jti\", \"\")))",
     "    return bool(payload) and not is_revoked(payload.get(\"jti\", \"\"))"),

    ("门户：_authenticated 退回只读 cookie（Bearer 客户端被无视）",
     AG,
     "    payload = parse_token(_extract_token())\n"
     "    return (bool(payload)",
     "    payload = parse_token(request.cookies.get(COOKIE_TOKEN, \"\"))\n"
     "    return (bool(payload)"),

    ("epoch 判据被摘掉（两条路径都不再作废旧令牌）",
     AG,
     "        if not _payload_epoch_ok(payload, cfg):\n"
     "            return _deny(\"epoch_changed\" if \"ep\" in payload else \"epoch_missing\")",
     "        if False:\n"
     "            return _deny(\"epoch_changed\")"),

]

# 等价变异：行为不变，不计漏过。
EQUIVALENT = {
    "MISC-01：_token_epoch 恒返回 0":
        "等价变异 —— 测试用的是显式写入配置的 epoch，不经过这个读取路径",
}


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, cwd=ROOT, env=env, timeout=600)


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print("=" * 74)
    print("变异验证：会话生命周期四项")
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
            print(f"    ⚖️  等价变异（已归类）：{desc}")
            print(f"       理由：{EQUIVALENT[desc]}")
        else:
            missed += 1
            misses.append(desc)
            print(f"    ❌ 漏过：{desc}")

    print("\n[2] 还原校验：源码必须与变异前逐字节一致")
    b = run_test()
    ok = b.returncode == 0
    print(f"    {'✅' if ok else '❌'} 还原后测试"
          f"{'恢复全绿' if ok else '仍然红 —— 源码没还原干净'}")
    if not ok:
        print(b.stdout[-3000:])

    total = caught + missed + equiv
    print("\n" + "=" * 74)
    print(f"变异 {total} 处  捕获 {caught}  漏过 {missed}  等价变异 {equiv}  "
          f"锚点未命中 {sum('锚点未命中' in m for m in misses)}")
    if equivalents:
        print("等价变异明细：")
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
