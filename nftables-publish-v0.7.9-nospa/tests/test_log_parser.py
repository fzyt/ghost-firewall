"""日志解析器回归测试（纯标准库，不碰真实路径）

运行:  python3 tests/test_log_parser.py

测的是 app.py 里的**真实源码**，不是复制品：按标记定位那段源码文本，
exec 进带 mock 的命名空间后驱动它。这样正则一改，这里立刻红，
不会出现「测的是副本、改的是原件」。

为什么值得单独测：`/api/system/logs` 的解析正则有三个刻意的放宽点
（星期/年份可选、facility 贪婪匹配、prog 与 pid 整段可选），
每一个都是为了「不让日志被静默丢弃」，但也每一个都可能悄悄改坏。
日志页一旦少给几行，用户就没法信任它了 —— 这种 bug 不会报错，只会少数据。
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "backend", "app.py")
SBX = "/tmp/nftv2-logparser-sbx"

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)
    return cond


def parse(SRE, ISO, line, year):
    """匹配并转时间戳。**不匹配时返回 (None, None) 而不是抛异常** ——
    测试崩掉和测试失败是两回事：崩掉说明测试自己有洞，
    真正要报的「这行没匹配上」反而被栈回溯淹掉了。"""
    m = SRE.match(line)
    if not m:
        return None, None
    ts, _epoch = ISO(m, year)
    return ts, m


def load_section():
    """从 app.py 真实源码里抽出日志解析段并执行。"""
    src = open(SRC, encoding="utf-8").read()
    start = "# 系统日志：logread + 认证审计"
    end = '@app.route("/api/system/logs"'
    if start not in src or end not in src:
        raise SystemExit(f"❌ app.py 里找不到日志段标记（{start!r} / {end!r}），"
                         f"解析段被改名或挪走了，本测试需要同步更新")
    i = src.rindex("# ═", 0, src.index(start))
    block = src[i:src.index(end)]
    ns = {
        "re": re, "datetime": datetime, "json": json,
        "subprocess": subprocess, "os": os,
        "app": type("A", (), {"route": lambda *a, **k: (lambda f: f)})(),
    }
    # 文件名用假的：传真名会让 traceback 的行号按 block 相对行去查真文件，
    # 显示出的源码和实际执行的代码完全对不上，排查时会被带偏。
    exec(compile(block, "<app.py::log-section>", "exec"), ns)
    # block 自己就定义了 AUTH_AUDIT_LOG，exec 会覆盖注入值，必须之后再改
    ns["AUTH_AUDIT_LOG"] = os.path.join(SBX, "audit.jsonl")
    return ns


def main():
    ns = load_section()
    SRE, ISO = ns["_SYSLOG_RE"], ns["_iso_from_syslog"]
    MONTHS, SRC_NAME = ns["_MONTHS"], ns["AUTH_SOURCE"]
    read_audit = ns["_read_audit_events"]
    year = datetime.datetime.now().year

    print("=" * 64)
    print("日志解析器回归测试")
    print("=" * 64)

    # ── 1. 月缩写表必须 12 个 ──
    print(f"\n【1】月缩写表 {len(MONTHS)} 个")
    check(len(MONTHS) == 12, f"月缩写表应有 12 个，实际 {len(MONTHS)}")

    # ── 2. 标准格式 ──
    print("\n【2】标准 syslog 格式")
    cases = [
        ("Tue Oct  6 18:52:41 2026 daemon.err dropbear[615]: Bad password",
         "dropbear", "err", "615", "Bad password"),
        ("Tue Oct  6 18:52:41 2026 user.notice nftv2-test: probe line",
         "nftv2-test", "notice", None, "probe line"),
        ("Thu Jan  1 08:00:00 1970 kern.emerg kernel: ",
         "kernel", "emerg", None, ""),
    ]
    for line, want_src, want_lvl, want_pid, want_msg in cases:
        ts, m = parse(SRE, ISO, line, year)
        if not check(m is not None, f"标准行没匹配: {line[:50]}"):
            continue
        check(ts is not None, f"时间戳解析失败: {line[:50]}")
        check(m.group("prog") == want_src,
              f"来源不对: 期望 {want_src} 实际 {m.group('prog')} —— {line[:40]}")
        check(m.group("lvl") == want_lvl,
              f"级别不对: 期望 {want_lvl} 实际 {m.group('lvl')}")
        check(m.group("pid") == want_pid, f"pid 不对: {line[:40]}")
        check(m.group("msg") == want_msg, f"消息不对: {line[:40]}")
        print(f"    ✅ {want_src:<12} [{want_lvl:<6}] ts={ts}")

    # ── 3. 三处刻意放宽：这些原本都会整行丢掉 ──
    print("\n【3】放宽点（原本会被静默丢行）")
    relaxed = [
        ("Oct  6 18:52:41 daemon.warn netifd: no weekday", "netifd", "warn"),
        ("Tue Oct  6 18:52:41 daemon.info probe[7]: no year", "probe", "info"),
        ("Tue Oct  6 18:52:41 2026 my.app-name_v2.info dotted.tag: hi",
         "dotted.tag", "info"),
        ("Tue Oct  6 18:52:41 2026 kernel.crit message with : colons :",
         None, "crit"),
    ]
    for line, want_src, want_lvl in relaxed:
        ts, m = parse(SRE, ISO, line, year)
        if not check(m is not None, f"放宽点未匹配: {line[:55]}"):
            print(f"    ❌ {line[:50]}")
            continue
        got = m.group("prog")
        check(ts is not None, f"放宽点时间戳失败: {line[:50]}")
        check(got == want_src, f"prog 不对: 期望 {want_src} 实际 {got}")
        check(m.group("lvl") == want_lvl, f"级别不对: {line[:50]}")
        print(f"    ✅ fac={m.group('fac'):<17} prog={str(got):<12} msg={m.group('msg')[:22]!r}")

    # 设施名带点时必须拆对：贪心 [\w.-]+ 只在单个 token 内生效
    _ts, _m = parse(SRE, ISO,
                    "Tue Oct  6 18:52:41 2026 my.app-name_v2.info tag: hi", year)
    if _m:
        check(_m.group("fac") == "my.app-name_v2",
              f"facility 拆错: 实际 {_m.group('fac')}")

    # ── 4. 12 个月全覆盖 ──
    print("\n【4】12 个月份")
    mon_names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    bad = []
    for n, mo in enumerate(mon_names, 1):
        ts, m = parse(SRE, ISO, f"{mo} 15 12:00:00 2026 daemon.info probe[{n}]: m", 2026)
        if not m or not ts or datetime.datetime.fromisoformat(ts).month != n:
            bad.append(mo)
    check(not bad, f"月份解析失败: {bad}")
    print(f"    {'✅ 12/12' if not bad else '❌ ' + str(bad)}")

    # ── 5. 年份：有值必须尊重，无值回落当年 ──
    print("\n【5】年份")
    ts2, _ = parse(SRE, ISO, "Tue Oct  6 18:52:41 2027 daemon.info p: y", year)
    ts1, _ = parse(SRE, ISO, "Dec 31 23:59:59 daemon.info p: x", year)
    if check(ts2 and ts1, "年份用例未匹配，解析器可能退化了"):
        check(datetime.datetime.fromisoformat(ts2).year == 2027,
              f"未尊重文件里的年份: {ts2}")
        check(datetime.datetime.fromisoformat(ts1).year == year,
              f"无年份未回落当年: {ts1}")
        print(f"    ✅ 有年份={ts2}  无年份回落={ts1}")

    # ── 6. 审计 JSONL → 统一条目 ──
    print("\n【6】认证审计并入")
    shutil.rmtree(SBX, ignore_errors=True)
    os.makedirs(SBX, exist_ok=True)
    with open(os.path.join(SBX, "audit.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-10-06T13:44:27", "event": "login_ok",
                            "ip": "192.168.100.1", "device": "devAAA",
                            "fp": "fpBBB", "user": "kirito",
                            "ua": "x" * 400, "uri": "/auth/login"}) + "\n")
        f.write(json.dumps({"ts": "2026-10-06T13:44:28", "event": "login_fail",
                            "ip": "192.168.100.2", "device": "devCCC"}) + "\n")
    ev = read_audit()
    check(len(ev) == 2, f"应读到 2 条审计事件，实际 {len(ev)}")
    for e in ev:
        check(e["source"] == SRC_NAME, f"来源应为 {SRC_NAME}，实际 {e['source']}")
        check(e["message"], "消息为空")
    if len(ev) == 2:
        by = {e["event"]: e for e in ev}
        check(by["login_ok"]["level"] == "info", "login_ok 应映射为 info")
        check(by["login_fail"]["level"] == "warn", "login_fail 应映射为 warn")
        check(by["login_ok"]["fp"] == "fpBBB", "指纹未带出")
        check(len(by["login_ok"]["ua"]) <= 200, "UA 未截断")
        check(by["login_fail"]["user"] == "", "user 为 null 时应落成空串")
        print(f"    ✅ login_ok→{by['login_ok']['level']} "
              f"login_fail→{by['login_fail']['level']} "
              f"fp={by['login_ok']['fp']} UA已截断={len(by['login_ok']['ua'])}")

    # ── 7. 坏数据不得让整体失败，也不得挤掉正常记录 ──
    print("\n【7】坏数据容错")
    with open(os.path.join(SBX, "audit.jsonl"), "a", encoding="utf-8") as f:
        f.write('{"ts": "2026-10-06T19:00:01", "event": "login_ok"  <<< 半截行\n')
        f.write("not json at all\n")
        f.write("[1,2,3]\n")                                   # 合法 JSON 但非对象
        f.write('{"ts": "不是时间", "event": "login_fail"}\n')  # 非法时间戳
        f.write('{"ts": "2026-10-06T19:00:00", "event": "logout"}\n')  # 正常，验证没被挤掉
        f.write("\n")
    after = read_audit()
    check(len(after) >= 3, f"坏数据导致整体读取失败，仅剩 {len(after)} 条")
    check(any(e["ts"] == "2026-10-06T19:00:00" and e["event"] == "logout"
              for e in after), "坏数据把正常记录挤掉了")
    check(not [e for e in after if not isinstance(e.get("event"), str)],
          "非对象 JSON 未被跳过")
    print(f"    ✅ 追加 5 条坏数据后仍读到 {len(after)} 条，正常记录未被挤掉")

    print("\n" + "=" * 64)
    if fails:
        print(f"❌ {len(fails)} 项失败：")
        for f in fails:
            print(f"   - {f}")
        return 1
    print("✅ 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())