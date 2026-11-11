#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阿里云 DDNS 更新链路的行为级测试（批 A）

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_aliyun_ddns_update.py

测什么
------
「DDNS 不断删除重新上传」这个问题，核心不是「删」这个动作，
而是**动作选错了**。这一版把三处都改成：

  · 值没变  ⇒ 一个写接口都不调
  · 值变了  ⇒ 只调 UpdateDomainRecord（**RecordId 不变**）
  · 记录没这 ⇒ 才调 AddDomainRecord
  · 永远不调 DeleteDomainRecord

怎么测
------
**不是**「源码里应该出现某段文字」那种文本匹配 —— 文本匹配抓不住
「先更新再删除」「值相同也更新」这类退化。

这里真的把 cron 脚本跑起来：
  1. 用 AST 从 backend/app.py 里提取 `script_content`（生成出来的脚本原文）
  2. 起一个**本地假阿里云服务端**（HTTP），记录每一次 API 调用
  3. 把脚本的端点/配置路径/日志路径/IP 源全部指向本地（脚本支持注入）
  4. 子进程跑脚本，断言**它发出的 API 调用序列**

⇒ 判据落在「真正会跑的那条路径」上：设备上跑的就是这份脚本。

面板侧（`_aliyun_ddns_update` 等）单独 mock `_aliyun_api` 断言调用序列。

⚠️ 为什么 IP 源要可注入
---------------------
脚本要取公网 IPv4。若测试真出网：结果会随时间变、网络不通就假失败，
那样的测试等于没有。所以脚本支持用 NFTW_IPV4_SOURCES 指向本地假源。
"""

import ast
import importlib
import importlib.util as ilu
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, "backend")
APP_PATH = os.path.join(BACKEND, "app.py")
FRONTEND_JS = os.path.join(ROOT, "frontend", "app.js")

PASS = 0
FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("[PASS] " + msg)
    else:
        FAIL += 1
        print("[FAIL] " + msg)


# ══════════════════════════════════════════════════════════
# 一、从 app.py 里提取生成的 cron 脚本
# ══════════════════════════════════════════════════════════

def extract_cron_script():
    """用 AST 提取 script_content。

    不用正则切：脚本里满是引号、缩进、三引号，正则切出来的边界
    经常差一个字符，而且**切错时不会报错**，只是脚本内容变了。
    AST 拿到的是 Python 解释后的真实字符串。
    """
    tree = ast.parse(open(APP_PATH, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_generate_ddns_update_script":
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign)
                        and getattr(stmt.targets[0], "id", "") == "script_content"):
                    return ast.literal_eval(stmt.value)
    return None


def script_actions(script):
    """取出脚本**实际调用**的阿里云 Action 集合（AST 层面，不看注释/文档字符串）"""
    actions = set()
    for node in ast.walk(ast.parse(script)):
        if isinstance(node, ast.Call):
            fn = node.func
            if getattr(fn, "id", "") == "_api" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    actions.add(first.value)
    return actions


# ══════════════════════════════════════════════════════════
# 二、假阿里云服务端
# ══════════════════════════════════════════════════════════

class FakeAliyun:
    """记录 API 调用，并按预设返回结果"""

    def __init__(self):
        self.calls = []           # [(action, params)]
        self.records = []         # DescribeDomainRecords 返回的记录
        self.fail_actions = set()  # 这些 Action 一律返回错误
        self.fail_once_actions = set()  # 这些 Action 只有第一次返回错误
        self.action_counts = {}
        self.ip_body = "203.0.113.7"
        self.ip_status = 200
        # TotalCount 覆盖：用来模拟「阿里云还有更多记录、这页没取全」的分页截断。
        # ⚠️ 不覆盖时必须等于 len(records)，否则「分页截断 ⇒ 中止」那条判据
        #   会在正常场景下误报，测试就失去意义了。
        self.total_count_override = None

    def action_seq(self):
        return [a for a, _ in self.calls]

    def params_of(self, action):
        for a, p in self.calls:
            if a == action:
                return p
        return None


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        fake = self.server.fake
        parsed = urlparse(self.path)
        if parsed.path == "/ip4":
            if fake.ip_status != 200:
                self._send(fake.ip_status, "boom", "text/plain")
            else:
                self._send(200, fake.ip_body, "text/plain")
            return
        qs = parse_qs(parsed.query)
        params = {k: v[0] for k, v in qs.items()}
        action = params.get("Action", "")
        fake.calls.append((action, params))
        fake.action_counts[action] = fake.action_counts.get(action, 0) + 1
        failed = (action in fake.fail_actions
                  or (action in fake.fail_once_actions
                      and fake.action_counts[action] == 1))
        if failed:
            self._send(400, json.dumps({"Code": "FakeError", "Message": "boom"}))
            return
        if action == "DescribeDomainRecords":
            total = fake.total_count_override
            if total is None:
                total = len(fake.records)
            self._send(200, json.dumps({
                "TotalCount": total,
                "PageSize": 500,
                "DomainRecords": {"Record": fake.records},
            }))
            return
        self._send(200, json.dumps({"RecordId": "999", "RequestId": "fake"}))


def start_fake():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.fake = FakeAliyun()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ══════════════════════════════════════════════════════════
# 三、跑脚本
# ══════════════════════════════════════════════════════════

def run_script(srv, script_text, records, extra_records=None,
               config_overrides=None, env_extra=None):
    """把脚本跑一遍，返回 (rc, stdout+stderr, 日志文本, 配置路径)"""
    fake = srv.fake
    tmp = tempfile.mkdtemp(prefix="ddns-test-")
    script_path = os.path.join(tmp, "aliyun-ddns-update.py")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_text)
    os.chmod(script_path, 0o755)

    cfg = {
        "access_key_id": "AKIDFAKE",
        "access_key_secret": "SECRETFAKE",
        "region_id": "cn-hangzhou",
        "domain": "example.com",
        "records": records,
    }
    if config_overrides:
        cfg.update(config_overrides)
    cfg_path = os.path.join(tmp, "aliyun-ddns-config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)

    log_path = os.path.join(tmp, "ddns.log")

    env = dict(os.environ)
    env["NFTW_ALIYUN_ENDPOINT"] = "http://127.0.0.1:%d/" % srv.server_address[1]
    env["NFTW_IPV4_SOURCES"] = "http://127.0.0.1:%d/ip4" % srv.server_address[1]
    env["NFTW_DDNS_LOG"] = log_path
    env["NFTABLES_WEB_ALIYUN_CONFIG"] = cfg_path
    env["NFTABLES_WEB_DDNS_RELAY_DIR"] = tmp
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)

    proc = subprocess.run([sys.executable, script_path], env=env,
                          capture_output=True, text=True, timeout=120)
    log_text = ""
    if os.path.exists(log_path):
        log_text = open(log_path, encoding="utf-8").read()
    return proc.returncode, proc.stdout + proc.stderr, log_text, tmp


def rec(rr="www", rtype="A", value="1.2.3.4", rid="1001", line="default", ttl=600):
    return {"RR": rr, "Type": rtype, "Value": value, "RecordId": rid,
            "Line": line, "TTL": ttl, "Status": "Enable"}


def cfg_record(rr="www", rtype="A", enabled=True, value="", extra=None):
    d = {"rr": rr, "type": rtype, "enabled": enabled, "value": value,
         "ipv6_source": ""}
    if extra:
        d.update(extra)
    return d


# ══════════════════════════════════════════════════════════
# 四、cron 脚本的行为
# ══════════════════════════════════════════════════════════

def test_cron_script(srv):
    script = extract_cron_script()
    check(script is not None, "能从 app.py 里提取出生成的 cron 脚本")
    if script is None:
        return None

    actions = script_actions(script)
    check("DeleteDomainRecord" not in actions,
          "脚本的 Action 集合里没有 DeleteDomainRecord（改成原地更新后不再需要删除）")
    check("UpdateDomainRecord" in actions, "脚本调用 UpdateDomainRecord（原地更新）")
    check("AddDomainRecord" in actions, "脚本保留 AddDomainRecord（记录不存在时才新增）")

    fake = srv.fake

    # ── A 组：值没变 ⇒ 一个写接口都不调 ───────────────────
    fake.calls = []
    fake.records = [rec(value="203.0.113.7")]   # 与 IP 源返回的一致
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check(seq == ["DescribeDomainRecords"],
          "值没变时只发一次查询，不发任何写请求（实际：%s）" % seq)
    check(rc == 0, "值没变时脚本退出码为 0（实际 %d）" % rc)

    # ── A2 反例：值变了 ⇒ 只调 Update ─────────────────────
    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check(seq == ["DescribeDomainRecords", "UpdateDomainRecord"],
          "值变了时是「查询 + 原地更新」，没有新增也没有删除（实际：%s）" % seq)
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("RecordId") == "1001",
          "原地更新沿用原记录的 RecordId=1001（记录 ID 不变）")
    check(p is not None and p.get("Value") == "203.0.113.7",
          "更新写入的是本次取到的公网 IPv4")

    # ── B 组：记录不存在才 Add ────────────────────────────
    fake.calls = []
    fake.records = []
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check(seq == ["DescribeDomainRecords", "AddDomainRecord"],
          "记录不存在时才新增（实际：%s）" % seq)
    p = fake.params_of("AddDomainRecord")
    check(p is not None and p.get("Value") == "203.0.113.7",
          "新增时写入当前公网 IPv4")

    # ── B2 反例：记录存在就不新增 ─────────────────────────
    fake.calls = []
    fake.records = [rec(value="203.0.113.7")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    check("AddDomainRecord" not in fake.action_seq(),
          "记录已存在时不调用 AddDomainRecord")

    # ── C 组：多线路保护（只动 default）────────────────────
    # ⚠️ 电信那条必须排在**前面**：去掉 Line 判定后 matched[0] 会变成它。
    # 阿里云返回记录的顺序不保证，电信那条完全可能排在 default 前面 ——
    # 老代码正是这样把别的线路的记录改掉的。
    fake.calls = []
    fake.records = [
        rec(value="192.0.2.55", rid="2002", line="telecom"),
        rec(value="198.51.100.9", rid="1001", line="default"),
    ]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check(seq == ["DescribeDomainRecords", "UpdateDomainRecord"],
          "default + 电信两条记录时，只对 default 发起更新（实际：%s）" % seq)
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("RecordId") == "1001",
          "被更新的是 default 线路那条（RecordId=1001），电信那条没被碰")
    check(p is not None and p.get("Value") == "203.0.113.7",
          "电信线路的旧值 192.0.2.55 没有被写回 default 线路")

    # ── C2 组：只有一条非 default 线路的记录时，更新它而不是新增一条 ──
    # 用户把 DDNS 配在「电信」等线路上是合法的。这时候若因为
    # 「没有 default 那条」而去 Add，会凭空多出一条 default 记录，
    # 原来那条还指着旧 IP ⇒ 解析变成两条轮询。
    fake.calls = []
    fake.records = [rec(value="198.51.100.9", rid="2002", line="telecom")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check(seq == ["DescribeDomainRecords", "UpdateDomainRecord"],
          "只有一条（电信线路）记录时更新它，不新增 default（实际：%s）" % seq)
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("RecordId") == "2002",
          "被更新的是那条电信线路的记录（RecordId=2002）")

    # ── D 组：取不到公网 IPv4 ⇒ 不动阿里云 ─────────────────
    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_body = "2001:db8::1"        # 源返回的是 IPv6
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    check(fake.action_seq() == [],
          "IP 源返回 IPv6 时不调用任何阿里云接口（实际：%s）" % fake.action_seq())
    check("取不到公网 IPv4" in log, "日志写明了「取不到公网 IPv4」")

    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_status = 500               # 源不可达
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    check(fake.action_seq() == [],
          "IP 源不可达时不调用任何阿里云接口（不会拿旧值去覆盖）")
    fake.ip_status = 200

    # ── D4 组：取不到公网 IPv4 时**不能**拿旧值去覆盖 ─────────
    # 配置里存着上一轮同步下来的旧 IP（存量配置就是这样）。
    # 若脚本在取不到 IP 时沿用这个旧值，就会把阿里云上正确的地址
    # 改回过期地址 —— 那比不更新更糟。
    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_body = "2001:db8::1"        # 源返回的是 IPv6 ⇒ 取不到合法 IPv4
    rc, out, log, _ = run_script(srv, script, [cfg_record(value="192.0.2.99")])
    check(fake.action_seq() == [],
          "取不到公网 IPv4 时不用配置里的旧值去覆盖阿里云（实际：%s）"
          % fake.action_seq())

    # ── D3 反例：能取到 IPv4 时才会去更新 ──────────────────
    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    check("UpdateDomainRecord" in fake.action_seq(),
          "能取到公网 IPv4 时确实会去更新（反例：否则上面的跳过断言没有意义）")

    # ── E 组：单条失败不影响其余记录 ──────────────────────
    # 只让**第一次** Update 失败（a 那条），b 那条必须照样被更新。
    # 若整个 records 循环被一个 try 包住，第一条一抛异常整轮就结束 ⇒ b 不被处理。
    fake.calls = []
    fake.records = [
        rec(rr="a", value="198.51.100.9", rid="1001"),
        rec(rr="b", value="198.51.100.9", rid="1002"),
    ]
    fake.ip_body = "203.0.113.7"
    fake.action_counts = {}      # 计数是累积的，要清掉，否则「第一次失败」落在前面某组
    fake.fail_once_actions = {"UpdateDomainRecord"}
    rc, out, log, _ = run_script(srv, script,
                                 [cfg_record(rr="a"), cfg_record(rr="b")])
    if "失败 a.A" not in log or "更新 b.A" not in log:
        print("    [E 组调试] rc=%s" % rc)
        print("    [E 组调试] 调用序列=%s" % fake.action_seq())
        print("    [E 组调试] 日志：\n%s" % log)
    log_ok = ("失败 a.A" in log) and ("更新 b.A" in log)
    check(log_ok, "第一条记录更新失败时，第二条仍然被更新（日志：%s）"
          % ("有" if log_ok else "缺"))
    check("失败 a.A" in log, "失败的那条在日志里写明了原因")
    fake.fail_once_actions = set()

    # ── F 组：每轮写摘要日志 ──────────────────────────────
    fake.calls = []
    fake.records = [rec(value="203.0.113.7")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    check(log.strip() != "", "脚本在日志文件里留下了摘要行（原来正常路径零日志）")
    check("www.A" in log, "日志里点出了是哪条记录（www.A）")

    # ── G 组：配置键大小写兼容 ────────────────────────────
    fake.calls = []
    fake.records = [rec(value="203.0.113.7")]
    fake.ip_body = "203.0.113.7"
    upper_cfg = [{"RR": "www", "Type": "A", "enabled": True, "Value": ""}]
    rc, out, log, _ = run_script(srv, script, upper_cfg)
    check("取不到 rr/type" not in log,
          "配置里只有大写键 RR/Type 时也能识别（不是「取不到 rr/type」）")
    check(fake.action_seq() == ["DescribeDomainRecords"],
          "大写键配置下同样走「值没变就只查询」（实际：%s）" % fake.action_seq())

    # ── H 组：未启用的记录不处理 ──────────────────────────
    fake.calls = []
    fake.records = [rec(value="198.51.100.9")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record(enabled=False)])
    check(fake.action_seq() == [],
          "未启用的记录不发起任何请求（实际：%s）" % fake.action_seq())

    # ── I 组：配置路径读环境变量 ──────────────────────────
    # ⚠️ 必须让环境变量指向一份**存在**且内容独特的配置：
    #   指向不存在的路径时，「读了指定路径」和「读了默认路径」的表现一样
    #   （都是文件不存在）⇒ 区分不开。
    #   用一个独有的 RR 名做判据：只有真读到这份配置，才会带着它去查阿里云。
    fake.calls = []
    fake.records = [rec(rr="envpath-test", value="198.51.100.9", rid="7001")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(
        srv, script,
        [cfg_record(rr="envpath-test")])
    p = fake.params_of("DescribeDomainRecords")
    check(p is not None and p.get("RRKeyWord") == "envpath-test",
          "环境变量指定的配置路径生效（查的是那份独有配置里的记录）")

    # ── I2 组：配置文件不存在时安静退出 ────────────────────
    fake.calls = []
    rc, out, log, _ = run_script(
        srv, script, [cfg_record()],
        env_extra={"NFTABLES_WEB_ALIYUN_CONFIG":
                   "/nonexistent/should-not-be-read.json"})
    check(rc == 0,
          "配置文件不存在时脚本退出码为 0（安静退出，不是异常退出），实际 %d" % rc)
    check("配置文件不存在" in log,
          "日志写明「配置文件不存在」，而不是让人看不懂的 FileNotFoundError")
    check("FileNotFoundError" not in log,
          "日志里不出现 FileNotFoundError 这种对用户无意义的字样")
    check(fake.action_seq() == [],
          "配置文件不存在时不发起任何阿里云请求")

    # ── O 组：不用已弃用的 datetime.utcnow() ───────────────
    # Python 3.13 起 utcnow() 已弃用，cron 每次跑都会往 stderr 打警告。
    check("utcnow()" not in script,
          "脚本里没有已弃用的 datetime.utcnow()（3.13 会打 DeprecationWarning）")

    # ── J 组：查询拉全量 ──────────────────────────────────
    fake.calls = []
    fake.records = [rec(value="203.0.113.7")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    p = fake.params_of("DescribeDomainRecords")
    check(p is not None and p.get("PageSize") == "500",
          "查询带上 PageSize=500（目标记录不会落在首屏之外）")

    # ── K 组：IPv6 中转目录读面板**同名**的环境变量 ──────────
    # 面板读 NFTABLES_WEB_DDNS_RELAY_DIR，脚本原来读 NFTW_RELAY_DIR ——
    # 两个名字不一样，改了面板那个环境变量，脚本这边读不到中转文件。
    relay_dir = tempfile.mkdtemp(prefix="ddns-relay-")
    with open(os.path.join(relay_dir, "ddns-ipv6-0"), "w") as f:
        f.write("2001:db8::1234")
    fake.calls = []
    fake.records = [rec(rr="ipv6", rtype="AAAA", value="2001:db8::999", rid="3001")]
    rc, out, log, _ = run_script(
        srv, script,
        [cfg_record(rr="ipv6", rtype="AAAA", extra={"ipv6_source": "router"})],
        env_extra={"NFTABLES_WEB_DDNS_RELAY_DIR": relay_dir})
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("Value") == "2001:db8::1234",
          "AAAA 记录从 NFTABLES_WEB_DDNS_RELAY_DIR 指向的目录读到中转值（实际 %s）"
          % (p or {}).get("Value"))

    # ══════════════════════════════════════════════════════
    # 批 A 组：2026-11-11 完整代码审查新增的 6 条判据
    # ══════════════════════════════════════════════════════

    # ── A1 组（S1）：IPv6 中转文件读不到 ⇒ 不许拿配置里的旧值去覆盖 ──
    # ⚠️ 这是**会写坏阿里云数据**的一条：
    #   OpenWrt 的 /tmp 是 tmpfs，重启即清空 ⇒ 中转文件经常不存在。
    #   原来读不到就 `pass`（沿用配置里的旧值）⇒ 把过期 IPv6 写回阿里云，
    #   而写回后每轮比较都相等 ⇒ **永远停在过期地址，不会自愈**。
    #   （A 记录的「取不到就跳过」规则在 AAAA 上一直没实现 —— D5 只做了一半。）
    fake.calls = []
    fake.records = [rec(rr="ipv6", rtype="AAAA", value="2001:db8::1", rid="3001")]
    rc, out, log, _ = run_script(
        srv, script,
        [cfg_record(rr="ipv6", rtype="AAAA", value="2001:db8::99",
                    extra={"ipv6_source": "router"})])
    seq = fake.action_seq()
    check("UpdateDomainRecord" not in seq,
          "读不到 IPv6 中转文件时不更新阿里云（实际：%s）" % seq)
    p_upd = fake.params_of("UpdateDomainRecord")
    check(p_upd is None or p_upd.get("Value") != "2001:db8::99",
          "没有把配置里的旧 IPv6（2001:db8::99）写回阿里云")
    check("读不到 IPv6 中转文件" in log,
          "日志写明了「读不到 IPv6 中转文件」")
    # 反例：中转文件**在**的时候确实要更新（否则上面的跳过断言没意义）
    relay_ok = tempfile.mkdtemp(prefix="ddns-relay-ok-")
    with open(os.path.join(relay_ok, "ddns-ipv6-0"), "w") as f:
        f.write("2001:db8::5555")
    fake.calls = []
    fake.records = [rec(rr="ipv6", rtype="AAAA", value="2001:db8::1", rid="3001")]
    rc, out, log, _ = run_script(
        srv, script,
        [cfg_record(rr="ipv6", rtype="AAAA", value="2001:db8::99",
                    extra={"ipv6_source": "router"})],
        env_extra={"NFTABLES_WEB_DDNS_RELAY_DIR": relay_ok})
    p_upd = fake.params_of("UpdateDomainRecord")
    check(p_upd is not None and p_upd.get("Value") == "2001:db8::5555",
          "中转文件在时确实会用它的值更新（反例：否则上一条断言可能是空转）")

    # ── A2 组（M1）：更新时沿用原记录的 TTL ──────────────────
    # 阿里云官方文档：TTL 非必填，「默认为 600 秒」⇒ 不传就把用户设的 TTL 改回 600。
    fake.calls = []
    fake.records = [rec(value="198.51.100.9", ttl=3600)]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("TTL") == "3600",
          "更新时沿用原记录的 TTL=3600（不传会被阿里云重置成 600），实际 %s"
          % (p or {}).get("TTL"))

    # ── A3 组（M2）：更新时沿用原记录的 Line ──────────────────
    # 阿里云官方文档：Line 非必填，「默认为 default」
    # ⇒ 不传有把「电信」等线路的记录搬到 default 的风险。
    fake.calls = []
    fake.records = [rec(value="198.51.100.9", rid="2002", line="telecom")]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("Line") == "telecom",
          "更新时沿用原记录的线路 Line=telecom（不传可能被搬到 default），实际 %s"
          % (p or {}).get("Line"))

    # ── A4 组（M3）：配置里的 record_id 优先定位 ──────────────
    # 配置里存了精确的 RecordId（面板从阿里云读到后回填的），
    # 靠 (RR, Type, Line) 猜会改到用户没配的那条。
    fake.calls = []
    fake.records = [
        rec(value="192.0.2.55", rid="2002", line="telecom"),
        rec(value="198.51.100.9", rid="1001", line="default"),
    ]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(
        srv, script, [cfg_record(extra={"record_id": "2002"})])
    p = fake.params_of("UpdateDomainRecord")
    check(p is not None and p.get("RecordId") == "2002",
          "配置里指定 record_id=2002 时更新的是那一条（不是猜出来的 default），实际 %s"
          % (p or {}).get("RecordId"))

    # ── A5 组（M4）：分页截断 ⇒ 中止，不新增 ──────────────────
    # PageSize 上限 500。目标记录落在第 501 条之后时，「没查到」会被
    # 误当成「记录不存在」⇒ 去 Add ⇒ 凭空多出一条重复记录 ⇒ 解析轮询。
    fake.calls = []
    fake.records = []
    fake.total_count_override = 1200
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check("AddDomainRecord" not in seq,
          "阿里云记录数超出取回条数时不新增（实际：%s）" % seq)
    check("分页截断" in log, "日志写明了「分页截断」")
    fake.total_count_override = None

    # ── A6 组（L10）：目标缺 RecordId ⇒ 跳过，不发 RecordId=None ──
    fake.calls = []
    fake.records = [{"RR": "www", "Type": "A", "Value": "198.51.100.9",
                     "Line": "default", "TTL": 600}]
    fake.ip_body = "203.0.113.7"
    rc, out, log, _ = run_script(srv, script, [cfg_record()])
    seq = fake.action_seq()
    check("UpdateDomainRecord" not in seq,
          "目标记录缺 RecordId 时不发起更新（实际：%s）" % seq)
    p = fake.params_of("UpdateDomainRecord")
    check(p is None or p.get("RecordId") != "None",
          "没有把字符串 \"None\" 当 RecordId 发给阿里云")
    check("缺少 RecordId" in log, "日志写明了「缺少 RecordId」")

    # ── L 组：没有可用值就跳过 ────────────────────────────
    fake.calls = []
    fake.records = [rec(rr="cn", rtype="CNAME", value="mail.example.com", rid="4001")]
    rc, out, log, _ = run_script(srv, script,
                                 [cfg_record(rr="cn", rtype="CNAME", value="")])
    check(fake.action_seq() == [],
          "没有可用值时跳过本条，不发任何请求（实际：%s）" % fake.action_seq())

    # ── M 组：IPv6 的不同写法在**调用链上**也要判为同一个值 ──
    # 只测纯函数不够：纯函数对了、调用处没用它，照样会误判成「值变了」。
    fake.calls = []
    fake.records = [rec(rr="v6", rtype="AAAA", value="2001:db8::1", rid="5001")]
    rc, out, log, _ = run_script(
        srv, script,
        [cfg_record(rr="v6", rtype="AAAA", value="2001:db8:0:0:0:0:0:1")])
    check(fake.action_seq() == ["DescribeDomainRecords"],
          "cron 侧：IPv6 同一地址的不同写法判为「值未变」，不调写接口（实际：%s）"
          % fake.action_seq())

    return script


# ══════════════════════════════════════════════════════════
# 五、面板侧
# ══════════════════════════════════════════════════════════

def load_app():
    """加载面板模块，配置路径指向临时目录。

    照抄 tests/test_system_info_endpoint.py 的做法：面板的来源白名单取自
    配置文件，而且是 fail-closed（取不到就拒绝一切来源）⇒ 测试机上没有那份
    配置时，所有请求都会被 403 挡在门外，根本测不到接口本身。
    """
    sys.path.insert(0, os.path.abspath(BACKEND))
    sys.modules.pop('app', None)
    mod = importlib.import_module('app')
    d = tempfile.mkdtemp(prefix="ddns-panel-")
    cfg = os.path.join(d, 'cfg.json')
    with open(cfg, 'w') as f:
        json.dump({
            'lan_subnet4': '127.0.0.0/8',
            'panel_allowed_nets': ['127.0.0.0/8'],
            'auth_session_timeout': 1800,
            'auth_token_epoch': 1,
        }, f)
    mod.CONFIG_PATH = cfg
    mod.LISTS_PATH = os.path.join(d, 'lists.json')
    mod.RULES_PATH = os.path.join(d, 'rules.nft')
    return mod


def login(client, appmod):
    """预设一个已登录且世代号匹配的会话（面板接口要登录态）"""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'admin'
        sess['auth_epoch'] = appmod._current_token_epoch()
        sess['last_active'] = time.time()


def test_panel_side():
    app = load_app()

    # ── 纯函数：归一化 ────────────────────────────────────
    check(app._ddns_norm_value("  1.2.3.4 ") == "1.2.3.4",
          "值归一化：去首尾空白")
    check(app._ddns_norm_value("2001:DB8::1") == app._ddns_norm_value("2001:db8:0:0:0:0:0:1"),
          "值归一化：IPv6 的不同写法判为同一个值")
    check(app._ddns_norm_value("") == "", "值归一化：空串仍是空串")
    check(app._ddns_norm_value("mail.example.com") == "mail.example.com",
          "值归一化：非 IP 的域名原样返回")

    # ── 纯函数：匹配记录（多线路保护）─────────────────────
    records = [
        {"RR": "www", "Type": "A", "Value": "1.1.1.1", "RecordId": "1", "Line": "default"},
        {"RR": "www", "Type": "A", "Value": "2.2.2.2", "RecordId": "2", "Line": "telecom"},
        {"RR": "www", "Type": "AAAA", "Value": "::1", "RecordId": "3", "Line": "default"},
        {"RR": "other", "Type": "A", "Value": "3.3.3.3", "RecordId": "4", "Line": "default"},
    ]
    m = app._ddns_match_records(records, "www", "A")
    check(len(m) == 2,
          "同 RR+Type 的 default 与电信两条都匹配上（匹配阶段不分线路）")
    check(sorted(r["RecordId"] for r in m) == ["1", "2"],
          "匹配到的是 RecordId 1 与 2（default + telecom）")
    m2 = app._ddns_match_records(records, "www", "AAAA")
    check(len(m2) == 1 and m2[0]["RecordId"] == "3", "按类型精确匹配 AAAA")
    m3 = app._ddns_match_records(records, "WWW", "a")
    check(len(m3) == 2, "RR/Type 大小写不敏感")
    m4 = app._ddns_match_records(records, "none", "A")
    check(m4 == [], "RR 不匹配时返回空")

    # ── 目标选择：单条就它 / 多条只 default ──────────────────
    only_telecom = [{"RR": "www", "Type": "A", "Value": "1.1.1.1",
                     "RecordId": "77", "Line": "telecom"}]
    check(app._ddns_pick_target(only_telecom)["RecordId"] == "77",
          "只有一条记录时选它（哪怕在电信线路）—— 否则会凭空多出一条 default")
    check(app._ddns_pick_target(m)["RecordId"] == "1",
          "有多条时选 default 线路那条")
    no_default = [
        {"RR": "www", "Type": "A", "Value": "1.1.1.1", "RecordId": "7", "Line": "telecom"},
        {"RR": "www", "Type": "A", "Value": "2.2.2.2", "RecordId": "8", "Line": "unicom"},
    ]
    check(app._ddns_pick_target(no_default)["RecordId"] == "7",
          "多条且没有 default 时取第一条（与旧行为一致，不新增记录）")

    # ── _aliyun_ddns_update 的调用序列 ────────────────────
    calls = []
    fake_total = None      # 分页截断模拟用；None = 按实际条数返回

    def fake_api(action, ak, secret, region, extra=None):
        calls.append((action, extra or {}))
        if action == "DescribeDomainRecords":
            # fake_total 用来模拟「阿里云还有更多记录、这页没取全」的分页截断。
            # None 表示按实际条数返回（正常场景必须如此，否则截断判据会误报）。
            total = fake_total if fake_total is not None else len(fake_records)
            return {"TotalCount": total,
                    "DomainRecords": {"Record": list(fake_records)}}
        return {"RecordId": "999"}

    app._aliyun_api = fake_api
    cfg = {"domain": "example.com", "access_key_id": "AK",
           "access_key_secret": "SK", "region_id": "cn-hangzhou"}

    # 值相同 ⇒ 不调写接口
    calls.clear()
    fake_records = [{"RR": "www", "Type": "A", "Value": "1.2.3.4",
                     "RecordId": "1001", "Line": "default"}]
    r = app._aliyun_ddns_update(cfg, "www", "A", "1.2.3.4")
    check([a for a, _ in calls] == ["DescribeDomainRecords"],
          "面板侧：值相同只查询，不调写接口（实际：%s）" % [a for a, _ in calls])
    check("无需更新" in r["message"], "面板侧：值相同返回「无需更新」")

    # 值不同 ⇒ 只调 Update
    calls.clear()
    fake_records = [{"RR": "www", "Type": "A", "Value": "1.2.3.4",
                     "RecordId": "1001", "Line": "default"}]
    r = app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    seq = [a for a, _ in calls]
    check(seq == ["DescribeDomainRecords", "UpdateDomainRecord"],
          "面板侧：值不同是「查询 + 原地更新」，没有删除没有新增（实际：%s）" % seq)
    check(calls[-1][1].get("RecordId") == "1001", "面板侧：更新沿用原 RecordId")

    # 记录不存在 ⇒ Add
    calls.clear()
    fake_records = []
    r = app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    seq = [a for a, _ in calls]
    check(seq == ["DescribeDomainRecords", "AddDomainRecord"],
          "面板侧：记录不存在才新增（实际：%s）" % seq)

    # 多线路 ⇒ 只改 default
    # ⚠️ 电信那条排在**前面**：取目标时若忽略「只有一条就选它」的特例、
    #   一律去找 default，就会挑错或新增
    calls.clear()
    fake_records = [
        {"RR": "www", "Type": "A", "Value": "9.9.9.9", "RecordId": "2002", "Line": "telecom"},
        {"RR": "www", "Type": "A", "Value": "1.2.3.4", "RecordId": "1001", "Line": "default"},
    ]
    r = app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    check(calls[-1][0] == "UpdateDomainRecord"
          and calls[-1][1].get("RecordId") == "1001",
          "面板侧：多线路时只更新 default 那条，电信那条不动")

    # 只有一条非 default 线路的记录 ⇒ 更新它，不新增 default
    calls.clear()
    fake_records = [{"RR": "www", "Type": "A", "Value": "1.2.3.4",
                     "RecordId": "2002", "Line": "telecom"}]
    r = app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    check(calls[-1][0] == "UpdateDomainRecord"
          and calls[-1][1].get("RecordId") == "2002",
          "面板侧：只有一条（电信线路）记录时更新它，不新增 default")
    check("AddDomainRecord" not in [a for a, _ in calls],
          "面板侧：这种情况下不调用 AddDomainRecord（不凭空多出一条记录）")

    # ══════════════════════════════════════════════════════
    # 批 A 组（面板侧）：2026-11-11 完整代码审查新增
    # ══════════════════════════════════════════════════════

    # ── 更新时沿用原记录的 TTL 与 Line ─────────────────────
    # 阿里云官方文档：TTL 非必填「默认为 600 秒」；Line 非必填「默认为 default」。
    # 不传 ⇒ 用户设的 TTL 被改回 600 / 非 default 线路的记录被搬到 default。
    calls.clear()
    fake_records = [{"RR": "www", "Type": "A", "Value": "1.2.3.4",
                     "RecordId": "2002", "Line": "telecom", "TTL": 3600}]
    app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    check(calls[-1][1].get("TTL") == "3600",
          "面板侧：更新沿用原记录 TTL=3600（实际 %s）" % calls[-1][1].get("TTL"))
    check(calls[-1][1].get("Line") == "telecom",
          "面板侧：更新沿用原记录 Line=telecom（实际 %s）" % calls[-1][1].get("Line"))

    # ── 指定 record_id 时精确定位 ─────────────────────────
    calls.clear()
    fake_records = [
        {"RR": "www", "Type": "A", "Value": "9.9.9.9", "RecordId": "2002", "Line": "telecom"},
        {"RR": "www", "Type": "A", "Value": "1.2.3.4", "RecordId": "1001", "Line": "default"},
    ]
    app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8", record_id="2002")
    check(calls[-1][0] == "UpdateDomainRecord"
          and calls[-1][1].get("RecordId") == "2002",
          "面板侧：指定 record_id=2002 时更新的是那一条（实际 %s）"
          % calls[-1][1].get("RecordId"))

    # ── 分页截断 ⇒ 报错，不新增 ───────────────────────────
    calls.clear()
    fake_records = []
    fake_total = 1200
    err = None
    try:
        app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    except Exception as e:
        err = e
    fake_total = None
    check("AddDomainRecord" not in [a for a, _ in calls],
          "面板侧：分页截断时不新增记录（实际：%s）" % [a for a, _ in calls])
    check(err is not None and "分页截断" in str(err),
          "面板侧：分页截断时如实报错（实际 %r）" % (err,))

    # ── 目标缺 RecordId ⇒ 报错，不退回删+增 ───────────────
    calls.clear()
    fake_records = [{"RR": "www", "Type": "A", "Value": "1.2.3.4", "Line": "default"}]
    err = None
    try:
        app._aliyun_ddns_update(cfg, "www", "A", "5.6.7.8")
    except Exception as e:
        err = e
    check("UpdateDomainRecord" not in [a for a, _ in calls],
          "面板侧：目标缺 RecordId 时不发起更新（实际：%s）" % [a for a, _ in calls])
    check(err is not None and "RecordId" in str(err),
          "面板侧：目标缺 RecordId 时如实报错（实际 %r）" % (err,))

    # 归一化要在**调用链上**也生效：只测纯函数不够 ——
    # 纯函数对了、调用处没用它，照样会把同一地址判成「值变了」。
    calls.clear()
    fake_records = [{"RR": "www6", "Type": "AAAA", "Value": "2001:db8::1",
                     "RecordId": "1009", "Line": "default"}]
    r = app._aliyun_ddns_update(cfg, "www6", "AAAA", "2001:db8:0:0:0:0:0:1")
    check([a for a, _ in calls] == ["DescribeDomainRecords"],
          "面板侧：IPv6 同一地址的不同写法判为「未变化」，不调写接口（实际：%s）"
          % [a for a, _ in calls])

    # 面板侧永远不调 Delete
    check("DeleteDomainRecord" not in os.path.join(APP_PATH) or
          "DeleteDomainRecord" not in open(APP_PATH, encoding="utf-8").read().split(
              "def _aliyun_ddns_update")[1].split("\ndef ")[0],
          "面板侧更新函数里没有 DeleteDomainRecord")

    # ── A 记录自动取公网 IPv4（测试接口）─────────────────
    saved = app._fetch_public_ipv4
    try:
        client = app.app.test_client()
        login(client, app)

        app._fetch_public_ipv4 = lambda: None
        resp = client.post("/api/aliyun-ddns/test",
                            json={"rr": "www", "type": "A"})
        body = resp.get_json() or {}
        check(resp.status_code == 400 and "公网 IPv4" in str(body.get("message", "")),
              "A 记录取不到公网 IPv4 时返回 400 并说明原因（实际 %d / %s）"
              % (resp.status_code, body.get("message")))

        # 取得到公网 IP 时，接口应当走到「去查阿里云」这一步，
        # 而不是停在「value 不能为空」。
        app._fetch_public_ipv4 = lambda: "203.0.113.77"
        resp = client.post("/api/aliyun-ddns/test",
                            json={"rr": "www", "type": "A"})
        body = resp.get_json() or {}
        check(resp.status_code == 400 and "域名" in str(body.get("message", "")),
              "取到公网 IP 后继续走到「没配域名」这一步（实际 %d / %s）"
              % (resp.status_code, body.get("message")))
        check("value 都不能为空" not in str(body.get("message", "")),
              "不再是「value 都不能为空」——A 记录的值由后端自己取")
    finally:
        app._fetch_public_ipv4 = saved


# ══════════════════════════════════════════════════════════
# 六、前端
# ══════════════════════════════════════════════════════════

def strip_js_comments(src):
    """去掉 JS 注释（行注释 + 块注释），保留字符串字面量里的内容。

    「不该出现的东西」类断言必须用去注释版源码 ——
    否则注释里写一句「原来这里传的是 rec.Value」就误判。
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'" or c == '`':
            quote = c
            out.append(c)
            i += 1
            while i < n:
                out.append(src[i])
                if src[i] == "\\":
                    i += 1
                    if i < n:
                        out.append(src[i])
                        i += 1
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def test_frontend():
    src = open(FRONTEND_JS, encoding="utf-8").read()
    code = strip_js_comments(src)
    m = re.search(r"/api/aliyun-ddns/test'\s*,\s*\{(.*?)\}\s*\)", code, re.S)
    check(m is not None, "能定位到前端调用 /api/aliyun-ddns/test 的那段代码")
    if m is None:
        return
    body = m.group(1)
    # ⚠ 2026-11-11（批 C）改了这条规则：
    #   A / AAAA 传空值（后端自己去取，和 cron 脚本同一条路径），
    #   但 CNAME / TXT **必须**传阿里云上现存的值 ——
    #   这两种类型没有「自动取值」的来源（后端只在 A 时取公网 IP、
    #   AAAA 读中转文件），不传值就恒 400「rr, type, value 都不能为空」。
    #   ⇒ 断言从「整体不传旧值」改成「A/AAAA 分支不传旧值」。
    #
    # ⚠ 这里只是**文本烟测**；真正的行为判据在
    #   tests/test_frontend_aliyun_batch_c.js（看真的发出去的请求体）。
    check("rtypeU === 'A' || rtypeU === 'AAAA'" in body,
          "测试按钮对 A/AAAA 走「传空值」的分支")
    check("rec.Value || rec.value || ''" in body,
          "测试按钮对 CNAME/TXT 传阿里云上现存的值（否则后端恒 400）")


def main():
    srv = start_fake()
    try:
        print("--- cron 脚本（设备上真正跑的那份）---")
        test_cron_script(srv)
        print("--- 面板侧 ---")
        test_panel_side()
        print("--- 前端 ---")
        test_frontend()
    finally:
        srv.shutdown()
        srv.server_close()
    print("  合计: [PASS] %d   [FAIL] %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
