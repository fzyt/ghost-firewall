#!/usr/bin/env python3
"""阿里云 DDNS「反复删除重新上传」现场取证脚本（只读）

用途
----
本脚本**只做观测，不做任何修改**：
- 不写 DNS 记录（不 Add / 不 Delete / 不 Update）
- 不改 crontab、不改配置文件、不改设备上任何文件
- 唯一的写动作是把观测快照追加到 /tmp/ddns-diag-snapshots.jsonl（tmpfs，重启即失）

它要回答的问题只有一个：
    「面板里那条记录每 10 分钟被删掉又重新添加」，
    到底是【代码判定错了】（该跳过的没跳过），
    还是【公网 IPv4 真的在变】（代码在如实同步）。

怎么用
------
    # 1) 拷到 DDNS 那台设备上（SSH 过去，或 scp）
    # 2) 跑一次
    python3 /tmp/ddns-aliyun-diagnose.py
    # 3) 等 11 分钟（cron 周期是 */10 * * * *），再跑一次
    python3 /tmp/ddns-aliyun-diagnose.py

第二次运行会把「与上一次快照的对比」打印出来。

判定表
------
    记录值变了 + 记录 ID 也变了  => 公网 IP 真的在变（外部原因），代码行为正确
    记录值没变 + 记录 ID 变了  => 代码 bug：值相同却仍然删了重加
    记录值没变 + 记录 ID 没变  => 本轮 cron 根本没动这条记录
    同 RR+Type 出现多行         => 存在重复记录，脚本每次只处理第一条
    多个源返回的 **IPv4** 不同  => 设备是多出口（负载均衡/CGNAT 池），根源在这
    同一个源多次采样的 IPv4 不同 => 公网出口 IPv4 在漂移，同上

⚠️ 只有 IPv4 参与判定：出问题的是 A 记录（IPv4），
   而探测源在有 IPv6 的网络上可能返回 IPv6 地址，那是另一个出口、另一个地址族。

选项
----
    --samples N     每个查 IP 源采几次（默认 3）
    --interval N    两次采样间隔秒数（默认 5）
    --no-api        不调用阿里云 API（只测本机侧）
    --api-only      跳过本机侧采样，只调阿里云 API
    --quiet         只打印结论区块

依赖：Python 3 标准库，无第三方包。OpenWrt 的 python3 可直接跑。
"""

import json
import os
import sys
import time
import datetime
import urllib.request
import urllib.parse
import hmac
import hashlib
import base64
import uuid

# ==== 路径（与 backend/app.py 保持一致；可用环境变量覆盖）====
CONFIG_PATH = os.environ.get(
    "NFTABLES_WEB_ALIYUN_CONFIG", "/etc/nftables/aliyun-ddns-config.json")
SCRIPT_PATH = os.environ.get(
    "NFTABLES_WEB_ALIYUN_SCRIPT", "/opt/nftables-web-v2/aliyun-ddns-update.py")
CRON_ERROR_LOG = "/tmp/aliyun-ddns-error.log"
SNAPSHOT_PATH = "/tmp/ddns-diag-snapshots.jsonl"

# ==== 查公网 IPv4 的探针 ====
# 多个源一起用，是为了分辨两件完全不同的事：
#   同一个源多次采样不同 => 出口 IP 在漂移（多出口 / CGNAT 池）
#   不同源之间就不同   => 出口链路本身不止一条
#
# ⚠️ 关键：只有 **IPv4** 参与比对。
# 用户的出问题的记录是 **A 记录（IPv4）**，而 A 记录的取值只来自
# ipv4.icanhazip.com（见 backend/app.py 里 cron 脚本的取值分支）。
# 有些源（如 ident.me）在有 IPv6 的网络上会返回 **IPv6 地址**，
# 那是另一个出口、另一个地址族，跟 A 记录的值毫无关系。
# 把 IPv6 混进比对会得出「多出口」的假结论 —— 这里显式按地址族分开。
IP_SOURCES = [
    ("icanhazip", "https://ipv4.icanhazip.com"),   # ← cron 脚本实际用的就是这个源
    ("ipify", "http://api.ipify.org"),
    ("myip", "https://api.myip.com"),
    ("identme", "https://ident.me"),
]

ALIYUN_ENDPOINT = "https://alidns.aliyuncs.com/"
ALIYUN_API_VERSION = "2015-01-09"


def _line(ch="=", n=72):
    return ch * n


def _section(title):
    print("\n" + _line())
    print(title)
    print(_line())


def _mask(secret):
    """脱敏：只留首 4 尾 4，中间用固定长度遮盖。绝不打印明文。"""
    s = str(secret or "")
    if not s:
        return "(空)"
    if len(s) <= 8:
        return "(长度 %d，已隐藏)" % len(s)
    return s[:4] + "****" + s[-4:]


def _read_text(path, limit=200000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception as e:
        return None


# ============================ 本机侧 ============================

def probe_cron():
    """读 crontab 里有没有 DDNS 条目（只读 crontab -l）"""
    out = {"found": [], "error": None}
    try:
        import subprocess
        p = subprocess.run(["crontab", "-l"], capture_output=True, timeout=15)
        txt = (p.stdout or b"").decode("utf-8", "replace")
        if p.returncode != 0:
            out["error"] = "crontab -l 返回码 %d：%s" % (
                p.returncode, (p.stderr or b"").decode("utf-8", "replace").strip())
            return out
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "aliyun" in s or "ddns" in s.lower():
                out["found"].append(s)
    except Exception as e:
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out


def probe_script_file():
    """设备上实际的 cron 脚本是否存在、关键行长什么样"""
    res = {"exists": False, "size": None, "mtime": None, "key_lines": [], "error": None}
    if not os.path.exists(SCRIPT_PATH):
        res["error"] = "脚本不存在：%s" % SCRIPT_PATH
        return res
    res["exists"] = True
    try:
        st = os.stat(SCRIPT_PATH)
        res["size"] = st.st_size
        res["mtime"] = datetime.datetime.fromtimestamp(
            st.st_mtime).isoformat(timespec="seconds")
    except Exception as e:
        res["error"] = "%s: %s" % (type(e).__name__, e)
    txt = _read_text(SCRIPT_PATH)
    if txt:
        want = ("DeleteDomainRecord", "AddDomainRecord", "UpdateDomainRecord",
                "DescribeDomainRecords", "icanhazip", "found_same",
                'get("rr"', 'get("type"', 'get("RR"', 'get("Type"')
        for i, line in enumerate(txt.splitlines(), 1):
            if any(w in line for w in want):
                res["key_lines"].append("%4d| %s" % (i, line.rstrip()))
    return res


def probe_config():
    """读面板写下去的 DDNS 配置（secret 脱敏）"""
    res = {"exists": False, "records": [], "error": None, "raw_keys": []}
    if not os.path.exists(CONFIG_PATH):
        res["error"] = "配置文件不存在：%s" % CONFIG_PATH
        return res
    res["exists"] = True
    try:
        with open(CONFIG_PATH, "r", errors="replace") as f:
            cfg = json.load(f)
    except Exception as e:
        res["error"] = "配置解析失败 %s: %s" % (type(e).__name__, e)
        return res
    res["domain"] = cfg.get("domain", "")
    res["region_id"] = cfg.get("region_id", "")
    res["access_key_id"] = cfg.get("access_key_id", "")
    res["access_key_secret"] = _mask(cfg.get("access_key_secret", ""))
    for rec in cfg.get("records", []):
        res["records"].append({
            "keys": sorted(rec.keys()),
            "rr": rec.get("rr", rec.get("RR", "")),
            "type": rec.get("type", rec.get("Type", "")),
            "value": rec.get("value", rec.get("Value", "")),
            "enabled": rec.get("enabled", False),
            "ipv6_source": rec.get("ipv6_source", ""),
            "record_id": rec.get("record_id", rec.get("RecordId", "")),
        })
    return res


def probe_error_log():
    txt = _read_text(CRON_ERROR_LOG)
    if not txt:
        return {"exists": os.path.exists(CRON_ERROR_LOG), "lines": []}
    lines = [l for l in txt.splitlines() if l.strip()]
    return {"exists": True, "lines": lines[-20:], "count": len(lines)}


def _is_ipv4(text):
    """判断字符串是不是一个合法的 IPv4 地址（IPv6 必须排除出 A 记录的比对）"""
    import ipaddress
    try:
        return isinstance(ipaddress.ip_address(str(text).strip()), ipaddress.IPv4Address)
    except Exception:
        return False


def _judge_stability(vals, samples):
    """判断一组采样值里的 IPv4 是否稳定（纯函数，可单测）

    ⚠️ 必须拿**原始采样值**判断，不能拿去重后的列表判断：
       去重列表只要非空就恒为长度 1，拿它跟 samples 比会把
       「采样 2 次都是同一个 IP」误判成「不稳定」。

    返回 True / False / None（一个 IPv4 都没采到时为 None，表示无法判断）
    """
    v4_samples = [v for v in vals if _is_ipv4(v)]
    if not v4_samples:
        return None
    return len(set(v4_samples)) == 1 and len(v4_samples) == samples


def probe_public_ip(samples=3, interval=5):
    """对每个探测源连采多次，用于判断出口 IPv4 是否稳定。

    返回结构里 v4 只装 IPv4，v6 单独装 IPv6，两者不混。
    """
    result = {}
    for name, url in IP_SOURCES:
        vals = []
        errs = []
        for _ in range(samples):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "curl/8", "Accept": "text/plain"})
                with urllib.request.urlopen(req, timeout=8) as r:
                    v = r.read().decode("utf-8", "replace").strip()
                vals.append(v)
            except Exception as e:
                errs.append("%s: %s" % (type(e).__name__, e))
            time.sleep(interval)
        v4 = []
        v6 = []
        other = []
        for v in vals:
            if _is_ipv4(v):
                if v not in v4:
                    v4.append(v)
            elif ":" in v:
                if v not in v6:
                    v6.append(v)
            elif v not in other:
                other.append(v)
        # ⚠️ 稳定性必须拿**原始样本**判断，不能拿去重后的列表判断：
        #    去重列表只要非空就恒为长度 1，拿它跟 samples 比会把
        #    「采样 2 次都是同一个 IP」误判成「不稳定」。
        v4_samples = [v for v in vals if _is_ipv4(v)]
        stable = _judge_stability(vals, samples)
        result[name] = {
            "samples": vals,
            "v4": v4,
            "v6": v6,
            "other": other,
            "errors": errs,
            "v4_sample_count": len(v4_samples),
            "stable": stable,
        }
    return result


# ============================ 阿里云侧（只读） ============================

def _sign(params, secret):
    qs = "&".join(
        "%s=%s" % (urllib.parse.quote(str(k), safe=''),
                   urllib.parse.quote(str(v), safe=''))
        for k, v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    return base64.b64encode(
        hmac.new((secret + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()


def aliyun_describe(ak_id, ak_secret, region, domain):
    """只读：DescribeDomainRecords，把域下所有记录的原始字段拉出来"""
    params = {
        "Action": "DescribeDomainRecords",
        "Format": "json",
        "Version": ALIYUN_API_VERSION,
        "AccessKeyId": ak_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "RegionId": region,
        "DomainName": domain,
    }
    params["Signature"] = _sign(params, ak_secret)
    url = ALIYUN_ENDPOINT + "?" + "&".join(
        "%s=%s" % (k, urllib.parse.quote(str(v), safe='')) for k, v in params.items())
    with urllib.request.urlopen(urllib.request.Request(url), timeout=20) as resp:
        return json.loads(resp.read())


# ============================ 快照与对比 ============================

def load_snapshots():
    out = []
    txt = _read_text(SNAPSHOT_PATH)
    if not txt:
        return out
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def save_snapshot(snap):
    try:
        with open(SNAPSHOT_PATH, "a") as f:
            f.write(json.dumps(snap, ensure_ascii=False) + "\n")
    except Exception as e:
        print("[WARN] 快照写不进去（不影响诊断）：%s: %s" % (type(e).__name__, e))


def compare(prev, cur):
    """与上一次快照对比：阿里云侧记录 ID/值有没有变，本机侧 IP 变没变"""
    lines = []
    pv = {(r.get("rr"), r.get("type"), r.get("value")) for r in prev.get("records", [])}
    cv = {(r.get("rr"), r.get("type"), r.get("value")) for r in cur.get("records", [])}
    pids = {(r.get("rr"), r.get("type")): r.get("record_id") for r in prev.get("records", [])}
    cids = {(r.get("rr"), r.get("type")): r.get("record_id") for r in cur.get("records", [])}
    for key in sorted(cids.keys(), key=lambda x: (str(x[0]), str(x[1]))):
        rr, ty = key
        old_id = pids.get(key)
        new_id = cids.get(key)
        vals = [v for (a, b, v) in cv if a == rr and b == ty]
        old_vals = [v for (a, b, v) in pv if a == rr and b == ty]
        if old_id is None:
            lines.append("[新增] %s.%s -> 值=%s 记录ID=%s" % (rr, ty, vals, new_id))
            continue
        id_changed = (old_id != new_id)
        val_changed = (old_vals != vals)
        tag = "值变+ID变" if (id_changed and val_changed) else (
            "值没变+ID变" if id_changed else (
                "值变+ID没变" if val_changed else "值没变+ID没变"))
        lines.append("[%s] %s.%s 上次值=%s 本次值=%s 上次ID=%s 本次ID=%s" % (
            tag, rr, ty, old_vals, vals, old_id, new_id))
    for key in sorted(set(pids.keys()) - set(cids.keys()), key=lambda x: (str(x[0]), str(x[1]))):
        lines.append("[消失] %s.%s 上次ID=%s" % (key[0], key[1], pids.get(key)))
    return lines


def print_conclusion(snap, prev, ipinfo):
    lines = []
    # 1) 出口 IPv4 稳定性 —— 只看 IPv4。
    #    A 记录的取值只来自 ipv4.icanhazip.com，IPv6 属于另一个地址族，
    #    混进比对会得出「多出口」的假结论。
    all_v4 = set()
    for info in ipinfo.values():
        for v in info.get("v4", []):
            all_v4.add(v)
    drifting = [name for name, info in ipinfo.items()
                if info.get("v4") and not info.get("stable")]
    if len(all_v4) > 1:
        lines.append("[发现] 多个探测源拿到的公网 IPv4 不一致：%s" % sorted(all_v4))
        lines.append("       => 设备到公网不止一条 IPv4 出口，或出口 IPv4 在漂移。")
        lines.append("       => 这种情况下「记录值每轮都变」是客观事实，不是代码判错。")
    elif drifting:
        lines.append("[发现] 同一源多次采样 IPv4 不一致：%s" % {
            k: v.get("v4") for k, v in ipinfo.items() if v.get("v4")})
        lines.append("       => 出口 IPv4 在漂移，同上结论。")
    elif all_v4:
        lines.append("[正常] 公网 IPv4 稳定：%s" % sorted(all_v4))
    v6vals = sorted({v for info in ipinfo.values() for v in info.get("v6", [])})
    if v6vals:
        lines.append("[旁证] 探测到的 IPv6 地址（与 A 记录无关，只看出网结构）：%s" % v6vals)

    # 1b) 决定性判据：cron 脚本这次真正会算出来的值 vs 阿里云现存的 A 记录值
    ican_v4 = (ipinfo.get("icanhazip") or {}).get("v4", [])
    aliyun_v4 = sorted({r.get("value") for r in snap.get("records", [])
                        if r.get("type") == "A" and r.get("value")})
    if ican_v4 and aliyun_v4:
        if ican_v4[0] in aliyun_v4:
            lines.append("[决定性] cron 脚本这次算出的 IPv4（%s）已经等于阿里云现存的 A 记录值"
                         % ican_v4[0])
            lines.append("           => 脚本本该判定「值相同、跳过」；"
                         "若记录 ID 却变了，就是代码 bug（匹配到了错的记录）")
        else:
            lines.append("[决定性] cron 脚本这次算出的 IPv4（%s）与阿里云现存 A 记录值 %s 不同"
                         % (ican_v4[0], aliyun_v4))
            lines.append("           => 值是真的变了，这一轮删+加属于如实同步，不是判错")

    # 2) 阿里云侧记录状况
    recs = snap.get("records", [])
    dup = {}
    for r in recs:
        dup.setdefault((r.get("rr"), r.get("type")), []).append(r)
    for key, group in dup.items():
        if len(group) > 1:
            lines.append("[发现] 同 RR+Type 有 %d 条记录（重复记录）：%s" % (
                len(group), [(g.get("record_id"), g.get("value")) for g in group]))
    for r in recs:
        if r.get("locked"):
            lines.append("[注意] 记录 %s.%s 处于 Locked 状态，删除会失败" % (
                r.get("rr"), r.get("type")))

    # 3) 与上次的对比
    if prev:
        lines.append("[对比] 与上一次快照（%s）的差异：" % prev.get("ts"))
        for l in compare(prev, snap):
            lines.append("       " + l)
        vals_same_ids_diff = any(
            l.startswith("[值没变+ID变]") for l in compare(prev, snap))
        if vals_same_ids_diff:
            lines.append("       => 结论：记录值没变但记录 ID 变了 —— 这是代码 bug，")
            lines.append("          该跳过的没跳过，删掉重加了同一条。")
        val_changed = any(l.startswith("[值变") for l in compare(prev, snap))
        if val_changed:
            lines.append("       => 记录值确实变了 —— 公网 IP 真的在变。")
    else:
        lines.append("[提示] 这是第一次采样，没有可对比的历史快照。")
        lines.append("       请等 11 分钟后再跑一次本脚本，才能拿到「值变没变 / ID 变没变」的对比。")
    return lines


# ============================ 主流程 ============================

def main():
    args = sys.argv[1:]
    samples = 3
    interval = 5
    no_api = False
    api_only = False
    quiet = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--samples" and i + 1 < len(args):
            samples = int(args[i + 1]); i += 2
        elif a == "--interval" and i + 1 < len(args):
            interval = int(args[i + 1]); i += 2
        elif a == "--no-api":
            no_api = True; i += 1
        elif a == "--api-only":
            api_only = True; i += 1
        elif a == "--quiet":
            quiet = True; i += 1
        else:
            print("未知参数：%s" % a)
            print(__doc__)
            return 2

    snap = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "records": [],
        "api_error": None,
        "ip": {},
    }

    # ---- 本机侧 ----
    if not api_only:
        _section("一、本机侧：cron / 脚本 / 配置 / 错误日志")
        cron = probe_cron()
        print("[cron 条目] 共 %d 条" % len(cron["found"]))
        for c in cron["found"]:
            print("    " + c)
        if cron["error"]:
            print("    [注意] " + cron["error"])
        if not cron["found"] and not cron["error"]:
            print("    [发现] crontab 里没有任何 DDNS/aliyun 条目")
            print("           => 自动更新压根没跑过，所谓「反复删加」不可能来自 cron")

        print()
        sf = probe_script_file()
        print("[设备上的 cron 脚本] %s" % SCRIPT_PATH)
        if not sf["exists"]:
            print("    [发现] " + str(sf["error"]))
        else:
            print("    存在，大小 %s 字节，最后修改 %s" % (sf["size"], sf["mtime"]))
            print("    关键行：")
            for l in sf["key_lines"]:
                print("    " + l)
            if not any("UpdateDomainRecord" in l for l in sf["key_lines"]):
                print("    [发现] 脚本里没有 UpdateDomainRecord —— 用的是「删除+新增」")
                print("           => 控制台上看到的「记录被删掉又新建」就是这么来的")

        print()
        cf = probe_config()
        print("[面板写下的配置] %s" % CONFIG_PATH)
        if not cf["exists"]:
            print("    [发现] " + str(cf["error"]))
        else:
            print("    域名=%s 地域=%s" % (cf.get("domain"), cf.get("region_id")))
            print("    AccessKeyId=%s" % cf.get("access_key_id"))
            print("    AccessKeySecret=%s" % cf.get("access_key_secret"))
            print("    记录条数=%d" % len(cf["records"]))
            for r in cf["records"]:
                print("      - 键=%s" % r["keys"])
                print("        rr=%r type=%r value=%r enabled=%r ipv6_source=%r record_id=%r"
                      % (r["rr"], r["type"], r["value"], r["enabled"],
                         r["ipv6_source"], r["record_id"]))
                if "rr" not in r["keys"] and "RR" in r["keys"]:
                    print("        [注意] 只有大写键 RR —— 脚本里 rec.get('rr') 取不到，"
                          "该记录永远匹配不上")
                if "type" not in r["keys"] and "Type" in r["keys"]:
                    print("        [注意] 只有大写键 Type —— 脚本里 rec.get('type') 取不到，"
                          "该记录永远匹配不上")
                if r["type"] == "A" and not r["enabled"]:
                    print("        [注意] A 记录但未启用 —— cron 会 continue 跳过它")
            snap["config"] = cf

        print()
        el = probe_error_log()
        print("[cron 错误日志] %s" % CRON_ERROR_LOG)
        if not el.get("exists"):
            print("    没有这个文件（正常路径本来就不写日志，只有异常才写）")
        else:
            print("    共 %s 行，末尾最多 20 条：" % el.get("count"))
            for l in el.get("lines", []):
                print("    " + l)

        # ---- 公网 IP 采样 ----
        print()
        _section("二、公网 IPv4 采样（每个源 %d 次，间隔 %d 秒）" % (samples, interval))
        ipinfo = probe_public_ip(samples, interval)
        snap["ip"] = ipinfo
        for name, info in ipinfo.items():
            print("[%s] %s" % (name, info.get("samples")))
            if info.get("v4") and not info.get("stable"):
                print("    [发现] 同一源采样 IPv4 不一致：%s" % info["v4"])
            if info.get("v6"):
                print("    [旁证] 该源返回的是 IPv6（%s），与 A 记录无关，不参与比对"
                      % info["v6"])
            for e in info.get("errors", []):
                print("    [取不到] %s" % e)

    # ---- 阿里云侧（只读） ----
    if not no_api:
        _section("三、阿里云侧：DescribeDomainRecords（只读，不做任何写入）")
        cf = snap.get("config") or probe_config()
        ak_id = cf.get("access_key_id") or ""
        ak_secret = ""
        if cf.get("exists"):
            try:
                with open(CONFIG_PATH, "r", errors="replace") as f:
                    ak_secret = json.load(f).get("access_key_secret", "")
            except Exception:
                ak_secret = ""
        domain = cf.get("domain") or ""
        if not (ak_id and ak_secret and domain):
            print("    [跳过] 本机没有可用的阿里云配置（缺 AK / 域名），无法查询")
        else:
            try:
                data = aliyun_describe(ak_id, ak_secret,
                                       cf.get("region_id") or "cn-hangzhou", domain)
                total = data.get("TotalCount")
                page = data.get("PageSize")
                recs = data.get("DomainRecords", {}).get("Record", [])
                print("    TotalCount=%s PageSize=%s 返回条数=%d" % (total, page, len(recs)))
                for r in recs:
                    snap["records"].append({
                        "record_id": r.get("RecordId"),
                        "rr": r.get("RR"),
                        "type": r.get("Type"),
                        "value": r.get("Value"),
                        "line": r.get("Line"),
                        "ttl": r.get("TTL"),
                        "status": r.get("Status"),
                        "locked": r.get("Locked"),
                    })
                    print("    RR=%-20s Type=%-6s Value=%-40s ID=%-12s Line=%s TTL=%s Status=%s Locked=%s"
                          % (r.get("RR"), r.get("Type"), r.get("Value"), r.get("RecordId"),
                             r.get("Line"), r.get("TTL"), r.get("Status"), r.get("Locked")))
                if total is not None and len(recs) < int(total):
                    print("    [注意] TotalCount(%s) > 本页返回(%d)：还有记录没被脚本看到" % (
                        total, len(recs)))
            except Exception as e:
                snap["api_error"] = "%s: %s" % (type(e).__name__, e)
                print("    [查询失败] %s: %s" % (type(e).__name__, e))

    # ---- 结论 ----
    _section("四、结论")
    prev_list = load_snapshots()
    prev = prev_list[-1] if prev_list else None
    for l in print_conclusion(snap, prev, snap.get("ip", {})):
        print(l)

    save_snapshot(snap)
    print()
    print("快照已追加到 %s（共 %d 份）" % (SNAPSHOT_PATH, len(prev_list) + 1))
    print("把上面全部输出贴给分析方即可。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
