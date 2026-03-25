#!/usr/bin/env python3
"""阿里云 DDNS 自动更新脚本（由 nftables-web 生成）"""
import json, sys, os, urllib.request, urllib.parse, hmac, hashlib, base64, datetime, uuid

CONFIG_PATH = "/etc/nftables/aliyun-ddns-config.json"

def _sign(params, secret):
    qs = "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    return base64.b64encode(hmac.new((secret + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()

def _api(action, ak_id, ak_secret, region, extra={}):
    params = {"Action": action, "Format": "json", "Version": "2015-01-09", "AccessKeyId": ak_id,
              "SignatureMethod": "HMAC-SHA1", "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "SignatureVersion": "1.0", "SignatureNonce": str(uuid.uuid4()), "RegionId": region}
    params.update(extra)
    params["Signature"] = _sign(params, ak_secret)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
        return json.loads(resp.read())

try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
    records = config.get("records", [])
    ak_id = config.get("access_key_id", "")
    ak_secret = config.get("access_key_secret", "")
    region = config.get("region_id", "cn-hangzhou")
    domain = config.get("domain", "")
    if not ak_id or not ak_secret or not domain:
        sys.exit(0)
    
    source_map = {"router": "0"}
    for i in range(1, 10):
        source_map[f"rule_{i}"] = str(i)
    
    for rec in records:
        if not rec.get("enabled"):
            continue
        rr = rec.get("rr", "")
        rtype = rec.get("type", "")
        ipv6_source = rec.get("ipv6_source", "")
        value = rec.get("value", "").strip()
        
        if ipv6_source:
            idx = source_map.get(ipv6_source)
            if idx is not None:
                try:
                    with open(f"/tmp/ddns-ipv6-{idx}") as f:
                        value = f.read().strip()
                except:
                    pass
            if not value:
                continue
        # A 记录自动获取路由器公网 IPv4
        if rtype == "A":
            try:
                import urllib.request as _ur
                _req = _ur.Request("https://ipv4.icanhazip.com")
                with _ur.urlopen(_req, timeout=5) as _r:
                    value = _r.read().decode().strip()
            except:
                pass
        if not value:
            continue
        
        # 查询现有记录，值相同则跳过
        result = _api("DescribeDomainRecords", ak_id, ak_secret, region, {"DomainName": domain, "RRKeyWord": rr, "Type": rtype})
        found_same = False
        for r in result.get("DomainRecords", {}).get("Record", []):
            if r.get("RR") == rr and r.get("Type") == rtype:
                if r.get("Value") == value:
                    found_same = True
                else:
                    _api("DeleteDomainRecord", ak_id, ak_secret, region, {"RecordId": str(r["RecordId"])})
                break
        if not found_same:
            _api("AddDomainRecord", ak_id, ak_secret, region, {"DomainName": domain, "RR": rr, "Type": rtype, "Value": value})
except Exception as e:
    with open("/tmp/aliyun-ddns-error.log", "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()}: {e}\n")
    sys.exit(1)
