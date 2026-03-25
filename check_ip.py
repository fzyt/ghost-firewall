#!/usr/bin/env python3
import json
with open("/etc/nftables/aliyun-ddns-config.json") as f:
    c = json.load(f)

import urllib.request, urllib.parse, hmac, hashlib, base64, datetime, uuid
def sign(params, secret):
    qs = "&".join(f"{urllib.parse.quote(str(k),safe='')}={urllib.parse.quote(str(v),safe='')}" for k,v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/",safe='') + "&" + urllib.parse.quote(qs,safe='')
    return base64.b64encode(hmac.new((secret+"&").encode(), sts.encode(), hashlib.sha1).digest()).decode()
def api(action, extra={}):
    params = {"Action":action,"Format":"json","Version":"2015-01-09","AccessKeyId":c["access_key_id"],
              "SignatureMethod":"HMAC-SHA1","Timestamp":datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "SignatureVersion":"1.0","SignatureNonce":str(uuid.uuid4()),"RegionId":c.get("region_id","cn-hangzhou")}
    params.update(extra)
    params["Signature"] = sign(params, c["access_key_secret"])
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v),safe='')}" for k,v in params.items())
    with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
        return json.loads(resp.read())

r = api("DescribeDomainRecords", {"DomainName": c["domain"], "RRKeyWord": "mail", "Type": "AAAA"})
for rec in r.get("DomainRecords",{}).get("Record",[]):
    if rec.get("RR") == "mail":
        print(f"阿里云: {rec['Value']}")
