#!/usr/bin/env python3
import urllib.request, urllib.parse, hmac, hashlib, base64, datetime, json, uuid

with open("/etc/nftables/aliyun-ddns-config.json") as f:
    c = json.load(f)
AK_ID = c["access_key_id"]
AK_SEC = c["access_key_secret"]
domain = c["domain"]

def sign(params):
    qs = "&".join(f"{urllib.parse.quote(str(k),safe='')}={urllib.parse.quote(str(v),safe='')}" for k,v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/",safe='') + "&" + urllib.parse.quote(qs,safe='')
    return base64.b64encode(hmac.new((AK_SEC+"&").encode(), sts.encode(), hashlib.sha1).digest()).decode()

def api(action, extra={}):
    params = {"Action":action,"Format":"json","Version":"2015-01-09","AccessKeyId":AK_ID,
              "SignatureMethod":"HMAC-SHA1","Timestamp":datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "SignatureVersion":"1.0","SignatureNonce":str(uuid.uuid4()),"RegionId":"cn-hangzhou"}
    params.update(extra)
    params["Signature"] = sign(params)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v),safe='')}" for k,v in params.items())
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())

# 查询 mail 记录
r = api("DescribeDomainRecords", {"DomainName":domain,"RRKeyWord":"mail","Type":"AAAA"})
recs = r.get("DomainRecords",{}).get("Record",[])
if not recs:
    print("未找到 mail AAAA 记录")
    exit()
rec = recs[0]
rid = rec["RecordId"]
old_val = rec["Value"]
print(f"当前: RR={rec['RR']}, Value={old_val}, RecordId={rid}")

# 用 ModifyDomainRecord 直接修改
new_ip = "240e:390:9999::1"
print(f"\n尝试 ModifyDomainRecord → {new_ip}")
r2 = api("ModifyDomainRecord", {"RecordId": str(rid), "RR": "mail", "Type": "AAAA", "Value": new_ip})
print(f"结果: {json.dumps(r2, ensure_ascii=False)}")

# 确认
r3 = api("DescribeDomainRecords", {"DomainName":domain,"RRKeyWord":"mail","Type":"AAAA"})
new_rec = r3["DomainRecords"]["Record"][0]
print(f"修改后: Value={new_rec['Value']}, RecordId={new_rec['RecordId']}")

# 恢复原值
print(f"\n恢复原值: {old_val}")
r4 = api("ModifyDomainRecord", {"RecordId": str(new_rec["RecordId"]), "RR": "mail", "Type": "AAAA", "Value": old_val})
print(f"结果: {json.dumps(r4, ensure_ascii=False)}")
