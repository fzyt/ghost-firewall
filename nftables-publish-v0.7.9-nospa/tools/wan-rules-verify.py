#!/usr/bin/env python3
"""WAN 规则有效性验证 v2 —— 判据改成读内核日志。

v1 的教训（写在这里免得再踩）：
  · 模板里一条 counter 都没有 → 看计数器等于什么都没测
  · BOTNET 规则在 input 链不在 input_wan 链 → 查错链也等于没测
  真正能判定的只有内核日志里的 `log prefix "[XXX] "`。

测法：把 wan_if 临时设成 netns 的入接口名，测完改回真实接口。
每个用例断言「日志里出现了对应的前缀」，没出现就是规则没生效。
"""
import ctypes
import http.cookiejar
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

from pyroute2 import IPRoute

CLONE_NEWNET = 0x40000000
VETH_HOST = '192.0.2.1'
VETH_CLI = '192.0.2.2'
WAN_ADDR = '203.0.113.5'
TEST_WAN_IF = 'tw0'
REAL_WAN_IF = 'eth1'
CONFIG = '/etc/nftables/nftables-web-config.json'
RULES = '/etc/nftables.d/99-custom-rules.nft'
KNOCK = (10376, 23224, 32760, 13550)
T0 = time.time()


def log(*a):
    print('[%6.1fs]' % (time.time() - T0), *a)
    sys.stdout.flush()


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)


def names(ipr):
    return {a.get_attr('IFLA_IFNAME'): a['index'] for a in ipr.get_links()}


def logread_mark():
    return len(sh('logread').stdout.splitlines())


def logread_since(mark):
    return sh('logread').stdout.splitlines()[mark:]


def login_opener():
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx))
    op.open(urllib.request.Request(
        'https://192.168.100.224:5443/api/auth/login',
        data=json.dumps({'password': 'TestGW2026'}).encode(),
        headers={'Content-Type': 'application/json'}), timeout=10).read()
    return op


def apply_rules(op):
    r = op.open(urllib.request.Request(
        'https://192.168.100.224:5443/api/rules/apply', data=b'{}',
        headers={'Content-Type': 'application/json'}), timeout=40)
    return json.loads(r.read())


def set_wan_if(op, value):
    cfg = json.load(open(CONFIG))
    cfg['wan_if'] = value
    tmp = CONFIG + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cfg, f)
    os.replace(tmp, CONFIG)
    return apply_rules(op)


def tcp_probe(ip, port, timeout=2.5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return 'OPEN'
    except ConnectionRefusedError:
        return 'REFUSED'
    except socket.timeout:
        return 'TIMEOUT'
    except OSError as e:
        return 'ERR%s' % e.errno
    finally:
        try:
            s.close()
        except OSError:
            pass


def udp_send(ip, port, payload=b'x'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((VETH_CLI, 0))
        s.sendto(payload, (ip, port))
    except OSError as e:
        return 'ERR %s' % e
    finally:
        s.close()
    return 'sent'


def prefixes(lines):
    """从日志行里抽出所有 [XXX] 前缀"""
    found = {}
    for ln in lines:
        for p in re.findall(r'\[([A-Z0-9\-]+)\] IN=', ln):
            found[p] = found.get(p, 0) + 1
    return found


def main():
    base_cfg = open(CONFIG).read()
    op = login_opener()
    results = []

    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(w1)
        os.close(r2)
        fout, fin = os.fdopen(w2, 'w'), os.fdopen(r1)
        if ctypes.CDLL('libc.so.6', use_errno=True).unshare(CLONE_NEWNET) != 0:
            os._exit(1)
        fout.write(json.dumps({'ready': True}) + '\n')
        fout.flush()
        fin.readline()
        ipr = IPRoute()
        idx = names(ipr)
        ipr.addr('add', index=idx['tw1'], address=VETH_CLI + '/24')
        for n in ('lo', 'tw1'):
            try:
                ipr.link('set', index=idx[n], state='up')
            except Exception:
                pass
        for dst in ('203.0.113.0/24', '192.168.100.0/24'):
            try:
                ipr.route('add', dst=dst, gateway=VETH_HOST)
            except Exception:
                pass
        fout.write(json.dumps({'ok': True}) + '\n')
        fout.flush()
        for line in fin:
            line = line.strip()
            if not line or line == b'quit':
                break
            p = line.split()
            if len(p) != 3:
                break
            kind, ip, val = p
            if kind == 'tcp':
                r = tcp_probe(ip, int(val))
            elif kind == 'udp':
                r = udp_send(ip, int(val))
            else:
                r = '?'
            fout.write(json.dumps({'r': r}) + '\n')
            fout.flush()
        os._exit(0)

    os.close(r1)
    os.close(w2)
    fout_p, fin_p = os.fdopen(w1, 'w'), os.fdopen(r2)
    json.loads(fin_p.readline())

    ipr = IPRoute()
    for n in [k for k in names(ipr) if k and k.startswith('tw')]:
        try:
            ipr.link('delete', ifname=n)
        except Exception:
            pass
    nfd = os.open('/proc/%d/ns/net' % pid, os.O_RDONLY)
    ipr.link('add', ifname=TEST_WAN_IF, kind='veth', peer={'ifname': 'tw1'})
    idx = names(ipr)
    ipr.link('set', index=idx['tw1'], IFLA_NET_NS_FD=nfd)
    ipr.addr('add', index=idx[TEST_WAN_IF], address=VETH_HOST + '/24')
    ipr.link('set', index=idx[TEST_WAN_IF], state='up')
    fout_p.write('GO\n')
    fout_p.flush()
    json.loads(fin_p.readline())

    def ask(kind, ip, val):
        fout_p.write('%s %s %s\n' % (kind, ip, val))
        fout_p.flush()
        line = fin_p.readline()
        return json.loads(line)['r'] if line else '(无响应)'

    try:
        log('=== wan_if 临时设为 %s ===' % TEST_WAN_IF)
        d = set_wan_if(op, TEST_WAN_IF)
        log('  apply: %s' % d.get('message'))
        log('  规则里: %s' % [l.strip() for l in open(RULES)
                            if l.startswith('define WAN_IF')][0])

        cases = [
            ('tcp', 3389, ['BOTNET-PORT'], 'RDP 3389 应命中 BOTNET 拦截'),
            ('tcp', 445, ['BOTNET-PORT'], 'SMB 445 应命中 BOTNET 拦截'),
            ('tcp', 25, ['BOTNET-PORT'], 'SMTP 25 应命中 BOTNET 拦截'),
            ('udp', 123, ['BOTNET-UDP'], 'NTP 123 应命中 BOTNET-UDP 拦截'),
            ('udp', 5353, ['BOTNET-UDP'], 'mDNS 5353 应命中 BOTNET-UDP 拦截'),
            ('tcp', 8443, ['I4-ALV-T'], '未敲门打 8443 不应出现放行日志'),
        ]
        for kind, port, expect, desc in cases:
            m = logread_mark()
            probe = ask(kind, WAN_ADDR, port)
            time.sleep(0.4)
            got = prefixes(logread_since(m))
            hit = [p for p in expect if p in got]
            results.append((desc, probe, hit, got))
            log('  %-34s 探测=%-8s 期望前缀=%s 实际日志=%s %s'
                % (desc, probe, expect, got or '（无）',
                   '✅' if (port == 8443 and not hit) or hit else '❌'))

        log('=== 四步敲门 %s ===' % (KNOCK,))
        m = logread_mark()
        for p in KNOCK:
            ask('udp', WAN_ADDR, p)
            time.sleep(0.2)
        time.sleep(0.5)
        got = prefixes(logread_since(m))
        wl = sh('nft', 'list', 'set', 'inet', 'fw4', 'allowed4').stdout
        in_wl = VETH_CLI in wl
        log('  敲门日志前缀: %s' % (got or '（无）'))
        log('  @allowed4 里有测试源 %s: %s' % (VETH_CLI, in_wl))

        log('=== 敲门后打 8443 ===')
        m = logread_mark()
        probe = ask('tcp', WAN_ADDR, 8443)
        time.sleep(0.4)
        got2 = prefixes(logread_since(m))
        log('  探测=%s  日志=%s' % (probe, got2 or '（无）'))
        results.append(('敲门后放行 8443', probe,
                        ['I4-ALV-T'] if 'I4-ALV-T' in got2 else [], got2))

        log('')
        log('═══ 汇总 ═══')
        ok = 0
        for desc, probe, hit, got in results:
            if port_ok(desc, hit):
                ok += 1
        print()
        for desc, probe, hit, got in results:
            print('  %-34s %s   %s' % (desc, probe, hit or got or '无日志'))
        print('\n  敲门是否进白名单: %s' % ('是' if in_wl else '否'))
        print('  白名单内容: %s' % ' '.join(
            l.strip() for l in wl.splitlines() if VETH_CLI in l))
    finally:
        log('>>> 还原 wan_if=%s <<<' % REAL_WAN_IF)
        set_wan_if(op, REAL_WAN_IF)
        for n in (TEST_WAN_IF, 'tw1'):
            try:
                IPRoute().link('delete', ifname=n)
            except Exception:
                pass
        try:
            fout_p.write('quit\n')
            fout_p.flush()
            os.close(w1)
        except Exception:
            pass
        log('[收尾] %s  nft 表数=%d  接口=%s'
            % ([l.strip() for l in open(RULES) if l.startswith('define WAN_IF')],
               sh('nft', 'list', 'tables').stdout.count('table'),
               sorted(k for k in names(IPRoute()) if k)))


def port_ok(desc, hit):
    if '未敲门' in desc:
        return not hit
    return bool(hit)


if __name__ == '__main__':
    main()
