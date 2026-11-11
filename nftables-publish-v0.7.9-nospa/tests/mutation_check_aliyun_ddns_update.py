#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阿里云 DDNS 更新链路的变异验证。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_aliyun_ddns_update.py

测什么有效
----------
「DDNS 不断删除重新上传」的修复，失败模式是「**看起来完全正常**」：

    值相同也照样删了再加 —— 面板不报错、控制台里记录确实变了、
    阿里云也不报错，只是 RecordId 每次都换。

这类退化单测很容易漏。所以这里的判据落在**行为**上：
把生成出来的 cron 脚本真的跑起来（配一个本地假阿里云服务端），
断言它**发出的 API 调用序列**。

每条变异都往「退化」方向改
--------------------------
  M1  原地更新改回「删除 + 新增」（回到 2026-11-11 之前的实现）
  M2  不再判断「值是否相同」（值没变也更新）
  M3  匹配记录时不看 Line（多线路配置会被当成同一条）
  M4  取不到公网 IPv4 时沿用配置里的旧值（把正确地址改回过期地址）
  M5  配置里的 rr/type 只认小写键（存量配置取不到）
  M6  配置路径写死（改了环境变量就读不到配置）
  M7  IPv6 中转目录用错环境变量名（面板改了、脚本没跟着改）
  M8  单条记录的异常直接冒泡（后面的记录不再处理）
  M9  查询不拉全量（目标记录落在首屏之外）
  M10 不写摘要日志（又变成悄无声息）
  M11 没有可用值也不跳过（拿空值去写）
  M12 面板侧改回「删除 + 新增」
  M13 面板侧匹配记录时不看 Line
  M14 面板侧值比较用裸字符串（IPv6 的不同写法被判成「变了」）
  M15 前端把阿里云上现存的旧值又传了回去（测试按钮永远绿）
  M16 cron 侧不做值归一化

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

保险丝：只备份 / 还原 **backend/app.py 与 frontend/app.js 两个文件**，
一个字节都不碰别的。还原后逐个比对 sha256 —— 源码没还原干净时
**必须**当成失败，不能把「测试假红」误报成「变异被捕获」。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
TEST = os.path.join(ROOT, 'tests', 'test_aliyun_ddns_update.py')

TARGETS = {APP_PY: open(APP_PY, encoding='utf-8').read(),
           APP_JS: open(APP_JS, encoding='utf-8').read()}
ORIG_SHA = {p: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for p, s in TARGETS.items()}


def restore():
    """把两个文件还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, src in TARGETS.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for path, want in ORIG_SHA.items():
        with open(path, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != want:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, want)
    return True, '源码已还原，sha256 一致'


def _restore_and_exit(signum, frame):
    restore()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    try:
        signal.signal(_sig, _restore_and_exit)
    except (ValueError, OSError):
        pass

atexit.register(restore)


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


# 每条变异只改一个文件
# 格式：(说明, 目标文件, [(原文, 变异后), ...])
MUTATIONS = [
    # ── M1：cron 侧原地更新改回「删除 + 新增」────────────────────
    ('M1  cron 侧：原地更新改回「删除+新增」（RecordId 又要每次变）',
     APP_PY,
     [('''                _api("UpdateDomainRecord", ak_id, ak_secret, region,
                     {"RecordId": str(target.get("RecordId")), "RR": rr, "Type": rtype, "Value": value})''',
       '''                _api("DeleteDomainRecord", ak_id, ak_secret, region,
                     {"RecordId": str(target.get("RecordId"))})
                _api("AddDomainRecord", ak_id, ak_secret, region,
                     {"DomainName": domain, "RR": rr, "Type": rtype, "Value": value})''')]),

    # ── M2：不再判断「值是否相同」────────────────────────────────
    ('M2  cron 侧：不再判断值是否相同（值没变也照样更新）',
     APP_PY,
     [('''            if same:
                # 值没变 ⇒ 一个写接口都不调''',
       '''            if False:
                # 【变异】不再判断值是否相同''')]),

    # ── M3：匹配记录时不看 Line（多线路配置被当成同一条）─────────
    ('M3  cron 侧：匹配记录时不看 Line（多线路会被改掉）',
     APP_PY,
     [('''        if str(r.get("Line", "default") or "default").lower() != "default":
            continue
''',
       '''        # 【变异】不看 Line
''')]),

    # ── M4：取不到公网 IPv4 时沿用旧值 ───────────────────────────
    ('M4  cron 侧：取不到公网 IPv4 时沿用配置里的旧值',
     APP_PY,
     [('''                if not ip4:
                    _log("跳过 %s.A：取不到公网 IPv4（本轮不动阿里云）" % rr)
                    continue
                value = ip4''',
       '''                if not ip4:
                    # 【变异】不 continue ⇒ 沿用配置里的旧 value
                    pass
                else:
                    value = ip4''')]),

    # ── M5：rr/type 只认小写键 ───────────────────────────────────
    ('M5  cron 侧：rr/type 只认小写键（存量配置的大写键取不到）',
     APP_PY,
     [('''        rr = str(rec.get("rr") or rec.get("RR") or "").strip()
        rtype = str(rec.get("type") or rec.get("Type") or "").strip()''',
       '''        rr = str(rec.get("rr") or "").strip()
        rtype = str(rec.get("type") or "").strip()''')]),

    # ── M6：配置路径写死 ──────────────────────────────────────────
    ('M6  cron 侧：配置路径写死（改了环境变量就读不到配置）',
     APP_PY,
     [('''CONFIG_PATH = os.environ.get("NFTABLES_WEB_ALIYUN_CONFIG", "/etc/nftables/aliyun-ddns-config.json")''',
       '''CONFIG_PATH = "/etc/nftables/aliyun-ddns-config.json"''')]),

    # ── M7：IPv6 中转目录用错环境变量名 ───────────────────────────
    ('M7  cron 侧：IPv6 中转目录用 NFTW_RELAY_DIR（面板那边不认这个名字）',
     APP_PY,
     [('''RELAY_DIR = os.environ.get("NFTABLES_WEB_DDNS_RELAY_DIR",
                           os.environ.get("NFTW_RELAY_DIR", "/tmp"))''',
       '''RELAY_DIR = os.environ.get("NFTW_RELAY_DIR", "/tmp")''')]),

    # ── M8：单条异常直接冒泡（后面的记录不再处理）────────────────
    ('M8  cron 侧：单条记录的异常直接冒泡（后面的记录不再处理）',
     APP_PY,
     [('''        except Exception as e:
            # 单条失败不影响其余记录
            _log("失败 %s.%s：%s: %s" % (rr, rtype, type(e).__name__, e))''',
       '''        except Exception as e:
            # 【变异】异常直接冒泡 ⇒ 整轮中断
            raise''')]),

    # ── M9：查询不拉全量 ──────────────────────────────────────────
    ('M9  cron 侧：查询不拉全量（目标记录落在首屏之外就找不到）',
     APP_PY,
     [('''                          {"DomainName": domain, "RRKeyWord": rr, "Type": rtype, "PageSize": 500})''',
       '''                          {"DomainName": domain, "RRKeyWord": rr, "Type": rtype})''')]),

    # ── M10：不写摘要日志 ─────────────────────────────────────────
    ('M10 cron 侧：不写摘要日志（又变成悄无声息）',
     APP_PY,
     [('''def _log(msg):
    """写一行摘要日志。失败绝不抛 —— 日志写不进去不该让 DDNS 停摆。"""''',
       '''def _log(msg):
    """【变异】不写日志"""
    return''')]),

    # ── M11：没有可用值也不跳过 ───────────────────────────────────
    ('M11 cron 侧：没有可用值也不跳过（拿空值去写）',
     APP_PY,
     [('''            if not value:
                _log("跳过 %s.%s：没有可用值" % (rr, rtype))
                continue''',
       '''            if not value:
                _log("跳过 %s.%s：没有可用值" % (rr, rtype))''')]),

    # ── M12：面板侧改回「删除 + 新增」─────────────────────────────
    ('M12 面板侧：改回「删除+新增」',
     APP_PY,
     [('''    _aliyun_api("UpdateDomainRecord", ak_id, ak_secret, region, {
        "RecordId": str(record_id),
        "RR": rr,
        "Type": rtype,
        "Value": value,
    })''',
       '''    _aliyun_api("DeleteDomainRecord", ak_id, ak_secret, region, {
        "RecordId": str(record_id),
    })
    _aliyun_api("AddDomainRecord", ak_id, ak_secret, region, {
        "DomainName": domain, "RR": rr, "Type": rtype, "Value": value,
    })''')]),

    # ── M13：面板侧匹配记录时不看 Line ────────────────────────────
    ('M13 面板侧：匹配记录时不看 Line（多线路会被改掉）',
     APP_PY,
     [('''        if str(r.get('Line', 'default') or 'default').lower() != 'default':
            continue
''',
       '''        # 【变异】不看 Line
''')]),

    # ── M14：面板侧值比较用裸字符串 ───────────────────────────────
    ('M14 面板侧：值比较用裸字符串（IPv6 的不同写法被判成「变了」）',
     APP_PY,
     [('''    norm_value = _ddns_norm_value(value)
    if any(_ddns_norm_value(r.get('Value')) == norm_value for r in matched):''',
       '''    norm_value = value
    if any(r.get('Value') == norm_value for r in matched):''')]),

    # ── M15：前端把阿里云上现存的旧值又传了回去 ──────────────────
    ('M15 前端：测试按钮又把阿里云上现存的旧值传了回去（永远显示「未变化」）',
     APP_JS,
     [('''          value: '',
        });''',
       '''          value: (rec.Value || rec.value || ''),
        });''')]),

    # ── M16：cron 侧不做值归一化 ──────────────────────────────────
    ('M16 cron 侧：值比较不做归一化（IPv6 的不同写法被判成「变了」）',
     APP_PY,
     [('''            norm_value = _norm_value(value)
            same = [r for r in matched if _norm_value(r.get("Value")) == norm_value]''',
       '''            norm_value = value
            same = [r for r in matched if r.get("Value") == norm_value''')]),

    # ── M17：不检查配置文件是否存在 ─────────────────────────────
    ('M17 cron 侧：配置文件不存在时不检查（用户看到的是 FileNotFoundError）',
     APP_PY,
     [('''    if not os.path.exists(CONFIG_PATH):
        _log("退出：配置文件不存在（%s）—— 面板上还没保存过阿里云 DDNS 配置" % CONFIG_PATH)
        sys.exit(0)
''',
       '''    # 【变异】不检查配置文件是否存在
''')]),

    # ── M18：Timestamp 改回已弃用的 utcnow ───────────────────────
    ('M18 cron 侧：Timestamp 用已弃用的 datetime.utcnow()（3.13 打 DeprecationWarning）',
     APP_PY,
     [('''              "SignatureMethod": "HMAC-SHA1", "Timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),''',
       '''              "SignatureMethod": "HMAC-SHA1", "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),''')]),
]


def main():
    print('=' * 74)
    print(' 阿里云 DDNS 更新链路 —— 变异验证')
    print('=' * 74)

    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线测试就没过，先修基线')
        for l in out.splitlines():
            if '[FAIL]' in l:
                print('       ' + l.strip())
        return 1
    base_pass = out.count('[PASS]')
    print('基线通过 %d 条断言\n' % base_pass)

    caught, missed = 0, 0
    for name, target, edits in MUTATIONS:
        try:
            mutated = apply_edits(TARGETS[target], edits)
        except ValueError as e:
            print('  [FAIL] %s' % name)
            print('      锚点没命中（源码变了？）：%s' % e)
            missed += 1
            continue
        with open(target, 'w', encoding='utf-8') as f:
            f.write(mutated)
        try:
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                print('      首个失败断言: %s' % first[:100])
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                missed += 1
        finally:
            ok, detail = restore_verified()
            if not ok:
                print('      [FAIL] %s' % detail)
                missed += 1
                return 1

    print()
    print('=' * 74)
    print('变异 %d 处  捕获 %d  漏网 %d' % (len(MUTATIONS), caught, missed))
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
        return 1
    print('全部变异均被捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
