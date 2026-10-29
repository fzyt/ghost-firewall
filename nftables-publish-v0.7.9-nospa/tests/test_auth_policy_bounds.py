#!/usr/bin/env python3
"""认证侧的两个「边界」必须有界：会话绝对上限、审计日志体积。

对应 Shannon 第二轮报告里剩下的两项 P2：
  · AUTH-VULN-05 审计日志无上限
  · AUTH-VULN-03 令牌无绝对上限（TOKEN_ABS_TTL_DEFAULT 出厂是 0 = 不启用）

两处都要注意**机制**和报告写的不一样：
  · 审计日志落在 tmpfs 上（.224 的 /var -> /tmp），吃的是 **RAM** 不是磁盘；
  · 绝对上限的问题不只在「默认值」，还在**存量配置**里躺着一个显式的 0 ——
    只改默认值等于没修。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_auth_policy_bounds.py
"""
import json
import os
import shutil
import sys
import tempfile
import time

SBX = tempfile.mkdtemp(prefix="authbounds-")
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")

# 必须在 import auth_gateway **之前**设好：模块级常量一次性读这些变量，
# 而 SECRET_FILE 尤其关键 —— 取不到时 _load_secret() 每次调用都现生成一把
# 新密钥，于是「登录发的令牌」和「我自己重签的令牌」签名对不上，
# verify 一律 no_token。这个坑第一次跑时把我整组断言带崩了。
CFG = f"{SBX}/gw-config.json"
PWD = f"{SBX}/password.json"
SEC_F = f"{SBX}/secret"
open(SEC_F, "w").write("test-secret-key-0123456789")
LOG = f"{SBX}/rot.log"
os.environ.update({
    "AUTH_CONFIG_PATH": CFG,
    "AUTH_PASSWORD_FILE": PWD,
    "AUTH_SECRET_FILE": SEC_F,
    "AUTH_RATELIMIT_FILE": f"{SBX}/ratelimit.json",
    "AUTH_AUDIT_LOG": LOG,
    "AUTH_API_PORT": "18447",
})

sys.path.insert(0, os.path.abspath(BACKEND))

import auth_gateway as ag  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  — {extra}" if extra and not cond else ""))


def sec(t):
    print(f"\n--- {t} ---")


print("=" * 74)
print("认证边界：会话绝对上限 / 审计日志体积")
print("=" * 74)

# ══════════════════════════════════════════════════════════════════════
# 1. 绝对上限的默认值必须非零，且必须真的会被执行
# ══════════════════════════════════════════════════════════════════════
sec("1. 绝对上限：默认值非零 + 执行点真的认它")

DEF_ABS = ag.TOKEN_ABS_TTL_DEFAULT
DEF_SES = ag.TOKEN_TTL_DEFAULT
check("TOKEN_ABS_TTL_DEFAULT 不是 0（旧出厂值 = 不启用）",
      isinstance(DEF_ABS, int) and DEF_ABS > 0, f"实际={DEF_ABS}")
check("默认值在 _absolute_ttl 认可的区间内（0 < x <= 604800）",
      0 < DEF_ABS <= 604800, f"实际={DEF_ABS}")
check("默认值 >= 滑动窗口（否则 validate_config 会判定它永不生效）",
      DEF_ABS >= DEF_SES, f"绝对={DEF_ABS} 滑动={DEF_SES}")

# 这一组是**执行点**的断言，不是常量的复读 —— 2026-10-16 之前
# `_absolute_ttl` 的 else 分支是 `return 0`，也就是说配置里哪怕写了
# 非法值也会静默变成「绝对上限关闭」。
check("配置缺这个键 → 取默认值（不是关闭）",
      ag._absolute_ttl({}) == DEF_ABS, f"实际={ag._absolute_ttl({})}")
check("**存量配置的 0 → 取默认值，不是关闭**（旧出厂值的最后一道口子）",
      ag._absolute_ttl({"auth_absolute_timeout": 0}) == DEF_ABS,
      f"实际={ag._absolute_ttl({'auth_absolute_timeout': 0})}")
check("越界值（999999）→ 取默认值",
      ag._absolute_ttl({"auth_absolute_timeout": 999999}) == DEF_ABS,
      f"实际={ag._absolute_ttl({'auth_absolute_timeout': 999999})}")
check("显式合法值 → 原样采纳",
      ag._absolute_ttl({"auth_absolute_timeout": 86400}) == 86400,
      f"实际={ag._absolute_ttl({'auth_absolute_timeout': 86400})}")
check("负值 → 取默认值",
      ag._absolute_ttl({"auth_absolute_timeout": -1}) == DEF_ABS,
      f"实际={ag._absolute_ttl({'auth_absolute_timeout': -1})}")
check("非数字垃圾值 → 取默认值",
      ag._absolute_ttl({"auth_absolute_timeout": "垃圾"}) == DEF_ABS,
      f"实际={ag._absolute_ttl({'auth_absolute_timeout': '垃圾'})}")

# 绝对上限必须真的把会话掐断 —— 走真实的 verify 链路，不能只调 helper。
_c = ag.app.test_client()
HOST = "192.168.100.224:8443"
_salt = "aabbccdd"
_dig = "0" * 64
json.dump({"hash": f"pbkdf2_sha256$200000${_salt}${_dig}"}, open(PWD, "w"))

# 先抓真身再打桩。第 3b 节要测「限流表不可用时的降级」，用桩测等于什么都没测：
# 桩恒返回 (0,0)，降级分支一次都进不去，所有断言会一起变成假红。
# 顺序写反过一次（先打桩再抓），抓到的就是桩自己。
_MUTATE_RATELIMIT_REAL = ag._mutate_ratelimit
ag._mutate_ratelimit = lambda ip, on_fail=False: (0, 0)
ag._password_hash = lambda: f"pbkdf2_sha256$200000${_salt}${_dig}"
ag._verify_password = lambda p, s: True


def write_cfg(**over):
    base = {
        "auth_session_timeout": 1800,
        "auth_absolute_timeout": DEF_ABS,
        "auth_lan_bypass": False,
        "auth_token_epoch": 0,
    }
    base.update(over)
    json.dump(base, open(CFG, "w"))
    ag._config_cache["mtime"] = None


# 造一张「iat 在绝对上限之前、exp 却拉到很久」的令牌：
# 正常签发不可能这样（issue_token 的 abs_deadline 会夹住 exp），
# 但它精确隔离了「绝对超时」这一个判据 —— 滑动窗口和 exp 都不背锅。
def _call(path, method="GET", body=None, token=None, extra=None):
    h = {"Host": HOST, "X-Real-IP": "8.8.8.8"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(extra or {})
    if body is not None:
        return _c.open(path, method=method, json=body, headers=h)
    return _c.open(path, method=method, headers=h)


write_cfg()
_tk = _call("/auth/login", "POST", {"password": "x"})
_tok = ""
for _p in (_tk.headers.get("Set-Cookie", "") or "").split(";"):
    if _p.strip().startswith("gw_token="):
        _tok = _p.strip().split("=", 1)[1]

# 把 exp 往后推、iat 往前挪，绕过 issue_token 的夹取，单独验证判据
import base64 as _b64  # noqa: E402
import hashlib  # noqa: E402
import hmac  # noqa: E402

_body = _tok.split(".")[0]
_pad = "=" * (-len(_body) % 4)
_payload = json.loads(_b64.urlsafe_b64decode(_body + _pad))
_now = int(time.time())
_payload["iat"] = _now - DEF_ABS - 60      # 签发于绝对上限之前
_payload["exp"] = _now + 7200              # 但还没到滑动窗口的尽头
_body2 = _b64.urlsafe_b64encode(
    json.dumps(_payload, separators=(",", ":")).encode()).decode().rstrip("=")
_sig = _b64.urlsafe_b64encode(
    hmac.new(ag._token_key(), _body2.encode(), hashlib.sha256).digest()
).decode().rstrip("=")
_stale = f"{_body2}.{_sig}"

_r = _call("/auth/verify", token=_stale)
check("超过绝对上限的令牌被拒（401）",
      _r.status_code == 401, f"HTTP {_r.status_code} —— 绝对上限没生效")
check("拒绝原因就是绝对超时",
      _r.headers.get("X-Auth-Deny-Reason") == "absolute_timeout"
      or b"absolute_timeout" in (_r.get_data() or b""),
      f"headers={dict(_r.headers)}")

# 对照组：iat 在上限之内，同样的令牌必须放行
_payload["iat"] = _now - 60
_payload["exp"] = _now + 7200
_body3 = _b64.urlsafe_b64encode(
    json.dumps(_payload, separators=(",", ":")).encode()).decode().rstrip("=")
_sig3 = _b64.urlsafe_b64encode(
    hmac.new(ag._token_key(), _body3.encode(), hashlib.sha256).digest()
).decode().rstrip("=")
_r2 = _call("/auth/verify", token=f"{_body3}.{_sig3}")
check("对照组：未超绝对上限的令牌放行（200）",
      _r2.status_code == 200, f"HTTP {_r2.status_code}")

# ══════════════════════════════════════════════════════════════════════
# 2. 存量配置的 0 必须被迁移 —— 且必须测**接线**，不是只测 helper
# ══════════════════════════════════════════════════════════════════════
sec("2. 存量配置 auth_absolute_timeout=0 的迁移")

_cwd = os.getcwd()
_tmp = tempfile.mkdtemp(prefix="panelbounds-")
try:
    os.chdir(_tmp)
    if "app" in sys.modules:
        del sys.modules["app"]
    import app as panel  # noqa: E402

    PCFG = f"{_tmp}/panel-config.json"

    def _fresh(abs_value):
        c = dict(panel.DEFAULT_CONFIG)
        c["auth_absolute_timeout"] = abs_value
        c["panel_allowed_nets"] = "127.0.0.0/8"
        c["lan_subnet4"] = "127.0.0.0/8"
        with open(PCFG, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False)
        return c

    _orig_cfg = panel.CONFIG_PATH
    panel.CONFIG_PATH = PCFG
    try:
        # 直接调 helper 只证明函数本身对，证明不了它被接上了 ——
        # 变异脚本会把这一行从 load_config 里摘掉而这里照样绿。
        _fresh(0)
        _got = panel.load_config()
        check("load_config 把存量 0 迁移成默认值（真实加载路径，不是只调 helper）",
              _got.get("auth_absolute_timeout") == DEF_ABS,
              f"实际={_got.get('auth_absolute_timeout')}")
        check("迁移后磁盘上仍是 0（load_config 是读路径，不许偷偷写盘）",
              json.load(open(PCFG, encoding="utf-8")).get("auth_absolute_timeout") == 0,
              "load_config 写了盘 —— 读操作有副作用，出错时很难查")

        # 已经是正数的不能被改（那可能是管理员特意配的）
        _fresh(86400)
        check("已配好的正数不被迁移覆盖",
              panel.load_config().get("auth_absolute_timeout") == 86400,
              f"实际={panel.load_config().get('auth_absolute_timeout')}")

        # 新装机器：磁盘上没有这个键，合并默认值后应拿到非零默认
        _c3 = dict(panel.DEFAULT_CONFIG)
        _c3.pop("auth_absolute_timeout", None)
        with open(PCFG, "w", encoding="utf-8") as f:
            json.dump(_c3, f, ensure_ascii=False)
        check("全新安装（无该键）也拿到非零默认值",
              panel.load_config().get("auth_absolute_timeout") == DEF_ABS,
              f"实际={panel.load_config().get('auth_absolute_timeout')}")

        # 启动落盘：网关读的是磁盘，内存迁移不落盘等于没迁
        _fresh(0)
        _starts = [n for n in dir(panel) if n == "_start_servers"]
        check("_start_servers 存在（启动落盘迁移的宿主）", bool(_starts))
        _src = open(os.path.join(os.path.abspath(BACKEND), "app.py"),
                    encoding="utf-8").read()
        check("启动路径里确实有「读盘 0 → 迁移 → 落盘」这一步",
              "auth_absolute_timeout" in _src.split("def _start_servers")[1]
              and "save_config(load_config())" in _src,
              "启动迁移那段代码不在 _start_servers 里 —— 网关读盘仍会看到 0")

        # 校验不能把新默认值判成非法（否则连保存都会被拒）
        _c4 = dict(panel.DEFAULT_CONFIG)
        _errs = panel.validate_config(_c4) if hasattr(panel, "validate_config") else []
        check("新默认值能通过 validate_config",
              isinstance(_errs, (list, tuple)) and not _errs,
              f"validate_config 报错：{_errs}")
    finally:
        panel.CONFIG_PATH = _orig_cfg
finally:
    os.chdir(_cwd)

# ══════════════════════════════════════════════════════════════════════
# 3. 审计日志必须有界（tmpfs 上吃的是 RAM）
# ══════════════════════════════════════════════════════════════════════
sec("3. 审计日志体积上限与轮转")

LOG = ag.AUDIT_LOG
ROT = LOG + ".1"
check("AUDIT_LOG_MAX_BYTES 是正整数（有界的前提）",
      isinstance(ag.AUDIT_LOG_MAX_BYTES, int) and ag.AUDIT_LOG_MAX_BYTES > 0,
      f"实际={ag.AUDIT_LOG_MAX_BYTES!r}")
check("上限量级合理（1 MiB ~ 16 MiB；太小会天天轮转丢取证材料，"
      "太大在 1 GB 内存的路由上危险）",
      1024 * 1024 <= ag.AUDIT_LOG_MAX_BYTES <= 16 * 1024 * 1024,
      f"实际={ag.AUDIT_LOG_MAX_BYTES}")

_audit_real_log = ag.AUDIT_LOG
_audit_real_max = ag.AUDIT_LOG_MAX_BYTES
ag.AUDIT_LOG = LOG
ag.AUDIT_LOG_MAX_BYTES = 4000        # 缩到能测的量级

with ag.app.test_request_context("/auth/login", headers={"User-Agent": "u"}):
    # 观察**过程中**达到过的最大体积，而不是最后一次的大小。
    #
    # 只在收尾时 stat 一次的话，「先判后写」的溢出恰好可能被下一次轮转抹掉：
    # 文件停在轮转点之后 → 看着很小，断言照样绿，而它上一秒刚到过
    # 上限 + 整整一行。变异脚本正是这么把这条漏过去的。
    _max_cur = [0]
    _max_total = [0]

    def _burst(start, n):
        for i in range(start, start + n):
            ag.audit("probe", i=i)
            _cur = os.path.getsize(LOG)
            _rot = os.path.getsize(ROT) if os.path.exists(ROT) else 0
            _max_cur[0] = max(_max_cur[0], _cur)
            _max_total[0] = max(_max_total[0], _cur + _rot)

    # 未超上限：正常追加，不产生 .1
    _burst(0, 5)
    _sz1 = os.path.getsize(LOG)
    check("未超上限时正常追加", _sz1 > 0, f"size={_sz1}")
    check("未超上限时不产生 .1", not os.path.exists(ROT))

    # 灌到超上限
    _burst(5, 195)
    _sz2 = os.path.getsize(LOG)
    _sz1f = os.path.getsize(ROT) if os.path.exists(ROT) else 0
    check("超上限后产生了 .1（发生轮转）", _sz1f > 0, f".1 size={_sz1f}")
    check("**轮转过程中当前文件从未超过上限**（含最后一行）",
          _max_cur[0] <= ag.AUDIT_LOG_MAX_BYTES,
          f"过程中最大={_max_cur[0]}，上限={ag.AUDIT_LOG_MAX_BYTES} —— "
          f"先判后写会溢出整整一行")
    check("**轮转过程中总占用从未超过 2×上限**",
          _max_total[0] <= 2 * ag.AUDIT_LOG_MAX_BYTES,
          f"过程中最大={_max_total[0]}，2×上限={2 * ag.AUDIT_LOG_MAX_BYTES}")
    check("当前文件此刻在上限以下", _sz2 < ag.AUDIT_LOG_MAX_BYTES,
          f"当前={_sz2} 上限={ag.AUDIT_LOG_MAX_BYTES}")

    # 轮转后仍然是合法 JSONL（面板的日志视图要读它）
    _lines = [ln for ln in open(LOG, encoding="utf-8").read().splitlines() if ln.strip()]
    _bad = 0
    for ln in _lines:
        try:
            if not isinstance(json.loads(ln), dict):
                _bad += 1
        except ValueError:
            _bad += 1
    check("轮转后仍是合法 JSONL（面板 tail 读要靠它）", _bad == 0,
          f"{_bad} 行解析失败，共 {len(_lines)} 行")

    # 持续写入不得让文件重新无界增长
    _burst(200, 700)
    check("持续写入后总占用仍然有界",
          _max_total[0] <= 2 * ag.AUDIT_LOG_MAX_BYTES,
          f"过程中最大={_max_total[0]}，2×上限={2 * ag.AUDIT_LOG_MAX_BYTES}")
    check("没有生出 .2（只留一代）",
          not os.path.exists(LOG + ".2"), "轮转代数不受控")

    # ── 轮转本身失败时：必须就地截断，不能就此放弃 ────────────────
    # /etc/nftables 变只读、跨设备、inode 耗尽……只要 os.replace 不成，
    # 文件就会继续无限长把内存吃光 —— 而报告里这条风险的后果正是 OOM。
    #
    # 换独立文件、上限压到 50 字节（**小于单行**，于是每次写入都必定走轮转
    # 分支，不用靠「灌文件」碰运气）。前两版都栽在这一步：判据是
    # 「当前大小 + 这一行 > 上限」，按固定余量估算的灌入量一次次停在上限
    # 之下，os.replace 压根没被调用，截断兜底自然测不到。
    LOG2 = f"{SBX}/rot-fail.log"
    _log_real = ag.AUDIT_LOG
    _cap_real = ag.AUDIT_LOG_MAX_BYTES
    _replace_real = ag.os.replace
    _rename_real = ag.os.rename
    _replace_hits = [0]

    def _boom(*a, **k):
        _replace_hits[0] += 1
        raise OSError(5, "模拟轮转失败")

    try:
        ag.AUDIT_LOG = LOG2
        ag.AUDIT_LOG_MAX_BYTES = 50
        # 两个名字都要打桩：前置断言数的是「轮转分支被进入了几次」，
        # 而不是「某个特定函数被调用了几次」。只桩 os.replace 的话，
        # 把实现换成 os.rename 的等价变异会让这条前置断言变红 ——
        # 行为一模一样，测试却说不绿。
        ag.os.replace = _boom
        ag.os.rename = _boom
        for _ in range(50):
            ag.audit("probe", fill=True)
        _s2 = os.path.getsize(LOG2)
        _txt2 = open(LOG2, encoding="utf-8").read()
    finally:
        ag.os.replace = _replace_real
        ag.os.rename = _rename_real
        ag.AUDIT_LOG = _log_real
        ag.AUDIT_LOG_MAX_BYTES = _cap_real

    check("前置：轮转分支确实被进入过（不然测的不是截断兜底）",
          _replace_hits[0] > 0, f"进入次数={_replace_hits[0]}")
    check("轮转失败时就地截断：50 次写入后文件仍只有一行量级",
          0 < _s2 < 400,
          f"size={_s2} —— 没收紧的话会涨到 50×单行≈7.8 KB，这就是 RAM 被吃光的路径")
    check("轮转失败后日志没有静默丢光（最后一次写入还在）",
          '"fill"' in _txt2, f"文件内容前 80 字={_txt2[:80]!r}")

# 日志写不进去时，认证链路不能被拖垮
with ag.app.test_request_context("/auth/login", headers={}):
    ag.AUDIT_LOG = "/proc/definitely-not-writable/x.log"
    try:
        ag.audit("probe", boom=True)
        check("日志路径不可写时 audit() 不抛（认证不能被日志拖垮）", True)
    except Exception as e:  # noqa: BLE001
        check("日志路径不可写时 audit() 不抛（认证不能被日志拖垮）", False,
              f"抛了 {type(e).__name__}: {e}")
    finally:
        ag.AUDIT_LOG = LOG

ag.AUDIT_LOG = _audit_real_log
ag.AUDIT_LOG_MAX_BYTES = _audit_real_max

sec("3b. 限流表不可用时不得把登录整个搞挂（.224 实测的真 bug）")

# .224 实测（跑真实用户流程时撞上）：/etc/nftables 是 drwxr-sr-x root:nftweb，
# **组只有 r-x、没有写权限**。网关降权后以 uid 1000 运行，建不了限流表。
# init 脚本以 root 预建了它，所以平时不暴露；但表一旦缺失，
# `open(path, "a+")` 抛 PermissionError → 整个 auth_login 走 except Exception
# → **HTTP 500**，而且 uid 1000 永远重建不出这张表 —— 没有任何自愈路径。
# 移走表后连续两次登录都是 500，表也不会被重建。
ag._mutate_ratelimit = _MUTATE_RATELIMIT_REAL   # 恢复第 1 节打的桩
RL = ag.RATELIMIT_FILE
RL_REAL = ag._RATELIMIT_DEGRADED["warned"]
ag._RATELIMIT_DEGRADED["warned"] = False
ag._RATE_FALLBACK.clear()
try:
    # 注入「表打不开」：目录存在但不可写，等价于 .224 上那张被移走的表
    _open_real3 = ag.os.open

    def _open_deny(path, flags, mode=0o777, **k):
        if str(path) == RL:
            raise PermissionError(13, "模拟限流表不可写（.224 上 uid 1000 建不了）")
        return _open_real3(path, flags, mode, **k)

    ag.os.open = _open_deny
    try:
        _locked, _fails = ag._mutate_ratelimit("10.0.0.1", on_fail=True)
        check("限流表打不开时 _mutate_ratelimit 不抛", True)
        check("降级时返回的失败计数仍然是 1（降级不等于不设防）",
              _fails == 1, f"实际={_fails}")
        # 内存版必须真的能锁：连续失败到阈值应当锁上
        for _ in range(ag.RATE_LIMIT_MAX_FAILS):
            ag._mutate_ratelimit("10.0.0.2", on_fail=True)
        _locked2, _ = ag._mutate_ratelimit("10.0.0.2", on_fail=True)
        check("**降级状态下暴力破解仍然会被锁**（内存版语义与落盘版一致）",
              _locked2 is True, f"实际 locked={_locked2}")
        # 别的 IP 不受影响
        _locked3, _ = ag._mutate_ratelimit("10.0.0.3", on_fail=True)
        check("降级状态下不同 IP 各自计数（不共用计数器）",
              _locked3 is False, f"实际={_locked3}")
        check("降级留下告警（只警告一次）", ag._RATELIMIT_DEGRADED["warned"] is True)
    finally:
        ag.os.open = _open_real3

    # 关键：真实登录链路必须仍然放行 —— 不能是「helper 不抛但路由 500」
    _rl_dir_saved = ag.RATELIMIT_FILE
    ag.RATELIMIT_FILE = "/proc/definitely-not-writable/rl.json"
    try:
        _r = _call("/auth/login", "POST", {"password": "x"})
        check("**限流表完全不可用时登录仍然 200**（不是 500 = 不是把所有人锁在门外）",
              _r.status_code == 200, f"HTTP {_r.status_code}")

        # ── 上锁判定必须走真实登录链路，不能只测 helper ──────────
        #
        # 第一版只直接调 `_mutate_ratelimit` 检查「降级时也会锁」，全绿。
        # 部署到 .224 一实测，7 次连续错密码全是 401、一次 429 都没有 ——
        # 因为 `auth_login` 的上锁判据是 `_is_locked()`，它**只读文件**，
        # 压根不看降级时写在内存里的计数。计数照记、锁定判定恒 False，
        # 暴力破解防护在降级期间被悄悄关掉。
        #
        # 这正是「只判 helper 不验证接线」：helper 测得再对，接线断了照样绿。
        # 所以这里必须打真实的 /auth/login。
        ag._RATE_FALLBACK.clear()
        # 必须让密码校验真的失败：第 1 节把 _verify_password 桩成了恒真，
        # 于是每次登录都「成功」并清空计数，序列全是 200 —— 限流根本没被触发。
        # 限流计数的清空规则是「成功登录即清空」，所以成功路径永远测不出锁定。
        _vp_real = ag._verify_password
        ag._verify_password = lambda p, s: False
        _codes = []
        try:
            for _ in range(ag.RATE_LIMIT_MAX_FAILS + 3):
                _codes.append(_call("/auth/login", "POST",
                                    {"password": "wrong"}).status_code)
        finally:
            ag._verify_password = _vp_real
        check("**降级状态下真实登录链路仍然会限流（出现 429）**",
              429 in _codes,
              f"序列={_codes} —— 计数记了但没人查，暴力破解防护等于被关掉")
        check("限流生效前一直是 401（密码错，不是 200）",
              all(c == 401 for c in _codes[:ag.RATE_LIMIT_MAX_FAILS - 1]),
              f"序列={_codes}")

        # ── 锁定期内，**密码正确**也必须被拒 ──────────────────────────
        #
        # auth_login 里 `_is_locked(ip)` 是**校验密码之前**的只读闸门。
        # 降级状态下锁定信息只存在内存里，这道闸门必须能读到它。
        #
        # 为什么上面那两条断言抓不住这一层：密码**错**的时候，
        # 「早期闸门 → 429」和「走到 _mutate_ratelimit → locked → 429」
        # 两条路径给的状态码**完全一样**。只有把密码换成正确的，
        # 差别才显出来：
        #   闸门在  → 429（锁定生效）
        #   闸门拆  → 200（降级期间已锁定的 IP 拿正确密码就能登录成功）
        # 后者等于锁定形同虚设 —— 而且没有任何断言能发现。
        _vp2 = ag._verify_password
        ag._verify_password = lambda p, s: True
        try:
            _r_locked = _call("/auth/login", "POST", {"password": "right"})
        finally:
            ag._verify_password = _vp2
        check("**降级状态下锁定期内的 IP 即使密码正确也必须被拒（429）**",
              _r_locked.status_code == 429,
              f"HTTP {_r_locked.status_code} —— 锁定只拦错密码、正确密码放行 = 锁定形同虚设")
    finally:
        ag.RATELIMIT_FILE = _rl_dir_saved

    # 恢复正常：表可用时不该降级
    ag._RATELIMIT_DEGRADED["warned"] = False
    _l, _f = ag._mutate_ratelimit("10.0.0.9", on_fail=True)
    check("表恢复正常后不再降级", ag._RATELIMIT_DEGRADED["warned"] is False)
    check("恢复正常后失败计数照常累加", _f == 1, f"实际={_f}")
finally:
    ag.RATELIMIT_FILE = RL
    ag._RATELIMIT_DEGRADED["warned"] = RL_REAL
    ag._RATE_FALLBACK.clear()

# 建表权限：必须 0600（不能是按 umask 建出的 0644）
_rl_new = f"{SBX}/newrl.json"
_seen_mode = []
_open_real4 = ag.os.open


def _open_spy4(path, flags, mode=0o777, **k):
    if str(path) == _rl_new and (flags & os.O_CREAT):
        _seen_mode.append(mode)
    return _open_real4(path, flags, mode, **k)


_rl_save = ag.RATELIMIT_FILE
ag.RATELIMIT_FILE = _rl_new
try:
    ag.os.open = _open_spy4
    try:
        ag._mutate_ratelimit("10.0.0.4", on_fail=True)
    finally:
        ag.os.open = _open_real4
    check("限流表用 os.open(..., 0600) **建**出来（创建即收紧）",
          _seen_mode == [0o600],
          f"实测传入 mode={_seen_mode} —— 用 open(a+) 会是 0777&~umask=0644")
    _rlm = os.stat(_rl_new).st_mode & 0o777 if os.path.exists(_rl_new) else None
    check("限流表最终权限 0600", _rlm == 0o600,
          f"实际={'没生成' if _rlm is None else format(_rlm, 'o')}")
finally:
    ag.RATELIMIT_FILE = _rl_save

print("\n" + "=" * 74)
print(f"通过 {len(PASS)} / 失败 {len(FAIL)}")
if FAIL:
    print("失败项：")
    for f in FAIL:
        print(f"  - {f}")
    shutil.rmtree(SBX, ignore_errors=True)
    sys.exit(1)
print("全部通过")
shutil.rmtree(SBX, ignore_errors=True)
