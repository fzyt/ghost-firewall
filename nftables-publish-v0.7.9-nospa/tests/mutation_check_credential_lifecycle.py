"""「凭据存放与生命周期」这批修复的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_credential_lifecycle.py

测什么有效
----------
这批修复最危险的退化不是「写错了」，而是**变回原来的写法**：
  · 凭据又写回共享配置（降权网关读得到）；
  · /etc/config/network 又是原地 truncate 重写；
  · 掩码取不到时又是「写空继续」；
  · 一张坏证书又是「中止全部续期」；
  · 中转文件又是「跟着软链写」。
这些退化**读起来完全正常**，成功路径也确实工作 ——
只有真的把修复拆掉，测试才会变红。所以下面每条变异都往「退化」方向改。

⚠️ 为什么不�� tests/_mutation_guard.py 的 MutationGuard
--------------------------------------------------
MutationGuard 的保险丝是「把**整个快照**的所有文件从快照写回去」。
同一个仓库里有另外两个 agent 在并行改 backend/app.py 的**其它区域** ——
全快照还原会把他们的改动一起冲掉（实测已造成两次改动丢失）。

所以这里只备份/还原 **backend/app.py 一个文件**：
  · 启动时把原文读进内存；
  · 每条变异前写变异版 → 跑测试 → **无条件**写回；
  · atexit + SIGTERM/SIGINT 兜底；
  · 不扫描 /tmp/mutguard-*，不碰任何别的文件。

并行安全（额外加的一层）
----------------------
还原时**先看当前文件是不是我写的那一份**：
  · 是 ⇒ 直接写回启动时读到的原文（精确还原）；
  · 不是 ⇒ 说明有人在这期间改了 app.py ⇒ **绝不整file覆盖**，
    只把「我这次变异的那几处」就地还原（surgical revert），
    别人的改动一个字节都不动。

每条变异独立改源码 → 跑测试 → 断言**变红** → 还原。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_credential_lifecycle.py')


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def _write(path, text):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


ORIG_APP = _read(APP_PY)

# 当前状态：None = 没写过；否则是我写进去的那份文本 + 那次变异的编辑对
_STATE = {'written': None, 'edits': None}


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须**在源码里唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError(f'锚点出现 {n} 次（要求唯一）: {old[:70]!r}')
        src = src.replace(old, new)
    return src


def revert_edits(src, edits):
    """把变异**就地**还原 —— 用于「别人同时改了 app.py」的情况。

    逐条把「变异后的文本」换回「变异前的文本」。任何一条换不回去
    （已经被别人改掉了）就跳过那一条，绝不整体覆盖。
    """
    for old, new in reversed(edits):
        if src.count(new) == 1 and src.count(old) == 0:
            src = src.replace(new, old)
        elif src.count(new) == 0:
            pass          # 已经被别的改动还原了 —— 不用管
        else:
            print(f'      ⚠️ 变异片段无法就地还原（出现 {src.count(new)} 次），跳过')
    return src


def restore():
    """无条件还原 backend/app.py。

    精确还原（文件仍是我写的那份）优先；否则就地还原我这次变异的那几处。
    """
    written = _STATE['written']
    edits = _STATE['edits']
    _STATE['written'] = None
    _STATE['edits'] = None
    if written is None:
        return
    try:
        cur = _read(APP_PY)
    except OSError:
        return
    try:
        if cur == written:
            _write(APP_PY, ORIG_APP)
        else:
            # 有人并行改了 app.py ⇒ 只能就地还原，不能整file覆盖
            _write(APP_PY, revert_edits(cur, edits or []))
    except OSError as e:
        print(f'[ERROR] 还原 backend/app.py 失败: {e}', flush=True)


def _emergency_restore(signum=None, frame=None):
    restore()
    if signum is not None:
        print(f'\n[WARN] 收到信号 {signum}，已还原 backend/app.py', flush=True)
        os._exit(1)


atexit.register(restore)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, _emergency_restore)
    except (ValueError, OSError):
        pass


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# 每条变异都只改 backend/app.py
# 格式：(说明, [(原文, 变异后), ...])
MUTATIONS = [
    # ── P1-20 ──────────────────────────────────────────────────────
    ('M1  凭据又写回共享配置（降权网关读得到）',
     [("        rp.pop(\"dns_credentials\", None)\n    save_config(config)",
       "        pass\n    save_config(config)")]),

    ('M2  迁移不再抹掉共享配置里的明文',
     [("    try:\n        save_config(config)\n"
       "    except Exception as e:\n"
       "        print(f'[MIGRATE] 清理共享配置里的 DNS 凭据失败",
       "    try:\n        pass\n    except Exception as e:\n"
       "        print(f'[MIGRATE] 清理共享配置里的 DNS 凭据失败")]),

    ('M3  凭据文件权限放宽到 0644',
     [("DNS_CREDENTIALS_MODE = 0o600", "DNS_CREDENTIALS_MODE = 0o644")]),

    ('M4  读不到独立文件时不回退到存量配置（向后兼容被破坏）',
     [("    rp[\"dns_credentials\"] = _dns_credentials_view(rp)",
       "    rp[\"dns_credentials\"] = (rp.get(\"dns_credentials\")\n"
       "                               if isinstance(rp.get(\"dns_credentials\"), dict) else {})")]),

    # ── P1-23 ──────────────────────────────────────────────────────
    ('M5  出厂配置里又带上了示例 DNAT 规则',
     [("    \"forward_rules\": [],\n    # 信任IP",
       "    \"forward_rules\": [\n        {\n"
       "            \"tcp_ports\": \"41820, 41825\",\n"
       "            \"udp_ports\": \"21116\",\n"
       "            \"target_ip\": \"192.168.4.226\"\n"
       "        }\n    ],\n    # 信任IP")]),

    # ── P1-29 ──────────────────────────────────────────────────────
    ('M6  /etc/config/network 退回原地 truncate 重写',
     [("        raise ValueError(err)\n    _atomic_write_network_config(path, new_content)",
       "        raise ValueError(err)\n"
       "    with open(path, 'w') as f:\n        f.write(new_content)")]),

    ('M7  写 /etc/config/network 前不再校验（会写出伤到 LAN 的配置）',
     [("    ok, err = _validate_network_config_content(''.join(lines), new_content)\n"
       "    if not ok:",
       "    ok, err = (True, '')\n    if not ok:")]),

    ('M7b 校验器不再拦「丢了 LAN 段」的内容',
     [("    if old_lan and not new_lan:\n"
       "        return False, '新配置里找不到 LAN 接口段，已拒绝写入（丢了 LAN 段 = 整机失联）'",
       "    if False:\n"
       "        return False, '新配置里找不到 LAN 接口段，已拒绝写入（丢了 LAN 段 = 整机失联）'")]),

    ('M8  _ensure_lan_essentials 又变成原地重写',
     [("        _atomic_write_network_config(path, new_content)",
       "        with open(path, 'w') as f:\n            f.write(new_content)")]),

    # ── P1-40 ──────────────────────────────────────────────────────
    ('M9  一张坏证书又中止剩下所有证书的续期',
     [("        except Exception as e:\n"
       "            # 一张证书出问题**绝不能**连累剩下的证书。",
       "        except Exception as e:\n            raise\n"
       "            # 一张证书出问题**绝不能**连累剩下的证书。")]),

    # ── P1-41 ──────────────────────────────────────────────────────
    ('M10 口令掩码还原不出来时又「写空继续」（静默清空）',
     [("        if unresolved:\n", "        if False and unresolved:\n")]),

    ('M11 阿里云 AccessKey Secret 掩码又被当成口令存进去',
     [("        if not old_secret:\n"
       "            print('[ERROR] AccessKey Secret 是掩码但读不到原值，已拒绝保存'",
       "        if False:\n"
       "            print('[ERROR] AccessKey Secret 是掩码但读不到原值，已拒绝保存'")]),

    # ── P2-13 ──────────────────────────────────────────────────────
    ('M12 规则删掉后残留的中转文件不再清理',
     [("        orphans = _cleanup_orphan_ddns_relays(len(forward_rules) + 1)",
       "        orphans = []")]),

    ('M13 规则的目标清空后，中转文件不再删除',
     [("                _remove_ddns_relay(idx)\n                continue",
       "                continue")]),

    # ── P2-14 ──────────────────────────────────────────────────────
    ('M14 中转文件又直接写目标路径（跟随软链）',
     [("        os.replace(tmp_path, path)\n        return True, ''",
       "        with open(path, 'w') as f:\n            f.write(content)\n"
       "        return True, ''")]),

    ('M15 cron 脚本里又直接写目标路径（跟随软链）',
     [("        os.replace(tmp, path)\n    except OSError as e:",
       "        with open(path, \"w\") as f:\n            f.write(content)\n"
       "    except OSError as e:")]),

    ('M16 cron 脚本里不再清理过期的中转文件',
     [("cleanup_orphans(len(rules) + 1)", "pass  # cleanup_orphans")]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-4000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        try:
            mutated = apply_edits(ORIG_APP, edits)
        except ValueError as e:
            print(f'  ⚠️  {name}')
            print(f'      ↓ 变异锚点没匹配上（源码变了？），跳过: {e}')
            missed += 1
            continue
        _STATE['written'] = mutated
        _STATE['edits'] = edits
        try:
            _write(APP_PY, mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '❌' in l), '')
                print(f'  ✅ {name}  —— 被捕获')
                print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  ❌ {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            restore()

    print()
    print(f'════════ 结果：捕获 {caught} / {caught + missed} ════════')
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 ❌ 的测试是假测试')
    else:
        print('源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
