#!/usr/bin/env python3
"""变异验证：配置归属与版本闸（2026-10-21 .1 事故的修复）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_config_ownership.py

改的是 tests/test_config_ownership.py。

判定标准只有一条：**旧代码必然让断言失败**。

这个脚本盯的是 .1 事故的根因链：

    前端提交整份旧快照 → 后端整份覆盖 → 反代规则与证书被清空

三道防线分别对应三类变异：
  · 主防线：/api/config 无条件剔除 reverse_proxy
  · 纵深防御：config_rev 版本闸（过期快照 409 拒收）
  · 连带修复：证书变更必须真的下发 nginx

外加两条相邻缺陷：_migrate_rp_rules 保留 created_at、
load_config 损坏兜底改成「移走」而不是「删除」。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_config_ownership.py')

SRC = open(APP, encoding='utf-8').read()

MUTANTS = [
    # ── 主防线：/api/config 不再剔除 reverse_proxy ───────────────────
    ('/api/config 不再剔除 reverse_proxy（.1 事故原样复现）',
     """    rp_hits = sorted(k for k in incoming if k in RP_OWNED_CONFIG_KEYS)
    for k in RP_OWNED_CONFIG_KEYS:
        incoming.pop(k, None)""",
     """    rp_hits = sorted(k for k in incoming if k in RP_OWNED_CONFIG_KEYS)
    for k in ():
        incoming.pop(k, None)"""),

    ('RP_OWNED_CONFIG_KEYS 变成空集（主防线整个失效）',
     """RP_OWNED_CONFIG_KEYS = frozenset({
    'reverse_proxy',
})""",
     """RP_OWNED_CONFIG_KEYS = frozenset({
})"""),

    # ── 纵深防御：config_rev 版本闸 ──────────────────────────────────
    ('版本闸不再拒收过期快照（改成永不触发）',
     "        if sent_rev != cur_rev:",
     "        if False:"),

    ('版本闸改成一律拒收（连新快照也存不进去）',
     "        if sent_rev != cur_rev:",
     "        if sent_rev:"),

    ('版本号把 reverse_proxy 也算进去（反代页改一条就莫名 409）',
     """    payload = {k: v for k, v in (config or {}).items()
               if k not in RP_OWNED_CONFIG_KEYS}""",
     """    payload = {k: v for k, v in (config or {}).items()
               if True}"""),

    # ── 预览必须与实际保存一致 ──────────────────────────────────────
    ('preview-changes 不再剔除 reverse_proxy（预览与结果对不上）',
     """    for k in RP_OWNED_CONFIG_KEYS:
        proposed.pop(k, None)""",
     """    for k in ():
        proposed.pop(k, None)"""),

    # ── 证书变更必须真的下发 nginx ──────────────────────────────────
    ('上传证书不再部署 nginx（.1 上「传了证书不生效」的根因）',
     """        deploy_ok, deploy_msg = _deploy_all_rules(config)
        if not deploy_ok:
            nginx_reloaded = False
    except Exception as e:
        nginx_reloaded = False
        deploy_msg = f'{type(e).__name__}: {e}'

    msg = "证书已重新上传（替换同域名旧证书）" if replaced else "证书上传成功\"""",
     """        deploy_ok, deploy_msg = True, 'ok'
        if not deploy_ok:
            nginx_reloaded = False
    except Exception as e:
        nginx_reloaded = False
        deploy_msg = f'{type(e).__name__}: {e}'

    msg = "证书已重新上传（替换同域名旧证书）" if replaced else "证书上传成功\""""),

    ('设默认证书不再部署 nginx（面板说换了、8443 还用旧证书）',
     """        deploy_ok, deploy_msg = _deploy_all_rules(config)
        if not deploy_ok:
            nginx_reloaded = False
    except Exception as e:
        nginx_reloaded = False
        deploy_msg = f'{type(e).__name__}: {e}'

    msg = "默认证书已设置\"""",
     """        deploy_ok, deploy_msg = True, 'ok'
        if not deploy_ok:
            nginx_reloaded = False
    except Exception as e:
        nginx_reloaded = False
        deploy_msg = f'{type(e).__name__}: {e}'

    msg = "默认证书已设置\""""),

    # ── 相邻缺陷 ────────────────────────────────────────────────────
    ('_migrate_rp_rules 漏掉 created_at（每次 load→save 都抹掉时间戳）',
     """            # created_at 同理：漏了它，每次 load→save 都会把这个时间戳抹掉。
            # 证书条目里就有这个字段（rp_upload_cert 写的），
            # 规则这边漏掉会让「这条规则什么时候建的」永远查不到。
            "created_at": r.get("created_at", ""),""",
     """            # created_at 被漏掉（变异）"""),

    ('load_config 损坏时「复制一份再删原件」（旧行为：非原子改名）',
     """                broken_path = CONFIG_PATH + f'.broken.{int(time.time())}'
                os.replace(CONFIG_PATH, broken_path)""",
     """                backup_path = CONFIG_PATH + f'.corrupted.{int(time.time())}'
                shutil.copy(CONFIG_PATH, backup_path)
                os.remove(CONFIG_PATH)"""),

    ('_config_lost_after_setup 不认 .broken.*（一次损坏被固化成永久配置）',
     """            if name.startswith(base + '.broken.') or name.startswith(base + '.corrupted.'):
                return True""",
     """            if False:
                return True"""),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=300, env=env)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
    if r.returncode != 0 and fails:
        print(f'  ✅ 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    print(f'  ❌ 漏过 {name}')
    if r.returncode != 0 and r.stderr:
        print('        ', r.stderr.strip().splitlines()[-1][:86])
    return False


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：配置归属与版本闸（.1 事故修复）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-2500:])
        if base.stderr:
            print(base.stderr[-1200:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for name, old, new in MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(APP, 'w', encoding='utf-8').write(SRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(APP, 'w', encoding='utf-8').write(SRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == len(MUTANTS) else '有变异漏过')
    return 0 if caught == len(MUTANTS) else 1


if __name__ == '__main__':
    sys.exit(main())
