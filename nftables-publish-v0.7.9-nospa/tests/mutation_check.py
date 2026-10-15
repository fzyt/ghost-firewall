#!/usr/bin/env python3
"""变异验证：把 v0.8.1 重构后的修复逐条改回旧行为，确认 tests/test_review_fixes.py 会变红。

全绿的测试套件不能证明它在测东西 —— 必须在缺陷重现时失败。

运行: python3 tests/mutation_check.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {
    'app': os.path.join(ROOT, 'backend', 'app.py'),
    'tpl': os.path.join(ROOT, 'backend', 'templates', 'nftables.conf'),
    'eng': os.path.join(ROOT, 'backend', 'template_engine.py'),
}
# 变异基线。原来只有 test_review_fixes.py 一个，2026-10-15 补的
# test_lists_concurrency.py（名单落盘并发 + 网关布尔校验 + 网关状态字段名）
# 不在里面 —— 意味着「save_lists 不再被调用」这类变异只能靠
# test_review_fixes.py 崩在 FileNotFoundError 上被算作捕获，报的是 0 条断言失败，
# 信号很弱。基线越全，越要证明「新修复不会被悄悄改坏」。
TESTS = [
    os.path.join(ROOT, 'tests', 'test_review_fixes.py'),
    os.path.join(ROOT, 'tests', 'test_lists_concurrency.py'),
]

# (描述, 文件键, 旧文本, 新文本, 期望出现次数)
MUTATIONS = [
    ('统一校验：target_protocol 白名单去掉（nginx 注入回归）', 'app',
     '    if proto not in ("http", "https"):', '    if False:', 1),

    ('统一校验：path_prefix 必填去掉', 'app',
     '    if not prefix:\n        return None, ("path_prefix 必填',
     '    if False:\n        return None, ("path_prefix 必填', 1),

    ('统一校验：保留前缀检测去掉（可覆盖 /auth）', 'app',
     '    if prefix in _RESERVED_GATEWAY_PREFIXES:', '    if False:', 1),

    ('统一校验：重复前缀检测去掉', 'app',
     '        if other == prefix:', '        if False:', 1),

    ('统一校验：client_max_body_size 净化去掉', 'app',
     '    except ValueError as e:\n        return None, str(e)\n\n    # WebSocket',
     '    except ValueError:\n        pass\n\n    # WebSocket', 1),

    ('网关上传限制改回硬编码 0（用户配置再次失效）', 'app',
     'client_max_body_size {cmbs};', 'client_max_body_size 0;', 1),

    ('_undo 把快照清理挪到 copytree 之前（同型顺序错误）', 'app',
     '        try:\n            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)\n'
     '            shutil.copytree(backup_dir, NGINX_CONF_DIR)\n        except Exception as e:',
     '        shutil.rmtree(backup_dir, ignore_errors=True)\n'
     '        try:\n            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)\n'
     '            shutil.copytree(backup_dir, NGINX_CONF_DIR)\n        except Exception as e:', 1),

    ('不再清理 v0.8.0 遗留的无认证站点 conf', 'app',
     '                if _is_managed_conf(full):', '                if False:', 1),

    ('迁移：去掉从 domain 派生路径前缀', 'app',
     "                base = _safe_path_prefix('/' + first) or ''", "                base = ''", 1),

    ('证书删除不再保护网关默认证书', 'app',
     '    if is_gateway_default:', '    if False:', 1),

    ('nginx reload 改回裸调 init 脚本（非 OpenWrt 会崩）', 'app',
     '        _r_ok, r_msg = _nginx_reload()\n'
     '        if not _r_ok:\n'
     '            return False, f"网关配置已写入，但 nginx 重载失败：{r_msg}"',
     '        subprocess.run([\'/etc/init.d/nginx\', \'reload\'],\n'
     '                       capture_output=True, text=True, timeout=15)', 1),

    ('迁移：不再挂到 load_config（旧配置不自动升级）', 'app',
     '        result = _migrate_rp_rules(result)', '        pass', 1),

    ('回滚：先删快照再恢复（_deploy_all_rules 同型错误）', 'app',
     '        try:\n            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)\n'
     '            shutil.copytree(backup_dir, NGINX_CONF_DIR)\n'
     '            _nginx_reload()\n'
     '        except Exception as e:\n'
     "            print(f'[WARN] nginx conf 回滚失败: {e}', flush=True)",
     '        shutil.rmtree(backup_dir, ignore_errors=True)\n'
     '        try:\n            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)\n'
     '            shutil.copytree(backup_dir, NGINX_CONF_DIR)\n'
     '            _nginx_reload()\n'
     '        except Exception as e:\n'
     "            print(f'[WARN] nginx conf 回滚失败: {e}', flush=True)", 1),

    ('名单回填去掉 IP 校验（nft 注入回归）', 'eng',
     '            except ValueError:\n                dropped += 1\n                continue',
     '            except ValueError:\n                lines.append(elem)\n                continue', 1),

    # 锚点曾写死 4 空格缩进（_mutate_lists 裸跑的形状）。2026-10-15 修名单落盘
    # 并发（P0-B）时给整个读-改-写套了 _lists_file_lock()，函数体多缩进一层，
    # 锚点匹配 0 次导致这条变异被**静默跳过** —— 变异覆盖悄悄少一条比挂了更糟。
    # 这里同步换锚点，变异代表的仍是同一个原始危害：save_lists 不再被调用。
    ('名单落盘变成空操作', 'app',
     '        data[set_name] = cur\n        save_lists(data)\n    return data',
     '        data[set_name] = cur\n    return data', 1),

    ('配置损坏守卫去掉', 'app',
     '    refused = _config_corrupted_response()\n    if refused is not None:\n        return refused',
     '    refused = None', 1),

    ('信任 IP 改回非 strict（回落硬编码网段）', 'app',
     '"TRUSTED_IP4": _safe_ip(config.get("trusted_ip4", ""), 4, "192.168.4.229", strict=True),',
     '"TRUSTED_IP4": _safe_ip(config.get("trusted_ip4", ""), 4, "192.168.4.229"),', 1),

    # 锚点曾写死 `1/minute burst 1`（P1-6 当时的形状）。2026-10-13 在 .224
    # 真机实测发现 burst=1 正是「敲门第 2 步起永远超限落链尾」的缺陷本体，
    # 模板已改成 1/second burst 4，这里同步换锚点，变异仍代表
    # 「退回规则级全局桶」这个原始危害。
    ('敲门限流改回规则级全局桶', 'tpl',
     'add @knock_rate4 { ip saddr limit rate 1/second burst 4 packets }',
     'limit rate 1/second burst 4 packets', 4),

    ('黑名单放回 established accept 之后', 'tpl',
     '        ip saddr @blacklist4 log prefix "[BLACKLIST4] " drop\n'
     '        ip6 saddr @blacklist6 log prefix "[BLACKLIST6] " drop\n\n'
     '        ct state { established, related } accept;',
     '        ct state { established, related } accept;\n'
     '        ip saddr @blacklist4 log prefix "[BLACKLIST4] " drop\n'
     '        ip6 saddr @blacklist6 log prefix "[BLACKLIST6] " drop', 1),

    ('forward 链的黑名单被挪到 established 之后（只挡新连接，挡不住进行中的会话）', 'tpl',
     '        ip saddr @blacklist4 log prefix "[BLACKLIST4-FWD] " drop\n'
     '        ip6 saddr @blacklist6 log prefix "[BLACKLIST6-FWD] " drop\n'
     '        ct state { established, related } accept',
     '        ct state { established, related } accept\n'
     '        ip saddr @blacklist4 log prefix "[BLACKLIST4-FWD] " drop\n'
     '        ip6 saddr @blacklist6 log prefix "[BLACKLIST6-FWD] " drop', 1),

    ('forward 链的黑名单被整条删掉（端口转发重新变成免黑名单）', 'tpl',
     '        ip saddr @blacklist4 log prefix "[BLACKLIST4-FWD] " drop\n'
     '        ip6 saddr @blacklist6 log prefix "[BLACKLIST6-FWD] " drop\n',
     '', 1),
]


def run_tests():
    """跑完整条基线。任一条红就算捕获；断言数由调用方从合并输出里统计。"""
    rc, out = 0, ''
    for t in TESTS:
        r = subprocess.run([sys.executable, t], capture_output=True, text=True, timeout=300)
        out += r.stdout + r.stderr
        if r.returncode != 0:
            rc = 1
    return rc, out


def main():
    backup = tempfile.mkdtemp()
    for key, path in FILES.items():
        shutil.copy(path, os.path.join(backup, key))
    originals = {key: open(path, encoding='utf-8').read() for key, path in FILES.items()}

    def restore():
        for key, path in FILES.items():
            shutil.copy(os.path.join(backup, key), path)

    print('=== 变异验证 ===')
    rc, _ = run_tests()
    if rc != 0:
        print('❌ 基线就不是全绿，先修好再谈变异')
        restore()
        return 2
    print('  基线全绿，开始注入变异\n')

    caught = missed = skipped = 0
    missed_list = []
    for desc, key, old, new, expect in MUTATIONS:
        src = originals[key]
        n = src.count(old)
        if n != expect:
            print(f'  ⚠️  {desc} —— 锚点出现 {n} 次（期望 {expect}），跳过')
            skipped += 1
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src.replace(old, new))
        rc, out = run_tests()
        fails = out.count('❌')
        if rc != 0:
            print(f'  ✅ {desc} —— 被捕获（{fails} 条断言失败）')
            caught += 1
        else:
            print(f'  ❌ {desc} —— 测试仍然全绿（无效变异！）')
            missed += 1
            missed_list.append(desc)
        restore()

    total = caught + missed + skipped
    print(f'\n=== 结果：捕获 {caught} / {total}'
          + (f'（跳过 {skipped}）' if skipped else '') + ' ===')
    for m in missed_list:
        print('  未捕获: ' + m)
    restore()
    shutil.rmtree(backup, ignore_errors=True)
    return 0 if missed == 0 and skipped == 0 else 1


if __name__ == '__main__':
    sys.exit(main())