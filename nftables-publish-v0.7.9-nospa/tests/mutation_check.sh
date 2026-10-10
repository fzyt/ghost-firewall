#!/bin/bash
# 变异验证：逐个把修复改回旧行为，确认 tests/test_review_fixes.py 会失败。
# 全绿的测试套件不能证明它在测东西 —— 必须在 bug 复现时变红。
set -u
cd "$(dirname "$0")/.." || exit 1

APP=backend/app.py
TPL=backend/templates/nftables.conf
ENG=backend/template_engine.py
BK=/tmp/nf-mut-backup
rm -rf "$BK"; mkdir -p "$BK"
cp "$APP" "$TPL" "$ENG" "$BK/"

restore() { cp "$BK/app.py" "$APP"; cp "$BK/nftables.conf" "$TPL"; cp "$BK/template_engine.py" "$ENG"; }

pass=0; fail=0
declare -a FAILED

# 锚点在文件里出现多次时的全量替换版变异
mutate_all() {
  local desc="$1" file="$2" from="$3" to="$4"
  restore
  python3 - "$file" "$from" "$to" <<'PY2'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding='utf-8').read()
n = s.count(old)
if n == 0:
    print(f'    !! 变异锚点不存在')
    sys.exit(2)
open(path, 'w', encoding='utf-8').write(s.replace(old, new))
print(f'    (替换 {n} 处)')
PY2
  if [ $? -ne 0 ]; then echo "  ⚠️  $desc —— 锚点没命中，跳过"; restore; fail=$((fail+1)); FAILED+=("$desc(锚点未命中)"); return; fi
  if timeout 180 python3 tests/test_review_fixes.py >/tmp/nf-mut.out 2>&1; then
    echo "  ❌ $desc —— 测试仍然全绿（无效变异！）"
    fail=$((fail+1)); FAILED+=("$desc")
  else
    n=$(grep -c '❌' /tmp/nf-mut.out)
    echo "  ✅ $desc —— 被捕获（$n 条断言失败）"
    pass=$((pass+1))
  fi
  restore
}

mutate() {
  local desc="$1" file="$2" from="$3" to="$4"
  restore
  python3 - "$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding='utf-8').read()
if s.count(old) != 1:
    print(f'    !! 变异锚点不唯一/不存在 (count={s.count(old)})')
    sys.exit(2)
open(path, 'w', encoding='utf-8').write(s.replace(old, new))
PY
  if [ $? -ne 0 ]; then echo "  ⚠️  $desc —— 锚点没命中，跳过"; restore; fail=$((fail+1)); FAILED+=("$desc(锚点未命中)"); return; fi
  if timeout 180 python3 tests/test_review_fixes.py >/tmp/nf-mut.out 2>&1; then
    echo "  ❌ $desc —— 测试仍然全绿（无效变异！）"
    fail=$((fail+1)); FAILED+=("$desc")
  else
    n=$(grep -c '❌' /tmp/nf-mut.out)
    echo "  ✅ $desc —— 被捕获（$n 条断言失败）"
    pass=$((pass+1))
  fi
  restore
}

echo "=== 变异验证 ==="

mutate "P0-1 反代序号改回未定义的 i" "$APP" \
  "            cert = certs.get(rule.get(\"ssl_cert_id\", \"\"))
            _write_nginx_conf_file(rule, cert, settings, idx)" \
  "            cert = certs.get(rule.get(\"ssl_cert_id\", \"\"))
            _write_nginx_conf_file(rule, cert, settings, i)"

mutate "P0-1 生成循环去掉 try/except（异常不再回滚）" "$APP" \
  "    except Exception as e:
        return _rollback(f\"生成 nginx 配置时异常: {type(e).__name__}: {e}\")" \
  "    except Exception as e:
        raise"

mutate "P0-2 load_config 改回「先合并默认值再迁移」" "$APP" \
  "        config = _migrate_forward_rules(config)
        # 合并默认值（防止新增字段丢失）
        result = dict(DEFAULT_CONFIG)
        result.update(config)
        return result" \
  "        result = dict(DEFAULT_CONFIG)
        result.update(config)
        return _migrate_forward_rules(result)"

mutate "P0-2 _rollback 把快照删除挪回判断之前" "$APP" \
  "        if backup_dir is None or not os.path.isdir(backup_dir):
            # 首次部署" \
  "        shutil.rmtree(backup_dir, ignore_errors=True)
        if backup_dir is None or not os.path.isdir(backup_dir):
            # 首次部署"

mutate "P1-3 名单落盘变成空操作" "$APP" \
  "    data[set_name] = cur
    save_lists(data)
    return data" \
  "    data[set_name] = cur
    return data"

mutate "P1-3 名单回填去掉 IP 校验（注入可利用）" "$ENG" \
  "            except ValueError:
                dropped += 1
                continue" \
  "            except ValueError:
                lines.append(elem)
                continue"

mutate "P1-4 apply_rules 去掉损坏配置守卫" "$APP" \
  "    refused = _config_corrupted_response()
    if refused is not None:
        return refused" \
  "    refused = None"

# 这一处修复有两道防线（备份异常 + 落盘校验）。必须**同时**拆掉才等于回到
# 修复前的真实状态；只拆一道时第二道仍然拦得住，缺陷不会重现 —— 那是变异太弱，
# 不是测试盲区。
mutate "P1-5 备份两道防线全拆（回到旧行为 had_old=False）" "$APP" \
  "        except OSError as e:
            # 备份失败 = 没有回滚材料。接下来的 os.replace 会把旧文件覆盖掉，
            # 万一 nft -f 再失败就什么都恢复不了。所以这里直接中止。
            # （此前是把 had_old 改成 False 继续往下走：失败分支看到
            #  not had_old 就把刚写好的 RULES_PATH 删掉，而 .lastgood 从没
            #  创建过 —— 结果是磁盘上既没有旧规则也没有新规则。）
            print(f'[ERROR] 备份旧规则失败，已中止应用（避免无回滚材料时覆盖现有规则）: {e}',
                  flush=True)
            _unlink_quiet(tmp_path)
            return False, f'备份现有规则失败，已中止应用（未改动现有规则）: {e}'
        # 备份必须真的可读。copy 返回成功不等于内容写全了（磁盘满、权限、
        # 配额都可能），拿一个打不开的备份当回滚材料比没有更危险。
        try:
            with open(lastgood, 'rb') as bf:
                bf.read(1)
        except OSError as e:
            print(f'[ERROR] 备份校验失败，已中止应用: {e}', flush=True)
            _unlink_quiet(tmp_path)
            return False, f'备份现有规则校验失败，已中止应用（未改动现有规则）: {e}'" \
  "        except OSError as e:
            print(f'[WARN] 备份旧规则失败: {e}', flush=True)
            had_old = False"

mutate "P2-9 回滚把 .lastgood 改回搬走（os.replace）" "$APP" \
  "            shutil.copy(backup, RULES_PATH)
            res = subprocess.run(['nft', '-f', RULES_PATH]," \
  "            os.replace(backup, RULES_PATH)
            res = subprocess.run(['nft', '-f', RULES_PATH],"

mutate "P1-7 信任 IP 改回非 strict（会回落硬编码网段）" "$APP" \
  '"TRUSTED_IP4": _safe_ip(config.get("trusted_ip4", ""), 4, "192.168.4.229", strict=True),' \
  '"TRUSTED_IP4": _safe_ip(config.get("trusted_ip4", ""), 4, "192.168.4.229"),'

mutate "P1-8 关闭转发目标语义校验" "$APP" \
  "                why = _bad_forward_target(tgt, r.get('target_ipv6', ''), cfg)
                if why:" \
  "                why = ''
                if why:"

mutate_all "P1-6 敲门限流改回规则级全局桶" "$TPL" \
  "add @knock_rate4 { ip saddr limit rate 1/minute burst 1 packets }" \
  "limit rate 1/minute burst 1 packets"

mutate "P2-10 兜底防火墙改回硬编码 br-lan" "$APP" \
  '        iifname "{lan_if}" tcp dport {{ {port_list} }} accept' \
  '        iifname "br-lan" tcp dport {{ {port_list} }} accept'

mutate "P2-11 DNS 递归开启时也放行无条件 LAN→WAN" "$ENG" \
  "    if variables.get('DNS_LAN_RESOLVER_ENABLED') == 'true':" \
  "    if False:"

mutate "P2-13 健康检查只看表在不在" "$APP" \
  "    if 'hook input' not in out:
        return False, 'input 链未挂载 —— 规则集不完整（可能被整体 flush 过）'
    if 'policy drop' not in out and 'policy reject' not in out:
        return False, 'input 链没有 drop/reject 默认策略 —— 防火墙可能未生效'
    if 'type filter hook input' not in out and 'type filter hook' not in out:
        return False, '未找到 filter 类型的 hook 链'
    return True, '正常'" \
  "    return not _ruleset_is_empty(), 'ok'"

mutate "P2-14 反代删除改回无条件 success" "$APP" \
  "    if not deploy_ok:
        return jsonify({
            \"success\": False,
            \"code\": \"NGINX_DEPLOY_FAILED\"," \
  "    if False:
        return jsonify({
            \"success\": False,
            \"code\": \"NGINX_DEPLOY_FAILED\","

mutate "黑名单放回 established accept 之后" "$TPL" \
  "        ip saddr @blacklist4 log prefix \"[BLACKLIST4] \" drop
        ip6 saddr @blacklist6 log prefix \"[BLACKLIST6] \" drop

        ct state { established, related } accept;" \
  "        ct state { established, related } accept;
        ip saddr @blacklist4 log prefix \"[BLACKLIST4] \" drop
        ip6 saddr @blacklist6 log prefix \"[BLACKLIST6] \" drop"

echo
echo "=== 结果：捕获 $pass / $((pass+fail)) ==="
if [ $fail -gt 0 ]; then
  printf '  未被捕获: %s\n' "${FAILED[@]}"
fi
restore
exit $([ $fail -eq 0 ] && echo 0 || echo 1)