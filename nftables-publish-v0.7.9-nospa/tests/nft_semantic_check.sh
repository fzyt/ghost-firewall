#!/bin/sh
# P0-8 的 nft 语义真机验证脚本（需要在有 root + nft + ip netns 的机器上跑）。
#
# 为什么需要它：P0-8 的正确性依赖几个**只有真机能确认**的 nft 语义事实 ——
#   ① `flush table X` 在表不存在时报错（→ linux_gateway 首次部署会整体失败）
#   ② ruleset 文件里 `table ip nat { chain ... }` 是**合并**语义，
#      陈旧规则不会自己消失（→ 用户删掉的端口转发仍在内核里生效）
#   ③ 同一个 `nft -f` 文件里「建链 → delete 链 → 正文重建同名链」是可行的
#   ④ `flush table ip nat` 会连宿主机 Docker 的规则一起清掉
#   ⑤ `nft -f` 是整文件一个事务 → 没有「规则空档」窗口
# 纯静态断言（tests/test_linux_gateway_preamble.py）只能守住**代码形状**，
# 语义层面的事实必须真机验。这脚本就是把那次实测固化成可重跑的证据。
#
# 用法：
#   1) 生成 linux_gateway 模式的规则集（用产品真实 build_rules）
#   2) sh tests/nft_semantic_check.sh /tmp/rules.nft
#
# 脚本只操作**隔离的 netns**，不碰宿主机的 ruleset。
# 注意：设备上若没有 dummy/veth 模块，netns 里只有 lo，接口名需替换成 lo。

set -u
RULESET="${1:-}"
if [ -z "$RULESET" ] || [ ! -f "$RULESET" ]; then
    echo "用法: $0 <linux_gateway 规则集文件>"
    exit 2
fi
if [ "$(id -u)" != "0" ]; then
    echo "需要 root（要建 netns）"
    exit 2
fi
command -v nft >/dev/null 2>&1 || { echo "没有 nft"; exit 2; }
command -v ip  >/dev/null 2>&1 || { echo "没有 ip"; exit 2; }

NS=nftweb_p0_8_check
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1${2:+  — $2}"; }
chk()  { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3" "实际=$1 期望=$2"; fi; }

new_ns() {
    ip netns del "$NS" 2>/dev/null
    ip netns add "$NS"
    ip netns exec "$NS" ip link set lo up
}

# 模拟「宿主机上有 Docker」：Docker 的 NAT 表 + 它自己的链和规则
seed_docker() {
    cat > /tmp/nftweb_docker.nft <<'DOCK'
table ip nat {
    chain PREROUTING { type nat hook prerouting priority dstnat - 10; }
    chain DOCKER { }
    chain POSTROUTING { type nat hook postrouting priority srcnat; }
}
table ip filter {
    chain DOCKER-USER { }
}
DOCK
    ip netns exec "$NS" nft -f /tmp/nftweb_docker.nft
    ip netns exec "$NS" nft add rule ip nat PREROUTING iifname "lo" tcp dport { 8080 } dnat to 172.17.0.2
    ip netns exec "$NS" nft add rule ip nat POSTROUTING oifname "lo" ip saddr 172.17.0.0/16 masquerade
}

# 用法: count <正则> "<表名>"   —— 表名含空格（"ip nat"）**必须加引号**，
# 否则会被 shell 拆成两个参数，函数只拿到 "ip"，nft 查不到表 → 全部返回 0，
# 断言会「假通过」。这是本脚本第一版的真实 bug。
count() {  # count <正则> "<表>"
    ip netns exec "$NS" nft list table "$2" 2>/dev/null | grep -E -c "$1"
}

# 应用规则集；失败必须**立刻判负**。
# 为什么要单独判：apply 失败时表根本没建出来，后面「陈旧规则=0」这类
# 断言会**因为查不到表而假通过**（负测第一版就踩了这个坑：原版规则集
# 在场景2 里 5 个断言里有 3 个是假绿）。apply 失败 = 整个检查无效。
apply_rules() {
    if ! ip netns exec "$NS" nft -f "$RULESET" 2>/tmp/nftweb_err.txt; then
        bad "应用规则集失败" "$(head -c 300 /tmp/nftweb_err.txt)"
        return 1
    fi
    return 0
}

echo "=== P0-8 nft 语义验证（规则集：$RULESET）==="

echo
echo "--- 场景1：首次部署（全新 netns，表还不存在）---"
new_ns
if ip netns exec "$NS" nft -f "$RULESET" 2>/tmp/nftweb_err.txt; then
    ok "全新 netns 上加载成功（表不存在时不能报错）"
    [ -s /tmp/nftweb_err.txt ] && echo "     stderr: $(head -c 200 /tmp/nftweb_err.txt)"
else
    bad "全新 netns 上加载失败" "$(head -c 300 /tmp/nftweb_err.txt)"
fi
chk "$(ip netns exec "$NS" nft list tables 2>/dev/null | wc -l | tr -d ' ')" "2" "两张顶层表都建好了"

echo
echo "--- 场景2：老部署升级（陈旧规则 + 宿主机有 Docker）---"
new_ns
seed_docker
# 先用规则集本身把表建起来，再注入陈旧规则
apply_rules || true
ip netns exec "$NS" nft add rule ip nat prerouting iifname "lo" tcp dport { 41820 } dnat to 192.168.100.10 2>/dev/null
ip netns exec "$NS" nft add rule ip nat postrouting oifname "lo" masquerade 2>/dev/null
echo "  （已注入陈旧规则：41820->.10、以及多出来的 masquerade）"
# 注入后先确认陈旧规则**确实在**（否则后面的「已清掉」是假通过）
chk "$(count 'dport 41820' "ip nat")" "1" "前置：陈旧规则已注入"
apply_rules || true
chk "$(count 'dport 41820' "ip nat")" "0" "陈旧的端口转发规则已清掉（P0-8 本体）"
chk "$(count 'dport 8080' "ip nat")" "1" "Docker 的端口转发规则没被误伤"
chk "$(count 'chain (PREROUTING|DOCKER|POSTROUTING)' "ip nat")" "3" "Docker 的三条链都还在"
chk "$(count 'DOCKER-USER' "ip filter")" "1" "Docker 的 filter 表没被误伤"
chk "$(count 'masquerade' "ip nat")" "2" "masquerade 不再累积（Docker 1 + 项目 1）"

echo
echo "--- 场景3：幂等性（连跑三次）---"
for _ in 1 2 3; do apply_rules || true; done
chk "$(count 'dport 41825' "ip nat")" "1" "端口转发规则不重复叠加"
chk "$(count 'masquerade' "ip nat")" "2" "masquerade 不重复叠加"

ip netns del "$NS" 2>/dev/null
rm -f /tmp/nftweb_docker.nft /tmp/nftweb_err.txt

echo
echo "=== 合计: ✅ $PASS   ❌ $FAIL ==="
[ "$FAIL" -eq 0 ] || exit 1
