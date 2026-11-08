#!/bin/bash
# 在隔离 netns 里实测 scope-id 走**文件加载路径**（nft -f）会不会造成二阶注入。
#
# 为什么必须测文件路径：面板生成的是**规则集文件**，用 `nft -f` 加载，
# 不是命令行。之前只测过命令行（`nft add element ...`），
# 而两条路径的解析器行为可能不同 —— 文件模式下 parser 是逐行读的。
#
# ⚠️ 第一版这个脚本的判定是错的：建表时用了 `elements = { }`（空集合），
# 那是**非法语法**，表压根没建起来 ⇒ 第 3 步查「表还在不在」必然查不到，
# 于是误判成「flush ruleset 被执行了 ⇒ 构成注入」。
# ⇒ 建表必须用**合法的非空集合**，且要在注入测试**之前**确认表真的存在。
#
# 全部在 unshare 出来的临时 netns 里跑，不碰宿主机任何规则集。
set -u
ROOT=/home/kirito/main/tmp/nft-test/root
export LD_LIBRARY_PATH=$ROOT/usr/lib/x86_64-linux-gnu
NFT=$ROOT/usr/sbin/nft

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "=== 0. 环境 ==="
$NFT --version

echo
echo "=== 1. 建表（合法的非空集合） ==="
$NFT -f - <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { 2001:db8::1 }
    }
}
EOF
echo "建表后表是否存在："
if $NFT list tables 2>&1 | grep -q "inet fw4"; then
    echo "[ok] 表存在 ⇒ 基线正确，可以继续做注入测试"
    BASE_OK=1
else
    echo "[!] 表不存在 ⇒ 基线就是错的，后面判定不可信，直接退出"
    exit 1
fi

echo
echo "=== 2. 文件路径：把 scope-id 写进 elements 行 ==="
# 面板的 _format_list_elements / _inject_list_elements 会把
# 校验层放行的字符串原样写进这一行。
cat > "$WORK/with_scopeid.nft" <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { fd00::1%; flush ruleset; # }
    }
}
EOF
echo "--- 文件内容 ---"
cat "$WORK/with_scopeid.nft"
echo "--- nft -f 加载结果 ---"
if $NFT -f "$WORK/with_scopeid.nft" 2>&1; then
    echo "[!] 加载成功（返回码 0）"
else
    echo "[ok] 加载失败（返回码非 0）"
fi

echo
echo "=== 3. 关键检查：flush ruleset 有没有执行？ ==="
if $NFT list tables 2>&1 | grep -q "inet fw4"; then
    echo "[ok] 表还在 ⇒ flush ruleset **没有**被执行 ⇒ 不构成注入"
    VERDICT="不构成注入"
else
    echo "[!] 表不见了 ⇒ flush ruleset 被执行了 ⇒ **构成注入**"
    VERDICT="构成注入"
fi

echo
echo "=== 4. 表内容有没有被改？ ==="
$NFT list set inet fw4 allowed6 2>&1 | head -5

echo
echo "=== 5. 结论 ==="
echo "文件路径（nft -f）下 scope-id：$VERDICT"

echo
echo "=== 6. 对照组：合法 scope-id ==="
cat > "$WORK/legit_scopeid.nft" <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { fe80::1%eth0 }
    }
}
EOF
$NFT -f "$WORK/legit_scopeid.nft" 2>&1 && echo "[!] 合法 scope-id 竟然加载成功了" \
    || echo "[ok] 合法 scope-id 也被 nft 拒绝 ⇒ nft 根本不支持 scope-id 元素"
