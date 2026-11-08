#!/bin/bash
# 实测：nft 1.1.7 对「规则里的地址字面量带 scope-id」是什么反应。
#
# 为什么必须单独测（2026-11-08）：
#   之前只测过 `elements = { fe80::1%eth0 }`（集合元素），
#   而**配置路径**（trusted_ip6 / router_ip6 / 转发目标）里的地址
#   是以**字面量**形式出现在规则里的（如 `ip6 saddr fe80::1%eth0`），
#   不是集合元素 ⇒ 解析路径不同，必须单独确认。
#
# 结论决定报告里「scope-id 到底会让谁失败」的表述：
#   · 若字面量也被拒 ⇒ 面板 apply 的语法预检（nft -c -f）必然失败
#     ⇒ apply 永久中止，但**已生效的规则不变**（预检在 os.replace 之前）
#   · 若字面量被接受 ⇒ 坏值会一路写进磁盘上的规则集文件 ⇒ 开机加载才炸
set -u
ROOT=/home/kirito/main/tmp/nft-test/root
export LD_LIBRARY_PATH=$ROOT/usr/lib/x86_64-linux-gnu
NFT=$ROOT/usr/sbin/nft

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "=== 0. 环境 ==="
$NFT --version

echo
echo "=== 1. 基线：不含 scope-id 的地址字面量（应当成功） ==="
cat > "$WORK/ok.nft" <<'EOF'
table inet fw4 {
    chain input {
        type filter hook input priority 0; policy accept;
        ip6 saddr fe80::1 accept
    }
}
EOF
if $NFT -c -f "$WORK/ok.nft" 2>"$WORK/ok.err"; then
    echo "  基线：语法预检通过（说明字面量写法本身合法）"
else
    echo "  基线：预检失败 —— $(cat "$WORK/ok.err")"
fi

echo
echo "=== 2. 关键用例：地址字面量带 scope-id ==="
cat > "$WORK/bad.nft" <<'EOF'
table inet fw4 {
    chain input {
        type filter hook input priority 0; policy accept;
        ip6 saddr fe80::1%eth0 accept
    }
}
EOF
if $NFT -c -f "$WORK/bad.nft" 2>"$WORK/bad.err"; then
    echo "  结果：预检**通过**（nft 接受带 scope-id 的地址字面量）"
    echo "  ⇒ 坏值会一路写进磁盘上的规则集文件 ⇒ 风险点转移到开机加载"
else
    echo "  结果：预检**失败** ⇒ $(cat "$WORK/bad.err")"
    echo "  ⇒ 面板 apply 的语法预检就会挂 ⇒ apply 永久中止"
    echo "  ⇒ 但已生效的规则不变（预检在 os.replace 之前，不会落盘）"
fi

echo
echo "=== 3. 对照：集合元素带 scope-id（之前已测过，这里复现一遍） ==="
cat > "$WORK/elem.nft" <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { fe80::1%eth0 }
    }
}
EOF
if $NFT -c -f "$WORK/elem.nft" 2>"$WORK/elem.err"; then
    echo "  结果：预检通过"
else
    echo "  结果：预检失败 ⇒ $(cat "$WORK/elem.err")"
fi
