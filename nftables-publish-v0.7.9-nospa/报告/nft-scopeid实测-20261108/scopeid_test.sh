#!/bin/bash
# 在隔离 netns 里实测：IPv6 scope-id 能不能把 nft 命令拆开 ⇒ 二阶注入。
#
# 为什么要实测：清单里 P2-15 / P2-29 当年的修复都建立在
# ipaddress 对 IP 字面量的严格解析上。但 Python 3.9+ 的 ipaddress 接受
# 形如 `fe80::1%<任意字符>` 的 scope-id 后缀（含空格、;、}、#）。
# 校验层放行之后，这个字符串会**原样**进 nft 的输入 ——
# nft 自己的解析器会不会把它当成「一个元素」还是「元素 + 后续命令」，
# 只能实测。
#
# 全部在 unshare 出来的临时 netns 里跑，不碰宿主机任何规则集。
set -u
ROOT=/home/kirito/main/tmp/nft-test/root
export LD_LIBRARY_PATH=$ROOT/usr/lib/x86_64-linux-gnu
NFT=$ROOT/usr/sbin/nft

PAYLOAD='fd00::1%} ; delete table inet fw4 ; #'

echo "=== 0. 环境 ==="
$NFT --version

echo
echo "=== 1. 建一张表和一个集合（模拟名单 set） ==="
$NFT -f - <<'EOF'
table inet fw4 {
    set allowed4 {
        type ipv4_addr
        elements = { 10.0.0.1 }
    }
    set allowed6 {
        type ipv6_addr
        elements = { 2001:db8::1 }
    }
}
EOF
echo "建表返回码: $?"
$NFT list tables

echo
echo "=== 2. 走【写路径】形态：argv 里带 payload 的 add element ==="
# 面板的 _nft_set_write(['add','element','inet','fw4',set_name,'{',ip,'}'])
$NFT add element inet fw4 allowed6 '{' "$PAYLOAD" '}' 2>&1 | head -5
echo "返回码: ${PIPESTATUS[0]}"
echo "--- 表还在吗 ---"
$NFT list tables

echo
echo "=== 3. 走【规则集文件】形态：elements 行里带 payload ==="
$NFT -f - <<EOF
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { $PAYLOAD }
    }
}
EOF
echo "返回码: $?"
echo "--- 表还在吗 ---"
$NFT list tables

echo
echo "=== 4. 对照：干净 IPv6（应正常进集合） ==="
$NFT -f - <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { 2001:db8::99 }
    }
}
EOF
$NFT list set inet fw4 allowed6 2>&1 | head -5

echo
echo "=== 5. 对照：纯 scope-id（合法但带接口名） ==="
$NFT -f - <<'EOF'
table inet fw4 {
    set allowed6 {
        type ipv6_addr
        elements = { fe80::1%eth0 }
    }
}
EOF
echo "返回码: $?"
$NFT list set inet fw4 allowed6 2>&1 | head -5
