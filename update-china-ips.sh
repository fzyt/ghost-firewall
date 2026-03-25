#!/bin/sh
# 中国IP集合自动更新脚本
# 从 GitHub 下载中国IP列表，转换为 nftables 集合格式
NFT_FILE="/etc/nftables/china-ips.nft"
URL="https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt"

TMP=$(mktemp)
wget -qO "$TMP" "$URL" 2>/dev/null
if [ ! -s "$TMP" ]; then
    echo "下载失败"
    rm -f "$TMP"
    exit 1
fi

mkdir -p /etc/nftables

# 生成 nftables 文件：先清空合集，再逐条添加
echo "# 中国IP集合 - 自动生成 $(date)" > "$NFT_FILE"
echo "flush set inet fw4 china_ipv4" >> "$NFT_FILE"

COUNT=0
ELEMENTS=""
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?')
    if [ -n "$line" ]; then
        if [ -n "$ELEMENTS" ]; then
            ELEMENTS="${ELEMENTS}, "
        fi
        ELEMENTS="${ELEMENTS}${line}"
        COUNT=$((COUNT+1))
        # 每500条flush一次避免单行过长
        if [ $((COUNT % 500)) -eq 0 ]; then
            echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
            ELEMENTS=""
        fi
    fi
done < "$TMP"

# 写入剩余的
if [ -n "$ELEMENTS" ]; then
    echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
fi

rm -f "$TMP"
echo "完成，共 $COUNT 条中国IP，已写入 $NFT_FILE"
echo "请执行: nft -f /etc/nftables/china-ips.nft"
