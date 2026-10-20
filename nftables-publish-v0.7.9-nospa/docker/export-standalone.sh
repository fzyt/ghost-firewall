#!/bin/bash
# 导出「独立可跑」的 Docker 测试环境
#
# 为什么有这个脚本
# --------------
# 用户要「复制一份代码去建个 docker」。有两种做法：
#   a) 在仓库里长期放一份代码副本  → 会漂移，改了一处忘了同步另一处，踩坑
#   b) 需要的时候生成一份快照      → 零漂移，永远是当前代码
#
# 选 b。这个脚本把「当前这份代码」打包成一个独立目录，拷到任何有 docker
# 的机器上都能直接跑，命令跟仓库里完全一样：
#
#   cd nftables-web-v2-docker
#   docker compose -f docker/docker-compose.yml up -d --build
#
# 目录结构刻意跟仓库保持一致（docker/ 放在最外层，context 指向它的父目录），
# 所以 Dockerfile 和 compose 文件一个都不用改。
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)

OUT=${1:-"$ROOT/../nftables-web-v2-docker"}

if [ -e "$OUT" ]; then
    echo "目标已存在：$OUT"
    echo "换个名字，或先把它挪走（不要直接覆盖，会留下半新半旧的混合目录）。"
    exit 1
fi

mkdir -p "$OUT"

echo "▶ 复制代码"
cp -r "$ROOT/backend"  "$OUT/backend"
cp -r "$ROOT/frontend" "$OUT/frontend"
mkdir -p "$OUT/setup/vendor"
cp -r "$ROOT/setup/vendor/blinker" "$OUT/setup/vendor/blinker"

echo "▶ 复制 docker 目录"
cp -r "$ROOT/docker" "$OUT/docker"

# 源码里的 __pycache__ / .pyc 不该进包
find "$OUT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$OUT" -name '*.pyc' -delete 2>/dev/null || true

cat > "$OUT/README-独立运行.md" <<'EOF'
# nftables-web-v2 —— 独立 Docker 测试环境

这是一份**独立快照**，不需要 git、不需要整个仓库，`docker/` 里的说明
（README.md）适用于本目录。

## 运行

```bash
cd nftables-web-v2-docker
docker compose -f docker/docker-compose.yml up -d --build
```

面板：<https://localhost:5443>　（自签证书，浏览器会警告，手动信任）

| 端口 | 是什么 |
|---|---|
| 5443 | 面板本体（Flask 自己监听 HTTPS） |
| 8443 | 认证网关（nginx）—— 要在面板里「启用网关」后才有内容 |
| 8444 | 认证服务，只监听 127.0.0.1（故意的） |

## 停止 / 清数据

```bash
docker compose -f docker/docker-compose.yml down      # 停掉，保留数据
docker compose -f docker/docker-compose.yml down -v   # 停掉并清空（重测「首次设密码」）
```

## 注意

- 镜像里**不装 nftables**（故意的），防火墙规则相关功能在这个环境里会报错，
  详见 `docker/README.md`。
- 局域网里别的机器访问时，来源 IP 不是 docker 网关，面板会回 403
  `IP_NOT_ALLOWED`。要收紧网段就改 `docker/.env`（从 `docker/.env.example` 复制）。
EOF

echo
echo "✅ 已导出到: $OUT"
echo
echo "拷到别的机器后："
echo "  cd $(basename "$OUT")"
echo "  docker compose -f docker/docker-compose.yml up -d --build"
echo
du -sh "$OUT"
