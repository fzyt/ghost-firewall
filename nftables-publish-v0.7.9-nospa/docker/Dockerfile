# nftables-web-v2 —— 面板 / 认证网关 的 Docker 测试环境
#
# 用途：**不碰任何路由器**，在本地把面板跑起来，让用户点一遍基本功能。
#       部署到真机之前先把 UI 层的 bug（预设列表不显示那一类）验完。
#
# 为什么镜像里**不装 nftables**
# ----------------------------
# 1. 容器里的 netfilter 规则管的是**容器自己**的网络命名空间，
#    对宿主机的 OpenWrt 毫无意义 —— 测了也是假的。
# 2. 更要命的是：面板的规则集是 `policy drop`，且 input 链只认
#    `iifname "br-lan"` / `iifname "eth1"`。容器里接口叫 eth0 ——
#    两条都匹配不上，流量会一路落到链尾的
#    `limit rate 2/minute burst 5 packets drop`，
#    **发 5 个包之后容器自己就把自己锁死了**，用户连面板都打不开。
#
# 所以：不装 nft ⇒ 面板的防火墙相关功能会明确报「无法执行 nft 命令」，
# 但**面板本身永远可达**，其它功能都能正常测。
#
# 想在容器里真跑防火墙，另开一个带 NET_ADMIN 的容器自己玩 —— 不在本次范围内。

FROM python:3.13-slim

LABEL org.opencontainers.image.title="nftables-web-v2 测试环境"
LABEL org.opencontainers.image.description="面板 + 认证网关的本地测试镜像（不含 nftables）"

# nginx：网关（8443）要用；openssl：面板自签证书要用
RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx-light openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── 代码 ──────────────────────────────────────────────────────
# 布局必须和仓库一致：app.py 从 '../frontend' 取静态资源
# （backend/app.py:1989 的 send_from_directory('../frontend', 'index.html')）
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY setup/vendor/blinker/ /tmp/vendor-blinker/

# ── Python 依赖 ───────────────────────────────────────────────
# blinker 不从 pip 装：25.x 的 OpenWrt 仓库里没有这个包，本项目把它
# **随包携带**（setup/vendor/blinker/，MIT）。这里用同一份源码装，
# 顺带证明"随包携带"这条路径在别的环境也成立。
RUN pip install --no-cache-dir flask \
    && cp -r /tmp/vendor-blinker \
         "$(python3 -c 'import site; print(site.getsitepackages()[0])')/blinker" \
    && rm -rf /tmp/vendor-blinker \
    && python3 -c "import blinker; from flask.signals import Namespace; print('blinker:', blinker.__file__)"

# ── nginx 基础配置 + reload 垫片 ──────────────────────────────
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx-reload.sh /usr/local/bin/nginx-reload.sh
RUN chmod +x /usr/local/bin/nginx-reload.sh \
    && mkdir -p /etc/nginx/conf.d /etc/nginx/ssl/nftables-web

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── 数据目录（全部挂卷，容器可随时重建）────────────────────────
RUN mkdir -p /data/nftables /data/log /data/nginx/ssl /data/nginx/conf.d \
    && mkdir -p /app/frontend && true

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AUTH_CONFIG_PATH=/data/nftables/nftables-web-config.json \
    AUTH_PASSWORD_FILE=/data/nftables/nftables-web-password \
    AUTH_SECRET_FILE=/data/nftables/nftables-web-secret \
    AUTH_RATELIMIT_FILE=/data/nftables/nftables-web-auth-ratelimit.json \
    AUTH_PANEL_RATELIMIT_FILE=/data/nftables/nftables-web-panel-ratelimit.json \
    AUTH_AUDIT_LOG=/data/log/nftables-web-auth.log \
    NFTABLES_WEB_LISTS_PATH=/data/nftables/nftables-web-lists.json \
    NFTABLES_WEB_RULES_PATH=/data/nftables.d/99-custom-rules.nft \
    NFTABLES_WEB_SSL_DIR=/data/nginx/ssl \
    NFTABLES_WEB_NGINX_CONF_DIR=/data/nginx/conf.d \
    NFTABLES_WEB_NGINX_INIT=/usr/local/bin/nginx-reload.sh \
    NFTABLES_WEB_LUCI_CONF=/data/luci/nginx \
    NFTABLES_WEB_LUCI_RENDERED=/data/luci/uci.conf \
    NFTABLES_WEB_LUCI_SNAPSHOT=/data/nftables/nginx-luci.snapshot \
    NFTABLES_WEB_ALIYUN_CONFIG=/data/nftables/aliyun-ddns-config.json \
    NFTABLES_WEB_BIND=0.0.0.0 \
    NFTABLES_WEB_HTTPS_PORT=5443 \
    AUTH_BIND_HOST=127.0.0.1 \
    AUTH_API_PORT=8444

EXPOSE 5443 8443

VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
