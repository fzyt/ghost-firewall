# nftables-web-v2 —— Docker 本地测试环境

不碰任何路由器，在本机把面板跑起来，让用户点一遍基本功能。
**部署到真机之前先把 UI 层的 bug（预设列表不显示那一类）验完。**

---

## 一分钟跑起来

```bash
cd nftables-publish-v0.7.9-nospa
docker compose -f docker/docker-compose.yml up -d --build
```

面板：<https://localhost:5443>　（自签证书，浏览器会警告，手动信任）

| 端口 | 是什么 |
|---|---|
| 5443 | 面板本体（Flask 自己监听 HTTPS） |
| 8443 | 认证网关（nginx）—— **要在面板里「启用网关」后才有内容** |
| 8444 | 认证服务，**只监听 127.0.0.1**，容器外访问不到（故意的） |

首次进入走 `/api/auth/setup` 设密码；之后用 `/api/auth/login` 登录。

常用命令：

```bash
docker compose -f docker/docker-compose.yml logs -f
docker compose -f docker/docker-compose.yml exec nftweb tail -f /data/log/panel.log
docker compose -f docker/docker-compose.yml down      # 停掉，保留数据
docker compose -f docker/docker-compose.yml down -v   # 停掉并清空数据（重测「首次设密码」）
```

---

## 这个环境**测不了**什么（都是刻意的，不是 bug）

### 1. 防火墙规则相关 —— 全部会报「无法执行 nft 命令」

镜像里**故意不装 nftables**，原因有两条，第二条是致命的：

1. 容器里的 netfilter 规则管的是**容器自己**的网络命名空间，对宿主机的 OpenWrt 毫无意义 —— 测了也是假的。
2. 面板的规则集是 `policy drop`，且 `input` 链只认 `iifname "br-lan"` / `iifname "eth1"`。容器里接口叫 `eth0` —— 两条都匹配不上，流量会一路落到链尾的 `limit rate 2/minute burst 5 packets drop`，**发 5 个包之后容器自己就把自己锁死**，用户连面板都打不开。

所以：**面板本身永远可达**，其它功能都能正常测；防火墙那部分只能上真机测。

### 2. OpenWrt 专属的东西

LuCI 关闭、UCI 配置读写、`/etc/config/nginx` 渲染 —— 容器里没有这些文件，相关接口会报错而不是静默返回假成功。

### 3. 白名单/黑名单显示「暂无数据」，卡片上方有一行琥珀色说明

> 当前环境没有 nft 命令，无法读取防火墙规则集。这里显示为空是因为读不到，不代表真的没有。

**这是预期的，不是故障。** 名单面板里的**白名单/黑名单**是从 nft 规则集里读的，
而这个镜像**故意不装 nftables**（理由见上）⇒ 这两项读不到。

面板把「环境固有」和「真故障」分开了：

| 情况 | 表现 |
|---|---|
| **没有 nft**（本环境） | 卡片里显示上面那行说明，**不弹红色报错** |
| 其它读取失败（超时等真故障） | 照旧弹红色 toast 报警 |

**预设（`/api/lists/presets`）和最近操作不受影响**，照常显示。

### 4. 真实凭据相关的

DDNS（缺阿里云 AccessKey）、ACME 证书签发（缺真实域名）、中国 IP 拦截（未真实下载大列表）—— 这三项在真机上补测。

---

## 能正常测的

| 功能 | 说明 |
|---|---|
| 登录 / 改密码 / 会话 | ✅ |
| 黑白名单、**预设标签** | ✅ 第十七节的 bug 就是在这儿抓出来的 |
| 操作历史、规则健康 | ✅ |
| 反向代理（服务增删改、`api_path_prefix`、Nginx 配置测试/重载） | ✅ |
| 证书管理的**流程**（申请会失败，缺真实域名） | ⚠️ 流程能走通 |
| 面板自身的配置增删改 | ✅ |

---

## 访问边界：为什么需要 `NFTABLES_WEB_PANEL_ALLOWED_NETS`

面板默认按 `lan_subnet4` 限制来源。容器里探测不到 OpenWrt 的 `br-lan`/`eth1`，这个值还是默认的 `192.168.4.0/24` —— **别人家**的网段。

而 docker 发布端口时，容器看到的来源地址取决于流量怎么进来：

| 访问方式 | 容器看到的来源 IP |
|---|---|
| 宿主机自己 `curl 127.0.0.1:5443` | docker 网关 `172.x.0.1` |
| 局域网里的机器访问 `192.168.100.218:5443` | **那台机器的真实 IP** |

所以只放行容器自己的网段，**用户从别的机器点面板会被 `IP_NOT_ALLOWED`（403）挡在门外**。

处理办法（`backend/app.py` 的 `_panel_allowed_networks()`）：

- `NFTABLES_WEB_PANEL_ALLOWED_NETS` 是**额外**放行的网段，跟配置里的取**并集**；
- 配置里本来就不限制时，保持不限制（这个环境变量是"放行"，不是"收紧"）；
- `docker/entrypoint.sh` 会自动**追加**容器网段，不覆盖 compose 里配的值。

compose 的默认值是整个 RFC1918（`192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8`）—— 本地测试环境优先保证"点得开"，面板本身有密码兜底。

**要收紧**：

```bash
cp docker/.env.example docker/.env
# 改成实际网段
#   PANEL_ALLOWED_NETS=192.168.100.0/24
```

---

## 真机部署时这些设置**不生效**

`docker/` 里的所有环境变量都只在 compose 里设，**`setup.sh` 一行都没改**。真机上的访问边界仍然由 OpenWrt 的 `lan_subnet4` / `panel_allowed_nets` 决定，行为与 Docker 环境无关。

`backend/app.py` 里那 19 个路径常量改成了 `os.environ.get(...)`，**默认值就是 OpenWrt 原路径** —— 不设环境变量时行为完全不变。
