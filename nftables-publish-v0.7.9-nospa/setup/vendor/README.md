# vendor/

## blinker/ 1.9.0

Flask 3.x 的硬依赖（`flask.signals` → `from blinker import ...`），
但 **OpenWrt 25.12 的 apk 仓库里没有 blinker 包**，`python3-flask` 的依赖里
也不含它。

原先的兜底是 `pip3 install blinker`，而 `python3-pip` 本身 **52.3 MiB** ——
在 OpenWrt 常见的 80~90MB overlay 上根本装不下（实测 `.245` 装完只剩 28MB）。

所以改成**随包携带**：`setup.sh` 在 `import blinker` 失败时，把
`vendor/blinker/` 复制进 site-packages。32KB，纯 Python，无编译。

许可：MIT（见 `blinker/LICENSE.txt`）。

## acme-dnsapi/（acme.sh DNS-01 插件）

面板的「申请证书 / 自动续期」用 **DNS-01** 验证，而 DNS-01 必须由 acme.sh 的
`dnsapi/dns_<provider>.sh` 插件去写 TXT 记录。

OpenWrt 的 apk/opkg 包 `acme-acmesh` 装的是**裁剪版** acme.sh —— 主脚本有，
但一个 `dnsapi/dns_*.sh` 都不带。所以面板点「申请证书」必然失败。

原先的做法是**运行时去 GitHub/Gitee 下载**这 6 个插件，代价是：

- `raw.githubusercontent.com` 在国内**间歇性**可达（同一台机器上 12:07
  curl 0.365 秒就通，12:11 同样的命令直接超时）
- 失败很慢：`--max-time 30 --retry 1` ⇒ 一个插件最坏烧 60 秒，6 个就是
  **6 分钟**纯等待，最后还可能一个都没下下来
- 老版本 setup.sh 只验「文件非空」，**不验内容是不是真插件** —— 代理返回一个
  200 的错误页也会被当成插件存下来
- 2026-10-31 在 `.142` / `.156` / `.230` 三台设备上连续踩到

所以改成**随包携带**：`setup.sh` 把 `vendor/acme-dnsapi/` 复制进
`~/.acme.sh/dnsapi/`，**完全不碰网络**。56KB，纯 shell 脚本，无编译。

网络下载保留为**兜底**（用户只下一个 `setup.sh`、不带 `vendor/` 的老用法
不能因此坏掉）。

清单（与面板支持的 DNS 提供商一一对应）：

| 文件 | 提供商 | 凭据字段 |
|---|---|---|
| `dns_ali.sh` | 阿里云 | `Ali_Key` / `Ali_Secret` |
| `dns_tencent.sh` | 腾讯云 | `Tencent_SecretId` / `Tencent_SecretKey` |
| `dns_cf.sh` | Cloudflare | `CF_Key` / `CF_Email` 或 `CF_Token` |
| `dns_huaweicloud.sh` | 华为云 | `HUAWEICLOUD_Username` / `HUAWEICLOUD_Password` |
| `dns_porkbun.sh` | Porkbun | `PORKBUN_API_KEY` / `PORKBUN_SECRET_API_KEY` |
| `dns_gd.sh` | GoDaddy | `GD_Key` / `GD_Secret` |

来源：acme.sh 官方仓库（`acmesh-official/acme.sh` 的 `dnsapi/` 目录），
Gitee 官方镜像 `neilpang/acme.sh`。许可：acme.sh 为 **GPL-3.0**，
本目录下的文件是 acme.sh 的组成部分，同样按 GPL-3.0 分发。

