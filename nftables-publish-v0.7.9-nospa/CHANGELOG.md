# Changelog

所有重要更改均记录在此文件中。

## [v0.8.3] - 2026-10-12

功能性审查发现的 7 个缺陷修复。**规则链相关问题不在本版范围**（P0-1 见文末）。

### P0-2  ACME 路径漏掉私钥权限加固（上一版引入的回归）

v0.8.2 把 nginx worker 降到了 `nobody`，但私钥仍是 `600 root`。
上传和重传两条路径都会 `chmod(key, 0o600)` 之后调 `_harden_key_for_nginx_worker()`，
**ACME 两条路径不会** —— acme.sh 自己写出 `privkey.pem` 600 root，项目这边根本不 chmod。

后果：手动传的证书能用，ACME 申请的证书一续期就 TLS 握手失败。而面板这侧
`expires_at` 正常、UI 照样显示「● 有效」，排障方向会被完全带偏到「是不是
nginx 配置错了」。

- `_acme_issue()` 与 `_acme_renew()` 各补一次 `_harden_key_for_nginx_worker()`
- 顺手修了 `_harden_key_for_nginx_worker` 的 docstring：原来写「三条路径
  （上传/ACME续期/自签）」，但第三条其实是 reupload 不是 ACME —— **注释自己
  撒谎，恰好掩盖了 ACME 的缺口**。改成如实列出五条

### P0-3  证书续期按钮永远不显示

后端写 `"source": "auto"`，前端判 `cert.source === 'acme'`。两边对不上，
ACME 证书的「续期」按钮从来不会出现。

改前端（`cert.source === 'auto'`）而不是改后端：后端 `auto` 已经落进存量
配置，`/renew` 的 `!= "auto"` 守卫也按 `auto` 写的，动后端会同时打断两者。

### P1-1  反代 CRUD 漏交叉校验，可构造免认证 DNAT 直达

`rp_create_rule` / `rp_update_rule` / `rp_delete_rule` 都不调 `validate_config`，
所以完全绕过了「端口转发目标不能是已启用的反代服务」这条交叉校验。
于是可以先建一条端口转发，再建一条指向同一后端的反代 —— DNAT 走 nftables，
根本不经过 nginx 的认证层，一条完全免登录的公网入口就成立了。

- 把交叉校验抽成唯一入口 `_rp_forward_conflicts(cfg)`，`validate_config` 与
  反代 CRUD 共用。两份逻辑迟早分叉，PUT 就是这么漏的
- `rp_create_rule` 在 append 后、部署前校验，冲突时 `rp["rules"].pop()` 撤销
- `rp_update_rule` 在 mutate 后、部署前校验，冲突时 `rule.update(original)` 还原
- 新增 `tools/check-api-coverage.py`：比对前后端接口覆盖度

### P1-2  `/auth/static/` 下的 HTML 拿不到 CSP

`location /auth/static/` 排在 `location /auth/` 之前，所以 `login.html` 和
`portal.html` 可以直接从静态路径取到（真机实测返回 200），**不带 CSP** ——
等于多了一条绕过 CSP 的路。

- `auth_gateway.py` 新增 `CSP_LOGIN_HTML` / `CSP_PORTAL_HTML` 常量
- `static_files` 对 `.html` 按文件名选对应 CSP；门户页与登录页改用常量，
  不再各自内联第二份（两份 form-action 不同的策略迟早分叉）

### P1-3  网关配置先落盘后部署

`/api/gateway/config` 里 `save_config()` 排在 `_deploy_gateway_nginx()` 前面。
nginx 部署失败时磁盘上已经是新配置、生效的却是旧配置，两者从此不一致；
提示还写着「配置已保存但网关部署失败」，用户下次动别的字段时又会基于这份
落盘配置重新生成，把问题静默放大。

改为**先部署、后落盘**，失败时明确返回「网关部署失败，配置未保存」。

### P2-1  手动更新 IPv6 不写 DDNS 中转文件

`/tmp/ddns-ipv6-*` 只有 cron 脚本会写。手动点「更新 IPv6」只改了内核 set，
中转文件始终是空的 —— 阿里云 DDNS 与通用 DDNS（`ip_script=/bin/cat
/tmp/ddns-ipv6-N`）读到的还是旧值，**IPv6 记录静默停在过期地址上，没有任何报错**。

`update_ipv6()` 现在同样写 `/tmp/ddns-ipv6-0` 与 `/tmp/ddns-ipv6-{idx}`，
且写失败只告警不阻断（IO 错误不该让整个接口 500）。

### P2-2  上传证书不校验证书与私钥配对

原来只做域名正则 + 三字段非空就落盘。传错私钥（换证书时两个文件选反，
非常容易）的话 nginx 拿着不匹配的 key 做 TLS 握手，而面板 `expires_at`
正常、UI 显示「● 有效」，排障方向同样被带偏。

- 新增 `_cert_key_pair_ok()`：比较两边公钥（`openssl x509 -pubkey` vs
  `openssl pkey -pubout`）。用 `pkey` 而非 `rsa`，ECDSA 私钥也能过
- openssl 不可用时**放行**：校验不了 ≠ 校验失败，环境问题不该拦住用户存证书
- `rp_upload_cert` / `rp_reupload_cert` 改为**先写 `.tmp` 校验、通过才
  `os.replace` 覆盖** —— 传错私钥时原来能用的证书必须保住

### P2-3  `/api/rules/save` 是一条绕过全部安全机制的旁路

这条是新写的 `tools/check-api-coverage.py` 报出来的：后端 75 条路由里，
它是唯一一条「有路由、前端零调用」**且**绕过 v0.8.x 全部加固的。

原实现 `build_rules()` + 直接写盘，同时绕过：

- `_config_corrupted_response()` —— 配置损坏时 `load_config()` 返回硬编码
  `DEFAULT_CONFIG`（内含他人网段），原实现拿它直接落盘，等于把陌生网段写进
  真实防火墙，还回报 `success: true`
- `_FW_APPLY_LOCK` —— 与看门狗的 `nft -f` 交叉执行
- `_apply_ruleset()` 的语法校验与失败回滚

`app.py:2082` 的注释早就写明「避免出现某条路径跳过了校验和回滚」——
这条路径当时就是那个例外。

改为转发给 `/api/rules/apply`（保留端点，不打断可能存在的 curl / 脚本调用方）。
**是否直接从路由表删掉更干净，留给你定。**

### 顺带修掉的工具 bug

`tools/check-api-coverage.py` 初版只抓 `api.get/post/...`，漏了 multipart
上传走的裸 `fetch(...)`，把整条证书上传链路误判成死接口；改用正则抓第一个实参
又会在拼接 URL 的闭合引号处截断。这两处都会产出「后端有路由但前端从不调用」
的**假结论** —— 假阳性比漏报更糟，它会让人去删一个其实在用的接口。改成正经解析
实参（跟踪引号与嵌套）后【A】前端调了但后端没有、【C】方法不匹配均为空。

修正后工具报出的另外 10 条真死接口（前端零调用，且无表单/location 等其他入口）：

```
/api/knock-info                 /api/network/wan-ipv6
/api/aliyun-ddns/test           /api/network/install-ipv6-cron
/api/firewall/china-ips-script  /api/scripts/update-ipv6.sh
/api/rules/health               /api/auth/change-password
/api/reverse-proxy/nginx/preview/:id
/api/reverse-proxy/certificates/:id/reupload
```

其中 **`/api/reverse-proxy/certificates/:id/reupload` 本轮刚加了配对校验，
但前端没有任何入口** —— 也就是说那个修复目前只有 curl 能触发。
是否补一个「重新上传」按钮，也留给你定。

### 测试

新增 `tests/test_functional_fixes.py`（52 条断言）+ `tests/mutation_check_functional.py`
（25 条变异）。所有变异 100% 被捕获。

跑测试时发现并修掉三处**测试自身的弱点**（不是代码 bug）：

1. 断言匹配到了解释性注释里的字面量（`save_config()`、「配置已保存但网关部署
   失败」）—— 已加 `strip_comments()`，位置判断前先剥注释
2. FIX-6 断言只找 `/tmp/ddns-ipv6-*` 这个串，旁边的 `print("[WARN] 写 …失败")`
   里有同样的串，于是「删掉真正的写入、留着警告」也能通过 —— 改成盯 `open()` 调用本身
3. `test_privilege_drop.py` 的 PD-11 按参数名 `(key_path|NFTABLES_WEB_KEY)` 统计
   加固调用点，**把两条 ACME 路径排除在统计之外** —— 这正是 P0-2 能长期存在的
   原因：断言号称「补权限与 chmod 一一对应」，却对 ACME 完全失明。改成数全部
   调用点（5 处）并新增「chmod 之后紧跟加固」的顺序断言，对应补 N8/N9/N10 三条变异

### 回归（改动前后各跑一遍）

```
单元  test_review_fixes 142 · test_privilege_drop 51 · test_auth_gateway 68
      test_security_fixes · test_fw_recovery · test_log_parser · test_functional_fixes 52
      前端 test_frontend.js 29                                  —— 全绿
变异  mutation_check 19/19 · mutation_check_security 10/10
      mutation_check_privilege 19/19 · mutation_check_functional 25/25 —— 全捕获
```

### 不在本版范围

- **P0-1**：开启「境外 IP 拦截」但集合为空时，`china_ipv4 drop` 在 `input_wan`
  链内排第 2 条，敲门在第 25 条、白名单放行在第 30 条 —— 空集合会让 WAN IPv4
  全断，且语法合法所以不回滚。**规则链问题按要求本轮不改**
- 面板 9 条低危 finding + 3 个网关低危 finding
- 证书链路的真机验证见下

### 尚未真机验证

本版代码**尚未部署到 .224**，以下仍需用户在真环境确认：
证书上传/重传链路、ACME 续期后的 worker 读权限、真实 NAS/DSM 门户后端、
真实 WAN 敲门限流（.224 无物理 WAN 口且内核不支持任何虚拟网卡类型，
结构上做不到）。

## [v0.8.2] - 2026-10-12

认证网关**降权运行**。这是本项目第一次把「公网可达的代码」移出 root 权限域。

### 问题

`auth_gateway.py` 是**唯一直接处理公网请求的进程**：面板只在 LAN、认证 API
只在回环，但 nginx 的 `auth_request` 会把公网流量送进这里。

它此前由 init 脚本以 root 启动，而它**根本不需要 root** —— 只读配置、
做 PBKDF2、绑 `127.0.0.1:8444`（>1024 不需特权）、调 `logger`（任意用户可调）。

后果不是「服务被攻破」，而是**整台机器沦陷**：任何一处 RCE 都可以
`nft flush ruleset` 关掉防火墙、`kill` 掉看门狗进程让规则集永远不再自愈、
读 SSH 私钥与 `/etc/shadow`。看门狗挡不住这个 —— 它和被保护对象在同一个
root 权限域，攻击者拿到 root 的第一件事就是把它关掉。

### 根因

降权不能靠外部工具：OpenWrt 没有 `useradd` / `adduser` / `su` / `setpriv`
（busybox 未编译这些 applet），`chroot` 也是 BusyBox 版且**没有 `--userspec`**，
只能切根目录不能降权。所以降权只能在 Python 进程内用 `os.setuid()` 完成。

### 改法

- `auth_gateway.py` 新增 `_drop_privileges()`，**模块级执行**（与既有的
  `_assert_loopback_bind()` 同一模式：导入即生效，gunicorn / waitress 加载也逃不掉）
- init 脚本幂等建 `nftweb` 用户（直接追加 `/etc/passwd`+`/etc/group`，
  与 dnsmasq / logd / ubus 同样的做法），预建数据文件并改属主
- `/etc/nftables` 设 setgid：日后 `app.py` 以 root 重建密码/密钥文件时，
  组仍归 `nftweb`，网关读得到 —— 少了这一步，「用户改密码 → 文件被重建 →
  属主变 root → 登录全断」会在某个随机时刻炸开

### 安全设计要点（每条都有对应测试）

- **失败即退出**：降权失败绝不「打印警告然后继续以 root 跑」——
  那比不写更糟，读代码的人会以为已经降权了
- **两道独立防线**：①`except` 里 `raise SystemExit(1)` ②降权后复核
  `geteuid`/`getuid`/`getgid`。只拆①，②仍然独立拦住 —— 变异验证里
  专门区分了这两种情况，避免把「变异太弱」误判成「测试没用」
- **`initgroups` 不可省**：只 `setuid` 不清组权限 = 假降权
- **顺序不可反**：`setgid` 必须在 `setuid` 之前，uid 一旦非 0 就再也改不了 gid
- **`AUTH_DROP_UID=0` 直接拒绝启动**：那等于没有降权
- init 脚本在进程起来后**再核一次 `/proc/<pid>/status` 的 uid**，为 0 就杀掉并报错

### 真机实测（.224，OpenWrt 24.10，Python 3.11.14）

```
进程身份    Uid: 1000 1000 1000 1000 / Gid: 1000 1000 1000 1000 / Groups: 1000
文件可读    password / secret / config.json  → OK（登录不断）
文件不可读  /etc/shadow、dropbear 私钥、/root 下任何东西 → Permission denied
反向验证    nft flush ruleset        → Operation not permitted (you must be root)
            nft add rule ... accept  → Operation not permitted
            kill -9 1                → Operation not permitted
端到端      网关登录成功 {"success":true,"user":"kirito"}，审计日志正常落盘
```

`cp nftables-web-secret → /tmp` 仍然成功，这是**必须保留**的能力 ——
网关要靠这个密钥签 token，砍掉它等于砍掉认证。

### 顺带修掉的两个问题

- `_drop_privileges()` 未配置环境变量时整体跳过，开发机与单元测试不受影响
- 发现 `/etc/nftables.d/` 下的规则文件本来就是 644 且含无密钥 —— 未改动，
  仅记录在此以免后续误以为与本次改动有关

---

## [v0.8.2-rc1] 2026-10-12 · nginx worker 同样降权

与上面的网关降权同属一类，但入口在 HTTP 层而不是应用层。

### 问题

`/etc/nginx/uci.conf` 里是显式的 `user root;`，worker 进程以 root 运行。
master 需要 root（读私钥、bind 低端口），但**真正处理公网流量的是 worker**。
nginx 侧任何一处漏洞（请求走私、模块缺陷、配置误伤）落地就是 root。

### 改法

新增 `tools/nginx-priv-drop.sh`：master 保留 root，worker 降到 `nobody`。
配套在 `app.py` 加 `_harden_key_for_nginx_worker()`，在**每一次私钥写入之后**
补组读权限 —— 见下面「私钥权限为什么必须跟着每次写入走」。

### 实测踩到的三个坑（都已写成回归测试）

1. **`nginx -t` 验的不是服务实际加载的配置。** 裸 `nginx -t` 读
   `/etc/nginx/nginx.conf`，而 init 脚本起的是 `nginx -c /etc/nginx/uci.conf`。
   两份文件不同，于是拿到一个**假绿灯**，真正的原因根本不在被验的那份里，
   `restart` 之后网关直接起不来。→ 脚本改为 `nginx -t -c "$CONF"`。

2. **nginx 的 `user` 指令内部是 `getpwnam()` + `getgrnam()`，两个都要查，
   而且用同一个名字。** OpenWrt 的 `/etc/passwd` 里有 `nobody`，
   `/etc/group` 里却只有 `nogroup` 没有 `nobody` —— 只查用户会漏掉这一半，
   nginx 报 `getgrnam("nobody") failed` 拒绝启动。→ 脚本检测并自动补建组。

3. **`user` 指令只在 master 启动时生效，`reload` 不改 worker 身份。**
   实测 reload 之后 worker 仍然是 uid=0。→ 指令有变更时走
   `/etc/init.d/nginx stop && start`。

另外复核那段原本写成「遍历进程、发现 worker 还是 uid=0 就报错」，
**但 nginx 一个进程都没有时循环体一次都不进，BAD 保持 0，脚本会谎报「完成」**。
已补进程数量下限判断。

### 私钥权限为什么必须跟着每次写入走

`app.py` 在三处（上传 `:5669`、ACME 续期 `:5773`、自签生成 `:6252`）
都会 `os.chmod(key, 0o600)`。那是对的 —— 私钥本就不该被别人读到。
但 worker 现在以 `nobody` 运行，必须能读私钥才能做 TLS 握手，于是：

> 只改一次 nginx 的 user → 下一次换证书，worker 立刻读不到私钥，
> 而 nginx 的表现只是「TLS 握手失败」，没有任何提示说明是权限问题。

规则：**谁把权限打回 600，谁就负责补成 worker 可读。**
`640 root:nobody` 对「其他用户」依然完全关闭，实际暴露面和 600 等价。

### 真机实测（.224）

```
master pid=6965 uid=0                      ← 保留 root，正确
worker pid=7172 uid=65534                  ← 已降权
worker pid=7173 uid=65534
privkey.pem  root:nogroup 640              ← worker 的 gid 65534 读得到
端到端      网关 200 / 登录 200 / 面板 200 / 防火墙 257 行
```

### 关于 chroot：评估后决定不做

评估过给认证网关加 chroot 做二层隔离，**结论是不做**，理由是数据不支持：

- 磁盘只剩 **19.6M**，Python stdlib + site-packages 是 **52M**
- 放进去只能走「硬链接约 3 万 inode」或「bind mount 等于把 52M 全搬进去」
  两条路，前者在 2 核机器上很慢，后者让「最小化」名存实亡
- 还要在主机上留 5 个 mount，崩溃即残留
- 而它相对已拿到的非 root 权限，边际收益很小：实测 `nftweb` 本来就
  读不到 `/etc/shadow`、SSH 私钥、`/root`，也动不了 `nft`、杀不了进程

风险收益不成比例，不做。

### 仍未覆盖

- **证书链路**（上传 / ACME / 续期 / 设默认 / 删除保护）真机零验证
- **WAN 侧规则在任何机器上都未执行过**：`.224` 无物理 WAN 口，且内核不支持
  任何虚拟网卡类型（veth / dummy / macvlan / ipvlan 均 `Not supported`），
  结构上不具备验证条件。需在有真 WAN 口的设备上验收
- 面板 9 条 finding + 网关 3 条低危仍按原划界暂缓

## [v0.8.1] - 2026-10-11

反代模块收敛为**认证网关单轨**，并重做管理界面。
v0.8.0 里一条规则同时生成「独立站点 conf」和「网关 location」两套暴露面，
但 `path_prefix` 既没有写入路径也没有 UI —— 实际只有无认证的独立站点在跑。
这一版砍掉独立站点，所有服务统一挂在网关的一个端口下。

### 后端：字段校验统一到唯一入口

`PUT /api/reverse-proxy/rules/<id>` 的 `target_protocol` 和 `listen_port` **零校验**。
实测传 `"http;}\n server { listen 9999; #"` 能注入出第二个 server 块并落盘；
`listen_port` 传 `''` / `True` / `443.5` / `[443]` 会拼出任意文件名。

根因是 POST 和 PUT 各抄了一份校验，PUT 那边漏了。现在统一为 `_validate_rp_service`，
POST/PUT 共用 —— 两份校验迟早会再次分叉。

### 后端：修掉一批审核缺陷

- 证书删除保护检查 `rules[].ssl_cert_id`（该字段已随单轨移除）→ 恒空 →
  删掉网关默认证书不被拦。改查 `settings.default_cert_id`
- `_deploy_gateway_nginx._undo` 先 `rmtree` 快照再 `copytree` 恢复 → 恢复必然失败，
  且失败前已把整个 `conf.d` 删光，用户自己的站点配置全丢
- nginx reload 三处裸调 `/etc/init.d/nginx`，普通 Linux 直接 `FileNotFoundError`
  → 统一走 `_nginx_reload`，`NGINX_INIT_PATH` 抽成常量
- `client_max_body_size` 只允许大写 `K/M/G`，照 nginx 文档填最常见的 `10m` 反被拒
  → 大小写都收、输出归一

### 后端：规则结构简化

规则简化为 `{id, name, enabled, path_prefix, target_address, target_protocol,
public_access, client_max_body_size, websocket_enabled, icon}`，
删除 `domain` / `listen_port` / `ssl_cert_id`。

删除 `_generate_nginx_conf` / `_write_nginx_conf_file` / `_remove_nginx_conf_file` /
`_remove_nginx_conf_by_domain_port`（约 250 行）。新增 `_migrate_rp_rules`：
旧规则自动派生 `path_prefix`（`nas.test` → `/nas`），挂在 `load_config` 上。

### 前端：界面重做

- 反代表单换字段，新增网关配置卡（总开关/端口/会话超时/绝对有效期/内网免登录/状态行）
- 修 6 个缺陷：编辑服务会变追加（`delete _editIndex` 写在判断之前，条件恒假）、
  新增按钮种子字段全是旧的、卡片不显示路径前缀和目标地址、
  卡片无任何操作按钮（`editRpRule`/`deleteRpRule`/`testRpRule` 从未被 HTML 引用）、
  `cancelRpEdit` 未定义导致点「取消」抛异常、WebSocket 说明里的损坏字符

### 验证

- 后端回归 142 + 68，变异验证 19/19 捕获
- 面板 e2e 24/24（连跑 3 次稳定）、网关 e2e 16/16、视觉 22/22
- 真机 OpenWrt：nginx -t 通过；`/nas/` 走 auth_request + 跳登录，
  `/dsm/` 走内网 allow/deny，60MB 上传被 413 拦下

### 已知未覆盖

- 证书链路（上传 / ACME / 续期 / 设默认 / 删除保护）在真机一次都没跑过，
  测试机用的是自签证书，证书库为空
- 门户后端是假服务（`/tmp/fake_services.py`），未对接真实群晖/DSM
- `.224` 无物理 WAN 口，敲门限流按源分桶虽有真实流量规则但未经真实 WAN 验证
- 反代保存仍会连带调用 `_apply_ruleset` 重刷防火墙，与「应用规则」按钮解耦待做

## [v0.8.0] - 2026-10-05

单端口认证网关（多进程架构）。**这一版的重点不是新功能，是把安全边界重新划清。**

### 架构：面板与认证彻底分离

```
进程 A  app.py           面板    5443   仅 LAN，公网不可达
nginx   系统自带          网关    自定义高位端口（默认 8443）
进程 B  auth_gateway.py  认证API  127.0.0.1:<auth_api_port>
```

- **面板不再有任何公网入口**。原先面板监听 `0.0.0.0` 且借用反代私钥（连带触发 HSTS
  `includeSubDomains` 锁死子域，即审查记录里的待定项 N-5），现在一并消失
- **认证服务只绑 `127.0.0.1`**，启动时检查 `AUTH_BIND_HOST`，非回环地址直接退出。
  nftables 侧不为该端口生成任何放行规则
- **认证崩了 = 网关 502 = 公网入口全断，但 LAN 上一切正常**，面板仍能打开修问题。
  这正是原设计稿最担心的「保险丝装在电表箱里」自锁问题

### 新增：单端口认证网关

- 所有服务收敛到**一个端口**，靠 URL 路径前缀区分（`/nas/`、`/dsm/`、`/photos/`）
- `auth_request` 子请求做认证，未认证 401 → 302 跳登录页
- **`public_access` 语义由「放行哪个端口」改为「限制来源」**：
  - `true` → 所有来源可达，但必须先过认证
  - `false` → nginx `allow <lan_subnet>; deny all;`，仅内网可达、不进认证
  - 认证层管「有没有 token」管不了「从哪来」，来源限制必须在 nginx 落地才有效
- **公网暴露面从「N 个反代端口」收敛成 1 个**。`tcp_services` 白名单里，
  网关开启时只放行 `gateway_port` 一个端口
- **网关端口完全可配置**（含家宽常用的非 443 高位端口），不写死
- 首次进入需验证，之后带 token 访问；滑动窗口默认 1800 秒（30 分钟），后台可改
- 新增 `access_log`（此前项目生成的 nginx conf **一条访问记录都没有**），
  记 `$uri` 而非 `$request_uri`，避免把查询串里的敏感参数写进日志

### 新增：认证安全基线

| 项 | 做法 |
|---|---|
| fail-closed | `/auth/verify` 结构上只有两处返回 200（内网豁免 / 校验通过），其余路径含**所有异常**一律 401。测试注入 `load_gateway_config` 与 `parse_token` 抛异常验证过 |
| 限流落盘 | 面板原有 `_failed_logins` 是内存 dict，**进程重启即清零 → 等重启即可绕过**。本进程计数落盘 + `fcntl` 锁 |
| token 密钥域分离 | 从 SECRET 文件派生独立子密钥，不复用 Flask `SECRET_KEY` |
| 续期换 jti | 每次续期重新签发，杜绝旧 token 重放 |
| 幂等时间比较 | 签名比对统一走 `hmac.compare_digest` |
| CSRF | 登录端点校验 `Origin`/`Referer`，跨站直接 403 |
| 抗枚举 | 登录失败响应体对「密码错」与「未设密码」完全一致 |
| 弱哈希拒绝 | PBKDF2 迭代数 < 100000 的存量哈希直接判失败，而不是降级接受 |
| Bearer 支持 | `/auth/verify` 同时认 cookie 与 `Authorization: Bearer`，供脚本使用 |
| 审计落盘 | 登录/登出/续期/拒绝全部写 JSONL，含来源 IP、设备标识、指纹、UA |

### 安全修复：Shannon 渗透测试实测确认的公网认证口缺陷

2026-10-07 用 Shannon v3.2.0 对认证网关（公网唯一入口）与管理面板各跑一轮，
逐条独立复现验证后修复。**本节只列公网认证口（进程 B）的 4 处**，
管理面板那 9 条按用户判断属 LAN 面，暂缓。

**① [critical] `0.0.0.0/0` / `::/0` 被当成合法网段 → 全员免认证**

`_safe_cidr` 只校验「是不是合法 CIDR」，`0.0.0.0/0` 完全合法。
`.224` 上实测完整链路：

```
POST /api/config {"lan_subnet4":"0.0.0.0/0","lan_subnet6":"::/0"}
→ {"success":true,"risks":[]}          ← 连风险提示都没有
→ 8.8.8.8 / 1.1.1.1 / 203.0.113.5 全部 /auth/verify → 200 + X-Auth-Via: lan-bypass
```

填错一个网段就让公网网关对**全互联网免认证**。双层修复：
`validate_config` 直接拒绝并给出中文原因（`0.0.0.0/0` → 400 INVALID_CONFIG，
不落盘），认证服务侧也忽略 `/0` 作为纵深防御（配置可能被手改或被备份恢复）。

**② [high] 回环绑定检查只在 `if __name__ == "__main__":` 里**

一旦模块被 WSGI 方式加载（gunicorn / uWSGI / waitress / `flask run`），
`__main__` 不成立，这道检查就**静默消失**。而绑 `0.0.0.0` 意味着认证系统
多一个可从公网直接触达的入口，是本项目安全模型里最不能破的一条。
改为 `_assert_loopback_bind()` 在**模块加载时**执行，导入即校验。

**③ [high] `client_ip()` 无条件采信 `X-Real-IP` / `X-Forwarded-For`**

和 ② 串成一条完整攻击链：能碰到认证端口 → 声明任意源 IP → 冒充内网
→ `is_lan_source` 放行 → 所有 `public_access=true` 的服务直通。
改为**只有 `request.remote_addr` 是回环时才采信代理头**（真实 nginx 走的就是
这条路径，实测未误伤）；非回环来源只认真实对端，判不出内网就落到「要认证」。

**④ [high] `is_lan_source` 在没有可用网段时回落 `is_private`**

回落意味着「对所有 RFC1918 地址免认证」——咖啡厅 / 酒店 / 公司 / 邻居
Wi-Fi 的访客源 IP 就是私网段，能直连公网网关端口并被放行。
改为**没有可用网段就一律要求认证**（fail-closed）。
副作用：从未配过网段的存量用户会突然需要登录，这是有意为之。

**⑤ [medium] PBKDF2 短路时序预言机**

哈希未配置/损坏时直接 `return False`，耗时不到 1ms；正常路径要跑几万到
几十万轮迭代。攻击者只发一个 `{"password":"x"}` 就能靠响应耗时区分
「部署没配密码」和「配了密码」，等于一个免认证的状态枚举口。
改为异常路径也真跑一次 PBKDF2（迭代数取下限，避免畸形配置触发天文数字
的迭代把请求线程拖死）。

**验证**：认证网关 40/40 → **64/64**；8 个人为变异**全部被测试捕获**
（`0.0.0.0/0` 放行 / 回落 is_private / 无条件信任头 / 移除 PBKDF2 dummy /
星期必填 / `Origin:null` 放行 / 续期不吊销 / 缺省改回 True）；
`.224` 真机复测 `/0` 返回 400 且不落盘；浏览器回归 面板 42/42 + 门户 13/13。

测试侧同时修掉两个自身缺陷：
- 时序测试原先用 `open(PWD).read()` 拿到的是 JSON 文本而非哈希串，
  `split("$")` 后 algo 对不上直接抛错 —— **两条路径都走 except，等于拿自己
  跟自己比**，测不出任何东西
- 配置读写散落 7 处手工失效 mtime 缓存，漏了一处；而同一时钟刻度内两次写入
  得到完全相同的 mtime，缓存 key 不变就读到陈旧配置，表现为「代码是对的但
  测试说功能坏了」。改成集中 `set_cfg()` helper

### 新增：日志页重构（设备指纹并入 + log_size 可调 + 远程转发）

在 `.224` 真机实测后重写。四条都是实测出来的，不是设想。

**① 认证审计并入系统日志时间线（此前完全看不到）**

`app.py` 从来没读过 `/var/log/nftables-web-auth.log`。认证服务一直在采集
设备指纹并落盘，面板却一条都显示不出来 —— 数据在采，但没有出口。
现在 `/api/system/logs` 同时读 `logread` 和该 JSONL，按时间倒序合并成一条时间线，
认证事件来源标记为 `nftables-web-auth`，日志表内联展示设备标识与浏览器指纹。

**② 缓冲区水位可视化（此前显示的「共 N 条」是假的）**

原实现固定 `logread -l 5000`，但 `log_size` 默认只有 128KB，环形缓冲写满后
`logread` 实际只返回约 1500 行（.224 实测 1582 行 / 136841 字节 ≈ 86 字节/行）。
UI 照常显示「共 N 条」，让人误以为是全量。现在返回并展示水位、已用字节、
平均行长和容量估算，缓冲 ≥70% 转琥珀色、≥90% 转红色。

**③ 时间戳统一为 ISO + 解析器放宽**

原时间戳直接透传 syslog 文本（`Tue Oct  6 18:52:41 2026`），排序和筛选都别扭，
现在统一为 `2026-10-06T18:52:41` 并带 `epoch`。
正则同时放宽三处，每处都是为了**不让日志被静默丢弃**：星期几与年份可选
（busybox `syslogd -L` 落文件的格式就没有星期）、facility 用 `[\w.-]+` 贪婪匹配
（`my.app-name_v2.info` 原本整行解析失败）、程序名与 pid 整段可选
（`kernel.crit <message>` 这类无 `prog:` 结构的行原本整行丢掉）。
无法解析的行数作为 `unparsed` 如实返回并在页面上标出，不再藏。

**④ `log_size` 可调 + 保存幂等 + 清空副作用如实上报**

- `log_size` 此前全项目从未被代码碰过。现在可在「日志开关」页调整，
  UI 给出预计容量与占物理内存比例，超过 10% 出警示
- **`log_size` 只在 logd 启动时读取**，改完必须重启 `/etc/init.d/log` 才生效；
  而**重启会清空内存环形缓冲**（.224 实测 1580 行 → 1 行）。
  这个副作用以前完全没有提示，现在保存前 confirm、返回 `restarted`/`buffer_cleared`、
  toast 用琥珀色警示
- **保存改为幂等**：比对现值，配置没变就不重启、不清空。
  旧实现每次保存转发配置都无条件重启 log —— 也就是说**保存一次转发配置
  就清空一次历史日志**，用户一直不知道

### 新增：认证事件转发到远程日志服务器

- `auth_gateway` 对 `login_ok` / `login_fail` / `logout` / `lockout` 双发 syslog
  （`logger -t nftables-web-auth`），使认证审计能随 logd 转发到远程日志服务器
- **`verify_denied` / `token_refreshed` 刻意排除**：前者每个未认证请求都触发，
  全 WAN 打过来会把远程日志刷爆，真正该看的几条反而被埋掉
  （这两类在本地 JSONL 里仍是全的）
- **日志注入防护**：UA / URI 全部由客户端可控，写进 syslog 等于给了伪造远程日志的能力。
  非可打印字符一律剥除，长度截断。实测用带换行的 UA 打过来，
  远程日志里只出现一条干净的 `login_fail`，注入内容消失
- 实测链路：`.224` → `do` 的 Log Center `:514/udp`，
  5 次登录失败本地生成 4 条（1 次被限流正确挡下），
  本地 JSONL / logread / do 三方对账 **4/4 一致**，无转发丢失

### 新增：日志导出（CSV / JSON）

导出**当前筛选结果**，所见即所得。所有字段加引号并翻倍内部引号
（日志消息里逗号和引号都很常见，如 `DHCPACK` 那类），CSV 前置 BOM
（否则 Excel 按本地代码页解码，中文全乱码）。

### 新增：部署模式（为 Linux 适配铺路）

- 新增 `deploy_mode`：`openwrt`（默认，行为与 0.7.9.1 完全一致）/ `linux_gateway`
- `linux_gateway` 模式下 `flush ruleset` 换成 `flush table inet fw4` ——
  **只重建本项目自己的表，不清空宿主机全局 ruleset**（否则会连带清掉 Docker 等规则）
- ⚠️ 这一版**只做了地基**。Linux 部署的完整适配（接口名、端口敲死在 NAT 下的失效、
  WAN IP 获取、systemd、包管理器）留待后续，见文末待办

### 修复

- **面板 CSP 补 `'unsafe-eval'`（P0，面板在浏览器里完全不可用）**。Alpine.js 不预编译
  `x-data` / `@click` / `x-show` 表达式，而是运行时用 `new Function()` 现场编译。
  原 CSP 为 `script-src 'self' 'unsafe-inline'`，缺 `unsafe-eval` 时浏览器直接抛
  `Refused to evaluate a string as JavaScript`，Alpine 整个起不来 → 所有 `x-show`
  失效 → 模态框遮罩常驻 → 连登录按钮都点不动。curl 级验收查不到这一层，
  必须真实浏览器才能发现。认证门户是自写原生 JS 不需要 eval，那两页保持 `'self'`
- **`diffModal` 与登录遮罩游离在 `x-data` 容器外（P0）**。两者父级是 `BODY` 而非
  `x-data` 根，Alpine 不初始化它们 → `x-show` 永远不生效。此前被 `x-cloak` 掩盖，
  cloak 一失效就暴露：登录成功后遮罩不消失、diffModal 永久盖屏。已移进容器
- **`x-show` 保护的控件内部仍对 null 求值（P1）**。`x-show` 只管显隐，Alpine 初始化
  时照样对内层 `x-model` 求值。`presetEditing`（5 处）与 `rpEditingRule`（10 处）
  初始为 null → 每次开页面必抛 `Cannot read properties of null`。改用
  `<template x-if>` 包裹，不满足就不渲染
- **`checkAuth()` 读错一层导致登录死循环（P1）**。后端 `/api/auth/status` 返回
  `{success, data:{...}}`（与其它端点一致的双层结构），`api.request` 只剥最外层，
  直接读 `data.authenticated` 恒为 undefined → `password_set` 读成 false →
  误判 `loginMode='setup'`。已设密码的面板首次打开显示「首次使用，请设置管理员密码」，
  提交后后端 400「密码已设置，请用 /login 登录」，**死循环且无法自愈**。
  改为兼容双层/扁平两种风格
- **`x-init` 无视 `x-show`（P1）**。Alpine 的 `x-init` 不管 `x-show` 是否为 true 都执行，
  页面一加载就调 `/api/rules/preview` → 401 → 派发 `auth-expired` →
  `handleAuthExpired()` 清空 `config`/`rp` 并提示「会话已过期」——用户还没输密码
  就被告知会话过期。守卫放在方法内（同时覆盖 x-init 与「刷新预览」两个入口），
  并在 `loadAllData()` 里补一次，登录后仍自动加载
- **认证端点默认开放，收敛为白名单（P1，公网攻击面）**。网关配置里写的是
  `location /auth/`，这是**前缀匹配**，会把认证服务下所有 `/auth/*` 一并暴露到公网，
  其中包括：
  - `/auth/verify` —— 只应由 `location = /_auth` 以 `auth_request` 子请求方式内部调用
    （该 location 自带 `internal;`，本不该有任何外部入口）。外部可达等于给了
    攻击者一个可以反复重放的 token 校验入口
  - `/auth/health` —— 探活端点，外部可达泄露服务存在与内部状态
  认证服务以后每加一个 `/auth/*` 端点都会被这个前缀匹配默认带出去，属于典型的
  「默认开放」。改为**逐个精确列举**公网必需的 5 个端点（`/auth/login`、
  `/auth/logout`、`/auth/status`、`/auth/portal`、`/auth/static/`），其余
  `/auth/*` 一律 `return 404`。实测 `/auth/verify`、`/auth/health`、
  `/auth/config` 均由 200 变 404，功能无损（门户 13/13 仍全过）

  另外核对了认证服务是否有设置类信息外泄：9 个端点的返回字段只有
  `authenticated / code / device_id / expires_in / fp / message / ok / remaining /
  services / user / via`，全为会话与服务列表，没有任何端点把配置或密钥序列化给客户端
- **DDNS 配置全部字段被写坏，DDNS 起不来（P1）**。`_uci_set()` 用**双引号**包裹值
  （`uci set key="250"`），而 uci 会把双引号当成值的一部分存进文件，于是
  `uci get` 读回来是 `"250"`。ddns-scripts 里的 `$((ddns_loglines + 1))` 直接报
  `arithmetic syntax error`，点「重启服务」恒 500；密码里的三重双引号也被转义成
  一串反斜杠。2026-10-06 在 .224 上逐条实测确认正确写法是**值完全不加引号** ——
  uci 自己按第一个 `=` 分割并处理转义，含空格 / 单引号 / 等号 / 分号 / 反斜杠 /
  三重双引号都能原样保留。加引号反而出错。修复后 DDNS 重启 500 → 200
- **PPPoE 在单网卡机器上会导致整机失联（P0）**。`update_uci_wan_config()` 原本以
  `wan_device = 'eth0'` 兜底，而 `eth0` 恰恰是 br-lan 的唯一从属端口（设备检测本就是
  为把它排除掉）—— 兜底等于把 WAN 强行绑到 LAN 的网卡上，桥塌掉即失联。
  2026-10-06 实测：x86 单网卡 OpenWrt 上点「PPPoE 拨号 → 保存网络配置 → 重启网络」，
  设备当场 ARP FAILED，且无带外恢复入口。改为**检测不到独立 WAN 网卡就拒绝**，
  返回 400 + `INVALID_NETWORK` 并说明原因；PPPoE 账号为空也一并拒绝
- **空值无保护（P2）**。`getRpDefaultCert()` 在证书列表为空时返回 undefined，
  HTML 直接 `.domain`；`handleAuthExpired()` 重置的 `this.rp` 不含 `dnsProviders`，
  HTML 直接 `.dnsProviders.find`。均已加保护
- **启动恢复规则的优先级**。规则文件 `99-custom-rules.nft` 丢失时原先落到 `.backup`
  —— 那是「首次 apply 之前」的快照，可能比当前配置旧数周。实测因此踩中：backup 里的
  trusted 白名单没有后来才加进去的管理机 IP，启动恢复把管理员自己的 SSH 和面板
  一起关在门外。改为规则文件缺失时**优先按当前配置重新生成**，backup 降为第三优先级
- **删除 HTTP 5000 跳转器**（死代码）。10-01 那轮把 `lan_allowed_ports` 从 5000
  改成 5443 之后，5000 就被防火墙 `policy drop` 拦住、从未可达，
  但代码里还留着并误导文档。对外只保留 HTTPS 5443 一个入口
- `HTTPS_PORT` 从文件中部提到顶部：`validate_config()` 要用它做
  「网关端口不能占用面板端口」的交叉校验
- 新增 `_safe_cidr()`。原先用 `_safe_ip()` 校验网段，而它只认单个 IP，
  `192.168.100.0/24` 会被判非法并**静默回落到 `192.168.0.0/16`** ——
  那会把「仅内网可达」的放行范围悄悄放大
- 网关端口白名单：无 public 服务时不再放行网关端口
- **`setup.sh` 装 `nginx-full` 而非 `nginx-ssl`**。认证网关每个公网请求都要经
  `auth_request` 子请求核对 token，而 `nginx-ssl` 不含该模块：装它不报错，
  但一开网关就整片 500。装完新增 `check_nginx_modules()` 当场校验 `nginx -V`，
  缺 `auth_request` 直接 `die`（不是 warn+skip），缺 `realip` 仅告警（只影响
  日志里客户端 IP 的还原）
- **`setup.sh` 改为校验真正在跑的那份 nginx 配置**。OpenWrt 实际运行的是
  `/var/lib/nginx/uci.conf`（procd 从 template 生成），它并不被
  `/etc/nginx/nginx.conf` include，原来的 `nginx -t` 校验的是一份没人跑的配置，
  真出语法错也照样「通过」
- **`setup.sh` 新增 80/443 占用提示**。网关默认 8443 不会撞，但用户把公网端口
  自定义成 443 时 nginx 会因 bind 失败进入崩溃循环。不自动停 uhttpd（停了会
  失去 LuCI），只在安装阶段讲清楚该怎么处理

### 验证

| 项 | 结果 |
|---|---|
| 认证网关功能测试 | **40/40 通过**（含 fail-closed 异常注入、限流落盘、吊销、滑动续期、CSRF、门户） |
| 真 HTTP 端到端 | 起真实进程 curl 验证：cookie/Bearer/篡改/登出失效/续期行为全部符合预期 |
| 前端逻辑测试 | **29/29 通过**（Node + DOM 桩，无 npm 依赖） |
| 页面/静态资源/CSP | **22/22 通过**（两页 CSP 均 `script-src 'self'`） |
| 端口与超时守卫 | 8 个 case 全部正确（冲突、越界、非法模式均被拦，合法组合通过） |
| nft 规则集语法 | 两种 deploy_mode 均过 **nft v1.0.6** 真实校验（542/543 行，0 语法错误） |
| **零回归** | openwrt 模式下生成规则与 10-01 版本**逐字节一致**（仅多一行说明注释） |
| 语法编译 | app.py / template_engine.py / auth_gateway.py / setup.sh / 2 个 init 脚本 全通过 |
| `check_nginx_modules()` | stub nginx 四用例：缺 `auth_request`→die(1)、模块齐全→ok(0)、缺 `realip`→warn+ok(0)、无 nginx→die(1) |
| 端口占用检测 | 在 `.224` 真实 `netstat` 输出上验证，正确识别 80/443 占用，对 8080/8443/9999 无误报 |
| **真机 30 项验收** | **30/30 通过**（`192.168.100.224`，含 fail-closed：杀进程 B → 公网 500、内网仍 200） |

### ⚠️ 状态

- **已在真机验证**：`192.168.100.224`（OpenWrt 24.10.0 x86_64）部署 v0.8.0，
  30/30 项验收通过，含 fail-closed 实测（杀掉进程 B → 公网 500、内网仍 200）
- `auth_request` 模块**已实测存在**，但代价是必须换包：OpenWrt 自带的
  `nginx-ssl` **不含**该模块，换 `nginx-full 1.26.3` 后才具备
  （`nginx -V` 可见 `--with-http_auth_request_module`）。`setup.sh` 已改为
  安装 `nginx-full` 并在装完当场校验，缺模块直接中止
- 前端（登录页 / 门户页 / 设备指纹采集）已实现并通过 29/29 逻辑测试
- 灰度开关 `gateway_enabled` 默认**关闭**，不影响现有访问

### 待办

1. ~~日志页重构 + 指纹并入~~ **已完成**（见上「日志页重构」与「认证事件转发」两节）；
   `log_size` 调大、远程转发到 do 的 Log Center 均已真机跑通
2. Linux 部署完整适配（见上）—— 6 项原始需求里**唯一还没开工**的一项
3. 真实公网穿透验证（当前靠 `X-Test-IP` 模拟来源，判定逻辑已验，公网行为未验）
4. 「端口转发绕过认证」检测已有基础实现，但需在新网关模型下重新验证
5. N-5（面板借反代私钥的 HSTS 副作用）随面板退出公网而自然消解，可关闭该待定项

---

## [v0.7.9.1] - 2026-09-13

### 安全加固（11 项审查全部修复）

#### High 修复
- **上传大小限制**：`app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024`
  - 在 `before_request` 早期主动检查 `Content-Length` header（不依赖 Werkzeug 惰性读 body），超限直接返回 413 `PAYLOAD_TOO_LARGE`
  - 证书 < 10KB、反代规则配置几百字节；16MB 富余足够
- **IPv6 客户端拒绝**：`before_request` 早期判断 `':' in request.remote_addr` → 403 `IPV6_NOT_ALLOWED`
  - 管理界面只支持 IPv4
  - defense-in-depth：服务当前监听 `0.0.0.0:5443`，IPv6 客户端本就连不上；代码层加固是给将来启用 IPv6 监听兜底

#### Medium 修复
- **`_failed_logins` 内存泄漏防御**：
  - `_MAX_FAILED_LOGINS_IPS = 50000` IP 数硬上限（防恶意创建大量 IP 条目撑爆内存）
  - `_gc_failed_logins()` 每 100 次请求触发一次全局 GC，清理过期 IP 条目
- **`/api/auth/change-password` 加限流**：
  - 复用 `_check_rate_limit`（5 次失败锁 15 分钟）
  - 旧密码错误也记录失败 → `_record_login_failure(client_ip)`
  - 修改密码成功 → `_clear_login_failures(client_ip)`
  - 防暴力枚举旧密码
- **CSP 响应头**：内网单页应用适配
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'self'
  ```
- **`save_config` 异常不要吞错**：
  - fcntl 锁失败记录 `WARNING` 后回退到无锁模式
  - 真正写失败必须 `raise`，让上层调用方能感知保存失败

#### 其他校验加固
- **`_sanitize_target_address` 加强校验**（反代规则 target_address 字段）：
  - IPv4：每段严格 0-255，否则 `IPv4 段数或越界`
  - port：必须数字，且 1-65535
  - host：不能为空
  - domain：复用 `_sanitize_domain` 严格校验（a-z 0-9 - .）

#### 测试
- 综合测试 70/70 全过（无回归）
- v0.7.9.1 专项验证全部通过：
  - CSP header ✅
  - change-password 限流：前 5 次 401，第 6-7 次 429 ✅
  - MAX_CONTENT_LENGTH：17MB upload → 413 `PAYLOAD_TOO_LARGE` ✅
  - `_sanitize_target_address`：IPv4 越界 / port 越界 / port 非数字 / 缺端口 / 非法 domain 都正确拒绝 ✅
  - IPv6：服务监听 `0.0.0.0:5443`，IPv6 客户端连不上 ✅

#### ⚠️ 状态
- 未完整验证版本 — 由 AI agent 自动完成，未经生产环境手动验证
- 建议先在测试环境部署验证，确认无误后再升级生产

---

## [v0.7.9] - 2026-09-13

### 安全加固（首版认证 + HTTPS + 限流 + dry-run + 风险检测）

#### 主要改动
- **认证系统**：PBKDF2-HMAC-SHA256 (200000 轮) + Flask session + 全局 `before_request` 拦截
- **限流**：5 次登录失败锁 IP 15 分钟（IP-based 内存 dict）
- **HTTPS**：自签证书自动生成 + HTTP:5000 → HTTPS:5443 重定向
- **反代证书自动接管**：扫 `/etc/nginx/ssl/` 优先用反代证书，自签 fallback
- **SSL 启动失败**：`sys.exit(1)` 拒绝明文 HTTP（避免密码明文传输）
- **安全响应头**：HSTS + X-Content-Type-Options + Referrer-Policy
- **Cookie**：HttpOnly + SameSite=Lax（CSRF 防护）

#### dry-run preview-changes
- `POST /api/rules/preview-changes`：模拟配置变更，不写文件、不应用 nft
- 风险检测 3 条规则：SSH 端口移除 / trusted_ip4 移除自己 IP / access_mode 变化
- 完整 diff 摘要 + 新规则文本

#### Bug 修复
- 部署路径：`app.py` 应在 `backend/` 子目录（之前错位导致 `/` 和 `/app.js` 返回 404）
- 反代 rule_id 重复：同 domain 已存在时 update 而非 append
- 黑名单 set flags：`blacklist4/6 flags` 是 dynamic 不支持 timeout，自动改永久写入
- nft timeout 语法：`timeout 18000s`（无空格+紧跟 s）兼容 OpenWrt nft 1.1.1
- 限制规则 / 黑名单 apply 时 nft set 不存在的错误处理
- `template_engine.py`：支持 list → nftables 集合语法 `{ a, b, c }`

#### 安全修复
- **Host Header 注入**：重定向 URL 用 `router_ip4` 配置，不用 `HTTP_HOST`

#### 前端
- 429 RATE_LIMITED 拦截
- diffModal Alpine state + saveConfig 改造（先 preview-changes → 弹 modal → 确认才 POST）
- HTTP 不安全警告 banner（指向 :5443）
- diff modal（风险警告 + diff 摘要 + 新增/删除行样例 + 完整新规则折叠）

#### ⚠️ 状态
- 未完整验证版本 — 由 AI agent 自动完成

---

## [v0.7.7] - 2026-03-22

### 修复
- **反向代理**：修复非标准端口反代时移动端登录失败的问题
  - `proxy_set_header Host $host;` → `proxy_set_header Host $http_host;`
  - `$http_host` 包含完整端口号，解决 DSM 移动端登录校验 Host 端口失败返回空响应的问题

## [v0.7.6] - 2026-03-22

### 修复

- 修复反向代理群晖 DSM 登录后提示"登录信息过期"的问题

### 变更详情

**Nginx 反代配置新增：**

- `proxy_set_header Host $http_host;` — 传递完整 Host 头（含端口号），解决手机端登录校验失败问题
- `proxy_set_header X-Forwarded-Host $host;` — 传递原始 Host
- `proxy_set_header X-Forwarded-Port $server_port;` — 传递原始端口
- `proxy_cookie_domain ~^(\d+\.\d+\.\d+\.\d+) $host;` — Cookie 域重写，将群晖 IP 的 Cookie 域改为反代域名
- `proxy_buffering off;` — 关闭代理缓冲
- `proxy_request_buffering off;` — 关闭请求缓冲

**超时调整：**

- `proxy_send_timeout` 和 `proxy_read_timeout` 从 60s 调整为 300s
