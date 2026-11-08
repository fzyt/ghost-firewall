# DeepSeek 建议 6 的可行性调研：`destroy chain` 替代 create+delete（2026-11-08）

## 一句话结论

**建议 6 在当前部署目标上不可用，建议维持现状。** 但现在有实测依据了，
不再只是「会抬高最低 nft 版本要求」这种含糊说法 —— 具体数字是：**nft ≥ 1.1.x**。

---

## 一、建议 6 到底指什么

出处：Shannon 8443 审查（`报告/Shannon-8443-20261029.md`）P0-8 的后续建议 6。

现在的实现（`backend/template_engine.py:160-165`，`linux_gateway` 模式的前导块）：

```
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat;
    }
}
delete chain ip nat prerouting
delete chain ip nat postrouting
```

**为什么要这两步**：`delete chain` 遇到不存在的链会报 `No such file or directory`，
整个 ruleset 加载失败；而前导块又必须先把这两条链删掉（用户早已在面板里删了转发规则，
但内核里还在生效 —— 这就是 P0-8）。所以先 `create` 出两条**空链**当脚手架，
再 `delete` 掉，让后面的模板重建带规则的链。

**建议 6 想改成**：`destroy chain` 一步到位。`destroy` 的语义是「不存在就忽略」，
所以不需要脚手架，前导块能少一半。

⚠️ 注意**不能用 `flush table ip nat`** —— 那是宿主机标准 NAT 表，
flush 会把 Docker 的 dnat/masquerade 一起清掉（P0-8 已实测）。

---

## 二、实测：`destroy` 命令要 nft ≥ 1.1.x

### 2.1 怎么测的（不需要 root）

nft 的**语法解析发生在 netlink 连接之前**，所以即使不是 root，
也能通过「报的是语法错误还是权限错误」判断某个词是不是已知命令：

- 已知命令 → 解析通过，只报 `Operation not permitted (you must be root)`
- 未知命令 → 报 `syntax error, unexpected ...`

对照组用 `delete chain`（已知）和 `zzznotacommand`（纯属捏造）夹逼。

### 2.2 实测结果

| nft 版本 | 来源 | `destroy chain inet foo bar` | `delete chain inet foo bar` | `zzznotacommand ...`（对照） |
|---|---|---|---|---|
| **1.0.6** | Debian bookworm（do 主机 192.168.100.218 实机） | **语法错误** | 解析通过 | 语法错误 |
| **1.1.3** | Debian unstable 实包解包实测 | 解析通过 | 解析通过 | 语法错误 |
| **1.1.7** | Debian sid 实包解包实测 | 解析通过 | 解析通过 | 语法错误 |

1.0.6 上的原始报错（注意 `destroy` 被当成了对象名，要的是一个字符串）：

```
Error: syntax error, unexpected chain, expecting string
destroy chain inet foo bar
        ^^^^^
```

1.1.7 上同样一条命令，语法完全通过，只差 root：

```
netlink: Error: cache initialization failed: Operation not permitted
```

⇒ **精确引入版本落在 1.0.6 与 1.1.3 之间**。保守说法：**要 nft ≥ 1.1.x**。

### 2.3 交叉验证

Debian bookworm（nft 1.0.6）的 `nft(8)` man page 里**没有** `destroy` 命令章节
（只有 `monitor [new | destroy]` 这个事件过滤参数）。与上面的实测一致。

---

## 三、为什么建议「维持现状」

### 3.1 影响面目前是零

`linux_gateway` 模式**目前没有真实部署目标**：

- README 明写：「已预留 `deploy_mode=linux_gateway`……但接口名、端口敲门（NAT 源 IP 下失效）、
  WAN IP 获取等完整适配**尚未实现**」。
- 唯一跑过的真机 `.232` 用的是默认的 `openwrt` 模式（它的配置里没有 `deploy_mode` 字段）。
- 前导块那段 `delete chain` **只在 `linux_gateway` 模式执行** —— 也就是说
  现在改成 `destroy`，在 `.232` 上**一行都不会走到**，改了也验证不了。

⇒ 为一个「还没落地、也没适配完」的模式去抬最低版本要求，是为不存在的问题付代价。

### 3.2 现在的方案已经被真机验证过

P0-8 那轮实测证明了：`flush table ip nat` 会清掉宿主机 Docker 的 dnat/masquerade，
所以必须走「delete 而不是 flush chain」这条路，而且模板必须始终是权威、
preamble 只是脚手架。这套结构连同 `tests/test_linux_gateway_preamble.py`
的 15 项断言、`mutation_check_p0_fixes.py` 的对应变异，都是钉住的。

### 3.3 真正的收益为零

`destroy` 省掉的是**两条空链的脚手架**。代价是最低 nft 版本从 1.0.x 抬到 1.1.x。
收益（少 6 行前导块）远小于代价（把一批还在用 1.0.x 的发行版挡在门外）。

---

## 四、给用户的建议

**维持现状**（不改成 `destroy`）。如果将来 `linux_gateway` 模式真要部署，
和「接口名 / 端口敲门 / WAN IP 适配」一起做，那一批再一起决定最低 nft 版本 ——
那时候版本要求本来就要重新声明。

**已经落地的防护**：README 的 `linux_gateway` 段落里加了这段约束，
免得以后有人（或者 AI）图省事把它改成 `destroy chain`：

> ⚠️ 前导块用的是「先建空链脚手架、再 `delete chain`」两步……
> **不要**图省事改成 `destroy chain` —— `destroy` 命令要 **nft ≥ 1.1.x** 才认识
> （实测 nft 1.0.6 完全不认识，会把 `destroy` 当成对象名报语法错误；
> 1.1.3 / 1.1.7 才解析通过），改了就把 linux_gateway 的最低 nft 版本要求整个抬上去。

---

## 五、复现方法

```bash
# 判定某个词是不是 nft 的已知命令（不需要 root）
nft destroy chain inet foo bar 2>&1 | head -2   # 语法错误 ⇒ 不认识
nft delete chain inet foo bar 2>&1 | head -2   # 只报权限错 ⇒ 认识
nft zzznotacommand inet foo bar 2>&1 | head -2 # 对照组

# 在没有 nft 的机器上测某个版本：从 Debian pool 取 deb 解包即可
cd /tmp && dpkg-deb -x nftables_1.1.7-3_amd64.deb root/
LD_LIBRARY_PATH=root/usr/lib/x86_64-linux-gnu root/usr/sbin/nft --version
```

## 六、还悬着的

- `linux_gateway` 模式本身：接口名、端口敲门在 NAT 下失效、WAN IP 获取、
  systemd / 包管理器适配 —— **全部未实现**。建议 6 的取舍等这一批一起做。
- 本报告没有验证 nft 1.0.7 ~ 1.0.9 / 1.1.0 ~ 1.1.2 这些中间版本
  （Debian pool 里没有对应 deb）。结论对决策无影响：保守按 ≥ 1.1.x 算。
- 1.1.3 / 1.1.7 是**解包实测**，没在真实 Linux 网关设备上跑过 apply。
  真要用的话，`linux_gateway` 首次部署时必须真机验证一遍。
