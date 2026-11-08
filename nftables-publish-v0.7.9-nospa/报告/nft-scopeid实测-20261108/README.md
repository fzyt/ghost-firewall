# nft 1.1.7 scope-id 实测（2026-11-08）

本目录是「面板侧 53 条静态判定对账」残留 **C2**（#60 IPv6 scope-id）的**实测证据**。

## 为什么需要它

C2 的判断完全依赖「nft 到底认不认 scope-id」这个事实：

- Python 3.9+ 的 `ipaddress` **认** scope-id（`IPv6Address('fe80::1%br-lan')`
  解析成功、`str()` 原样保留）⇒ 面板的宽松判定会放行；
- 而 **nft 1.1.7 不认** ⇒ 带 scope-id 的地址写进规则集就是非法语法
  ⇒ `nft -f` 整份文件加载失败。

而「不构成注入」这个结论**也是实测出来的**，不是推理出来的
（见主报告 10.3）：注入载荷里的 `flush ruleset` 没有被执行。

## 怎么复现

需要 nft 1.1.7 二进制与 `unshare -rn`（隔离 network namespace）：

```bash
# nft 1.1.7 测试包解压到 ROOT
export LD_LIBRARY_PATH=$ROOT/usr/lib/x86_64-linux-gnu
NFT=$ROOT/usr/sbin/nft

# 全部在临时 netns 里跑，不碰宿主机任何规则集
unshare -rn bash scopeid_literal_test.sh
```

⚠️ **必须在隔离 netns 里跑**：这些脚本会 `nft -f` 真实规则集文件。
隔离是第一道保险，不是可选项。

## 文件

| 文件 | 内容 |
|---|---|
| `scopeid_literal_test.sh` | 地址**字面量**与**集合元素**两种写法的 scope-id 反应 |
| `scopeid_literal_out.txt` | 上述脚本的原始输出（2026-11-08） |
| `scopeid_file_test.sh` | 文件加载路径（`nft -f`，面板真正的路径）的二阶注入检查 |
| `scopeid_test.sh` | 命令行路径（`nft add element ...`）的注入检查 |

## 结论摘要

| 用例 | `nft -c -f` 结果 |
|---|---|
| `elements = { fe80::1%eth0 }` | `syntax error, unexpected junk`（指针在 `%` 后） |
| `ip6 saddr fe80::1%eth0 accept` | `syntax error, unexpected junk`（指针在 `%` 后） |
| 基线 `ip6 saddr fe80::1 accept` | 通过 |

⇒ 集合元素与地址字面量**两种写法 nft 都拒**；连**合法**的 scope-id 也不认。

⚠️ 旧脚本第一版的判定是错的：建表时用了 `elements = { }`（空集合），
那是**非法语法**，表压根没建起来 ⇒ 「查表还在不在」必然查不到
⇒ 误判成「flush ruleset 被执行了 ⇒ 构成注入」。
⇒ **注入测试的基线本身**也要先验证。

## 关联

- 主报告：`../e2e真机全链验证-2026-11-08.md` 第 10.3 / 10.9 节
- 修复与测试：`tests/test_c2_c3_c4_fixes.py`、`tests/mutation_check_c2_c3_c4.py`
