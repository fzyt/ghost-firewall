#!/bin/bash
# 本地全量回归 —— **唯一权威入口**
#
# 用法: bash tests/run_all.sh [--skip-mutation]
#
# 为什么要有这个脚本（2026-10-19 立）
# ----------------------------------
# 之前全量回归的命令散在各处、每次手敲，于是漏过一个文件：
#
#   tests/mutation_check.py      ← 没有下划线！
#   tests/mutation_check_*.py    ← 通配符匹配不到上面那个
#
# 结果 `mutation_check.py` 长期**不在回归里**。它自己的一个变异
# （client_max_body_size 净化去掉）已经变成**空转**（测试仍全绿），
# 却没人发现 —— 直到本轮把它加进回归才暴露出来。
#
# 所以：**通配符一律用 `mutation_check*.py`（不带下划线约束）**，
# 或者干脆用本脚本，别再手敲。
#
# 另外：变异脚本会**改写并还原源码**，运行期间
#   · 不要编辑源码
#   · 不要部署
#   · 不要并行跑两个变异脚本（会互相踩）
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
export PYTHONDONTWRITEBYTECODE=1

SKIP_MUT=0
[ "${1:-}" = "--skip-mutation" ] && SKIP_MUT=1

TP=0; TF=0; FAILED=""

hr() { printf '%s\n' "════════════════════════════════════════════════════════════════════"; }

# ── 断言计数 ─────────────────────────────────────────────────
# 必须**只数真正的断言行**。
#
# 踩过的坑（2026-10-19 第一版）：原来用 `grep -c '❌'` 统计，
# 把 3 个文件结尾的「  合计: ✅ 4   ❌ 0」计成 3 次失败 ——
# 硬指标「失败数恒为 0」永远红灯，于是没人再看它。指标失效等于没有指标。
#
# 又踩了一次（2026-10-20 第二版，本轮）：改用
#   `grep '✅' | grep -vcE '合计|全部通过|[0-9]+/[0-9]+'`
# 想排除「12/12」这类整文件汇总。**但 `[0-9]+/[0-9]+` 会命中断言详情里的
# CIDR 和临时路径**：
#   ✅ 旧值被 _safe_cidr 归一化成 /32  — 实际=192.168.100.0/32   ← "0/32" 命中，被漏算
#   ✅ 规则文件坏掉时确实尝试过装它  — tried=['/tmp/tmpfaun1p78/99-...']  ← "78/99" 命中
# 于是**断言总数随随机临时目录名而变**（实测同一份代码两次跑出 1408 / 1410）——
# 一个会自己变的数字没法用来发现回归。
#
# 同时它还**多算**了应用日志行：
#   [INFO] ✅ 已从 /tmp/xxx/r.nft.backup 恢复 ruleset
#   [WATCHDOG] ✅ 已从 basic lockdown 切回完整规则集
# 这些是**被测代码的日志输出**，不是断言。
#
# 现在用行首锚定：只数「行首（可带缩进）就是 ✅/❌」的行。
#   · 汇总行是「  合计: ✅ 13   ❌ 0」→ 行首是"合计:" → 自动不计
#   · 「全部通过」→ 没有标记 → 不计
#   · 「[INFO] ✅ ...」→ 行首是"[INFO]" → 不计（那不是断言）
#   · 断言详情里带 IP/CIDR/临时路径 → 照计，不再被误伤
count_pass() {
    printf '%s\n' "$1" | grep -cE '^[[:space:]]*✅' || true
}
count_fail() {
    printf '%s\n' "$1" | grep -cE '^[[:space:]]*❌' || true
}

hr
echo " 本地全量回归  ($(basename "$ROOT"))"
hr

# ── 源码指纹：防「运行期间的改动被静默吞掉」──────────────────
# 2026-10-20 实测踩到：一边跑全量回归，一边改了 backend/app.py。
# 回归跑完，改动**没了** —— 没有报错、没有告警。
# 原因是各变异脚本都在 finally 里 open(path,'w').write(orig_src)，
# 而 orig_src 是它们 **import 那一刻**读的版本 —— 覆盖掉了后来的改动。
# 更糟的是那一轮回归还报"全绿"：它测的是**旧代码**。
#
# 所以这里做一道全局兜底：开始时记指纹，结束时对账。
#   · 一致     → 期间没人动过源码，变异也还原干净了
#   · 不一致   → 要么有人运行期间改了源码，要么某个变异没还原干净
#                —— 两种都得报出来，不能让它悄悄过去
#
# 覆盖 tests/ 是为了把变异脚本自身也算进去（它们同样是"源码"）。
# 测试文件写到 /tmp 的临时目录，不在本仓库内，不会误报。
FP_BEFORE=$(mktemp); FP_AFTER=$(mktemp)
fingerprint() {
  find backend frontend setup tests docker -type f \
       ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.pyo' \
       -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null
}
fingerprint > "$FP_BEFORE"

# ── 1. Python 单元测试 ──────────────────────────────────────────
echo
echo "▶ 1/3  Python 单元测试  (tests/test_*.py)"
for f in tests/test_*.py; do
  out=$(python3 "$f" 2>&1); rc=$?
  p=$(count_pass "$out"); fl=$(count_fail "$out")
  TP=$((TP + p)); TF=$((TF + fl))
  if [ $rc -ne 0 ]; then
    FAILED="$FAILED $f"
    printf '  ❌ %-42s ✅%s ❌%s rc=%s\n' "$(basename "$f")" "$p" "$fl" "$rc"
    printf '%s\n' "$out" | grep '❌' | head -5 | sed 's/^/       /'
  else
    printf '  ✅ %-42s ✅%s ❌%s\n' "$(basename "$f")" "$p" "$fl"
  fi
done

# ── 2. 前端测试 ────────────────────────────────────────────────
echo
echo "▶ 2/3  前端测试  (tests/test_*.js)"
for f in tests/test_*.js; do
  out=$(node "$f" 2>&1); rc=$?
  p=$(count_pass "$out"); fl=$(count_fail "$out")
  TP=$((TP + p)); TF=$((TF + fl))
  if [ $rc -ne 0 ]; then
    FAILED="$FAILED $f"
    printf '  ❌ %-42s ✅%s ❌%s rc=%s\n' "$(basename "$f")" "$p" "$fl" "$rc"
    printf '%s\n' "$out" | tail -15 | sed 's/^/       /'
  else
    printf '  ✅ %-42s ✅%s ❌%s\n' "$(basename "$f")" "$p" "$fl"
  fi
done

# ── 3. 变异脚本 ────────────────────────────────────────────────
# ⚠️ 通配符用 mutation_check*.py —— 不带下划线约束，
#    那样 mutation_check.py（老脚本）也在内。别再写成 mutation_check_*.py。
if [ $SKIP_MUT -eq 1 ]; then
  echo
  echo "▶ 3/3  变异脚本  —— 已跳过（--skip-mutation）"
else
  echo
  echo "▶ 3/3  变异脚本  (tests/mutation_check*.py)  —— 需独占运行，源码会被临时改写"
  for f in tests/mutation_check*.py; do
    out=$(python3 "$f" 2>&1); rc=$?
    last=$(printf '%s' "$out" | grep -E '全部变异均被捕获|有变异漏过|锚点未命中|捕获 [0-9]+ /' | head -1)
    if [ $rc -ne 0 ]; then
      FAILED="$FAILED $f"
      printf '  ❌ %-42s %s\n' "$(basename "$f")" "$last"
      printf '%s\n' "$out" | grep -E '❌|⚠️' | head -8 | sed 's/^/       /'
    else
      printf '  ✅ %-42s %s\n' "$(basename "$f")" "$last"
    fi
  done
fi

# ── 收尾：源码必须干净 ─────────────────────────────────────────
hr
echo " 源码状态（应只有本轮有意改动，不该有变异残留）:"
git status --short 2>/dev/null | sed 's/^/   /'
if git diff --quiet backend/ frontend/ 2>/dev/null; then
  echo "   （backend/ frontend/ 无改动）"
fi
hr

# ── 源码指纹对账（见开头注释）───────────────────────────────
fingerprint > "$FP_AFTER"
if ! cmp -s "$FP_BEFORE" "$FP_AFTER"; then
  echo " ⚠️  源码指纹不一致 —— 回归运行期间有文件被改动："
  diff "$FP_BEFORE" "$FP_AFTER" 2>/dev/null | grep -E '^[<>]' | sed 's/^/     /' | head -30
  echo "     可能是：① 有人在运行期间改了源码（改动不会被自动还原，"
  echo "             但也不能保证没被某个脚本的 finally 覆盖）"
  echo "          ② 某个变异脚本没把源码还原干净"
  FAILED="$FAILED (回归期间源码被改动)"
else
  echo " 源码指纹一致（运行期间无改动，变异已还原干净）"
fi
rm -f "$FP_BEFORE" "$FP_AFTER"
hr
printf ' 断言合计: ✅ %s   ❌ %s\n' "$TP" "$TF"
if [ "$TF" -ne 0 ]; then
  # 打了 ❌ 却 exit 0 的测试文件 = **说谎的测试**。
  # 报告第十七节「测试永远是对的」那类失明就是这么来的：
  # 断言失败了，脚本却因为退出码是 0 而全绿。
  # 所以失败数不只是"看数字"，它必须**能拦住回归**。
  FAILED="$FAILED (有测试打了 ❌ 却 exit 0)"
fi
if [ -n "$FAILED" ]; then
  echo " 失败:$FAILED"
  hr
  exit 1
fi
echo " 全部通过"
hr
exit 0
