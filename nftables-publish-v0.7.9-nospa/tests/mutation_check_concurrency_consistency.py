"""变异检查：并发/一致性这批修复，每条至少一条变异必须被测试抓住。

运行：
    cd <项目目录>
    PATH=/tmp/nftvenv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 \
        python3 tests/mutation_check_concurrency_consistency.py

⚠️ 为什么**不用** tests/_mutation_guard.py 的 MutationGuard
----------------------------------------------------------
MutationGuard 的保险丝在触发时会把**整个快照的所有文件**从快照写回去 ——
包括本仓库里其它 agent 正在改的文件。实测已经因此把并行 agent 的改动
冲掉过两次（同一个仓库里三个 agent 同时改 backend/app.py）。

本脚本只碰 `backend/app.py` 一个文件，并且：

  · **不扫描 /tmp/mutguard-***，不读任何别的快照目录；
  · 每条变异是「就地定点替换」：读**当前**磁盘内容 → 替换锚点 → 写回；
  · 还原也是**反向定点替换**：把变异串换回原串。

为什么不用「启动时读原文进内存 → 结束时整份写回」
------------------------------------------------
那样还原会把别的 agent 在此期间对 app.py 的改动一起抹掉。
反向定点替换只动**变异所在的那几行**，其余字节原样保留 ——
别的 agent 改到别处不受影响，改到同一处时反向替换会因为
「变异串已经不在文件里」而自然放弃（那时变异也已经不存在了）。

安全网：atexit + SIGTERM/SIGINT 都会尝试还原尚未还原的变异。

判定标准
--------
每条变异：
    1. 定点替换（锚点必须在源码里**唯一**，否则报错跳过并说明）；
    2. 跑 tests/test_concurrency_consistency.py；
    3. **必须变红**（退出码非 0）—— 没红就说明这条修复没有对应的行为断言；
    4. 无条件还原。

最后再跑一次全量测试，确认还原后仍然是绿的。
"""
import atexit
import os
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_concurrency_consistency.py')

# ── 变异表 ────────────────────────────────────────────────────────────
# old / new 必须是**成对精确字符串**，且在源码里**唯一**。
MUTATIONS = [
    {
        'id': 'P1-17',
        'desc': 'IPv6 cron 不再检查 nft 返回码（失败被当成成功）',
        'old': """    if r.returncode != 0:
        # ⚠️ 必须看返回码：原来两条命令都不查，add 失败也当成功。
        fail("%s 更新失败: %s" % (set_name, (r.stderr or r.stdout or "").strip()))
        rc = 1
        continue""",
        'new': """    if False:
        # ⚠️ 必须看返回码：原来两条命令都不查，add 失败也当成功。
        fail("%s 更新失败: %s" % (set_name, (r.stderr or r.stdout or "").strip()))
        rc = 1
        continue""",
    },
    {
        'id': 'P1-18',
        'desc': '中国 IP 列表不再做 SHA-256 校验（投毒/变化直接写进规则集）',
        'old': 'if pinned and pinned != digest and not allow_update:',
        'new': 'if False and pinned and pinned != digest and not allow_update:',
    },
    {
        'id': 'P1-30a',
        'desc': 'save_config 拿不到锁时照样往下写（回退到无锁写入）',
        'old': """        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # ── 备份：**在锁内**做（P1-30）────────────────────────────────""",
        'new': """        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError:
            pass  # MUTATION: 拿不到锁也继续写
        # ── 备份：**在锁内**做（P1-30）────────────────────────────────""",
    },
    {
        'id': 'P1-30b',
        'desc': 'save_config 干脆不加锁（备份与写入都没有互斥保护）',
        'old': """    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # ── 备份：**在锁内**做（P1-30）────────────────────────────────""",
        'new': """    try:
        pass  # MUTATION: 完全不加锁
        # ── 备份：**在锁内**做（P1-30）────────────────────────────────""",
    },
    {
        'id': 'P1-42',
        'desc': '名单变更不再同步进规则集文件（重启即丢）',
        'old': '            _persist_list_elements_to_ruleset(data)',
        'new': '            pass  # MUTATION: 不再同步进规则集',
    },
    {
        'id': 'P1-43a',
        'desc': '名单读-改-写退回宽松模式（读失败当空名单 → 整份被覆盖）',
        'old': '        data = load_lists(strict=True)',
        'new': '        data = load_lists()',
    },
    {
        'id': 'P1-43b',
        'desc': 'save_lists 整份回写时把没传入的集合清空',
        'old': '        items = data.get(n) if (isinstance(data, dict) and n in data) else current.get(n)',
        'new': '        items = (data.get(n) if isinstance(data, dict) else None) or []',
    },
    {
        'id': 'P1-44',
        'desc': '读 syslog 时不再用 errors="replace"（一个坏字节就 500）',
        'old': """            ["logread"], capture_output=True, text=True,
            errors="replace", timeout=20""",
        'new': """            ["logread"], capture_output=True, text=True, timeout=20""",
    },
    {
        'id': 'P1-47',
        'desc': '网关 nginx 配置跳过候选校验（先安装后校验）',
        'old': '            ok, msg = _nginx_test_candidate(content)',
        'new': "            ok, msg = True, 'MUTATION: 跳过候选校验'",
    },
    {
        'id': 'P2-10',
        'desc': '中国 IP 片段改成原地重写（失败留下半截内容）',
        'old': '    os.replace(tmp, nft_file)',
        'new': '    open(nft_file, "w").write(content)',
    },
    {
        'id': 'P2-12',
        'desc': 'IPv6 /64 前缀退回朴素字符串切片（边界算错）',
        'old': "    return ':'.join(hextets[:4])",
        'new': "    return ':'.join(str(addr).split(':')[:4])",
    },
    {
        'id': 'P2-12b',
        'desc': 'IPv6 cron 里的前缀计算退回朴素字符串切片',
        'old': 'prefix = ":".join(hx[:4])',
        'new': 'prefix = ":".join(str(addr_text).split(":")[:4])',
    },
    {
        'id': 'P2-25',
        'desc': 'nft 读 set 失败时返回空集合（报成功但名单看着是空的）',
        'old': """        # 注意：**不把 nft 的原始输出回显给请求方**（可能含路径/内部细节），
        # 只把「哪个 set 读失败」这个事实带出去。
        raise NftSetReadError(f'nft list set {set_name} 失败')""",
        'new': """        # 注意：**不把 nft 的原始输出回显给请求方**（可能含路径/内部细节），
        # 只把「哪个 set 读失败」这个事实带出去。
        return {}  # MUTATION: 读失败当空集合""",
    },
]

# 当前待还原的变异（进程被打断时由 atexit / 信号处理还原）
_pending = {'m': None, 'mutated_text': None}


def read_app():
    with open(APP, encoding='utf-8') as f:
        return f.read()


def write_app(text):
    with open(APP, 'w', encoding='utf-8') as f:
        f.write(text)


def restore(reason=''):
    """还原当前变异：**只做反向定点替换**。

    为什么不用「整份写回原文」
    ----------------------
    整份写回会把「读原文到写回之间」这段时间里**别的 agent 的改动**一起抹掉。
    反向定点替换只动变异所在的那几行，其余字节原样保留。

    ⚠️ 反向替换要求变异串在文件里**唯一**。
    所以写变异版之前就会检查这一点：变异串不唯一 ⇒ 直接报错跳过，
    绝不写进去（否则还原时无法定位，会把变异留在文件里）。

    ⚠️ 还有一个**外来**风险：同一个仓库里别的 agent 也在跑变异脚本，
    他们的脚本用「整份快照写回」还原 —— 如果他们的快照是在我的变异生效期间
    取的，他们还原时会把**我的变异一起写回来**。
    所以本脚本跑完还会做一次**残留扫描**（见 scan_leftovers），
    把漏网的变异串反向换回去。
    """
    m = _pending['m']
    _pending['m'] = None
    _pending['mutated_text'] = None
    if not m:
        return True
    try:
        cur = read_app()
    except OSError as e:
        print(f'  ⚠️ 还原时读不到 {APP}: {e}')
        return False
    if m['new'] not in cur:
        print('  ↩ 变异串已不在文件里（已被其它改动覆盖），无需还原')
        return True
    n = cur.count(m['new'])
    if n != 1:
        print(f'  ⚠️ 变异串在文件里出现 {n} 次，无法安全定点还原，'
              f'请人工检查 {APP}')
        return False
    write_app(cur.replace(m['new'], m['old'], 1))
    print(f'  ↩ 已还原{("（" + reason + "）") if reason else ""}')
    return True


def scan_leftovers():
    """扫描 app.py 里是否还有**没被还原**的变异串，有就反向换回去。

    这是给「别的 agent 的整份快照还原把我的变异写回来了」兜底的。
    返回残留条数。
    """
    try:
        cur = read_app()
    except OSError:
        return -1
    fixed = 0
    for m in MUTATIONS:
        if m['new'] in cur and m['old'] not in cur:
            n = cur.count(m['new'])
            if n == 1:
                write_app(cur.replace(m['new'], m['old'], 1))
                print(f'  ⚠️ 发现残留变异 {m["id"]}，已反向还原')
                fixed += 1
                cur = read_app()
            else:
                print(f'  ⚠️ 残留变异 {m["id"]} 出现 {n} 次，需人工处理')
                fixed += 1
    return fixed


def on_signal(signum, frame):
    restore(f'收到信号 {signum}')
    sys.exit(128 + signum)


atexit.register(restore, 'atexit')
signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)


def run_test():
    env = dict(os.environ)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    p = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       env=env, timeout=600, cwd=ROOT)
    return p.returncode, p.stdout + p.stderr


def main():
    if not os.path.exists(TEST):
        print(f'找不到测试文件 {TEST}')
        return 2

    print('=' * 68)
    print('变异检查：并发/一致性修复 —— 每条变异都必须被测试抓住')
    print('=' * 68)

    # 先确认基线是绿的（否则后面的「变红」没有意义）
    rc, out = run_test()
    if rc != 0:
        print('❌ 基线测试就没绿，先修测试再谈变异：')
        print(out[-4000:])
        return 2
    print('  ✅ 基线测试通过（未变异时全绿）\n')

    caught, missed, skipped = [], [], []

    for m in MUTATIONS:
        mid = m['id']
        print(f'▶ {mid}  {m["desc"]}')
        try:
            cur = read_app()
        except OSError as e:
            print(f'  ⚠️ 读不到 {APP}: {e}')
            skipped.append((mid, m['desc'], '读不到源文件'))
            continue
        n = cur.count(m['old'])
        if n != 1:
            print(f'  ⚠️ 锚点在源码里出现 {n} 次（要求唯一）—— 报错跳过，'
                  f'请更新本脚本的锚点')
            skipped.append((mid, m['desc'], f'锚点出现 {n} 次'))
            continue

        mutated = cur.replace(m['old'], m['new'], 1)
        # 变异串必须在变异后的文件里**唯一** —— 否则还原时无法定位，
        # 变异会留在源码里（这是真的踩过：'return {}' 在 app.py 里有 5 处，
        # 还原时定位不到，变异就留在文件里了）。
        cnt_new = mutated.count(m['new'])
        if cnt_new != 1:
            print(f'  ⚠️ 变异串在变异后出现 {cnt_new} 次（要求唯一，'
                  f'否则无法安全还原）—— 报错跳过，请换一条变异串')
            skipped.append((mid, m['desc'],
                            f'变异串出现 {cnt_new} 次，无法安全还原'))
            continue
        try:
            write_app(mutated)
        except OSError as e:
            print(f'  ⚠️ 写变异版失败: {e}')
            skipped.append((mid, m['desc'], f'写变异版失败: {e}'))
            continue
        m['orig_text'] = cur
        _pending['m'] = m
        _pending['mutated_text'] = mutated

        try:
            rc, out = run_test()
        except subprocess.TimeoutExpired:
            rc, out = -1, '（测试超时）'

        if rc != 0:
            print('  ✅ 变异被抓住（测试变红）')
            caught.append((mid, m['desc']))
        else:
            print('  ❌ 变异**没被抓住**（测试仍然全绿）—— 这条修复缺少行为断言')
            missed.append((mid, m['desc']))
            tail = [ln for ln in out.splitlines() if '❌' in ln]
            for ln in tail[:10]:
                print('       ' + ln.strip())

        restore('变异后')

    # 还原后再跑一次，确认回到绿
    leftover = scan_leftovers()
    if leftover > 0:
        print(f'\n  ⚠️ 扫描到 {leftover} 处残留变异（多半是别的 agent 的整份快照'
              f'还原把我的变异写了回来），已尝试反向还原')
    rc, out = run_test()
    print()
    if rc == 0:
        print('  ✅ 还原后基线仍然全绿')
    else:
        print('  ❌ 还原后基线**不是绿的**，源码可能没还原干净：')
        print(out[-3000:])

    print('\n' + '=' * 68)
    print(f'  变异: {len(caught) + len(missed) + len(skipped)} 条'
          f'   捕获: {len(caught)}   漏网: {len(missed)}   跳过: {len(skipped)}')
    print('=' * 68)
    if missed:
        print('\n漏网的变异（对应修复没有行为断言）：')
        for mid, desc in missed:
            print(f'  - {mid}  {desc}')
    if skipped:
        print('\n跳过的变异（锚点失配，需要人工处理）：')
        for mid, desc, why in skipped:
            print(f'  - {mid}  {desc}  —— {why}')
    if missed or skipped:
        return 1
    return 0 if rc == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
