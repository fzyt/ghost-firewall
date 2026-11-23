#!/usr/bin/env python3
"""变异验证：第五批修复（证书申请/删除死锁 + /etc/config/network 解析容错）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch5_fixes.py

改的是 backend/app.py 里的三处：
  · UCI 段头/option 的解析（_UCI_SECTION_RE / _uci_section_name /
    _uci_find_section / _uci_has_option / extract_uci_value）
  · 证书判重与删除（rp_request_cert / rp_delete_cert）
  · 证书存放目录（_cert_dir_name）

判定标准只有一条：**改坏之后断言必须失败**。

⚠ 捕获口径：rc≠0 但输出里**没有 [FAIL] 行不算捕获** ——
  那说明测试自己崩了（导入失败、源码语法错误），不是「测试抓到了缺陷」。
  ⇒ 测试必须「红」而不是「死」。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_batch5_fixes.py')

SRC = {'app': open(APP, encoding='utf-8').read()}
TARGET = {'app': APP}

MUTANTS = [
    # ── ① 段头解析退回「精确串」的老写法 ─────────────────────────────
    # 「config」后面只准一个空格 ⇒ `config  interface 'lan'`（两个空格）
    # 这种用户手工编辑出来的写法就认不出段了（老代码就是这么死的）。
    ('app', 'UCI 段头正则退回不容错的写法（加个空格就认不出段）',
     '_UCI_SECTION_RE = re.compile(r"^[ \\t]*config[ \\t]+([A-Za-z0-9_.-]+)[ \\t]*(.*?)[ \\t]*$")',
     '_UCI_SECTION_RE = re.compile(r"^config ([A-Za-z0-9_.-]+)[ \\t]*(.*?)[ \\t]*$")'),

    ('app', '段名不剥引号（双引号/不带引号的写法认不出）',
     "    return r.split()[0].strip('\\'\"')",
     "    return r.split()[0]"),

    ('app', '段名只按空白切（引号留在名字里 ⇒ 匹配不上）',
     "    return r.split()[0].strip('\\'\"')",
     "    return r.split()[0]"),

    # ── ② 段体边界退回「每行必须以空白开头」的老截断 ──────────────────
    # 老行为：段体靠「每行都得缩进」来划边界，段内只要有一行顶格，
    # 段体就在那儿被截断，后面的字段校验器根本看不见。
    ('app', '段体边界改成靠行首空白截断（顶格写的行后面全看不见）',
     "            cur = (m.group(1), _uci_section_name(m.group(2)), off + len(ln))\n"
     "        off += len(ln)",
     "            cur = (m.group(1), _uci_section_name(m.group(2)), off + len(ln))\n"
     "        elif cur is not None and not ln[:1].isspace():\n"
     "            return text[cur[2]:off], cur[2], off\n"
     "        off += len(ln)"),

    # ── ③ option 检测退回精确串 ────────────────────────────────────
    ('app', 'option 检测退回精确串匹配（多一个空格就当字段不存在）',
     "        if kind == 'option' and k == key:\n"
     "            return True",
     "        if kind == 'option' and k == key and ('option ' + key) in line:\n"
     "            return True"),

    ('app', 'option 检测完全失效（永远说字段不存在）',
     "        if kind == 'option' and k == key:\n"
     "            return True\n"
     "    return False",
     "        if kind == 'option' and k == key:\n"
     "            return False\n"
     "    return False"),

    # ── ④ 值里的空格又漏出来了 ──────────────────────────────────────
    ('app', 'extract_uci_value 不去引号里的尾随空格',
     '        return parts[2].strip().strip("\'\\"").strip()',
     '        return parts[2].strip().strip("\'\\"")'),

    # ── ⑤ 证书目录不再区分泛域名（两张证书互相覆盖文件）──────────────
    ('app', '泛域名证书不再单独建目录（会冲掉普通证书的文件）',
     '    return f"{domain}.wildcard" if wildcard else domain',
     '    return domain'),

    # ── ⑥ 申请端点判重退回「已有证书 ⇒ 400」 ────────────────────────
    ('app', '申请端点判重退回 400（同名证书就把用户挡死）',
     "    same_idx = -1\n"
     "    for _i, _c in enumerate(rp.get(\"certificates\", [])):\n"
     "        if _c.get(\"domain\") == domain and bool(_c.get(\"wildcard\")) == wildcard:\n"
     "            same_idx = _i\n"
     "            break",
     "    same_idx = -1\n"
     "    for _i, _c in enumerate(rp.get(\"certificates\", [])):\n"
     "        if _c.get(\"domain\") == domain:\n"
     "            return jsonify({\"success\": False, \"message\": f\"域名 {domain} 已有证书\"}), 400"),

    ('app', '申请端点不判 wildcard（普通证书也会把泛域名挡死）',
     "        if _c.get(\"domain\") == domain and bool(_c.get(\"wildcard\")) == wildcard:",
     "        if _c.get(\"domain\") == domain and not bool(_c.get(\"wildcard\")):"),

    ('app', '申请端点总是追加（同名证书出现两条，id 打架）',
     "    if same_idx >= 0:\n"
     "        # 原地替换：保留原 id（默认证书指向的是 id，换 id 会让\n"
     "        # default_cert_id 指向一张不存在的证书 ⇒ 网关退到自签证书）。\n"
     "        cert_entry[\"id\"] = rp[\"certificates\"][same_idx][\"id\"]\n"
     "        rp[\"certificates\"][same_idx] = cert_entry\n"
     "        replaced = True\n"
     "    else:",
     "    if False:\n"
     "        replaced = True\n"
     "    else:"),

    ('app', '申请端点原地替换时不保留 id（默认证书指向会失效）',
     "        cert_entry[\"id\"] = rp[\"certificates\"][same_idx][\"id\"]\n",
     "        cert_entry[\"id\"] = _next_id(\"cert\", [c[\"id\"] for c in rp.get(\"certificates\", [])])\n"),

    # ── ⑦ 删除默认证书又变回死锁 ────────────────────────────────────
    ('app', '删除默认证书又变回拒绝（用户只有一张证书时删不掉）',
     "        settings[\"default_cert_id\"] = \"\"\n"
     "        default_cleared = True",
     "        default_cleared = True"),

    ('app', '删除默认证书不清掉 default_cert_id（网关指向已删证书）',
     "        settings[\"default_cert_id\"] = \"\"\n"
     "        default_cleared = True",
     "        default_cleared = True"),

    # ── ⑧ 签发 / 续期时把泛域名当普通证书（装错目录，覆盖别人的文件）───
    ('app', '签发时按普通证书目录装（泛域名证书会冲掉普通证书的文件）',
     "    cert_dir = os.path.join(NGINX_SSL_DIR, _cert_dir_name(domain, wildcard))\n"
     "    os.makedirs(cert_dir, exist_ok=True)",
     "    cert_dir = os.path.join(NGINX_SSL_DIR, domain)\n"
     "    os.makedirs(cert_dir, exist_ok=True)"),

    ('app', '续期时按普通证书目录装（泛域名证书会冲掉普通证书的文件）',
     "    cert_dir = os.path.join(NGINX_SSL_DIR, _cert_dir_name(domain, wildcard))\n"
     "    fullchain = os.path.join(cert_dir, \"fullchain.pem\")",
     "    cert_dir = os.path.join(NGINX_SSL_DIR, domain)\n"
     "    fullchain = os.path.join(cert_dir, \"fullchain.pem\")"),

    # ── ⑨ 上传端点：泛域名也要分目录、也不能挤掉普通证书 ────────────
    ('app', '上传端点把泛域名装进普通证书目录（两张证书互相覆盖文件）',
     "    cert_dir = os.path.join(NGINX_SSL_DIR, _cert_dir_name(domain, _parsed_wildcard))",
     "    cert_dir = os.path.join(NGINX_SSL_DIR, domain)"),

    ('app', '上传端点只按 domain 找旧证书（泛域名上传会挤掉普通证书）',
     "        if (c.get(\"domain\") == domain and c.get(\"source\") == \"manual\"\n"
     "                and bool(c.get(\"wildcard\")) == is_wildcard):",
     "        if (c.get(\"domain\") == domain and c.get(\"source\") == \"manual\"):"),

    # ── ⑩ 写 wan 段时判段头退回老写法（后面的段头被吞掉）─────────────
    # 这三处互为兜底：单独退一处，另一处仍能把段头认出来 ⇒ 那是等价变异，
    # 不算真变异。退回「老写法」必须**同时**放开三处（一条变异改多处）。
    ('app', '写 wan/wan6 段时段头判定退回 startswith（后面的段头被吞掉）',
     [("                if _UCI_SECTION_RE.match(next_stripped):\n"
       "                    break",
       "                if next_stripped.startswith('config '):\n"
       "                    break"),
      ("                    if i + 1 < len(lines) and not _UCI_SECTION_RE.match(lines[i+1].strip()):",
       "                    if i + 1 < len(lines) and not lines[i+1].strip().startswith('config '):"),
      ("                if _UCI_SECTION_RE.match(lines[i].strip()):\n"
       "                    break",
       "                if lines[i].strip().startswith('config '):\n"
       "                    break")],
     None),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=600, env=env)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '[FAIL]' in l]
    if fails:
        print(f'  [OK] 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    if r.returncode != 0:
        print(f'  [FAIL] 漏过 {name} —— 但测试是**崩了**不是红了，不算捕获')
        tail = (r.stderr.strip().splitlines() or ['(无 stderr)'])
        print('        ', tail[-1][:86])
    else:
        print(f'  [FAIL] 漏过 {name}')
    return False


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：第五批修复（证书死锁 + network 解析容错）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('[FAIL] 基线没过：')
        print(base.stdout[-2500:])
        if base.stderr:
            print(base.stderr[-1200:])
        return 1
    print(f'基线通过 {base.stdout.count("[PASS]")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for key, name, old, new in MUTANTS:
            src = SRC[key]
            # 一条变异可以改多处（old 是 [(原文, 替换), ...]）——
            # 有些老写法在源码里有好几处互相兜底的等价实现，
            # 单独退一处是等价变异，退**全部**才是真变异。
            pairs = old if isinstance(old, list) else [(old, new)]
            missing = None
            for o, _n in pairs:
                if src.count(o) != 1:
                    missing = src.count(o)
                    break
            if missing is not None:
                print(f'  [FAIL] 锚点未命中（出现 {missing} 次）: {name}')
                noanchor.append(name)
                continue
            mutated = src
            for o, n in pairs:
                mutated = mutated.replace(o, n, 1)
            with open(TARGET[key], 'w', encoding='utf-8') as f:
                f.write(mutated)
            caught += report(name, run_test())
            with open(TARGET[key], 'w', encoding='utf-8') as f:
                f.write(src)
    finally:
        for key, path in TARGET.items():
            with open(path, 'w', encoding='utf-8') as f:
                f.write(SRC[key])

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == len(MUTANTS) else '有变异漏过')
    return 0 if caught == len(MUTANTS) else 1


if __name__ == '__main__':
    sys.exit(main())
