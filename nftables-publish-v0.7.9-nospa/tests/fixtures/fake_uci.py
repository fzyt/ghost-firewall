#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""假 uci —— 只为**沙箱判据**服务，绝不能在真机上跑。

⚠️ 安全闸（硬性）：
   没有 `FAKE_UCI_DIR` 环境变量 ⇒ **直接退出**。
   ⇒ 这个脚本永远碰不到真实的 `/etc/config`。
   ⚠️ 它自己**不删东西**：只有 `delete` 子命令会改配置，
      而那只在沙箱目录里跑。

为什么需要它
------------
`backend/dhcp_hosts.py` 用 uci 写 `/etc/config/dhcp`。
判据要验「备份 → 写 → 语法校验 → 回滚」这条链，
但**绝不能**在开发机上真的改 `/etc/config/dhcp`，更不能碰真机。

⇒ 这里实现 uci 的一个**子集**，行为按 .232 上的真 uci 对齐
（下面每条都标了 .232 实测依据）。

实现的子集
----------
  show <pkg>              打印 `pkg.sec=type` / `pkg.sec.opt='v'`
  get  <pkg.sec>          打印段类型（不带引号）
  get  <pkg.sec.opt>      打印选项值（不带引号）
  set  <pkg.sec=type>     建段
  set  <pkg.sec.opt=val>  设选项（段不存在 ⇒ rc=1）
  set  <pkg.sec.opt=      设空值 ⇒ rc=1（.232 实测：Entry not found）
  commit <pkg>            写回文件
  delete <pkg.sec>        删段（不存在 ⇒ rc=1）

⚠️ **delta 语义**（必须实现，否则假 uci 与真 uci 行为不一致）
   真 uci 的 `set` 不会立刻改文件，而是把变更存在 `/tmp/.uci/` 里，
   `commit` 才落盘 ⇒ 所以「先 set 建段、再 set 设选项」不用中间 commit
   也能成（.232 实测：`uci set dhcp.s0=host` → `uci set dhcp.s0.name=X`
   → `uci commit dhcp` 一次成功）。
   ⇒ 这里用 `FAKE_UCI_DELTA` 指向的 JSON 文件模拟这份 delta。

⚠️ 故意保留的两个「假」特性，供判据制造故障：
  · 值等于 `__CORRUPT__` 时，写出的文件引号不闭合 ⇒ 模拟「uci 写出坏配置」
    ⇒ 真 uci 的 `show` 会 rc=1（.232 实测：Parse error ⇒ rc=1）
  · `FAKE_UCI_FAIL_COMMIT=1` ⇒ commit 返回 rc=1
"""
import json
import os
import sys

PKG = 'dhcp'
CORRUPT_MARK = '__CORRUPT__'


def die(msg, rc=1):
    sys.stderr.write(msg + '\n')
    sys.exit(rc)


def cfg_dir():
    """配置目录。**没有环境变量就拒绝运行**（安全闸）。"""
    d = os.environ.get('FAKE_UCI_DIR')
    if not d:
        die('fake_uci: 缺少 FAKE_UCI_DIR，拒绝运行（防止误改真实配置）', 2)
    return d


def cfg_file():
    return os.path.join(cfg_dir(), PKG)


def delta_file():
    """delta 文件（模拟真 uci 的 /tmp/.uci/）。"""
    p = os.environ.get('FAKE_UCI_DELTA')
    if not p:
        die('fake_uci: 缺少 FAKE_UCI_DELTA，拒绝运行', 2)
    return p


def parse_value(val):
    """返回 (值, 是否合法)。引号没闭合 ⇒ 非法（模拟 uci 的 Parse error）。"""
    v = val.strip()
    if v.startswith("'"):
        out = []
        j = 1
        while j < len(v):
            if v[j:j + 4] == "'\\''":
                out.append("'")
                j += 4
                continue
            if v[j] == "'":
                return ''.join(out), True
            out.append(v[j])
            j += 1
        return ''.join(out), False
    if v.startswith('"'):
        if len(v) >= 2 and v.endswith('"'):
            return v[1:-1], True
        return v, False
    return v, True


def escape_value(v):
    """按 uci 的规矩转义并加引号（.232 实测：值里的单引号写成 '\\''）。"""
    return "'" + str(v).replace("'", "'\\''") + "'"


def load():
    """读配置文件 → (sections, 错误信息)。

    sections = [{'type', 'name', 'opts': {key: value}}]
    """
    path = cfg_file()
    if not os.path.exists(path):
        return None, 'uci: Entry not found'
    with open(path, encoding='utf-8', errors='replace') as f:
        text = f.read()
    sections = []
    cur = None
    for raw in text.split('\n'):
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        if s.startswith('config '):
            parts = s.split(None, 2)
            cur = {'type': parts[1] if len(parts) > 1 else '', 'name': '',
                   'opts': {}}
            if len(parts) > 2:
                nm, ok = parse_value(parts[2])
                if not ok:
                    return None, "uci: Parse error (unterminated quote)"
                cur['name'] = nm
            sections.append(cur)
            continue
        if s.startswith('option '):
            parts = s.split(None, 2)
            if cur is None:
                continue
            key = parts[1] if len(parts) > 1 else ''
            val, ok = parse_value(parts[2] if len(parts) > 2 else '')
            if not ok:
                return None, "uci: Parse error (unterminated quote)"
            cur['opts'][key] = val
            continue
        # 其它行忽略
    return sections, None


def dump(sections):
    """按 uci 的格式写回文件。"""
    out = ['']
    for sec in sections:
        if sec['name']:
            out.append("config %s '%s'" % (sec['type'], sec['name']))
        else:
            out.append('config %s' % sec['type'])
        for k, v in sec['opts'].items():
            if v == CORRUPT_MARK:
                # 故意写出没闭合的引号 ⇒ 模拟「uci 写出坏配置」
                out.append("\toption %s 'BROKEN" % k)
            else:
                out.append("\toption %s %s" % (k, escape_value(v)))
        out.append('')
    with open(cfg_file(), 'w', encoding='utf-8') as f:
        f.write('\n'.join(out))


def load_delta():
    """读 delta（模拟真 uci 的 /tmp/.uci/ 变更集）。"""
    p = delta_file()
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_delta(ops):
    with open(delta_file(), 'w', encoding='utf-8') as f:
        json.dump(ops, f, ensure_ascii=False)


def clear_delta():
    p = delta_file()
    if os.path.exists(p):
        os.remove(p)


def find_section(sections, name):
    for sec in sections:
        if sec['name'] == name:
            return sec
    return None


def apply_delta(sections, ops):
    """把 delta 应用到 sections 上（就地改）。

    返回 None 成功；失败时返回错误字符串（uci 的报错文本）。
    """
    for op in ops:
        kind = op.get('op')
        if kind == 'newsec':
            sec = find_section(sections, op['name'])
            if sec is None:
                sections.append({'type': op['type'], 'name': op['name'],
                                 'opts': {}})
            else:
                sec['type'] = op['type']
        elif kind == 'setopt':
            sec = find_section(sections, op['name'])
            if sec is None:
                # .232 实测：段不存在时设选项 ⇒ uci: Invalid argument
                return 'uci: Invalid argument'
            sec['opts'][op['key']] = op['value']
        elif kind == 'del':
            sec = find_section(sections, op['name'])
            if sec is None:
                return 'uci: Entry not found'
            sections.remove(sec)
    return None


def state():
    """当前状态 = 配置文件 + delta。返回 (sections, 错误信息)。"""
    sections, err = load()
    if err:
        return None, err
    err = apply_delta(sections, load_delta())
    if err:
        return None, err
    return sections, None


def ident(sec):
    """show 输出里的段标识：有名字用名字，没名字用 @type[index]。"""
    return sec['name'] if sec['name'] else '@%s[%d]' % (
        sec['type'], sec['_idx'])


def main(argv):
    cfg_dir()
    args = argv[1:]
    if not args:
        die('uci: no arguments')
    cmd = args[0]
    rest = args[1:]

    # ── 写类子命令：改 delta，不直接动文件 ────────────────────
    if cmd == 'set':
        if not rest:
            die('uci: Invalid argument')
        target = rest[0]
        if '=' not in target:
            die('uci: Invalid argument')
        path, _, value = target.partition('=')
        pkg, _, rest2 = path.partition('.')
        if pkg != PKG:
            die('uci: Entry not found')
        head, _, opt = rest2.partition('.')
        ops = load_delta()
        if not opt:
            # 建段（段已存在就是改类型）
            ops.append({'op': 'newsec', 'name': head, 'type': value})
            save_delta(ops)
            return 0
        # 设选项
        if value == '':
            # .232 实测：uci set pkg.sec.opt=（空值）⇒ rc=1 Entry not found
            die('uci: Entry not found')
        ops.append({'op': 'setopt', 'name': head, 'key': opt, 'value': value})
        save_delta(ops)
        # 段必须已经存在（真 uci 的行为：先建段，再设选项）
        _secs, err = state()
        if err:
            die(err, 1)
        return 0

    if cmd == 'delete':
        if not rest:
            die('uci: Invalid argument')
        target = rest[0]
        pkg, _, path = target.partition('.')
        if pkg != PKG:
            die('uci: Entry not found')
        ops = load_delta()
        ops.append({'op': 'del', 'name': path})
        save_delta(ops)
        _secs, err = state()
        if err:
            die(err, 1)
        return 0

    if cmd == 'commit':
        if os.environ.get('FAKE_UCI_FAIL_COMMIT') == '1':
            # ⚠️ 失败时**不清 delta** —— 真 uci 就是这样（.232 实测 2026-11-12：
            #    commit 失败后 `uci changes dhcp` 仍然列着那一段）。
            #    这条语义是「回滚必须清 delta」那条判据的地基。
            die('uci: I/O error', 1)
        sections, err = state()
        if err:
            die(err, 1)
        dump(sections)
        clear_delta()
        return 0

    if cmd == 'revert':
        # ⚠️ 丢弃**未提交**的变更（.232 实测 2026-11-12：
        #    `uci revert dhcp` 之后 `uci changes dhcp` 变空，
        #    而且**已提交**的内容不受影响 —— 文件仍要靠备份还原）。
        #    对**空** delta 调用也是 rc=0（.232 实测）。
        if rest and rest[0] != PKG:
            die('uci: Entry not found')
        clear_delta()
        return 0

    if cmd == 'changes':
        # 列出未提交的变更（真 uci 的格式：pkg.sec='type' 等）
        ops = load_delta()
        lines = []
        for op in ops:
            if op.get('op') == 'newsec':
                lines.append("%s.%s='%s'" % (PKG, op['name'], op['type']))
            elif op.get('op') == 'setopt':
                lines.append("%s.%s.%s='%s'" % (PKG, op['name'], op['key'],
                                               op['value']))
            elif op.get('op') == 'del':
                lines.append("%s.%s='del'" % (PKG, op['name']))
        sys.stdout.write('\n'.join(lines) + ('\n' if lines else ''))
        return 0

    # ── 读类子命令：看的是「文件 + delta」的合并结果 ───────────
    sections, err = state()
    if err:
        # 文件不存在或语法坏 ⇒ 真 uci 的 show/get 都 rc=1
        die(err, 1)

    if cmd == 'show':
        for i, sec in enumerate(sections):
            sec['_idx'] = i
        lines = []
        for sec in sections:
            sid = ident(sec)
            lines.append('%s.%s=%s' % (PKG, sid, sec['type']))
            for k, v in sec['opts'].items():
                lines.append('%s.%s.%s=%s' % (PKG, sid, k, escape_value(v)))
        sys.stdout.write('\n'.join(lines) + ('\n' if lines else ''))
        return 0

    if cmd == 'get':
        if not rest:
            die('uci: Invalid argument')
        target = rest[0]
        if '.' not in target:
            die('uci: Invalid argument')
        pkg, _, path = target.partition('.')
        if pkg != PKG:
            die('uci: Entry not found')
        head, _, opt = path.partition('.')
        for sec in sections:
            if sec['name'] == head:
                if not opt:
                    sys.stdout.write(sec['type'] + '\n')
                    return 0
                if opt in sec['opts']:
                    sys.stdout.write(sec['opts'][opt] + '\n')
                    return 0
                die('uci: Entry not found')
        die('uci: Entry not found')

    die('uci: Invalid argument')


if __name__ == '__main__':
    sys.exit(main(sys.argv))
