#!/usr/bin/env python3
"""恢复配置不得回退会话世代号（auth_token_epoch）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_restore_epoch_guard.py

背景（2026-11-08 .232 真机 e2e 实测）
------------------------------------
面板上点「恢复配置」之后：

  · 落盘的 config 里 ``auth_token_epoch`` 从 **1** 变成 **0**
  · 紧接着的 GET /api/config 返回 **401**，面板上所有操作按钮变成 disabled
    （用户被硬踢下线，而 restoreConfig() 只弹一句「配置已恢复」）
  · 更严重的一侧：世代号调小 = **撤销「改密码作废全部会话」的保证** ——
    改密码之前签发的旧令牌会重新生效

根因：``restore_config`` 原来是 ``shutil.copy(backup, tmp)`` + ``os.replace``
整份覆盖，**绕过了** app.py 里 READONLY 名单对 ``auth_token_epoch`` 的保护
（那个名单的注释写得很清楚：「它**只能**由改密码路径写」）。

「恢复配置」恢复的是防火墙配置，不是安全状态 ——
所以世代号必须**从当前配置继承**，不能从 backup 继承。

沙箱运行：配置/凭据路径全部指到临时目录，不碰真实路径。
"""
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def strip_py_comments(src):
    """去掉 Python 注释（保留字符串字面量里的 #）。

    为什么需要：本文件里有几条断言是「某段代码**不再**出现」。
    修复时为了说明「原来怎么错的」，注释里会**引用旧代码原文** ——
    源码级断言直接搜原文会把注释当成代码 → 误判「还在」。
    """
    out = []
    for line in src.splitlines():
        buf = []
        quote = None
        i = 0
        while i < len(line):
            c = line[i]
            if quote:
                buf.append(c)
                if c == '\\' and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in ('"', "'"):
                quote = c
                buf.append(c)
                i += 1
                continue
            if c == '#':
                break
            buf.append(c)
            i += 1
        out.append(''.join(buf))
    return '\n'.join(out)


def fn_body(src, name):
    """取函数体（从 def 行到下一个顶层 def/@app.route 之前）。"""
    lines = src.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.startswith(f'def {name}(') or line.startswith(f'def {name} ('):
            start = idx
            break
    if start is None:
        return ''
    body = []
    for line in lines[start + 1:]:
        if line.startswith('def ') or line.startswith('@app.route'):
            break
        body.append(line)
    return '\n'.join(body)


def load_app(tmpdir):
    """加载 app 模块，配置与凭据路径全部指到临时目录。

    返回的是**模块**（模块里的 Flask 实例叫 mod.app）——
    别把这两个混起来：模块名叫 app、Flask 实例也叫 app，
    写成 app.test_request_context() 会报「模块没有这个属性」。
    """
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
    }
    os.environ.update(paths)
    sys.path.insert(0, os.path.abspath(BACKEND))
    spec = importlib.util.spec_from_file_location(
        'app_restore_epoch_test', os.path.join(BACKEND, 'app.py'))
    mod = importlib.util.module_from_spec(spec)
    sys.modules['app_restore_epoch_test'] = mod
    spec.loader.exec_module(mod)
    return mod, paths


def write_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def do_restore(mod):
    """在请求上下文里真调一次 restore_config，返回 (status_code, 响应体)。

    注意失败分支返回的是 **tuple**（`return jsonify({...}), 500`），
    成功分支才是单个 Response —— 两种形态都要接住。
    """
    with mod.app.test_request_context():
        resp = mod.restore_config()
        if isinstance(resp, tuple):
            body, status = resp
            return status, body.get_json()
        return resp.status_code, resp.get_json()


def main():
    tmpdir = tempfile.mkdtemp(prefix='nft-restore-epoch-')
    mod, paths = load_app(tmpdir)
    cfg_path = paths['AUTH_CONFIG_PATH']
    backup_path = cfg_path + '.backup'

    # ──────────────────────────────────────────────────────────────
    sec('第 1 组：行为级 —— 恢复后世代号必须继承当前配置')
    # ──────────────────────────────────────────────────────────────

    # 场景 1：当前 epoch=5，backup 里 epoch=0（真机上就是这样：backup 更旧）
    write_json(cfg_path, {'auth_token_epoch': 5, 'lan_subnet4': '192.168.100.0/24',
                          'marker_current': 'v2'})
    write_json(backup_path, {'auth_token_epoch': 0, 'lan_subnet4': '10.0.0.0/8',
                              'marker_current': 'v1'})
    status, body = do_restore(mod)
    after = read_json(cfg_path)
    check('restore 返回 200', status == 200, f'status={status} {body}')
    check('世代号继承当前配置（5），不被 backup 的 0 覆盖',
          after.get('auth_token_epoch') == 5,
          f"落盘 auth_token_epoch={after.get('auth_token_epoch')}")
    check('其余字段确实被恢复（证明恢复动作本身生效，不是啥也没干）',
          after.get('marker_current') == 'v1' and after.get('lan_subnet4') == '10.0.0.0/8',
          f"marker={after.get('marker_current')} lan={after.get('lan_subnet4')}")

    # 场景 2：当前配置根本没有 epoch 键（从没改过密码）
    write_json(cfg_path, {'lan_subnet4': '192.168.100.0/24'})
    write_json(backup_path, {'auth_token_epoch': 7, 'lan_subnet4': '10.0.0.0/8'})
    status, _ = do_restore(mod)
    after = read_json(cfg_path)
    check('当前无 epoch 键时，恢复后是 0（不凭空造出 backup 的 7）',
          after.get('auth_token_epoch') == 0,
          f"落盘 auth_token_epoch={after.get('auth_token_epoch')}")

    # 场景 3：backup 被改坏（不是配置对象）⇒ 必须拒绝，且正式配置原封不动
    write_json(cfg_path, {'auth_token_epoch': 5, 'marker_current': 'v2'})
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(['not', 'a', 'config'], f)
    status, body = do_restore(mod)
    after = read_json(cfg_path)
    check('backup 内容不是配置对象时拒绝恢复（HTTP 500）',
          status == 500, f'status={status}')
    check('拒绝时正式配置未被改动',
          after.get('auth_token_epoch') == 5 and after.get('marker_current') == 'v2',
          f"落盘 {after}")

    # 场景 4：backup 文件不存在 ⇒ 400，且正式配置不动
    os.rename(backup_path, backup_path + '.away')
    status, _ = do_restore(mod)
    after = read_json(cfg_path)
    check('没有 backup 时返回 400', status == 400, f'status={status}')
    check('没有 backup 时正式配置未被改动',
          after.get('auth_token_epoch') == 5, f"落盘 {after}")
    os.rename(backup_path + '.away', backup_path)

    # ──────────────────────────────────────────────────────────────
    sec('第 2 组：源码级 —— 防线不能只是「这次恰好对」')
    # ──────────────────────────────────────────────────────────────

    with open(os.path.join(BACKEND, 'app.py'), encoding='utf-8') as f:
        raw = f.read()
    code = strip_py_comments(raw)
    body = fn_body(code, 'restore_config')

    check('restore_config 函数体找得到', bool(body))
    check('不再整份拷贝 backup（shutil.copy(backup_path, tmp_path) 已移除）',
          'shutil.copy(backup_path, tmp_path)' not in body)
    check('函数体里有对 auth_token_epoch 的显式赋值（世代号被显式接管）',
          "restored['auth_token_epoch']" in body,
          body[body.find('auth_token_epoch') - 40:body.find('auth_token_epoch') + 60]
          if 'auth_token_epoch' in body else '未找到')
    check('函数体里有非 dict 的备份拒绝分支',
          'isinstance(restored, dict)' in body)
    check('端点仍在路由表里', '/api/config/restore' in
          {str(r.rule) for r in mod.app.url_map.iter_rules()})

    print()
    print('=' * 60)
    print(f'  通过 {len(PASS)} / 失败 {len(FAIL)}')
    if FAIL:
        for f in FAIL:
            print(f'  [FAIL] {f}')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
