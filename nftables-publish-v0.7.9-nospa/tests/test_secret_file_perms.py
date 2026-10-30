"""敏感文件必须「落盘即正确」—— 写权限的那一刻就是最终权限。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_secret_file_perms.py

背景（2026-10-30 Shannon 问题清单 P1-27 / P1-28 / P1-31 / P2-26）
------------------------------------------------------------------
面板往磁盘上写敏感文件时，用的全是「**先写、再 chmod**」：

    with open(path, 'w') as f:      # ← 按 umask 建文件，默认 0644
        f.write(secret)
    os.chmod(path, 0o600)            # ← 之后才收紧

中间那一小段时间里，文件对**所有本地用户**可读。这个窗口不是「理论上」：

  · **TLS 私钥**（P1-28）：`key_file.save(tmp_k)` → `os.replace(tmp_k, key_path)`
    → `os.chmod(key_path, 0o600)`。replace 之后正式私钥就是 0644，
    chmod 在**之后**才做。私钥泄露 = 身份凭据泄露，不是「信息泄露」。
  · **阿里云 AccessKey secret**（P1-27）：同样先 0644 再 chmod。
  · **规则集 / .lastgood**（P1-31）：`open(tmp,'w')` + `shutil.copy` 都按 umask 建。
  · **名单 json + 名单锁文件**（P2-26）：`os.open(..., O_CREAT|O_RDWR)` 不带 mode
    ⇒ 更是直接 0644。

正确做法是**创建那一刻**就是目标权限。POSIX 正好有个特性能用：
`open(path, 'w')` 对**已存在**的文件只截断、**不改权限** ⇒
「先用目标权限把文件建好，再往里写」就没有窗口。

这个测试怎么验「那一刻」
----------------------
不看事后 chmod 完的权限（那是旧写法也能做到的），而是**在文件被打开写入的
那一刻**把它的权限记下来 —— 那正是内容落盘时的权限。

两个让「蒙对」也过不了的机关
---------------------------
1. **umask 设成 0**。任何「靠 umask 蒙对权限」的写法在这里会直接建出 0666，
   一眼红。默认 umask 022 的话，0644 和 0640 的差别只在 group 那一位，
   容易看漏。
2. **看的是 tmp 而不是最终文件**。名单/配置/私钥都走「tmp + os.replace」，
   真正危险的是 tmp 落盘那一刻的权限（replace 之后权限原样带过去）。
   所以探针按「目标路径 + .tmp*」匹配，而不是只看最终文件。
"""
import builtins
import importlib.util as ilu
import io
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')

# app.py 顶层 `from template_engine import ...` —— backend 必须在 sys.path 上
sys.path.insert(0, os.path.abspath(BACKEND))

# 测试用的面板口令（第 1 节写入、第 5 节登录用同一个）
TEST_PASSWORD = 'perm-test-pw'

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def not_wider(actual, target):
    """actual 没有任何一位超出 target —— 比 exact 更贴合「不能多开」。

    例：口令文件目标 0640，实际 0600（测试机没有 nftweb 组，属组没设成）
    仍然是安全的（只会更紧），所以不能简单判等。
    """
    return actual is not None and (actual & ~target) == 0


# ── 「落盘那一刻」的权限探针 ────────────────────────────────────────────
# 包装 builtin open：文件**被打开写入的那一刻**记录它的权限。
# 这比事后 chmod 的结果严格得多 —— 旧写法在这里会暴露 0644/0666。
_MOMENT = {}
_real_open = builtins.open

# 锁文件是 os.open(..., mode) 建的，后面还跟着一次 os.chmod。
# 只看事后权限的话，「把 mode 参数删掉」这种退化抓不住（chmod 会兜回来）。
# 所以额外探 os.open：**创建时请求的 mode** 才是「落盘那一刻」的真实契约。
_CREATE_MODE = {}
_real_os_open = os.open


def _spy_open(file, mode='r', *args, **kwargs):
    fh = _real_open(file, mode, *args, **kwargs)
    try:
        writable = any(c in mode for c in 'wxa+')
        if writable and isinstance(file, (str, bytes, os.PathLike)):
            _MOMENT[str(file)] = os.stat(file).st_mode & 0o777
    except OSError:
        pass
    return fh


def _spy_os_open(path, flags, mode=0o777, *args, **kwargs):
    fd = _real_os_open(path, flags, mode, *args, **kwargs)
    try:
        if flags & os.O_CREAT and isinstance(path, (str, bytes, os.PathLike)):
            _CREATE_MODE[str(path)] = mode
    except (OSError, TypeError):
        pass
    return fd


class MomentProbe:
    """一轮探针的收集结果。

    · open_perms   —— 文件被打开写入那一刻的实际权限
    · create_modes —— os.open 创建时**请求**的 mode
    """

    def __init__(self):
        self.open_perms = {}
        self.create_modes = {}


class moment_perms:
    """在 with 块内记录「打开写入那一刻」的权限。

    注意：__exit__ 里**不能**清空被记录的那个 dict —— 调用方拿到的就是它，
    清了等于什么都没记（这正是第一版一直显示「落盘时是 ?」的原因）。
    正确做法是进出时**换掉**模块级引用，把这一轮收集到的独立交出去。
    """

    def __enter__(self):
        global _MOMENT, _CREATE_MODE
        self._prev_moment = _MOMENT
        self._prev_create = _CREATE_MODE
        self._prev_open = builtins.open
        self._prev_os_open = os.open
        probe = MomentProbe()
        _MOMENT = probe.open_perms
        _CREATE_MODE = probe.create_modes
        builtins.open = _spy_open
        os.open = _spy_os_open
        return probe

    def __exit__(self, *exc):
        global _MOMENT, _CREATE_MODE
        builtins.open = self._prev_open
        os.open = self._prev_os_open
        _MOMENT = self._prev_moment
        _CREATE_MODE = self._prev_create
        return False


def moment_of(mom, target):
    """取「落盘那一刻」的权限。

    原子写路径下真正被写的是 tmp（名单是 `.tmp.<pid>.<tid>`，配置是 `.tmp`，
    私钥是 `.upload.tmp` / `.reupload.tmp`），所以目标本身没被记录时，
    退而找「以目标 + '.tmp' 开头」的那一个。
    """
    if target in mom:
        return mom[target]
    cands = [v for k, v in mom.items()
             if k.startswith(target + '.tmp') or k.startswith(target + '.upload.tmp')
             or k.startswith(target + '.reupload.tmp')]
    if cands:
        return cands[-1]
    return None


def load_app(env, paths):
    """加载 app 模块，所有落盘路径都指到临时目录。"""
    os.environ.update(env)
    for k, v in paths.items():
        os.environ[k] = v
    spec = ilu.spec_from_file_location('app_secret_perms', os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    sys.modules['app_secret_perms'] = mod
    spec.loader.exec_module(mod)
    return mod


def make_selfsigned(dirpath, cn='perm-test.example.com'):
    """生成一对真的自签证书/私钥（_cert_key_pair_ok 走 openssl 校验）。"""
    key = os.path.join(dirpath, 'k.pem')
    crt = os.path.join(dirpath, 'c.pem')
    r = subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
         '-keyout', key, '-out', crt, '-days', '1', '-subj', f'/CN={cn}'],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f'openssl 生成自签证书失败: {r.stderr}')
    return crt, key


def main():
    tmpdir = tempfile.mkdtemp(prefix='nft-perms-')
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmpdir, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmpdir, 'aliyun.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmpdir, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmpdir, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmpdir, 'nginx-conf'),
    }
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)

    print('=' * 62)
    print('敏感文件：落盘那一刻的权限必须已经是最终权限')
    print('=' * 62)

    # umask 设成 0：任何「靠 umask 蒙对」的写法会直接建出 0666，一眼红。
    old_umask = os.umask(0o000)

    try:
        app = load_app({}, paths)

        # ── 1. 口令哈希 ────────────────────────────────────────────────
        sec('1. 面板口令哈希（AUTH_PASSWORD_FILE）')

        pw_real = getattr(app, 'AUTH_PASSWORD_FILE', None)
        check('AUTH_PASSWORD_FILE 指向临时目录（测试隔离）',
              bool(pw_real) and pw_real.startswith(tmpdir), str(pw_real))

        if pw_real:
            # 用**真实口令的哈希**写，后面的登录环节才能真登录上
            with moment_perms() as probe:
                app._write_password_hash(app._hash_password(TEST_PASSWORD))
            got = moment_of(probe.open_perms, pw_real)
            check('写入口令文件的那一刻权限就是 0640（不是 0644 再 chmod）',
                  got == 0o640, f'落盘时是 {oct(got) if got is not None else "?"}')
            post = os.stat(pw_real).st_mode & 0o777
            check('事后权限没有比 0640 更宽（测试机无 nftweb 组 ⇒ 退回 0600 是允许的）',
                  not_wider(post, 0o640), oct(post))

        # 登录一次拿会话 —— 后面的「恢复配置」「上传证书」都要走真实鉴权，
        # 绕过鉴权测的就不是真实链路了。
        #
        # 来源地址用 lan_subnet4 段内的地址：配置一旦落盘，面板就按
        # lan_subnet4 收窄来源网段（_panel_allowed_networks），127.0.0.1
        # 会被判 IP_NOT_ALLOWED 挡在门外 —— 这正是真机上 LAN 管理员的处境。
        client = app.app.test_client()
        client.environ_base['REMOTE_ADDR'] = '192.168.100.50'
        r = client.post('/api/auth/login', json={'password': TEST_PASSWORD})
        check('面板会话建立成功（真实 login 接口）',
              r.status_code == 200 and (r.get_json() or {}).get('success'),
              f'HTTP {r.status_code}')

        # ── 2. 阿里云 AccessKey secret ─────────────────────────────────
        sec('2. 阿里云 DDNS 配置（AccessKey secret）')

        aliyun_real = getattr(app, 'ALIYUN_DDNS_CONFIG_PATH', None)
        with moment_perms() as probe:
            app._save_aliyun_ddns_config({'access_key_id': 'AK', 'access_key_secret': 'SECRET'})
        got = moment_of(probe.open_perms, aliyun_real)
        check('写入阿里云 secret 的那一刻权限就是 0600',
              got == 0o600, f'落盘时是 {oct(got) if got is not None else "?"}')
        post = os.stat(aliyun_real).st_mode & 0o777
        check('事后权限也是 0600', post == 0o600, oct(post))
        with open(aliyun_real, encoding='utf-8') as f:
            check('secret 真的落盘了（别是「因为没写所以权限对」）',
                  'SECRET' in f.read())

        # ── 3. 名单 json + 名单锁文件 ────────────────────────────────────
        sec('3. 名单 json + 名单锁文件')

        lists_real = getattr(app, 'LISTS_PATH', None)
        with moment_perms() as probe:
            app.save_lists({'whitelist': ['1.2.3.4'], 'blacklist': []})
        got = moment_of(probe.open_perms, lists_real)
        check('写入名单 json 的那一刻权限就是 0600',
              got == 0o600, f'落盘时是 {oct(got) if got is not None else "?"}')
        post = os.stat(lists_real).st_mode & 0o777
        check('事后权限也是 0600', post == 0o600, oct(post))

        lock_real = lists_real + '.lock'
        if os.path.exists(lock_real):
            os.unlink(lock_real)
        with moment_perms() as probe:
            with app._lists_file_lock():
                pass
        check('名单锁文件创建出来就是 0600（os.open 不带 mode ⇒ umask=0 时是 0666）',
              os.path.exists(lock_real)
              and os.stat(lock_real).st_mode & 0o777 == 0o600,
              oct(os.stat(lock_real).st_mode & 0o777)
              if os.path.exists(lock_real) else '没建出来')
        # 后面的 os.chmod 会把事后权限兜回 0600 —— 所以「创建时请求的 mode」
        # 才是落盘那一刻的真实契约，必须单独断言（删掉 mode 参数时只有它能红）
        check('名单锁文件创建时请求的 mode 就是 0600（不是靠后面的 chmod 兜）',
              probe.create_modes.get(lock_real) == 0o600,
              oct(probe.create_modes[lock_real])
              if lock_real in probe.create_modes else '没记录到创建')

        # ── 4. 共享配置 + 配置锁 ─────────────────────────────────────
        sec('4. 共享配置 + 配置锁')

        cfg_real = getattr(app, 'CONFIG_PATH', None)
        with moment_perms() as probe:
            app.save_config({'lan_subnet4': '192.168.100.0/24', 'wan_if': 'eth0',
                             'lan_if': 'br-lan', 'router_ip4': '192.168.100.1'})
        got = moment_of(probe.open_perms, cfg_real)
        check('写入配置的那一刻权限就是目标权限（0640）',
              got == 0o640, f'落盘时是 {oct(got) if got is not None else "?"}')
        post = os.stat(cfg_real).st_mode & 0o777
        check('事后权限也是 0640', post == 0o640, oct(post))

        cfg_lock = cfg_real + '.lock'
        check('配置锁文件不是 0666（umask=0 时 os.open 不带 mode 就是 0666）',
              os.path.exists(cfg_lock)
              and os.stat(cfg_lock).st_mode & 0o777 != 0o666,
              oct(os.stat(cfg_lock).st_mode & 0o777)
              if os.path.exists(cfg_lock) else '没建出来')
        check('配置锁文件创建时请求的 mode 就是 0640（不是靠后面的 chmod 兜）',
              probe.create_modes.get(cfg_lock) == 0o640,
              oct(probe.create_modes[cfg_lock])
              if cfg_lock in probe.create_modes else '没记录到创建')

        # ── 4b. 配置备份 + 配置恢复 ───────────────────────────────────
        sec('4b. 配置备份（.backup）与配置恢复')

        # 第二次保存：这次 CONFIG_PATH 已存在 ⇒ 会生成 .backup
        with moment_perms() as probe:
            app.save_config({'lan_subnet4': '192.168.100.0/24', 'wan_if': 'eth0',
                             'lan_if': 'br-lan', 'router_ip4': '192.168.100.1',
                             'trusted_ip4': '192.168.100.9'})
        backup_real = cfg_real + '.backup'
        got = moment_of(probe.open_perms, backup_real)
        check('配置 .backup 落盘那一刻权限就是 0640'
              '（shutil.copy 按 umask 建 ⇒ 先 0644/0666 再 copystat）',
              got == 0o640, f'落盘时是 {oct(got) if got is not None else "?"}')
        check('.backup 事后权限也是 0640',
              os.stat(backup_real).st_mode & 0o777 == 0o640,
              oct(os.stat(backup_real).st_mode & 0o777))

        # 恢复配置：走真实接口。恢复用的 tmp 同样必须是落盘即 0640。
        with moment_perms() as probe:
            r = client.post('/api/config/restore')
        check('配置恢复接口返回成功',
              r.status_code == 200 and (r.get_json() or {}).get('success'),
              f'HTTP {r.status_code}')
        check('恢复用的配置锁创建时请求的 mode 就是 0640',
              probe.create_modes.get(cfg_lock) == 0o640,
              oct(probe.create_modes[cfg_lock])
              if cfg_lock in probe.create_modes else '没记录到创建')
        got = moment_of(probe.open_perms, cfg_real + '.restore.tmp')
        check('恢复用的 tmp 落盘那一刻权限就是 0640',
              got == 0o640, f'落盘时是 {oct(got) if got is not None else "?"}')
        post = os.stat(cfg_real).st_mode & 0o777
        check('恢复出来的主配置权限是 0640（不是跟着备份文件的权限走）',
              post == 0o640, oct(post))

        # ── 5. TLS 私钥（真证书，走真实上传接口）─────────────────────────
        sec('5. TLS 私钥（真证书 · 端到端走上传接口）')

        crt, key = make_selfsigned(tmpdir)

        # 部署 nginx 的部分与本用例无关（这里没有 nginx），
        # 换掉它免得测试去改真机上的反代配置。
        app._deploy_all_rules = lambda cfg: (True, '测试里跳过 nginx 部署')

        domain = 'perm-test.example.com'
        key_path = os.path.join(paths['NFTABLES_WEB_SSL_DIR'], domain, 'privkey.pem')

        with moment_perms() as probe:
            r = client.post(
                '/api/reverse-proxy/certificates/upload',
                data={'domain': domain,
                      'cert_file': (io.BytesIO(open(crt, 'rb').read()), 'c.pem'),
                      'key_file': (io.BytesIO(open(key, 'rb').read()), 'k.pem')},
                content_type='multipart/form-data')
        body = r.get_json() or {}
        check('证书上传成功', r.status_code == 200 and body.get('success'),
              f"HTTP {r.status_code} {body.get('message', '')}")

        got = moment_of(probe.open_perms, key_path)
        check('私钥写入的那一刻权限就是 0600（不是 0644/0666 再 chmod）',
              got == 0o600, f'落盘时是 {oct(got) if got is not None else "?"}')

        if os.path.exists(key_path):
            post = os.stat(key_path).st_mode & 0o777
            check('正式私钥落地后权限不超出 0640（其他用户完全读不到）',
                  not_wider(post, 0o640), oct(post))
            check('正式私钥对「其他用户」完全关闭',
                  (post & 0o007) == 0, oct(post))
        else:
            check('正式私钥落地后权限不超出 0640（其他用户完全读不到）', False, '文件没建出来')

        # ── 6. 源码层兜底：防止以后新加一条路径又用回老写法 ──────────────
        sec('6. 源码层兜底（防止以后新加一条路径又用回老写法）')

        with open(os.path.join(BACKEND, 'app.py'), encoding='utf-8') as f:
            src = f.read()
        code = '\n'.join(l for l in src.split('\n') if not l.strip().startswith('#'))

        check('_ensure_file_mode 辅助函数存在', 'def _ensure_file_mode(' in src)
        check('规则集 tmp 在写入前先按 0600 建好',
              '_ensure_file_mode(tmp_path, 0o600)' in code)
        check('名单 tmp 在写入前先按 0600 建好',
              '_ensure_file_mode(tmp, 0o600)' in code)
        check('私钥 tmp 在写入前先按 0600 建好',
              code.count('_ensure_file_mode(tmp_k, 0o600)') >= 2)
        check('阿里云 secret 在写入前先按 0600 建好',
              '_ensure_file_mode(ALIYUN_DDNS_CONFIG_PATH, 0o600)' in code)
        check('口令文件在写入前先按 0640 建好',
              '_ensure_file_mode(AUTH_PASSWORD_FILE, 0o640)' in code)
        check('名单锁文件创建时带 0600 mode',
              re.search(r'os\.open\(LISTS_LOCK_PATH,[^)]*0o600\)', code) is not None)
        check('配置锁文件创建时带权限（不再依赖 umask）',
              re.search(r'os\.open\(lock_path,[^)]*_CONFIG_FILE_MODE\)', code) is not None)
        # worker 组读权限必须在 replace 之前给好 —— 正式私钥一落地
        # 就是最终形态（640 root:<worker 组>），不需要「先 0600 再放宽」的过渡态。
        # upload 和 reupload 两处都得满足，所以逐处查（不能只看第一处）。
        harden_at = [m.start() for m in re.finditer(r'_harden_key_for_nginx_worker\(tmp_k\)', code)]
        replace_at = [m.start() for m in re.finditer(r'os\.replace\(tmp_k', code)]
        check('worker 组读权限在 replace 之前给好（正式私钥一落地就是最终形态）',
              len(harden_at) >= 2 and len(replace_at) >= 2
              and all(h < r for h, r in zip(harden_at, replace_at)),
              f'harden×{len(harden_at)} replace×{len(replace_at)}')

    finally:
        os.umask(old_umask)

    print('\n' + '=' * 62)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败:')
        for f in FAIL:
            print('   - ' + f)
    else:
        print(' 全部通过')
    print('=' * 62)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
