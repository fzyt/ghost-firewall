#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""重新生成阿里云 DDNS 自动更新脚本（部署后由 setup.sh 调用）。

为什么需要这一步
----------------
`/opt/nftables-web-v2/aliyun-ddns-update.py` 是**生成物**：它由
`backend/app.py` 里的 `_generate_ddns_update_script()` 写出来。

部署只换 `app.py` ⇒ 设备上那份脚本**不会自动更新** ⇒ 跑的仍是旧逻辑。

⚠️ 这不是纸上担心：2026-11-11 在 `.232` 真机实测过 ——
改了「只有一条记录时就更新它」的规则、部署了新版本，但设备上那份脚本
还是旧的，于是真机跑出来仍是「按线路过滤 → 走新增」的旧行为
（同一个测试场景在本地过、在真机挂）。重新生成后才符合预期。

⇒ 部署完必须重新生成一次，否则修复等于没修，而且**现象照旧**，
很容易被误判成「没修好」。

为什么不用 `import app` 再调那个函数
------------------------------------
`app.py` 顶层可能起后台线程（watchdog 之类）。在设备上 import 它，
有可能触发防火墙规则切换 ⇒ **有失联风险**。

这里改用 **AST 提取模板**再写文件：
  · 零副作用（不 import 整个模块）
  · 写入内容与 `_generate_ddns_update_script()` 完全等价
    （那个函数体就是 `write(script_content)`）

用法
----
    python3 backend/regen_ddns_script.py

路径可用环境变量覆盖（测试用）：
    NFTABLES_WEB_APP_PY     —— app.py 的路径
    NFTABLES_WEB_DDNS_SCRIPT —— 生成物的路径
"""

import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_PY = os.environ.get("NFTABLES_WEB_APP_PY", os.path.join(HERE, "app.py"))
# 兜底输出路径。**只在 app.py 里提取不到 script_path 时**才会用到
# （正常路径永远用 app.py 里的真源，见 resolve_out）。
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "aliyun-ddns-update.py")


def extract_template(app_path):
    """从 app.py 里取出 cron 脚本模板**和它的目标路径**。

    两个都要取 —— 目标路径（`script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"`）
    是面板写盘时用的**唯一真源**。

    ⚠️ 以前这里按目录层级**推导**（backend 的父目录），而面板侧是**硬编码** ——
      两套机制，今天相等只是布局巧合。哪天布局变了（INSTALL_DIR 改名、
      或者 Docker 变体把 app.py 放在 /app/backend），重新生成就写到别处去了，
      而 cron 跑的还是旧文件 ⇒ **修复静默失效，而且 regen 还报「已重新生成」**。

    返回 (脚本内容, 目标路径)；任一取不到就是 (None, None)。
    """
    tree = ast.parse(open(app_path, encoding="utf-8").read())
    for node in tree.body:
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_generate_ddns_update_script"):
            script = None
            path = None
            for stmt in node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                target = getattr(stmt.targets[0], "id", "")
                if target == "script_content":
                    script = ast.literal_eval(stmt.value)
                elif target == "script_path":
                    path = ast.literal_eval(stmt.value)
            if script:
                return script, path
            return None, None
    return None, None


def resolve_out(script_path):
    """决定写到哪个文件。

    优先级：环境变量（**只给测试用**）＞ app.py 里的真源 ＞ 兜底推导。

    ⚠️ 环境变量可以让它写到任意路径 —— 调用方（setup.sh）以 root 运行，
      所以 setup.sh 那边会用 `env -u` 把它清掉，保证设备上永远走真源。
    """
    env = os.environ.get("NFTABLES_WEB_DDNS_SCRIPT")
    if env:
        return env
    return script_path or DEFAULT_OUT


def write_script(script, out_path):
    """写出脚本。

    ⚠️ 目标路径若是软链，先解引用到真实文件再写 ——
    替换软链本身会把内容写到别处去（面板的静态资源目录就有软链）。
    """
    real = os.path.realpath(out_path)
    tmp = real + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(tmp, 0o755)
    os.replace(tmp, real)
    return real


def main():
    try:
        if not os.path.exists(APP_PY):
            print("[SKIP] 找不到 %s" % APP_PY)
            return 0
        script, script_path = extract_template(APP_PY)
        if not script:
            print("[SKIP] app.py 里提取不到 cron 脚本模板")
            return 0
        # 输出路径由 app.py 里的真源决定（见 resolve_out）。
        # ⚠ 环境变量优先级最高是**只给测试用**的：setup.sh 调用本脚本时
        #   用 `env -u` 清掉它，保证设备上永远写 app.py 指定的那个路径。
        out_path = resolve_out(script_path)
        # ⚠ 先编译再写：模板被改坏时**不留下**半截文件
        #   （旧脚本还能继续跑，比写成一份坏脚本强）。
        compile(script, out_path, "exec")
        real = write_script(script, out_path)
        print("已重新生成阿里云 DDNS 自动更新脚本：%s（%d 字节）"
              % (real, os.path.getsize(real)))
        return 0
    except Exception as exc:
        # ⚠ 不抛 traceback：调用方（setup.sh / 面板）看的是**中文一行**，
        #   拿到退出码就能决定要不要提示用户手工再生成一次。
        print("[FAIL] 重新生成阿里云 DDNS 自动更新脚本失败：%s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
