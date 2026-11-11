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
OUT = os.environ.get("NFTABLES_WEB_DDNS_SCRIPT",
                      os.path.join(os.path.dirname(HERE), "aliyun-ddns-update.py"))


def extract_script(app_path):
    """从 app.py 里取出 cron 脚本模板。

    用 AST 而不是正则切：脚本里满是引号、缩进、三引号，正则切出来的
    边界经常差一个字符，而且**切错时不会报错**，只是内容变了。
    AST 拿到的是 Python 解释后的真实字符串。
    """
    tree = ast.parse(open(app_path, encoding="utf-8").read())
    for node in tree.body:
        if (isinstance(node, ast.FunctionDef)
                and node.name == "_generate_ddns_update_script"):
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign)
                        and getattr(stmt.targets[0], "id", "") == "script_content"):
                    return ast.literal_eval(stmt.value)
    return None


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
        script = extract_script(APP_PY)
        if not script:
            print("[SKIP] app.py 里提取不到 cron 脚本模板")
            return 0
        # ⚠ 先编译再写：模板被改坏时**不留下**半截文件
        #   （旧脚本还能继续跑，比写成一份坏脚本强）。
        compile(script, OUT, "exec")
        real = write_script(script, OUT)
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
