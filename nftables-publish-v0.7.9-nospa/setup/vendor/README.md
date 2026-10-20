# vendor/

## blinker/ 1.9.0

Flask 3.x 的硬依赖（`flask.signals` → `from blinker import ...`），
但 **OpenWrt 25.12 的 apk 仓库里没有 blinker 包**，`python3-flask` 的依赖里
也不含它。

原先的兜底是 `pip3 install blinker`，而 `python3-pip` 本身 **52.3 MiB** ——
在 OpenWrt 常见的 80~90MB overlay 上根本装不下（实测 `.245` 装完只剩 28MB）。

所以改成**随包携带**：`setup.sh` 在 `import blinker` 失败时，把
`vendor/blinker/` 复制进 site-packages。32KB，纯 Python，无编译。

许可：MIT（见 `blinker/LICENSE.txt`）。
