#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
按钮清单抽取器 —— 一次性检索出所有可交互元素

用途
----
开发完一轮后想知道「到底有多少个按钮、分别在哪个页面、点了会发生什么」，
不该靠人肉翻 2000 行 HTML。这个脚本把 Alpine.js 页面里所有可交互元素
抽成结构化清单，供 e2e 测试对账用（保证「静态有 102 个 @click，实测就必须
点到 102 个」，漏了立刻暴露）。

为什么不直接用浏览器 dump
------------------------
浏览器只看得到**当前渲染**的元素。而这个面板是 Alpine SPA，一次只渲染
一个 currentNav —— 剩下 13 个页面的按钮在 DOM 里但不可见。所以必须静态
全量抽取，再用浏览器逐页激活后对账，两边取交集才算测全。

覆盖的交互元素
--------------
  button          按钮
  [role=button]   语义化按钮（<div role="button"> 之类）
  a[href]         链接
  input           输入框 / 复选框 / 单选 / 滑块 / 文件选择
  select          下拉选择
  textarea        多行输入
  form[\\@submit]  提交行为由表单承载

用法
----
    python3 tests/button_audit.py                 # 人读表格
    python3 tests/button_audit.py --json          # 机器读，供 e2e 对账
    python3 tests/button_audit.py --page ports    # 只看某一页
    python3 tests/button_audit.py --portal        # 抽认证门户（login/portal）

零依赖：只用 Python 标准库。
"""

import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser

# 相对本文件定位项目根，保证在任何 cwd 下都能跑
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INTERACTIVE_TAGS = {"button", "a", "input", "select", "textarea", "form"}

# 归一化属性名：Alpine 的 @click / :class / x-on:click 都映射到同一个 key
ATTR_ALIASES = {
    "click": "CLICK",
    "submit": "SUBMIT",
    "change": "CHANGE",
    "input": "INPUT",
    "keydown": "KEYDOWN",
}


def norm_attr(name):
    """@click / x-on:click / :click -> click；其余原样。"""
    if name.startswith("@"):
        return name[1:]
    if name.startswith("x-on:"):
        return name[5:]
    return name


class Auditor(HTMLParser):
    """扫一遍 HTML，把可交互元素连同它所属的 SPA 页面一起收集起来。

    实现要点（踩过的坑）：
    - **void 元素必须当场结算**。`<input>` / `<img>` 没有 endtag，如果把状态
      挂在 `self._pending` 上等 endtag 回收，它会被下一个元素的 starttag 直接
      冲掉 —— 52 个 input 只捞回 1 个就是这么丢的。
    - **文本要归属到栈顶帧**，不能挂在一个全局 pending 上。按钮里的 <span>、
      <i> 都会触发 starttag，用全局 pending 一样会被冲掉。
    - 页面是**平铺的兄弟 div**（靠 x-show 逐个显隐），不是嵌套的，所以归属
      只能靠"当前元素最深祖先声明的 currentNav"来判断。
    """

    # HTML void 元素：没有 endtag，不能进栈
    VOID = {"input", "img", "br", "hr", "meta", "link", "source",
            "area", "base", "col", "embed", "param", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.items = []
        self.stack = []      # [(tag, page_or_None, line, item_or_None)]

    def _page_of(self):
        for frame in reversed(self.stack):
            if frame[1]:
                return frame[1]
        return "default"

    @staticmethod
    def _page_from_expr(expr):
        """从 x-show="currentNav === 'ports' && !loading" 里抠出页名。"""
        m = re.search(r"currentNav\s*===?\s*'([a-z0-9-]+)'", expr or "")
        return m.group(1) if m else None

    def _record(self, tag, ad, depth):
        is_role_btn = ad.get("role", "").lower() == "button"
        if tag not in INTERACTIVE_TAGS and not is_role_btn:
            return None
        it = {
            "tag": tag,
            "page": self._page_of(),
            "id": ad.get("id", ""),
            "type": ad.get("type", ""),
            "name": ad.get("name", ""),
            "x_model": ad.get("x-model", ""),
            "href": ad.get("href", ""),
            "cls": (ad.get("class", "") or "")[:60],
            "actions": {},
            "text": "",
            "line": depth,
            "disabled": "disabled" in ad,
        }
        for ev in ("click", "submit", "change", "input", "keydown"):
            if ev in ad:
                it["actions"][ATTR_ALIASES[ev]] = ad[ev]
        self.items.append(it)
        return it

    def handle_starttag(self, tag, attrs):
        ad = {}
        for k, v in attrs:
            ad[norm_attr(k)] = v if v is not None else ""

        page = self._page_from_expr(ad.get("x-show")) or self._page_from_expr(ad.get("show"))
        # 归属在入栈前算，否则本页 div 会把自己算进去
        it = self._record(tag, ad, self.getpos()[0])

        if tag in self.VOID:
            return
        # 栈帧记下这个标签是不是交互元素：文字只回填给"当前还开着的"那个，
        # 否则按钮 A 里的文字会被后面的按钮 B 抢走（实测出现过「清空历史」
        # 的文案串到信任IP 页的按钮上）。
        self.stack.append((tag, page, self.getpos()[0], it))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        """把可见文字回填给当前栈上最近的那个交互元素。"""
        if not data.strip():
            return
        for _tag, _page, _line, it in reversed(self.stack):
            if it is not None:
                if not it["text"]:
                    it["text"] = re.sub(r"\s+", " ", data).strip()[:60]
                return

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return


def audit_html(path):
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    a = Auditor()
    a.feed(src)
    a.close()
    return a.items


def describe(it):
    """给人看的一行描述。"""
    if it["tag"] == "input":
        kind = f"input[{it['type'] or 'text'}]"
    elif it["tag"] == "select":
        kind = "select"
    else:
        kind = it["tag"]
    label = it["text"] or it["x_model"] or it["id"] or it["name"] or it["href"] or "(无标签)"
    act = it["actions"].get("CLICK") or it["actions"].get("SUBMIT") or ""
    act = re.sub(r"\s+", " ", act).strip()
    if len(act) > 58:
        act = act[:55] + "…"
    return kind, label, act


def main():
    ap = argparse.ArgumentParser(description="抽取 Alpine 页面里所有可交互元素")
    ap.add_argument("--json", action="store_true", help="输出 JSON（供 e2e 对账）")
    ap.add_argument("--page", help="只看某个 SPA 页面")
    ap.add_argument("--portal", action="store_true", help="抽认证门户（login/portal）")
    ap.add_argument("--actions-only", action="store_true", help="只列带点击/提交行为的")
    args = ap.parse_args()

    targets = []
    if args.portal:
        targets = [
            ("login", os.path.join(ROOT, "backend/static/login.html")),
            ("portal", os.path.join(ROOT, "backend/static/portal.html")),
        ]
    else:
        targets = [("panel", os.path.join(ROOT, "frontend/index.html"))]

    result = {}
    for name, path in targets:
        if not os.path.exists(path):
            print(f"找不到文件: {path}", file=sys.stderr)
            continue
        items = audit_html(path)
        if args.actions_only:
            items = [i for i in items if i["actions"]]
        if args.page:
            items = [i for i in items if i["page"] == args.page]
        result[name] = items

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    total = 0
    for name, items in result.items():
        print("=" * 78)
        print(f"  {name}   可交互元素 {len(items)} 个")
        print("=" * 78)
        by_page = {}
        for it in items:
            by_page.setdefault(it["page"], []).append(it)
        for page in sorted(by_page, key=lambda p: (p != "default", p)):
            group = by_page[page]
            clicks = sum(1 for i in group if i["actions"].get("CLICK"))
            print(f"\n── 页面 [{page}]  {len(group)} 个（其中 {clicks} 个带点击行为）")
            for i in group:
                kind, label, act = describe(i)
                flags = []
                if i["disabled"]:
                    flags.append("disabled")
                if not act and i["x_model"]:
                    flags.append(f"x-model={i['x_model'][:28]}")
                suffix = ("  [" + ", ".join(flags) + "]") if flags else ""
                print(f"   L{i['line']:<5} {kind:<14} {label:<30} {act}{suffix}")
        total += len(items)

    print("\n" + "=" * 78)
    print(f"  合计 {total} 个可交互元素")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
