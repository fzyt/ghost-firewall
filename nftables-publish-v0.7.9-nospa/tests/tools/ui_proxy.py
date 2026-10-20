#!/usr/bin/env python3
"""本地 HTTP → 面板 HTTPS 的转发代理（给 Firefox headless 用）。

为什么需要
----------
面板是自签证书的 HTTPS。Firefox 的 Marionette 虽然支持 acceptInsecureCerts，
但它在 checkReadyState 阶段对**已缓存的证书错误**不生效，报 'insecure certificate'。

而面板的 session cookie 带 `Secure` 标志（backend/app.py:84，
SESSION_COOKIE_SECURE = True），走明文 HTTP 的话浏览器根本不存 —— 直接点页面就废了。

所以：**本地起一个明文 HTTP 代理**，转发到面板的 HTTPS（校验关掉），
并把响应里的 `Secure` 从 Set-Cookie 上剥掉。
浏览器看到的是 http://127.0.0.1:15443 → 纯 HTTP，没有证书问题。

安全性说明：只监听 127.0.0.1，仅供本机 headless 浏览器测试用，
不改变面板本身的任何行为（代理不做任何认证/授权判断）。
"""
import http.client
import os
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_HOST = os.environ.get('NFTWEB_TEST_UPSTREAM_HOST', '192.168.100.218')
UPSTREAM_PORT = int(os.environ.get('NFTWEB_TEST_UPSTREAM_PORT', '5443'))
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = int(os.environ.get('NFTWEB_TEST_PROXY_PORT', '15443'))

CTX = ssl._create_unverified_context()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        pass

    def _proxy(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else None

        conn = http.client.HTTPSConnection(
            UPSTREAM_HOST, UPSTREAM_PORT, context=CTX, timeout=60)
        hdrs = {k: v for k, v in self.headers.items()
                if k.lower() not in ('host', 'content-length', 'connection')}
        # 保留原始 Host，面板据此生成绝对 URL
        hdrs['Host'] = f'{UPSTREAM_HOST}:{UPSTREAM_PORT}'
        if body is not None:
            hdrs['Content-Length'] = str(len(body))
        conn.request(self.command, self.path, body=body, headers=hdrs)
        resp = conn.getresponse()

        data = resp.read()
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in ('transfer-encoding', 'connection', 'content-length'):
                continue
            if k.lower() == 'set-cookie':
                # 剥掉 Secure —— 明文 HTTP 下浏览器不存 Secure cookie
                v = v.replace('; Secure', ';').replace('; secure', ';')
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _proxy


def serve():
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == '__main__':
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    print(f'proxy on http://{LISTEN_HOST}:{LISTEN_PORT} -> '
          f'https://{UPSTREAM_HOST}:{UPSTREAM_PORT}', flush=True)
    try:
        t.join()
    except KeyboardInterrupt:
        pass
