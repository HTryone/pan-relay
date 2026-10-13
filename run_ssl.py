# -*- coding: utf-8 -*-
"""pan-relay HTTPS 启动器（带 TLS 握手超时保护）。

用法:
    python run_ssl.py

环境变量:
    HOST                         监听地址，默认 0.0.0.0
    PORT                         监听端口，默认 5004
    PAN_RELAY_CERT_FILE          证书链路径
    PAN_RELAY_KEY_FILE           私钥路径
    PAN_RELAY_HANDSHAKE_TIMEOUT  TLS 握手超时秒数，默认 10

为什么需要这个启动器（而不是直接用 app.run(ssl_context=...)）:

    Werkzeug 自带的开发服务器会把监听套接字整体包成 SSL，并在 accept()
    里同步完成 TLS 握手。这个握手是**阻塞且没有超时**的。只要有人
    建立 TCP 连接后不发 ClientHello —— 端口扫描器、半开连接、断网掉线
    的客户端都会这样 —— 整个进程就会一直卡在那一次握手等待上。

    表现极具迷惑性：端口仍在 LISTEN、systemd 仍显示 active、进程也没退出，
    但所有请求一律超时，而且**永远不会自行恢复**。systemd 的
    Restart=on-failure 对此完全无效，因为进程自始至终没有退出。

    本启动器把握手从 accept 循环移入每个连接自己的处理线程，并加上超时:
    坏连接最多占用一个线程、到点即被丢弃，不再影响其他请求。
"""

import io
import os
import ssl

from werkzeug.serving import WSGIRequestHandler, make_server

DEFAULT_CERT_FILE = "/root/cert/us.315461.xyz/fullchain.pem"
DEFAULT_KEY_FILE = "/root/cert/us.315461.xyz/privkey.pem"
DEFAULT_HANDSHAKE_TIMEOUT = 10.0


class HandshakeTimeoutHandler(WSGIRequestHandler):
    """在连接线程内完成 TLS 握手，并施加超时。

    握手失败或超时的连接会被立即关闭，不影响监听套接字与其他请求。
    """

    ssl_context: ssl.SSLContext
    handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT

    def setup(self) -> None:
        self._tls_ok = False
        raw = self.request
        try:
            raw.settimeout(self.handshake_timeout)
            tls_sock = self.ssl_context.wrap_socket(
                raw, server_side=True, do_handshake_on_connect=False
            )
            tls_sock.do_handshake()
            tls_sock.settimeout(None)
            self.request = tls_sock
            self._tls_ok = True
        except Exception:
            # 握手失败（超时、非 TLS 数据、客户端中途断开等）：丢弃这条连接。
            try:
                raw.close()
            except Exception:
                pass
            # 补上基类 finish() 需要的属性，避免善后阶段二次报错。
            self.connection = raw
            self.rfile = io.BytesIO()
            self.wfile = io.BytesIO()
            return
        super().setup()

    def handle(self) -> None:
        if not getattr(self, "_tls_ok", False):
            return
        super().handle()


def make_tls_server(
    host,
    port,
    wsgi_app,
    cert_file,
    key_file,
    handshake_timeout=DEFAULT_HANDSHAKE_TIMEOUT,
):
    """构造一个对 TLS 握手加超时保护的 WSGI 服务器（多线程）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    timeout = float(handshake_timeout)

    class Handler(HandshakeTimeoutHandler):
        pass

    Handler.ssl_context = ctx
    Handler.handshake_timeout = timeout

    server = make_server(host, port, wsgi_app, threaded=True, request_handler=Handler)
    # 监听套接字保持明文（握手已在连接线程内完成），
    # 但要让框架知道对外是 https，否则 request.scheme 会退化成 http，
    # 影响 sitemap/robots 与 url_for(_external=True) 生成的绝对地址。
    server.ssl_context = ctx
    return server


def main():
    # 延迟导入：导入 run_ssl 本身不应触发应用初始化与后台调度器启动。
    from app import app

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5004"))
    cert_file = os.getenv("PAN_RELAY_CERT_FILE", DEFAULT_CERT_FILE)
    key_file = os.getenv("PAN_RELAY_KEY_FILE", DEFAULT_KEY_FILE)
    timeout = float(os.getenv("PAN_RELAY_HANDSHAKE_TIMEOUT", str(DEFAULT_HANDSHAKE_TIMEOUT)))

    server = make_tls_server(host, port, app, cert_file, key_file, timeout)
    server.serve_forever()


if __name__ == "__main__":
    main()
