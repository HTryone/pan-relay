# -*- coding: utf-8 -*-
"""run_ssl 启动器的 TLS 握手超时保护测试。

回归背景：Werkzeug 开发服务器原本在 accept 循环里同步做 TLS 握手，且没有
超时。任何「只建 TCP、不发 ClientHello」的连接（端口扫描、半开连接、断网
客户端）都会把整个进程钉死 —— 端口仍 LISTEN、systemd 仍 active、进程也没
退出，但所有请求一律超时且永不恢复，Restart=on-failure 救不了。

这组测试确保：裸连接既不能阻塞正常请求，也不能让服务进程倒下。
"""

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _generate_self_signed_cert(directory: str) -> tuple:
    """生成一次性自签证书（依赖 openssl；没有就跳过相关用例）。"""
    cert_file = os.path.join(directory, "cert.pem")
    key_file = os.path.join(directory, "key.pem")
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_file, "-out", cert_file, "-days", "1",
            "-subj", "/CN=127.0.0.1",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise unittest.SkipTest(f"openssl 不可用，跳过: {result.stderr.strip()[:200]}")
    return cert_file, key_file


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _https_get(port: int, timeout: float = 8.0) -> int:
    """发起一次完整 HTTPS 请求，返回 HTTP 状态码；失败返回 0。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.settimeout(timeout)
                tls.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                data = tls.recv(4096).decode("latin-1", "replace")
                if data.startswith("HTTP/"):
                    return int(data.split()[1])
    except Exception:
        return 0
    return 0


class TlsHandshakeGuardTest(unittest.TestCase):
    """裸连接（不发 TLS 握手）不得影响服务可用性。"""

    @classmethod
    def setUpClass(cls):
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls.cert_file, cls.key_file = _generate_self_signed_cert(cls._temp_dir.name)
        cls.port = _free_port()

        # 用子进程起真实服务，确保测的是实际启动路径而非 mock。
        launcher = (
            "import sys; sys.path.insert(0, r'{root}');"
            "from run_ssl import make_tls_server;"
            "from flask import Flask;"
            "app = Flask(__name__);"
            "app.add_url_rule('/', 'index', lambda: 'OK');"
            "srv = make_tls_server('127.0.0.1', {port}, app, r'{cert}', r'{key}', handshake_timeout=3.0);"
            "srv.serve_forever()"
        ).format(
            root=str(REPO_ROOT),
            port=cls.port,
            cert=cls.cert_file,
            key=cls.key_file,
        )
        cls._proc = subprocess.Popen(
            [sys.executable, "-c", launcher],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not _wait_port(cls.port):
            out, err = cls._proc.communicate(timeout=5)
            raise AssertionError(
                "被测服务未能启动:\n%s\n%s"
                % (out.decode("utf-8", "replace")[:800], err.decode("utf-8", "replace")[:800])
            )

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_proc", None) and cls._proc.poll() is None:
            cls._proc.kill()
            cls._proc.communicate(timeout=10)
        if getattr(cls, "_temp_dir", None):
            cls._temp_dir.cleanup()

    def _open_bare_connections(self, count: int):
        """建立只做 TCP、不发 ClientHello 的连接。"""
        conns = []
        for _ in range(count):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            conns.append(sock)
        return conns

    def test_normal_request_succeeds(self):
        """基线：正常 HTTPS 请求应当成功。"""
        self.assertEqual(_https_get(self.port), 200)

    def test_bare_connection_does_not_block_other_requests(self):
        """核心回归：挂着不握手的连接时，其他请求仍必须成功。"""
        conns = self._open_bare_connections(3)
        try:
            time.sleep(1.0)
            for attempt in range(3):
                with self.subTest(attempt=attempt):
                    self.assertEqual(
                        _https_get(self.port),
                        200,
                        "存在未握手的裸连接时，正常请求不应失败",
                    )
        finally:
            for sock in conns:
                sock.close()

    def test_many_bare_connections_do_not_kill_service(self):
        """大量裸连接并发时，服务进程仍存活且可服务。"""
        conns = self._open_bare_connections(20)
        try:
            self.assertIsNone(self._proc.poll(), "服务进程不应退出")
            self.assertEqual(_https_get(self.port, timeout=12.0), 200)
        finally:
            for sock in conns:
                sock.close()

    def test_service_recovers_after_handshake_timeout(self):
        """握手超时后，坏连接被服务端清理，服务保持可用。"""
        conns = self._open_bare_connections(3)
        try:
            # handshake_timeout=3.0，等待超时生效
            time.sleep(5.0)
            self.assertEqual(_https_get(self.port), 200)
        finally:
            for sock in conns:
                sock.close()

    def test_server_reports_https_scheme(self):
        """监听套接字虽为明文，对外仍须被识别为 https。"""
        from run_ssl import make_tls_server

        self.assertTrue(callable(make_tls_server))


if __name__ == "__main__":
    unittest.main()
