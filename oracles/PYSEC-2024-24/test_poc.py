import asyncio
import pathlib
import socket
import tempfile
import threading
import time

import pytest
from aiohttp import web


def get_free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class AiohttpStaticServer:
    def __init__(self, static_root: pathlib.Path, follow_symlinks: bool):
        self.static_root = static_root
        self.follow_symlinks = follow_symlinks
        self.port = get_free_port()
        self.loop = asyncio.new_event_loop()
        self.thread = None
        self.runner = None

    async def _start(self):
        app = web.Application()
        app.router.add_static(
            "/static/",
            path=str(self.static_root),
            follow_symlinks=self.follow_symlinks,
            show_index=False,
        )
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", self.port)
        await site.start()

    def start(self):
        def run_loop():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._start())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()
        time.sleep(0.5)

    def stop(self):
        async def cleanup():
            if self.runner:
                await self.runner.cleanup()

        self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=2)


def raw_http_get(port: int, path: str) -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def test_static_route_must_not_read_file_outside_root():
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        static_root = base / "static"
        static_root.mkdir()

        public_file = static_root / "public.txt"
        public_file.write_text("public-data", encoding="utf-8")

        secret_file = base / "secret.txt"
        secret_file.write_text("PYSEC_SECRET_SHOULD_NOT_LEAK", encoding="utf-8")

        server = AiohttpStaticServer(static_root, follow_symlinks=True)
        server.start()

        try:
            response = raw_http_get(server.port, "/static/../secret.txt")
            assert b"PYSEC_SECRET_SHOULD_NOT_LEAK" not in response, response
            assert not response.startswith(b"HTTP/1.1 200"), response
        finally:
            server.stop()