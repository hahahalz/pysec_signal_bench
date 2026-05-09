import asyncio
import socket
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


class AiohttpEchoServer:
    def __init__(self):
        self.port = get_free_port()
        self.loop = asyncio.new_event_loop()
        self.thread = None
        self.runner = None

    async def _handler(self, request):
        data = await request.read()
        return web.Response(text=f"OK:{len(data)}")

    async def _start(self):
        app = web.Application()
        app.router.add_route("*", "/", self._handler)
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
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=2)


def send_raw(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(request)
        chunks = []
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
        except socket.timeout:
            pass
        return b"".join(chunks)


def test_invalid_transfer_encoding_with_content_length_is_rejected():
    server = AiohttpEchoServer()
    server.start()

    try:
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 4\r\n"
            b"Transfer-Encoding: chunked123\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"0\r\n"
            b"\r\n"
        )

        response = send_raw(server.port, raw)

        assert b"400" in response.split(b"\r\n", 1)[0], response
        assert b"OK:" not in response, response
    finally:
        server.stop()