"""Local-only proxy regression tests; run after make on Linux."""
import concurrent.futures
import socket
import socketserver
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COUNTS = {}
REQUESTS = {}
LOCK = threading.Lock()
STALL = threading.Event()
RELEASE = threading.Event()
BINARY = bytes(range(256)) * 128


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = bytearray()
        while not request.endswith(b"\r\n\r\n"):
            data = self.request.recv(8192)
            if not data:
                return
            request.extend(data)
        first = request.split(b"\r\n", 1)[0]
        path = first.split()[1].decode()
        with LOCK:
            COUNTS[path] = COUNTS.get(path, 0) + 1
            REQUESTS[path] = bytes(request)
        body = BINARY
        headers = b""
        if path == "/stall":
            STALL.set()
            RELEASE.wait(5)
        elif path == "/short":
            self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            return
        elif path == "/negative":
            self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n")
            return
        elif path == "/no-length":
            self.request.sendall(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n" + body)
            return
        elif path == "/long-headers":
            headers = b"X-Padding: " + b"x" * 7000 + b"\r\n"
            headers *= 16
        elif path == "/large":
            body = BINARY * 4
        elif path.startswith("/evict/"):
            body = (path.encode() * 20000)[:90000]
        response = (b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(body)).encode()
                    + b"\r\n" + headers + b"Connection: close\r\n\r\n" + body)
        try:
            self.request.sendall(response)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def exchange(port, request):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(request)
        data = bytearray()
        while True:
            chunk = sock.recv(16384)
            if not chunk:
                return bytes(data)
            data.extend(chunk)


def main():
    origin = Server(("127.0.0.1", 0), Origin)
    origin_port = origin.server_address[1]
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    process = subprocess.Popen([str(ROOT / "proxy"), str(proxy_port)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def request(path, host="lab.example", origin_override=None):
        port = origin_port if origin_override is None else origin_override
        raw = (f"GET http://127.0.0.1:{port}{path} HTTP/1.1\r\n"
               f"Host: {host}\r\nUser-Agent: test\r\nConnection: keep-alive\r\n"
               "Proxy-Connection: keep-alive\r\nX-Test: preserved\r\n\r\n").encode()
        return exchange(proxy_port, raw)

    def body(response):
        return response.split(b"\r\n\r\n", 1)[1]

    try:
        for attempt in range(100):
            if process.poll() is not None:
                raise AssertionError("Proxy exited at startup")
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise AssertionError("Proxy did not start")

        assert body(request("/binary")) == BINARY
        forwarded = REQUESTS["/binary"]
        assert forwarded.startswith(b"GET /binary HTTP/1.0\r\n")
        for expected in (b"Host: lab.example\r\n", b"X-Test: preserved\r\n",
                         b"Connection: close\r\n", b"Proxy-Connection: close\r\n",
                         b"User-Agent: Mozilla/5.0"):
            assert expected in forwarded, expected
        assert b"keep-alive" not in forwarded
        assert body(request("/binary")) == BINARY
        assert COUNTS["/binary"] == 1
        request("/binary", host="other.example")
        assert COUNTS["/binary"] == 2
        print("PASS protocol, Host, forwarded headers, binary cache, Host isolation")

        for _ in range(2):
            assert body(request("/no-length")) == BINARY
            assert body(request("/short")) == b"0123456789"
            assert body(request("/large")) == BINARY * 4
            request("/negative")
        assert COUNTS["/no-length"] == 1
        assert COUNTS["/short"] == 2
        assert COUNTS["/large"] == 2
        assert COUNTS["/negative"] == 2
        long_response = request("/long-headers")
        assert body(long_response) == BINARY
        assert long_response.count(b"X-Padding:") == 16
        print("PASS EOF cache, truncated/invalid lengths, object limit, long headers")

        # Keep a port bound but not listening: connecting must fail without killing proxy.
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            response = request("/refused", origin_override=unused.getsockname()[1])
            assert response.startswith(b"HTTP/1.0 502")
        for bad in (b"GET\r\n\r\n", b"GET http://x/ HTTP/1.0 extra\r\n\r\n",
                    b"GET http://x:99999/ HTTP/1.0\r\n\r\n"):
            assert exchange(proxy_port, bad).startswith(b"HTTP/1.0 400")
        assert body(request("/still-alive")) == BINARY
        print("PASS refused origin and malformed requests leave proxy alive")

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            pending = pool.submit(request, "/stall")
            assert STALL.wait(2)
            assert body(request("/concurrent")) == BINARY
            RELEASE.set()
            assert body(pending.result(timeout=4)) == BINARY
            results = list(pool.map(lambda _: body(request("/binary")), range(64)))
            assert all(value == BINARY for value in results)
        print("PASS stalled origin and concurrent cache hits")

        # Fill cache, refresh entry 0, then force eviction. Entry 1 must be oldest.
        for i in range(11):
            request(f"/evict/{i}")
        request("/evict/0")
        assert COUNTS["/evict/0"] == 1
        request("/evict/11")
        request("/evict/0")
        assert COUNTS["/evict/0"] == 1
        request("/evict/1")
        assert COUNTS["/evict/1"] == 2
        assert process.poll() is None
        print("PASS cache capacity and LRU eviction")
        print("All proxy regression tests passed.")
    finally:
        RELEASE.set()
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        origin.shutdown()
        origin.server_close()


if __name__ == "__main__":
    main()
