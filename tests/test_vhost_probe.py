import importlib
import io
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


def probe_vhost(*args, **kwargs):
    return importlib.import_module("vhost_probe").probe_vhost(*args, **kwargs)


def test_http_probe_pins_connection_and_uses_candidate_host_without_redirect():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Host")))
            self.send_response(302)
            self.send_header("Location", "https://outside.example/secret")
            self.send_header("X-Probe", "one")
            self.end_headers()
            self.wfile.write(b"abcdefghij")

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = probe_vhost(
            "127.0.0.1", server.server_port, "gateway.example",
            "/vpn/index.html", scheme="http", max_body=4,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert requests == [("/vpn/index.html", "gateway.example")]
    assert result["status"] == 302
    assert result["headers"]["location"] == "https://outside.example/secret"
    assert result["headers"]["x-probe"] == "one"
    assert result["body"] == "abcd"
    assert result["truncated"] is True
    assert result["error"] is None


def test_https_probe_uses_candidate_sni_but_connects_to_pinned_ip(monkeypatch):
    calls = []

    class FakeSocket:
        def sendall(self, data):
            calls.append(("request", data))

        def makefile(self, _mode):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nX-NS-Version: NS14.1: Build 73.37\r\n"
                              b"Content-Length: 2\r\n\r\nOK")

        def close(self):
            pass

    class FakeContext:
        def wrap_socket(self, raw_socket, *, server_hostname):
            calls.append(("sni", server_hostname))
            return raw_socket

    def connect(address, timeout):
        calls.append(("connect", address, timeout))
        return FakeSocket()

    monkeypatch.setattr(socket, "create_connection", connect)
    result = probe_vhost(
        "192.0.2.44", 8443, "gateway.example", "/nitro/v1/config/nsversion",
        context=FakeContext(), timeout=3,
    )

    assert ("connect", ("192.0.2.44", 8443), 3) in calls
    assert ("sni", "gateway.example") in calls
    request_bytes = next(item[1] for item in calls if item[0] == "request")
    assert b"Host: gateway.example\r\n" in request_bytes
    assert result["status"] == 200
    assert result["headers"]["x-ns-version"] == "NS14.1: Build 73.37"
    assert result["body"] == "OK"


@pytest.mark.parametrize("hostname", [
    "https://gateway.example", "gateway.example/path", "gateway.example:443",
    "gateway.example\r\nX-Injected: yes", "*.example", "bad_name.example",
    "-bad.example", "bad-.example", "", "192.0.2.2",
])
def test_invalid_candidate_hostnames_are_rejected_before_network(monkeypatch, hostname):
    def reject_connection(*_args, **_kwargs):
        raise AssertionError("network request was attempted")

    monkeypatch.setattr(socket, "create_connection", reject_connection)
    with pytest.raises(ValueError):
        probe_vhost("192.0.2.44", 443, hostname)


@pytest.mark.parametrize("kwargs", [
    {"ip": "gateway.example"}, {"ip": 1}, {"port": 0}, {"port": True},
    {"path": "https://outside.example/"}, {"path": "//outside.example/"},
    {"path": "/ok\r\nX: bad"}, {"method": "POST"},
    {"scheme": "ftp"}, {"timeout": 0}, {"timeout": 60},
    {"max_body": -1}, {"max_body": 65537},
])
def test_invalid_probe_parameters_are_rejected_before_network(monkeypatch, kwargs):
    def reject_connection(*_args, **_kwargs):
        raise AssertionError("network request was attempted")

    monkeypatch.setattr(socket, "create_connection", reject_connection)
    args = dict(ip="192.0.2.44", port=443, hostname="gateway.example")
    args.update(kwargs)
    with pytest.raises(ValueError):
        probe_vhost(**args)


def test_head_probe_does_not_read_body(monkeypatch):
    class FakeSocket:
        def sendall(self, _data):
            pass

        def makefile(self, _mode):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")

        def close(self):
            pass

    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    result = probe_vhost("192.0.2.44", 80, "gateway.example", method="HEAD", scheme="http")
    assert result["status"] == 200
    assert result["body"] == ""
    assert result["truncated"] is False


def test_binary_response_keeps_only_bounded_bytes_for_gzip_fingerprinting(monkeypatch):
    gzip_header = b"\x1f\x8b\x08\x00\x01\x02\x03\x04\x00\x03"

    class FakeSocket:
        def sendall(self, _data):
            pass

        def makefile(self, _mode):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
                              + gzip_header + b"xy")

        def close(self):
            pass

    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    result = probe_vhost("192.0.2.44", 80, "gateway.example", scheme="http", max_body=8)
    assert result["data"] == gzip_header[:8]
    assert result["truncated"] is True
