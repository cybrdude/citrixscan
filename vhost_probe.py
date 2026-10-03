"""Bounded, single-request probes of an authorized IP:port virtual host.

The candidate hostname controls HTTP Host and HTTPS SNI. DNS resolution is
never used for the TCP destination, and redirects are returned without being
followed. Response content is untrusted data for the caller to assess.
"""

import http.client
import ipaddress
import math
import re
import socket
import ssl


_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_MAX_BODY = 65536
_MAX_TIMEOUT = 30


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, connect_ip, hostname, port, timeout):
        self._connect_ip = connect_ip
        super().__init__(hostname, port=port, timeout=timeout)

    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, connect_ip, hostname, port, timeout, context):
        self._connect_ip = connect_ip
        super().__init__(hostname, port=port, timeout=timeout, context=context)

    def connect(self):
        raw_socket = socket.create_connection((self._connect_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _validate_probe(ip, port, hostname, path, scheme, method, timeout, max_body):
    if not isinstance(ip, str):
        raise ValueError("ip must be a literal IPv4 or IPv6 address")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("ip must be a literal IPv4 or IPv6 address") from exc
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("scoped IPv6 addresses are unsupported")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    if not isinstance(hostname, str) or not 1 <= len(hostname) <= 253:
        raise ValueError("hostname must be a valid DNS name")
    if any(not _LABEL.fullmatch(label) for label in hostname.split(".")):
        raise ValueError("hostname must be a valid DNS name")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("hostname must be a DNS name, not an IP address")
    if (not isinstance(path, str) or not path.startswith("/") or
            path.startswith("//") or "#" in path or "\\" in path or
            any(ord(char) <= 32 or ord(char) >= 127 for char in path)):
        raise ValueError("path must be a safe origin-form ASCII path")
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    if method not in ("GET", "HEAD"):
        raise ValueError("method must be GET or HEAD")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or not 0 < timeout <= _MAX_TIMEOUT):
        raise ValueError("timeout must be greater than zero and at most 30 seconds")
    if (isinstance(max_body, bool) or not isinstance(max_body, int) or
            not 0 <= max_body <= _MAX_BODY):
        raise ValueError("max_body must be between 0 and 65536 bytes")
    return str(address)


def probe_vhost(ip, port, hostname, path="/", *, scheme="https", method="GET",
                timeout=5, max_body=8192, context=None):
    """Probe one authorized endpoint while keeping its TCP destination pinned.

    ``context`` may be a caller-supplied SSL context. When omitted, Python's
    normal certificate verification is used. Validation errors raise
    ``ValueError``; connection and HTTP failures appear in ``error``. The
    returned ``data`` contains at most ``max_body`` raw bytes for binary
    fingerprints; ``body`` is a UTF-8 replacement-decoded view of those bytes.
    Keep ``data`` in memory and exclude it from serialized scan reports.
    """
    connect_ip = _validate_probe(ip, port, hostname, path, scheme, method,
                                 timeout, max_body)
    result = {
        "ip": connect_ip,
        "port": port,
        "hostname": hostname,
        "scheme": scheme,
        "method": method,
        "path": path,
        "status": None,
        "headers": {},
        "data": b"",
        "body": "",
        "truncated": False,
        "error": None,
    }
    if scheme == "https":
        connection = _PinnedHTTPSConnection(
            connect_ip, hostname, port, timeout,
            context if context is not None else ssl.create_default_context(),
        )
    else:
        connection = _PinnedHTTPConnection(connect_ip, hostname, port, timeout)

    try:
        connection.request(method, path, headers={
            "Host": hostname,
            "User-Agent": "CitrixScan/1.0 (Security Assessment)",
            "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
        })
        response = connection.getresponse()
        result["status"] = response.status
        for name, value in response.getheaders():
            key = name.lower()
            if key in result["headers"]:
                result["headers"][key] += ", " + value
            else:
                result["headers"][key] = value
        if method == "GET":
            body = response.read(max_body + 1)
            result["truncated"] = len(body) > max_body
            result["data"] = body[:max_body]
            result["body"] = result["data"].decode("utf-8", errors="replace")
    except (OSError, http.client.HTTPException) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        connection.close()
    return result
