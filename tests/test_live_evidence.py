import json
import sys
import urllib.request
from contextlib import nullcontext

import citrixscan


def test_ipv6_http_urls_are_bracketed_and_literal_skips_ipv4_dns(monkeypatch):
    requested = []

    class Response:
        status = 200
        headers = {}

        def read(self, _limit):
            return b"ok"

        def geturl(self):
            return "http://[2001:db8::10]:8080/vpn/index.html"

    class Opener:
        def open(self, request, timeout):
            requested.append(request.full_url)
            return Response()

    monkeypatch.setattr(citrixscan.urllib.request, "build_opener",
                        lambda *_handlers: Opener())
    response = citrixscan.http_get("2001:db8::10", 8080, "/vpn/index.html",
                                   None, 1, scheme="http")
    binary = citrixscan.http_get_binary("2001:db8::10", 8080,
                                        "/vpn/index.html", None, 1,
                                        scheme="http")
    assert response["status"] == binary["status"] == 200
    assert requested == ["http://[2001:db8::10]:8080/vpn/index.html"] * 2

    monkeypatch.setattr(citrixscan.socket, "gethostbyname",
                        lambda _host: (_ for _ in ()).throw(AssertionError("IPv4 DNS used")))
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(citrixscan, "http_get", lambda *_args, **_kwargs: None)
    scanned = citrixscan.scan_target("2001:db8::10", port=8080,
                                     modules="cve", deep_scan=False,
                                     scheme="http")
    assert scanned.ip == "2001:db8::10"
    assert scanned.reachable is True


def test_http_transport_stays_on_same_ip_port_and_scheme(monkeypatch):
    requests = []
    installed = []

    class Response:
        status = 200
        headers = {"Server": "Apache"}

        def read(self, _limit):
            return b"ok"

        def geturl(self):
            return "http://192.0.2.10:8080/vpn/index.html"

    class Opener:
        def open(self, request, timeout):
            requests.append(request.full_url)
            return Response()

    def opener(*handlers):
        installed.extend(handlers)
        return Opener()

    monkeypatch.setattr(citrixscan.urllib.request, "build_opener", opener)
    response = citrixscan.http_get("192.0.2.10", 8080, "/vpn/index.html",
                                   None, 1, scheme="http")
    assert response["status"] == 200
    assert requests == ["http://192.0.2.10:8080/vpn/index.html"]
    assert any(isinstance(handler, urllib.request.ProxyHandler) and
               handler.proxies == {} for handler in installed)

    request = urllib.request.Request(requests[0])
    handler = citrixscan.TargetRedirectHandler()
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "http://192.0.2.11:8080/"
    ) is None
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "https://192.0.2.10:8080/"
    ) is None
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "/login"
    ).full_url == "http://192.0.2.10:8080/login"


def test_live_product_ignores_reflected_paths_and_generic_citrix_mentions():
    reflected = [{"status": 200, "headers": {"Server": "Apache"},
                  "body": "Unknown path /vpn/js/ and /cgi/login. See Citrix docs."}]
    assert citrixscan.detect_live_product(reflected, {}) is False
    native = [{"status": 200, "headers": {"Set-Cookie": "NSC_AAAC=abc"},
               "body": ""}]
    assert citrixscan.detect_live_product(native, {}) is True


def test_nitro_version_requires_expected_json_field():
    arbitrary = {"status": 200, "headers": {},
                 "body": '{"message": "old NS14.1: Build 29.72 in a log"}'}
    assert citrixscan.extract_nitro_version(arbitrary, nitro_path=True) is None
    actual = {"status": 200, "headers": {},
              "body": '{"errorcode":0,"nsversion":[{"version":"NetScaler NS14.1: Build 29.72.nc"}]}'}
    assert citrixscan.extract_nitro_version(actual, nitro_path=True) == (
        "NetScaler NS14.1: Build 29.72.nc"
    )
    denied = {"status": 401, "headers": {},
              "body": '{"errorcode":401,"nsversion":[{"version":"NetScaler NS14.1: Build 29.72.nc"}]}'}
    assert citrixscan.extract_nitro_version(denied, nitro_path=True) is None


def test_redirected_nitro_json_cannot_supply_high_confidence_build(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    response = {
        "status": 200, "headers": {},
        "body": '{"errorcode":0,"nsversion":[{"version":"NS14.1: Build 73.37"}]}',
        "url": "https://192.0.2.10:443/nitro/v1/config/nsversion",
        "final_url": "https://192.0.2.10:443/other.json",
    }
    evidence = []
    raw, _source, confidence, _diagnostic = citrixscan.extract_version(
        [], [response], {"/nitro/v1/config/nsversion": response}, None,
        "192.0.2.10", 443, 1, allow_epa_download=False,
        evidence_out=evidence,
    )
    assert raw == ""
    assert confidence == ""
    assert not any(item["confidence"] == "HIGH" for item in evidence)


def test_conflicting_live_builds_suppress_verdict(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    responses = [
        {"status": 200, "headers": {"x-ns-version": "NS14.1: Build 73.37"},
         "body": "", "url": "https://192.0.2.10/"},
        {"status": 200, "headers": {}, "body": "NetScaler NS14.1: Build 29.72",
         "url": "https://192.0.2.10/vpn/index.html"},
    ]
    evidence = []
    raw, source, confidence, diagnostic = citrixscan.extract_version(
        responses, [], {}, None, "192.0.2.10", 443, 1,
        allow_epa_download=False, evidence_out=evidence
    )
    assert (raw, source, confidence) == ("", "", "")
    assert "conflict" in diagnostic.lower()
    assert {x["version"] for x in evidence} == {"14.1-73.37", "14.1-29.72"}


def test_lowercase_header_can_supply_build(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    responses = [{"status": 200,
                  "headers": {"x-ns-version": "NS14.1: Build 73.37"},
                  "body": ""}]
    raw, source, confidence, _diagnostic = citrixscan.extract_version(
        responses, [], {}, None, "192.0.2.10", 443, 1,
        allow_epa_download=False
    )
    assert raw == "NS14.1: Build 73.37"
    assert source == "HTTP header (x-ns-version)"
    assert confidence == "MEDIUM"


def test_server_header_build_remains_medium_confidence(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    responses = [{"status": 200, "headers": {"Server": "NetScaler NS14.1: Build 73.37"},
                  "body": ""}]
    raw, _source, confidence, _diagnostic = citrixscan.extract_version(
        responses, [], {}, None, "192.0.2.10", 443, 1,
        allow_epa_download=False
    )
    assert raw == "NS14.1: Build 73.37"
    assert confidence == "MEDIUM"


def test_same_numeric_build_with_disagreeing_editions_is_conflict(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    responses = [
        {"status": 200, "headers": {"X-NS-version": "NS13.1: Build 37.279 FIPS"},
         "body": ""},
        {"status": 200, "headers": {"Server": "NetScaler NS13.1: Build 37.279"},
         "body": ""},
    ]
    raw, _source, _confidence, diagnostic = citrixscan.extract_version(
        responses, [], {}, None, "192.0.2.10", 443, 1,
        allow_epa_download=False
    )
    assert raw == ""
    assert "conflict" in diagnostic.lower()


def test_invalid_gzip_header_does_not_identify_build(monkeypatch):
    stamp = next(iter(citrixscan.RDX_EN_STAMP_TO_VERSION))
    invalid = b"\x1f\x8b\x00\x00" + stamp.to_bytes(4, "little") + b"\x00" * 12
    monkeypatch.setattr(citrixscan, "http_get_binary",
                        lambda *_a, **_k: {"status": 200, "data": invalid})
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    raw, _source, _confidence, _diagnostic = citrixscan.extract_version(
        [], [], {}, None, "192.0.2.10", 443, 1,
        allow_epa_download=False
    )
    assert raw == ""


def test_http_scan_skips_tls_and_reports_no_native_product(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info",
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("TLS attempted")))

    def response(_host, _port, path, _ctx, _timeout, **kwargs):
        assert kwargs["scheme"] == "http"
        return {"status": 200, "headers": {"Server": "Apache"},
                "body": f"Unknown path {path}; see Citrix docs", "url": path}

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", port=8080, modules="cve",
                                    deep_scan=False, scheme="http")
    assert result.reachable is True
    assert result.http_scheme == "http"
    assert result.is_netscaler is False
    assert result.version_parsed is None


def test_live_shodan_export_uses_auto_transport_for_tls_and_plain_http_records(tmp_path, monkeypatch):
    export = tmp_path / "shodan.jsonl"
    export.write_text("\n".join(json.dumps(item) for item in [
        {"ip_str": "192.0.2.10", "port": 8080, "http": {}},
        {"ip_str": "192.0.2.11", "port": 8443, "ssl": {}, "http": {}},
    ]), encoding="utf-8")
    targets = citrixscan.load_live_shodan_targets(export)
    assert targets == [("192.0.2.10", 8080, "auto"),
                       ("192.0.2.11", 8443, "auto")]


def test_auto_scheme_falls_back_to_http_after_tls_failure(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_a, **_k: {
        "protocol": "", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    schemes = []

    def response(_host, _port, _path, _ctx, _timeout, **kwargs):
        schemes.append(kwargs.get("scheme"))
        return {"status": 404, "headers": {}, "body": "", "url": ""}

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", port=8080, modules="cve",
                                    scheme="auto")
    assert result.http_scheme == "http"
    assert schemes and set(schemes) == {"http"}


def test_live_shodan_cli_scans_only_record_ips_and_ports(tmp_path, monkeypatch):
    export = tmp_path / "services.jsonl"
    export.write_text("\n".join(json.dumps(item) for item in [
        {"ip_str": "192.0.2.10", "port": 8080, "http": {},
         "hostnames": ["other.example"], "data": "HTTP/1.1 200 OK"},
        {"ip_str": "192.0.2.11", "port": 8443, "ssl": {}, "http": {}},
    ]), encoding="utf-8")
    output = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "--live-shodan-export",
                                      str(export), "--modules", "cve", "-o",
                                      str(output)])
    calls = []

    def scanned(*args):
        calls.append(args)
        return citrixscan.ScanResult(target=args[0], ip=args[0], port=args[1],
                                     timestamp="2026-10-03T00:00:00Z")

    monkeypatch.setattr(citrixscan, "scan_target", scanned)
    assert citrixscan.main() == 0
    assert {(args[0], args[1], args[6] if len(args) > 6 else "https")
            for args in calls} == {
                ("192.0.2.10", 8080, "auto"),
                ("192.0.2.11", 8443, "auto"),
            }
    assert len(json.loads(output.read_text(encoding="utf-8"))["results"]) == 2


def test_stock_asset_token_uses_all_corpus_candidates(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_a, **_k: None)
    token = "a" * 32
    corpus = {"schema_version": 1, "fingerprints": {
        "vpn_index_v": {token: [
            {"build": "14.1-73.37", "package_sha256": "1" * 64},
            {"build": "14.1-29.72", "package_sha256": "2" * 64},
        ]},
        "rdx_en_gzip_mtime": {},
    }}
    responses = [{"status": 200, "headers": {},
                  "body": f'<html><title>Citrix Gateway</title><script src="/vpn/a.js?v={token}"></script></html>',
                  "url": "https://192.0.2.10/vpn/index.html"}]
    raw, _source, _confidence, diagnostic = citrixscan.extract_version(
        responses, [], {"/vpn/index.html": responses[0]}, None,
        "192.0.2.10", 443, 1, allow_epa_download=False, corpus=corpus
    )
    assert raw == ""
    assert "conflict" in diagnostic.lower()


def test_repeated_cross_host_content_is_reported_without_erasing_evidence():
    results = [
        citrixscan.ScanResult(target=f"192.0.2.{index}", ip=f"192.0.2.{index}",
                              port=8080, timestamp="2026-10-03T00:00:00Z",
                              is_netscaler=True,
                              response_hashes={"/vpn/index.html": "a" * 64,
                                               "/nitro/v1/config/nsversion": "b" * 64})
        for index in range(1, 4)
    ]
    citrixscan.mark_repeated_content(results)
    assert all(result.shared_response_hosts == 3 for result in results)
    assert all(any("identical" in note.lower() for note in result.recommendations)
               for result in results)


def test_repeated_cross_host_content_annotates_cve_claim():
    results = [
        citrixscan.ScanResult(target=f"192.0.2.{index}", ip=f"192.0.2.{index}",
                              port=8080, timestamp="2026-10-03T00:00:00Z",
                              is_netscaler=True, version_raw="NS14.1: Build 38.53",
                              version_parsed=(14, 1, 38, 53),
                              version_confidence="HIGH",
                              version_evidence=[{"version": "14.1-38.53"}],
                              response_hashes={"/vpn/index.html": "a" * 64,
                                               "/nitro/v1/config/nsversion": "b" * 64},
                              cve_results=[{"cve_id": "CVE-2026-88771", "vulnerable": True}],
                              total_vulns=1, critical_cves=1,
                              risk_rating="CRITICAL")
        for index in range(1, 4)
    ]
    citrixscan.mark_repeated_content(results)
    assert all(result.version_evidence for result in results)
    assert all(result.cve_results for result in results)
    assert all(result.risk_rating == "CRITICAL" for result in results)
    assert all(result.shared_response_hosts == 3 for result in results)
    assert all(any("identical" in note.lower() for note in result.recommendations)
               for result in results)


def test_body_only_build_is_a_candidate_not_a_cve_verdict(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_a, **_k: {
        "protocol": "TLSv1.3", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)

    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/index.html":
            return {"status": 200, "headers": {"Server": "NetScaler"},
                    "body": "NetScaler NS14.1: Build 29.72", "url": path}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", modules="cve", deep_scan=False)
    assert result.version_display == "14.1-29.72"
    assert result.version_confidence == "MEDIUM"
    assert result.cve_results == []
    assert "CVE-2026-88771" in result.unassessed_cves


def test_unknown_live_netscaler_marks_latest_cve_unassessed(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_a, **_k: {
        "protocol": "TLSv1.3", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)

    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/index.html":
            return {"status": 200, "headers": {"Server": "NetScaler"},
                    "body": "<html><title>Citrix Gateway</title></html>", "url": path}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", modules="cve", deep_scan=False)
    assert result.is_netscaler is True
    assert result.version_parsed is None
    assert "CVE-2026-88771" in result.unassessed_cves


def test_conflicting_live_builds_mark_latest_cve_unassessed(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_a, **_k: {
        "protocol": "TLSv1.3", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_a, **_k: None)

    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/index.html":
            return {"status": 200, "headers": {"Server": "NetScaler"},
                    "body": "<html><title>Citrix Gateway</title>NS14.1: Build 29.72</html>",
                    "url": path}
        if path == "/nitro/v1/config/nsversion":
            return {"status": 200, "headers": {},
                    "body": '{"errorcode":0,"nsversion":[{"version":"NS14.1: Build 73.37"}]}',
                    "url": path}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", modules="cve", deep_scan=False)
    assert result.is_netscaler is True
    assert result.version_parsed is None
    assert {item["version"] for item in result.version_evidence} == {
        "14.1-29.72", "14.1-73.37"}
    assert "CVE-2026-88771" in result.unassessed_cves


def test_tls_info_uses_der_cert_when_unverified_cert_dict_is_empty(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, binary_form=False):
            return b"DER" if binary_form else {}

    class Context:
        def wrap_socket(self, _socket, server_hostname):
            assert server_hostname == "192.0.2.10"
            return Connection()

    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_a, **_k: Connection())
    monkeypatch.setattr(citrixscan, "decode_der_certificate", lambda der: {
        "subject": ((('commonName', 'gateway.example'),),),
        "subjectAltName": (("DNS", "gateway.example"),),
        "issuer": ((('organizationName', 'Example CA'),),),
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    } if der == b"DER" else {})
    info = citrixscan.get_tls_info("192.0.2.10", 443, Context())
    assert info["cn"] == "gateway.example"
    assert info["san"] == "DNS:gateway.example"
