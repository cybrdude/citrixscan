import json
import csv
import sys
import urllib.request
from contextlib import nullcontext

import pytest

import citrixscan
from citrixscan import ScanResult


def result(**kwargs):
    fields = {"target": "adc.example", "ip": "192.0.2.1", "port": 443,
              "timestamp": "2026-10-02T00:00:00Z", "reachable": True,
              "is_netscaler": True, "risk_rating": "LOW"}
    fields.update(kwargs)
    return ScanResult(**fields)


@pytest.mark.parametrize(("config", "status"), [
    ("add authentication samlAction idp -samlIdPCertName cert\n"
     "add vpn vserver gateway SSL 192.0.2.1 443\n", "configuration_match"),
    ("add authentication samlIdPProfile idp\n"
     "add authentication vserver aaa SSL 192.0.2.1 443\n", "configuration_match"),
    ("add authentication samlAction idp\n", "saml_configuration_only"),
    ("# add authentication samlAction old\nadd vpn vserver gateway SSL 192.0.2.1 443\n",
     "no_pattern_found"),
])
def test_saml_config_screening(config, status):
    review = citrixscan.review_saml_config(config)
    assert review["status"] == status
    assert "samlIdPCertName" not in str(review)


def test_uncertain_edition_does_not_become_confirmed_cve():
    cve = next(c for c in citrixscan.CVE_DATABASE if c.cve_id == "CVE-2026-88771")
    finding = citrixscan.check_cve_applicability(
        (13, 1, 37, 279), {}, cve, version_raw="13.1-37.279"
    )
    assert finding["edition_unconfirmed"] is True
    assert finding["vulnerable"] is False
    assert finding["possible_vulnerability"] is True


def test_fail_on_risk_and_incomplete_scan_exit_codes():
    assert citrixscan.determine_exit_code([result()], [], "high", False) == 0
    assert citrixscan.determine_exit_code([result(risk_rating="HIGH")], [], "high", False) == 2
    assert citrixscan.determine_exit_code([result(risk_rating="HIGH")], [], "critical", False) == 0
    assert citrixscan.determine_exit_code([result(saml_advisory_status="configuration_match")],
                                          [], None, True) == 2
    assert citrixscan.determine_exit_code([result(errors=["TCP unreachable"])], [], None, False) == 3
    assert citrixscan.determine_exit_code([], ["adc.example"], None, False) == 3
    assert citrixscan.determine_exit_code(
        [result(risk_rating="CRITICAL")], ["broken.example"], "high", False
    ) == 4
    assert citrixscan.determine_exit_code(
        [result(errors=["TCP unreachable"], saml_advisory_status="configuration_match")],
        [], None, True
    ) == 4
    assert citrixscan.determine_exit_code(
        [], ["adc.example"], None, True,
        {"status": "configuration_match", "signals": ["samlAction", "Gateway vserver"]}
    ) == 4


def test_json_report_exposes_advisory_and_actual_modules(tmp_path):
    path = tmp_path / "report.json"
    citrixscan.export_json([result(saml_advisory_status="configuration_match")],
                           str(path), modules="cve", failed_targets=["broken.example"],
                           requested_targets=2)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["scan_metadata"]["modules"] == "cve"
    assert report["scan_metadata"]["requested_targets"] == 2
    assert report["summary"]["failed_targets"] == 1
    assert report["security_notice"]["id"] == "CITRIX-SAML-2026-10-02"
    assert report["results"][0]["saml_advisory_status"] == "configuration_match"


def test_no_deep_skips_epa_binary_download(monkeypatch):
    calls = []

    def get(_host, _port, _path, _ctx, _timeout, **kwargs):
        if kwargs.get("method") == "HEAD":
            return {"status": 200, "headers": {"Content-Length": "20000"}, "body": ""}
        return None

    def get_binary(_host, _port, path, _ctx, _timeout, **_kwargs):
        calls.append(path)
        return None

    monkeypatch.setattr(citrixscan, "http_get", get)
    monkeypatch.setattr(citrixscan, "http_get_binary", get_binary)
    citrixscan.extract_version([], [], {}, None, "adc.example", 443, 1,
                               allow_epa_download=False)
    assert not any(path in citrixscan.EPA_PATHS for path in calls)


def test_ioc_stock_alias_and_php_variable_detection(monkeypatch):
    def stock_get(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/../vpns/portal/scripts/newbm.pl":
            return {"status": 200, "body": "NetScaler bookmark manager stock script",
                    "headers": {}, "url": f"https://adc.example:443{path}"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", stock_get)
    assert citrixscan.check_iocs("adc.example", 443, None, 1) == []

    def shell_get(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/js/cmd.php":
            return {"status": 200, "body": "<?php echo $_GET['cmd']; ?>",
                    "headers": {}, "url": f"https://adc.example:443{path}"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", shell_get)
    findings = citrixscan.check_iocs("adc.example", 443, None, 1)
    assert any(f["path"] == "/vpn/js/cmd.php" and f["severity"] == "CRITICAL"
               for f in findings)


@pytest.mark.parametrize("body", [
    "request parameter $_GET['cmd'] observed in this script",
    "preg_replace('/foo/e', 'bar', 'input')",
    "A" * 9000 + "<?php echo 'probe'; ?>",
], ids=["php-variable", "legacy-preg-replace", "indicator-after-8kb"])
def test_ioc_content_signatures_and_bounded_read(monkeypatch, body):
    max_bodies = []

    def response(_host, _port, path, _ctx, _timeout, **kwargs):
        max_bodies.append(kwargs.get("max_body"))
        if path == "/vpn/js/cmd.php":
            return {"status": 200, "body": body, "headers": {},
                    "url": f"https://adc.example:443{path}"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    findings = citrixscan.check_iocs("adc.example", 443, None, 1)
    assert any(f["path"] == "/vpn/js/cmd.php" for f in findings)
    assert all(size == 65536 for size in max_bodies)


def test_ioc_redirect_off_target_is_ignored(monkeypatch):
    def redirected(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/js/cmd.php":
            return {"status": 200, "body": "<?php echo $_GET['cmd']; ?>",
                    "headers": {}, "url": f"https://adc.example:443{path}",
                    "final_url": "https://other.example/sso"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", redirected)
    assert citrixscan.check_iocs("adc.example", 443, None, 1) == []


@pytest.mark.parametrize(("body", "expected_findings"), [
    ("<html><body>Login username password Citrix Gateway</body></html>", 0),
    ("<html><body>Login username password <?php echo $_GET['cmd']; ?></body></html>", 1),
])
def test_login_shaped_ioc_response_needs_strong_code_evidence(
    monkeypatch, body, expected_findings
):
    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/vpn/js/cmd.php":
            return {"status": 200, "body": body, "headers": {},
                    "url": f"https://adc.example:443{path}"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    assert len(citrixscan.check_iocs("adc.example", 443, None, 1)) == expected_findings


@pytest.mark.parametrize("redirect", [
    "https://other.example/login", "http://adc.example/login",
    "https://adc.example:8443/login",
])
def test_http_redirect_handler_rejects_off_target_requests(redirect):
    request = urllib.request.Request("https://adc.example:443/vpn/index.html")
    handler = citrixscan.TargetRedirectHandler()
    assert handler.redirect_request(request, None, 302, "Found", {}, redirect) is None
    same_target = handler.redirect_request(
        request, None, 302, "Found", {}, "https://adc.example:443/login"
    )
    assert same_target.full_url == "https://adc.example:443/login"


def test_http_helpers_install_target_redirect_guard(monkeypatch):
    installed = []

    class Response:
        status = 200
        headers = {}

        def read(self, _size):
            return b"ok"

        def geturl(self):
            return "https://adc.example:443/probe"

    class Opener:
        def open(self, _request, timeout):
            return Response()

    def build_opener(*handlers):
        installed.append(handlers)
        return Opener()

    monkeypatch.setattr(citrixscan.urllib.request, "build_opener", build_opener)
    citrixscan.http_get("adc.example", 443, "/probe", None, 1)
    citrixscan.http_get_binary("adc.example", 443, "/probe", None, 1)
    assert len(installed) == 2
    assert all(any(isinstance(handler, citrixscan.TargetRedirectHandler)
                   for handler in handlers) for handlers in installed)


def test_main_exports_report_before_finding_exit(monkeypatch, tmp_path):
    report_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "adc.example", "--fail-on-risk",
                                      "high", "-o", str(report_path)])
    monkeypatch.setattr(citrixscan, "scan_target", lambda *_args: result(risk_rating="HIGH"))

    assert citrixscan.main() == 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["high"] == 1
    assert report["scan_metadata"]["requested_targets"] == 1


def test_main_reports_partial_coverage_and_saml_match(monkeypatch, tmp_path):
    config_path = tmp_path / "ns.conf"
    config_path.write_text(
        "add authentication samlAction idp\nadd vpn vserver gateway SSL 192.0.2.1 443\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "adc.example", "--saml-config",
                                      str(config_path), "--fail-on-saml-match", "-o",
                                      str(report_path)])

    def failed_scan(_target, _port, _timeout, _modules, _deep, saml_review):
        return result(reachable=False, errors=["TCP unreachable"],
                      saml_advisory_status=saml_review["status"],
                      saml_advisory_signals=saml_review["signals"])

    monkeypatch.setattr(citrixscan, "scan_target", failed_scan)
    assert citrixscan.main() == 4
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["failed_targets"] == 1
    assert report["results"][0]["saml_advisory_status"] == "configuration_match"


def test_csv_report_keeps_failed_target_visible(monkeypatch, tmp_path):
    csv_path = tmp_path / "report.csv"
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "adc.example", "broken.example",
                                      "--csv", str(csv_path)])

    def scan(target, *_args):
        if target == "broken.example":
            raise RuntimeError("probe failed")
        return result()

    monkeypatch.setattr(citrixscan, "scan_target", scan)
    assert citrixscan.main() == 3
    with csv_path.open(encoding="utf-8", newline="") as report:
        rows = {row["target"]: row for row in csv.DictReader(report)}
    assert rows["adc.example"]["scan_status"] == "complete"
    assert rows["broken.example"]["scan_status"] == "error"


def test_worker_exception_preserves_local_saml_alert(monkeypatch, tmp_path):
    config_path = tmp_path / "ns.conf"
    config_path.write_text(
        "add authentication samlAction idp\nadd vpn vserver gateway SSL 192.0.2.1 443\n",
        encoding="utf-8",
    )
    json_path = tmp_path / "report.json"
    csv_path = tmp_path / "report.csv"
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "adc.example", "--saml-config",
                                      str(config_path), "--fail-on-saml-match", "-o",
                                      str(json_path), "--csv", str(csv_path)])

    def raising_scan(*_args):
        raise RuntimeError("probe failed")

    monkeypatch.setattr(citrixscan, "scan_target", raising_scan)
    assert citrixscan.main() == 4
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["scan_metadata"]["local_saml_review"]["status"] == "configuration_match"
    assert report["summary"]["failed_targets"] == 1
    with csv_path.open(encoding="utf-8", newline="") as report_file:
        row = next(csv.DictReader(report_file))
    assert row["scan_status"] == "error"
    assert row["saml_advisory_status"] == "configuration_match"


def test_invalid_modules_are_rejected(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "adc.example", "--modules", "typ0"])
    with pytest.raises(SystemExit) as error:
        citrixscan.main()
    assert error.value.code == 1


def test_local_saml_match_visible_when_remote_identity_unknown(capsys):
    scanned = result(is_netscaler=False, risk_rating="INFO",
                     saml_advisory_status="configuration_match",
                     saml_advisory_signals=["samlAction", "Gateway vserver"])
    scanned.recommendations = citrixscan.build_recommendations(scanned)
    citrixscan.print_result(scanned)
    output = capsys.readouterr().out
    assert "configuration_match" in output
    assert "remote product identification unverified" in output
    assert any("Local configuration matches" in item for item in scanned.recommendations)


def test_patched_build_still_gets_post_patch_advice():
    scanned = result(version_raw="NS14.1: Build 73.37",
                     version_parsed=(14, 1, 73, 37))
    advice = citrixscan.build_recommendations(scanned)
    assert any("POST-PATCH" in item for item in advice)
    assert any("independent of CTX697096" in item for item in advice)


def test_cve_disabled_does_not_print_no_vulnerabilities(capsys):
    scanned = result(version_raw="NS14.1: Build 73.37",
                     version_parsed=(14, 1, 73, 37), modules_run="ioc")
    citrixscan.print_result(scanned)
    output = capsys.readouterr().out
    assert "CVE module not run" in output
    assert "None found" not in output


def test_medium_ioc_guidance_conditions_isolation_on_confirmation():
    scanned = result(ioc_findings=[{"severity": "MEDIUM", "path": "/vpn/js/info.php"}])
    advice = citrixscan.build_recommendations(scanned)
    assert any("If confirmed, isolate" in item for item in advice)
    assert not any(item.startswith("  → Isolate affected") for item in advice)


def test_tcp_open_without_https_response_is_incomplete(monkeypatch, capsys):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _target: "192.0.2.1")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_args, **_kwargs: {
        "protocol": "", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get", lambda *_args, **_kwargs: None)
    scanned = citrixscan.scan_target("adc.example")
    assert scanned.reachable is True
    assert scanned.is_netscaler is False
    assert any("No HTTPS response" in error for error in scanned.errors)
    assert citrixscan.determine_exit_code([scanned], [], "high", False) == 3
    citrixscan.print_result(scanned)
    assert "Scan incomplete: No HTTPS response" in capsys.readouterr().out
