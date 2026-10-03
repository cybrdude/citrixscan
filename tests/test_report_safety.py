import csv
import hashlib
import json
from contextlib import nullcontext

import citrixscan


SECRET = "FAKE_SECRET_DO_NOT_REPORT_123"
ETAG_SECRET = "FAKE_ETAG_DO_NOT_REPORT_456"
SERVER_SECRET = "FAKE_SERVER_DO_NOT_REPORT_789"


def scan_result(**overrides):
    values = {
        "target": "192.0.2.10", "ip": "192.0.2.10", "port": 443,
        "timestamp": "2026-10-03T00:00:00Z", "reachable": True,
        "is_netscaler": True,
    }
    values.update(overrides)
    return citrixscan.ScanResult(**values)


def test_ioc_finding_and_reports_exclude_raw_response_body(tmp_path, monkeypatch, capsys):
    path = "/vpn/js/cmd.php"
    body = f"<?php echo '{SECRET}'; ?>"

    def response(_host, _port, requested_path, _ctx, _timeout, **_kwargs):
        if requested_path == path:
            return {"status": 200, "headers": {}, "body": body,
                    "final_url": f"https://192.0.2.10:443{path}"}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    findings = citrixscan.check_iocs("192.0.2.10", 443, None, 1)
    assert len(findings) == 1
    assert findings[0]["type"] == "webshell"
    assert "content_preview" not in findings[0]
    assert SECRET not in json.dumps(findings)
    assert findings[0]["content_sha256"] == hashlib.sha256(body.encode()).hexdigest()

    result = scan_result(ioc_findings=findings)
    report = tmp_path / "report.json"
    citrixscan.export_json([result], report)
    citrixscan.print_result(result)
    assert SECRET not in report.read_text(encoding="utf-8")
    assert SECRET not in capsys.readouterr().out


def test_nsconf_and_nitro_misconfig_findings_never_expose_secrets(tmp_path, monkeypatch, capsys):
    config = f"add system user fakeuser {SECRET}\n"
    nitro = json.dumps({"errorcode": 0, "nsconfig": [{"password": SECRET}]})

    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/nsconfig/ns.conf":
            return {"status": 200, "headers": {}, "body": config}
        if path == "/nitro/v1/config/nsconfig":
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": nitro}
        return None

    monkeypatch.setattr(citrixscan, "http_get", response)
    findings = citrixscan.check_misconfigs("192.0.2.10", 443, None, 1, {})
    paths = {finding["path"] for finding in findings}
    assert {"/nsconfig/ns.conf", "/nitro/v1/config/nsconfig"} <= paths
    assert all("content_preview" not in finding for finding in findings)
    assert SECRET not in json.dumps(findings)

    result = scan_result(misconfig_findings=findings)
    report = tmp_path / "report.json"
    citrixscan.export_json([result], report)
    citrixscan.print_result(result)
    assert SECRET not in report.read_text(encoding="utf-8")
    assert SECRET not in capsys.readouterr().out


def test_server_and_etag_raw_values_are_not_exported_or_printed(tmp_path, capsys):
    result = scan_result(server_header=f"NetScaler {SERVER_SECRET}",
                         etag_values=[f"/vpn/index.html: {ETAG_SECRET}"])
    report = tmp_path / "report.json"
    citrixscan.export_json([result], report)
    citrixscan.print_result(result)
    exported = report.read_text(encoding="utf-8")
    console = capsys.readouterr().out
    assert SERVER_SECRET not in exported + console
    assert ETAG_SECRET not in exported + console


def test_output_boundaries_discard_legacy_content_previews(tmp_path, capsys):
    result = scan_result(
        ioc_findings=[{"severity": "HIGH", "path": "/vpn/js/cmd.php",
                       "detail": "Unexpected file", "content_preview": SECRET}],
        misconfig_findings=[{"severity": "CRITICAL", "path": "/nsconfig/ns.conf",
                             "detail": "Configuration file accessible",
                             "content_preview": SECRET}],
    )
    report = tmp_path / "report.json"
    citrixscan.export_json([result], report)
    citrixscan.print_result(result)
    exported = report.read_text(encoding="utf-8")
    console = capsys.readouterr().out
    assert SECRET not in exported + console
    assert "content_preview" not in exported


def test_generic_front_end_with_valid_nitro_schema_identifies_netscaler(monkeypatch):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _host: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_args, **_kwargs: {
        "protocol": "TLSv1.3", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_args, **_kwargs: None)
    requested = []

    def response(_host, _port, path, _ctx, _timeout, **_kwargs):
        requested.append(path)
        if path == "/nitro/v1/config/nsversion":
            return {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body": '{"errorcode":0,"nsversion":[{"version":"NetScaler NS14.1: Build 73.37"}]}',
                    "url": path}
        return {"status": 200, "headers": {"Server": "Apache"},
                "body": "<html><title>Welcome</title></html>", "url": path}

    monkeypatch.setattr(citrixscan, "http_get", response)
    result = citrixscan.scan_target("192.0.2.10", modules="cve", deep_scan=False)
    assert "/nitro/v1/config/nsversion" in requested
    assert result.is_netscaler is True
    assert result.version_display == "14.1-73.37"


def test_human_output_labels_served_build_candidate_and_unverified_patch_status(capsys):
    result = scan_result(
        modules_run="cve", version_raw="NS14.1: Build 29.72",
        version_parsed=(14, 1, 29, 72), version_display="14.1-29.72",
        version_source="NITRO API", version_confidence="HIGH",
        patch_status="unverified_external", branch="14.1",
        cve_results=[{
            "cve_id": "CVE-2026-88771", "vulnerable": True,
            "cvss": 9.5, "severity": "CRITICAL", "title": "Unauthenticated RCE",
            "fixed_version": "14.1-73.37", "advisory": "CTX697096",
        }], total_vulns=1, critical_cves=1,
    )
    citrixscan.print_result(result)
    printed = capsys.readouterr().out.lower().replace("-", " ")
    assert "served build" in printed
    assert "candidate" in printed
    assert "patch status" in printed
    assert "unverified" in printed


def test_csv_and_markdown_preserve_external_patch_status(tmp_path):
    result = scan_result(
        modules_run="cve", version_raw="NS14.1: Build 73.37",
        version_parsed=(14, 1, 73, 37), version_display="14.1-73.37",
        version_source="NITRO API", version_confidence="HIGH",
        patch_status="unverified_external", branch="14.1",
    )
    csv_path = tmp_path / "report.csv"
    markdown_path = tmp_path / "report.md"
    citrixscan.export_csv([result], csv_path)
    citrixscan.export_markdown([result], markdown_path)
    with csv_path.open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    assert row["patch_status"] == "unverified_external"
    markdown = markdown_path.read_text(encoding="utf-8").lower()
    assert "patch status" in markdown
    assert "unverified_external" in markdown


def test_unknown_build_recommendations_do_not_treat_epa_as_firmware():
    result = scan_result(epa_available=True, gateway_detected=True)
    advice = " ".join(citrixscan.build_recommendations(result)).lower()
    assert "nsroot:pass" not in advice
    assert "file properties for version" not in advice
    assert "assume vulnerable" not in advice
    assert "running build and edition" in advice
    assert "authenticated nitro" in advice
