import csv
import json
import re
from contextlib import nullcontext
import pytest

import citrixscan
from citrixscan import (
    CVE_DATABASE,
    ScanResult,
    build_recommendations,
    check_cve_applicability,
    export_csv,
    export_json,
    export_markdown,
    extract_nitro_version,
    extract_version,
    parse_netscaler_version,
    print_result,
    print_summary,
    scan_target,
)


@pytest.mark.parametrize(
    ("version", "vulnerable", "fixed_version"),
    [
        ("14.1-73.36", True, "14.1-73.37"),
        ("14.1-73.37", False, "14.1-73.37"),
        ("13.1-64.22", True, "13.1-64.23"),
        ("13.1-64.23", False, "13.1-64.23"),
    ],
)
def test_cve_2026_88771_standard_build_boundary(version, vulnerable, fixed_version):
    cve = next(entry for entry in CVE_DATABASE if entry.cve_id == "CVE-2026-88771")
    parsed = parse_netscaler_version(version)

    result = check_cve_applicability(parsed, {}, cve)

    assert result["vulnerable"] is vulnerable
    assert result["fixed_version"] == fixed_version
    assert result["config_applicable"] is True

@pytest.mark.parametrize(
    ("version", "vulnerable", "fixed_version"),
    [
        ("13.1-37.278 FIPS", True, "13.1-37.279"),
        ("13.1-37.279 FIPS", False, "13.1-37.279"),
        ("13.1-37.278 NDcPP", True, "13.1-37.279"),
        ("13.1-37.279 NDcPP", False, "13.1-37.279"),
        ("14.1-73.36 FIPS", True, "14.1-73.37"),
        ("14.1-73.37 FIPS", False, "14.1-73.37"),
    ],
)
def test_cve_2026_88771_explicit_edition_boundary(version, vulnerable, fixed_version):
    cve = next(entry for entry in CVE_DATABASE if entry.cve_id == "CVE-2026-88771")
    parsed = parse_netscaler_version(version)

    result = check_cve_applicability(parsed, {}, cve, version_raw=version)

    assert result["vulnerable"] is vulnerable
    assert result["fixed_version"] == fixed_version
    assert result["edition_unconfirmed"] is False


def test_cve_2026_88771_does_not_assert_unsupported_branch_is_affected():
    cve = next(entry for entry in CVE_DATABASE if entry.cve_id == "CVE-2026-88771")
    parsed = parse_netscaler_version("13.0-92.20")

    result = check_cve_applicability(parsed, {}, cve)

    assert result["branch_match"] is False
    assert result["vulnerable"] is False


def _unknown_gzip_stamp(monkeypatch):
    stamp = 1_999_999_999
    payload = b"\x1f\x8b\x08\x00" + stamp.to_bytes(4, "little") + b"\x00" * 12

    def binary_response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path.endswith("/lang/rdx_en.json.gz"):
            return {"status": 200, "data": payload}
        return None

    monkeypatch.setattr(citrixscan, "http_get_binary", binary_response)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_args, **_kwargs: None)


def test_unknown_gzip_stamp_falls_back_to_header_version(monkeypatch):
    _unknown_gzip_stamp(monkeypatch)
    responses = [{"status": 200, "headers": {"X-NS-version": "NS14.1: Build 73.36"}, "body": ""}]

    raw, source, confidence, diagnostic = extract_version(
        responses, [], {}, None, "example.invalid", 443, 1
    )

    assert raw == "NS14.1: Build 73.36"
    assert source == "HTTP header (X-NS-version)"
    assert confidence == "HIGH"
    assert "not in" in diagnostic


def test_unknown_gzip_stamp_without_fallback_stays_unknown(monkeypatch):
    _unknown_gzip_stamp(monkeypatch)

    raw, source, confidence, diagnostic = extract_version(
        [], [], {}, None, "example.invalid", 443, 1
    )

    assert raw == ""
    assert source == ""
    assert confidence == ""
    assert "not in" in diagnostic


@pytest.mark.parametrize(
    "body",
    [
        "NetScaler NS13.1: Build 37.279 FIPS",
        "NetScaler NS13.1: Build 37.279.nc FIPS",
        "NetScaler FIPS NS13.1: Build 37.279",
        "NetScaler FIPS Release 13.1 Build 37.279",
    ],
)
def test_plain_text_nitro_response_preserves_fips_edition(body):
    response = {"status": 200, "headers": {}, "body": body}

    assert extract_nitro_version(response) == "NS13.1: Build 37.279 FIPS"


def test_page_body_version_preserves_ndcpp_edition(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_args, **_kwargs: None)
    responses = [{
        "status": 200,
        "headers": {},
        "body": "Firmware: NS13.1: Build 37.279 NDcPP",
    }]

    raw, _source, _confidence, _diagnostic = extract_version(
        responses, [], {}, None, "example.invalid", 443, 1
    )

    assert raw == "NS13.1: Build 37.279 NDcPP"


def test_unknown_netscaler_version_calls_out_latest_patch_status():
    result = ScanResult(target="example.invalid", ip="192.0.2.10", port=443,
                        timestamp="2026-10-01T00:00:00Z", is_netscaler=True)

    recommendations = build_recommendations(result)

    assert any("CVE-2026-88771" in item for item in recommendations)
    assert any("show ns version" in item for item in recommendations)


def test_eol_recommendation_uses_current_fixed_build():
    result = ScanResult(target="example.invalid", ip="192.0.2.10", port=443,
                        timestamp="2026-10-01T00:00:00Z", is_netscaler=True,
                        eol=True, branch="13.0")

    recommendations = build_recommendations(result)

    assert any("14.1-73.37" in item for item in recommendations)


def test_unlabelled_13_1_build_reports_edition_uncertainty():
    cve = next(entry for entry in CVE_DATABASE if entry.cve_id == "CVE-2026-88771")
    raw = "13.1-37.279"
    parsed = parse_netscaler_version(raw)

    finding = check_cve_applicability(parsed, {}, cve, version_raw=raw)

    assert finding["edition_unconfirmed"] is True
    result = ScanResult(target="example.invalid", ip="192.0.2.10", port=443,
                        timestamp="2026-10-01T00:00:00Z", is_netscaler=True,
                        version_raw=raw, version_parsed=parsed,
                        cve_results=[finding], critical_cves=1)
    assert any("edition" in item.lower() and "show ns version" in item
               for item in build_recommendations(result))


def test_csv_report_identifies_detected_cve(tmp_path):
    result = ScanResult(target="example.invalid", ip="192.0.2.10", port=443,
                        timestamp="2026-10-01T00:00:00Z", is_netscaler=True,
                        cve_results=[{"cve_id": "CVE-2026-88771", "vulnerable": True}],
                        total_vulns=1)
    report_path = tmp_path / "report.csv"

    export_csv([result], str(report_path))

    with report_path.open(encoding="utf-8", newline="") as report:
        row = next(csv.DictReader(report))
    assert row["cve_ids"] == "CVE-2026-88771"


@pytest.mark.parametrize(
    ("version", "expected_eol", "expected_88771"),
    [
        ("NS13.0: Build 92.20 FIPS", True, False),
        ("NS13.1: Build 37.278 FIPS", False, True),
        ("NS13.1: Build 37.279 FIPS", False, False),
    ],
)
def test_scan_uses_identified_edition_for_cve_and_eol(
    monkeypatch, version, expected_eol, expected_88771
):
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", lambda _host: "192.0.2.10")
    monkeypatch.setattr(citrixscan.socket, "create_connection",
                        lambda *_args, **_kwargs: nullcontext())
    monkeypatch.setattr(citrixscan, "get_tls_info", lambda *_args, **_kwargs: {
        "protocol": "TLSv1.3", "cipher": "", "bits": 0, "cn": "", "san": "",
        "issuer": "", "not_after": "",
    })
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_args, **_kwargs: None)

    def http_response(_host, _port, path, _ctx, _timeout, **_kwargs):
        if path == "/":
            return {"status": 200, "headers": {"Server": "NetScaler"},
                    "body": "Citrix Gateway", "url": path}
        if path == "/nitro/v1/config/nsversion":
            return {"status": 200, "headers": {},
                    "body": f'{{"version": "{version}"}}', "url": path}
        return None

    monkeypatch.setattr(citrixscan, "http_get", http_response)

    result = scan_target("example.invalid", modules="cve", deep_scan=False)

    assert result.is_netscaler is True
    assert result.eol is expected_eol
    assert any(finding["cve_id"] == "CVE-2026-88771"
               for finding in result.cve_results) is expected_88771
    if version == "NS13.1: Build 37.279 FIPS":
        assert "CVE-2023-3519" in result.unassessed_cves
        assert all(finding["cve_id"] != "CVE-2023-3519"
                   for finding in result.cve_results)
        assert result.risk_rating == "HIGH"
        assert any("unassessed" in item.lower() for item in result.recommendations)


def test_official_fips_release_in_header_identifies_version(monkeypatch):
    monkeypatch.setattr(citrixscan, "http_get_binary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(citrixscan, "http_get", lambda *_args, **_kwargs: None)
    responses = [{
        "status": 200,
        "headers": {"Server": "NetScaler FIPS Release 13.1 Build 37.279"},
        "body": "",
    }]

    raw, source, _confidence, _diagnostic = extract_version(
        responses, [], {}, None, "example.invalid", 443, 1
    )

    assert raw == "NetScaler FIPS Release 13.1 Build 37.279"
    assert source == "HTTP header (Server)"



def test_explicit_fips_without_edition_fix_is_unassessed():
    cve = next(entry for entry in CVE_DATABASE if entry.cve_id == "CVE-2023-3519")
    version = "NS13.1: Build 37.279 FIPS"

    finding = check_cve_applicability(
        parse_netscaler_version(version), {"gateway": True}, cve, version_raw=version
    )

    assert finding["branch_match"] is False
    assert finding["vulnerable"] is False
    assert finding["edition_unconfirmed"] is True


def test_unassessed_edition_output_does_not_claim_no_vulnerabilities(capsys):
    result = ScanResult(target="example.invalid", ip="192.0.2.10", port=443,
                        timestamp="2026-10-01T00:00:00Z", is_netscaler=True,
                        version_raw="NS13.1: Build 37.279 FIPS",
                        version_parsed=(13, 1, 37, 279),
                        version_display="13.1-37.279 FIPS", branch="13.1-FIPS",
                        unassessed_cves=["CVE-2023-3519"])

    print_result(result)

    output = capsys.readouterr().out
    assert "unassessed" in output.lower()
    assert "None found" not in output


def test_bulk_summaries_count_unassessed_edition_cves(tmp_path, capsys):
    fips = ScanResult(target="fips.example.invalid", ip="192.0.2.10", port=443,
                      timestamp="2026-10-01T00:00:00Z", reachable=True,
                      is_netscaler=True, version_raw="NS13.1: Build 37.279 FIPS",
                      risk_rating="HIGH",
                      unassessed_cves=["CVE-2023-3519", "CVE-2023-4966"])
    standard = ScanResult(target="standard.example.invalid", ip="192.0.2.11",
                          port=443, timestamp="2026-10-01T00:00:00Z",
                          reachable=True, is_netscaler=True,
                          version_raw="NS14.1: Build 73.37", risk_rating="LOW")
    results = [fips, standard]

    print_summary(results)
    cli_output = capsys.readouterr().out
    assert re.search(r"Unassessed CVEs\s*:\s*2", cli_output)
    assert re.search(r"Targets with Unassessed CVEs\s*:\s*1", cli_output)

    json_path = tmp_path / "report.json"
    export_json(results, str(json_path))
    summary = json.loads(json_path.read_text(encoding="utf-8"))["summary"]
    assert summary["unassessed_cves"] == 2
    assert summary["targets_with_unassessed_cves"] == 1

    markdown_path = tmp_path / "report.md"
    export_markdown(results, str(markdown_path))
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "| Unassessed CVEs | 2 |" in markdown
    assert "| Targets with Unassessed CVEs | 1 |" in markdown
