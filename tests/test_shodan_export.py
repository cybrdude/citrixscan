"""Offline triage of cached Shodan service records."""

import json
import sys

import citrixscan
import pytest


def sample_record(*, version="14.1-38.53", html="", headers=None):
    record = {
        "ip_str": "192.0.2.10",
        "port": 443,
        "timestamp": "2026-10-02T20:30:07.716997",
        "product": "Citrix Netscaler",
        "http": {
            "status": 200,
            "headers": headers or {"set-cookie": "NSC_AAAC=PRIVATE_TOKEN"},
            "html": html,
        },
    }
    if version is not None:
        record["version"] = version
    return record


def test_conflicting_shodan_and_html_builds_require_verification():
    record = sample_record(
        html="<!-- NetScaler NS14.1: Build 65.11.nc -->",
        headers={"x-citrix-version": "14.1", "set-cookie": "NSC_AAAC=PRIVATE_TOKEN"},
    )

    result = citrixscan.analyze_shodan_record(record)

    assert result["version_status"] == "conflict"
    assert result["version_evidence"] == [
        {"source": "shodan_version", "version": "14.1-38.53"},
        {"source": "http_html", "version": "14.1-65.11"},
    ]
    assert result["cve_2026_88771"]["assessment"] == "requires_verification"
    assert result["cve_2026_88771"]["all_candidates_below_fixed"] is True
    assert result["cve_2026_88771"]["fixed_build"] == "14.1-73.37"
    assert "PRIVATE_TOKEN" not in json.dumps(result)


def test_branch_only_header_does_not_become_a_firmware_build():
    result = citrixscan.analyze_shodan_record(sample_record(
        version=None,
        headers={"x-citrix-version": "14.1", "set-cookie": "NSC_AAAC=PRIVATE_TOKEN"},
    ))

    assert result["product_detected"] is True
    assert result["version_status"] == "unknown"
    assert result["cve_2026_88771"]["assessment"] == "unknown_build"


def test_single_cached_build_uses_candidate_language():
    below = citrixscan.analyze_shodan_record(sample_record(version="14.1-65.11"))
    above = citrixscan.analyze_shodan_record(sample_record(version="14.1-73.37"))

    assert below["cve_2026_88771"]["assessment"] == "below_fixed_candidate"
    assert above["cve_2026_88771"]["assessment"] == "at_or_above_fixed_candidate"


def test_untrusted_timestamp_text_is_not_copied_to_report():
    record = sample_record()
    record["timestamp"] = "READ_THIS_PRIVATE_TOKEN"

    result = citrixscan.analyze_shodan_record(record)

    assert result["timestamp"] is None
    assert "READ_THIS_PRIVATE_TOKEN" not in json.dumps(result)


def test_version_on_unidentified_product_is_not_a_cve_candidate():
    record = sample_record(version="14.1-65.11", headers={"server": "Apache"})
    record["product"] = "Apache HTTP Server"

    result = citrixscan.analyze_shodan_record(record)

    assert result["product_detected"] is False
    assert result["cve_2026_88771"]["assessment"] == "product_unverified"
    assert result["cve_2026_88771"]["all_candidates_below_fixed"] is False


def test_header_only_firmware_build_is_assessed_as_cached_candidate():
    result = citrixscan.analyze_shodan_record(sample_record(
        version=None, headers={"X-NS-Version": "NS14.1: Build 65.11"},
    ))

    assert result["version_evidence"] == [
        {"source": "http_header:x-ns-version", "version": "14.1-65.11"},
    ]
    assert result["version_status"] == "consistent"
    assert result["cve_2026_88771"]["assessment"] == "below_fixed_candidate"


def test_raw_banner_firmware_build_is_not_lost_when_http_fields_are_sparse():
    record = sample_record(version=None, headers={})
    record["data"] = "HTTP/1.1 200 OK\nNetScaler NS14.1: Build 65.11.nc"

    result = citrixscan.analyze_shodan_record(record)

    assert result["version_evidence"] == [
        {"source": "raw_banner", "version": "14.1-65.11"},
    ]


def test_fips_body_pattern_does_not_conflict_with_its_own_overlap():
    result = citrixscan.analyze_shodan_record(sample_record(
        version=None, html="NetScaler FIPS NS13.1: Build 37.279.nc",
    ))

    assert result["version_status"] == "consistent"
    assert result["version_evidence"] == [
        {"source": "http_html", "version": "13.1-37.279", "edition": "FIPS"},
    ]
    assert result["cve_2026_88771"]["assessment"] == "at_or_above_fixed_candidate"


def test_explicit_edition_resolves_matching_unlabelled_build():
    result = citrixscan.analyze_shodan_record(sample_record(
        version="13.1-37.279", html="NetScaler FIPS NS13.1: Build 37.279.nc",
    ))

    assert result["version_status"] == "consistent"
    assert result["cve_2026_88771"]["assessment"] == "at_or_above_fixed_candidate"


def test_scoped_ipv6_is_rejected_from_sanitized_report():
    record = sample_record()
    record["ip_str"] = "fe80::1%INJECTED_TEXT"

    with pytest.raises(ValueError, match="invalid IP address"):
        citrixscan.analyze_shodan_record(record)


def test_sparse_raw_banner_can_identify_a_product_candidate():
    result = citrixscan.analyze_shodan_record({
        "ip_str": "192.0.2.11",
        "port": 443,
        "data": "HTTP/1.1 200 OK\nServer: NetScaler\n\nNetScaler NS14.1: Build 65.11.nc",
    })

    assert result["product_detected"] is True
    assert result["cve_2026_88771"]["assessment"] == "below_fixed_candidate"


def test_shodan_http_server_field_identifies_product_candidate():
    record = sample_record(version="14.1-65.11", headers={"server": "Apache"})
    record["product"] = "Unknown"
    record["http"]["server"] = "NetScaler"

    result = citrixscan.analyze_shodan_record(record)

    assert result["product_detected"] is True
    assert result["cve_2026_88771"]["assessment"] == "below_fixed_candidate"


def test_shodan_cli_reads_jsonl_without_scanning_hosts(tmp_path, monkeypatch):
    source = tmp_path / "shodan.jsonl"
    source.write_text(json.dumps(sample_record(
        html="<!-- NetScaler NS14.1: Build 65.11.nc -->",
    )) + "\n", encoding="utf-8")
    report = tmp_path / "report.json"

    def reject_live_scan(*_args, **_kwargs):
        raise AssertionError("offline export mode attempted a live scan")

    monkeypatch.setattr(citrixscan, "scan_target", reject_live_scan)
    monkeypatch.setattr(citrixscan, "http_get", reject_live_scan)
    monkeypatch.setattr(citrixscan, "http_get_binary", reject_live_scan)
    monkeypatch.setattr(citrixscan.socket, "create_connection", reject_live_scan)
    monkeypatch.setattr(citrixscan.socket, "gethostbyname", reject_live_scan)
    monkeypatch.setattr(sys, "argv", [
        "citrixscan.py", "--shodan-export", str(source), "-o", str(report),
    ])

    assert citrixscan.main() == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["mode"] == "offline_shodan_export"
    assert payload["summary"]["records"] == 1
    assert payload["summary"]["version_conflicts"] == 1
    assert payload["records"][0]["ip"] == "192.0.2.10"
    assert "PRIVATE_TOKEN" not in report.read_text(encoding="utf-8")


def test_invalid_jsonl_line_is_reported_as_incomplete(tmp_path):
    source = tmp_path / "shodan.jsonl"
    source.write_text(json.dumps(sample_record()) + "\n{bad json}\n", encoding="utf-8")

    result = citrixscan.analyze_shodan_export(source)

    assert result["summary"]["records"] == 1
    assert result["summary"]["invalid_records"] == 1
    assert result["errors"][0]["line"] == 2
    assert "bad json" not in json.dumps(result)


def test_multiple_ports_on_one_host_count_as_one_host(tmp_path):
    first = sample_record(html="<!-- NetScaler NS14.1: Build 65.11.nc -->")
    second = sample_record(html="<!-- NetScaler NS14.1: Build 65.11.nc -->")
    second["port"] = 8443
    source = tmp_path / "shodan.jsonl"
    source.write_text("\n".join(json.dumps(row) for row in (first, second)) + "\n",
                      encoding="utf-8")

    summary = citrixscan.analyze_shodan_export(source)["summary"]

    assert summary["records"] == 2
    assert summary["unique_hosts"] == 1
    assert summary["conflict_hosts"] == 1
    assert summary["unknown_build_hosts"] == 0


def test_empty_export_does_not_report_success(tmp_path, monkeypatch):
    source = tmp_path / "empty.jsonl"
    source.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["citrixscan.py", "--shodan-export", str(source)])

    assert citrixscan.main() == 1
