import importlib
import json

import pytest


def followup():
    return importlib.import_module("vhost_followup")


def write_inputs(tmp_path, shodan_records, live_results):
    shodan = tmp_path / "shodan.jsonl"
    shodan.write_text("\n".join(json.dumps(record) for record in shodan_records),
                      encoding="utf-8")
    live = tmp_path / "live.json"
    live.write_text(json.dumps({"results": live_results}), encoding="utf-8")
    return shodan, live


def write_allowlist(tmp_path, rows):
    path = tmp_path / "approved-hostnames.csv"
    path.write_text("ip,port,hostname\n" + "".join(
        f"{ip},{port},{hostname}\n" for ip, port, hostname in rows
    ), encoding="utf-8")
    return path


def test_selects_only_unresolved_live_netscaler_endpoints_and_two_valid_fqdns(tmp_path):
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 443,
         "http": {"host": "portal.example"},
         "hostnames": ["portal.example", "vpn.example", "third.example", "bad_name.example"]},
        {"ip_str": "192.0.2.11", "port": 443, "hostnames": ["down.example"]},
        {"ip_str": "192.0.2.12", "port": 443, "hostnames": ["apache.example"]},
        {"ip_str": "192.0.2.13", "port": 443, "hostnames": ["patched.example"]},
        {"ip_str": "192.0.2.14", "port": 8443, "hostnames": ["medium.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": ""},
        {"ip": "192.0.2.11", "port": 443, "reachable": False,
         "is_netscaler": True, "version_display": ""},
        {"ip": "192.0.2.12", "port": 443, "reachable": True,
         "is_netscaler": False, "version_display": ""},
        {"ip": "192.0.2.13", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": "14.1-73.37",
         "version_confidence": "HIGH"},
        {"ip": "192.0.2.14", "port": 8443, "reachable": True,
         "is_netscaler": True, "version_display": "14.1-65.11",
         "version_confidence": "MEDIUM"},
    ])

    approved = followup().load_approved_hostnames(write_allowlist(tmp_path, [
        ("192.0.2.10", 443, "portal.example"),
        ("192.0.2.10", 443, "vpn.example"),
        ("192.0.2.10", 443, "third.example"),
        ("192.0.2.14", 8443, "medium.example"),
    ]))
    targets = followup().load_targets(shodan, live, approved_hostnames=approved)
    assert targets == [
        {"ip": "192.0.2.10", "port": 443,
         "scheme": "https", "hostnames": ["portal.example", "vpn.example"]},
        {"ip": "192.0.2.14", "port": 8443,
         "scheme": "https", "hostnames": ["medium.example"]},
    ]


def test_collects_sanitized_conflicting_build_evidence_without_patch_verdict():
    module = followup()
    paths = []
    token = "a" * 32
    gzip_header = b"\x1f\x8b\x08\x00" + (1762299316).to_bytes(4, "little") + b"\x00\x03"

    def fake_probe(ip, port, hostname, path, **options):
        paths.append((ip, port, hostname, path, options["scheme"]))
        headers = {"set-cookie": "SECRET_COOKIE=do-not-report", "cache-control": "public, max-age=300",
                   "age": "120", "via": "proxy", "x-cache": "HIT"}
        if path == "/vpn/index.html":
            data = f'<script src="/vpn/js/app.js?v={token}"></script>'.encode()
        elif path == "/nitro/v1/config/nsversion":
            data = b'{"errorcode":0,"nsversion":[{"version":"NetScaler NS14.1: Build 73.37"}]}'
        else:
            data = gzip_header + b"SECRET_RAW_PAYLOAD"
        return {"status": 200, "headers": headers, "data": data,
                "body": data.decode("utf-8", errors="replace"),
                "truncated": False, "error": None}

    report = module.collect_followup(
        [{"ip": "192.0.2.10", "port": 443, "hostnames": ["portal.example"]}],
        approved_hostnames={("192.0.2.10", 443, "portal.example")},
        timeout=3, threads=1, probe_func=fake_probe,
    )
    assert paths == [
        ("192.0.2.10", 443, "portal.example", path, "https")
        for path in module.PROBE_PATHS
    ]
    endpoint = report["endpoints"][0]
    assert endpoint["version_status"] == "conflict"
    assert endpoint["candidate_builds"] == ["14.1-66.59", "14.1-73.37"]
    observations = endpoint["hosts"][0]["observations"]
    assert observations[0]["gui_version_token"] == token
    assert observations[1]["nitro_build"] == "14.1-73.37"
    assert observations[2]["gzip_mtime"] == 1762299316
    assert observations[2]["gzip_lookup_build"] == "14.1-66.59"
    assert observations[0]["cache_flags"]["cache_hit"] is True
    serialized = json.dumps(report)
    assert "SECRET_COOKIE" not in serialized
    assert "SECRET_RAW_PAYLOAD" not in serialized
    assert '"body"' not in serialized
    assert '"data"' not in serialized
    assert "vulnerable" not in serialized
    assert "patched" not in serialized


def test_nitro_build_requires_expected_success_schema():
    module = followup()
    assert module.parse_nitro_build(
        b'{"errorcode":0,"nsversion":[{"version":"NetScaler NS14.1: Build 73.37"}]}'
    ) == "14.1-73.37"
    assert module.parse_nitro_build(
        b'{"message":"NS14.1: Build 73.37","errorcode":0}'
    ) is None
    assert module.parse_nitro_build(
        b'{"errorcode":1,"nsversion":[{"version":"NS14.1: Build 73.37"}]}'
    ) is None


def test_gzip_stamp_requires_valid_header_and_known_mapping():
    module = followup()
    header = b"\x1f\x8b\x08\x00" + (1762299316).to_bytes(4, "little") + b"\x00\x03"
    assert module.parse_gzip_stamp(header) == (1762299316, "14.1-66.59")
    assert module.parse_gzip_stamp(b"\x1f\x8b\x00\x00" + header[4:]) == (None, None)
    assert module.parse_gzip_stamp(b"\x1f\x8b\x08\xe0" + header[4:]) == (None, None)
    zero = b"\x1f\x8b\x08\x00" + b"\x00" * 6
    assert module.parse_gzip_stamp(zero) == (0, None)


def test_cli_writes_sanitized_json_and_rejects_unbounded_options(tmp_path, monkeypatch):
    module = followup()
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 443, "hostnames": ["portal.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": ""},
    ])
    output = tmp_path / "followup.json"
    approved = write_allowlist(tmp_path, [("192.0.2.10", 443, "portal.example")])
    calls = []

    def fake_probe(ip, port, hostname, path, **_options):
        calls.append((ip, port, hostname, path))
        return {"status": 404, "headers": {"set-cookie": "SECRET_COOKIE"},
                "data": b"PRIVATE_BODY", "body": "PRIVATE_BODY",
                "truncated": False, "error": None}

    monkeypatch.setattr(module, "probe_vhost", fake_probe)
    assert module.main([
        "--shodan-export", str(shodan), "--live-report", str(live),
        "--approved-hostnames", str(approved),
        "--output-json", str(output), "--timeout", "2", "--threads", "1",
    ]) == 0
    assert len(calls) == 3
    exported = output.read_text(encoding="utf-8")
    assert "PRIVATE_BODY" not in exported
    assert "SECRET_COOKIE" not in exported
    assert json.loads(exported)["mode"] == "live_vhost_followup"
    with pytest.raises(SystemExit):
        module.main([
            "--shodan-export", str(shodan), "--live-report", str(live),
            "--approved-hostnames", str(approved),
            "--output-json", str(output), "--threads", "99",
        ])


def test_allowlist_must_match_exact_ip_port_and_hostname(tmp_path):
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 443,
         "hostnames": ["portal.example", "vpn.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": ""},
    ])
    wrong = followup().load_approved_hostnames(write_allowlist(tmp_path, [
        ("192.0.2.10", 8443, "portal.example"),
        ("192.0.2.11", 443, "vpn.example"),
    ]))
    assert followup().load_targets(shodan, live, approved_hostnames=wrong) == []


def test_followup_uses_each_live_result_http_scheme_with_exact_approval(tmp_path):
    module = followup()
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 8080, "hostnames": ["http.example"]},
        {"ip_str": "192.0.2.11", "port": 443, "hostnames": ["https.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 8080, "reachable": True,
         "is_netscaler": True, "http_scheme": "http", "version_display": ""},
        {"ip": "192.0.2.11", "port": 443, "reachable": True,
         "is_netscaler": True, "http_scheme": "https", "version_display": ""},
    ])
    approved = module.load_approved_hostnames(write_allowlist(tmp_path, [
        ("192.0.2.10", 8080, "http.example"),
        ("192.0.2.11", 443, "https.example"),
    ]))
    targets = module.load_targets(shodan, live, approved_hostnames=approved)
    assert [target["scheme"] for target in targets] == ["http", "https"]
    calls = []

    def fake_probe(ip, port, hostname, path, **options):
        calls.append((ip, port, hostname, path, options["scheme"]))
        return {"status": 404, "headers": {}, "data": b"", "error": None}

    report = module.collect_followup(
        targets, approved_hostnames=approved, threads=1, probe_func=fake_probe,
    )
    assert len(calls) == 6
    assert {call[4] for call in calls[:3]} == {"http"}
    assert {call[4] for call in calls[3:]} == {"https"}
    assert [item["scheme"] for item in report["endpoints"]] == ["http", "https"]


def test_direct_collection_rejects_missing_or_empty_allowlist_without_probe():
    module = followup()
    calls = []
    targets = [{"ip": "192.0.2.10", "port": 443,
                "hostnames": ["portal.example"]}]

    def fake_probe(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("probe attempted")

    with pytest.raises(ValueError):
        module.collect_followup(targets, probe_func=fake_probe)
    with pytest.raises(ValueError):
        module.collect_followup(targets, approved_hostnames=set(), probe_func=fake_probe)
    assert calls == []

    report = module.collect_followup(
        targets, approved_hostnames={("192.0.2.10", 8443, "portal.example")},
        probe_func=fake_probe,
    )
    assert report["summary"]["selected_endpoints"] == 0
    assert calls == []


def test_cli_rejects_missing_or_empty_allowlist_before_probe(tmp_path, monkeypatch):
    module = followup()
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 443, "hostnames": ["portal.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": ""},
    ])
    output = tmp_path / "followup.json"

    def reject_probe(*_args, **_kwargs):
        raise AssertionError("probe attempted")

    monkeypatch.setattr(module, "probe_vhost", reject_probe)
    common = ["--shodan-export", str(shodan), "--live-report", str(live),
              "--output-json", str(output)]
    with pytest.raises(SystemExit):
        module.main(common)
    empty = write_allowlist(tmp_path, [])
    with pytest.raises(SystemExit):
        module.main(common + ["--approved-hostnames", str(empty)])
    assert not output.exists()


@pytest.mark.parametrize("input_name", ["shodan", "live", "approved"])
def test_cli_rejects_output_path_that_overwrites_an_input(
        tmp_path, monkeypatch, input_name):
    module = followup()
    shodan, live = write_inputs(tmp_path, [
        {"ip_str": "192.0.2.10", "port": 443, "hostnames": ["portal.example"]},
    ], [
        {"ip": "192.0.2.10", "port": 443, "reachable": True,
         "is_netscaler": True, "version_display": ""},
    ])
    approved = write_allowlist(tmp_path, [("192.0.2.10", 443, "portal.example")])
    inputs = {"shodan": shodan, "live": live, "approved": approved}
    original = {name: path.read_bytes() for name, path in inputs.items()}
    calls = []

    def reject_probe(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("probe attempted")

    monkeypatch.setattr(module, "probe_vhost", reject_probe)
    with pytest.raises(SystemExit):
        module.main([
            "--shodan-export", str(shodan), "--live-report", str(live),
            "--approved-hostnames", str(approved),
            "--output-json", str(inputs[input_name]),
        ])
    assert {name: path.read_bytes() for name, path in inputs.items()} == original
    assert calls == []
