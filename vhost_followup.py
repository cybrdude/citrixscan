"""Collect cautious virtual-host evidence for unresolved live NetScaler scans.

This program reads an existing live report and a Shodan JSONL export. It only
probes endpoints the live report already marked reachable and NetScaler-like,
pins each connection to that endpoint's IP:port, and never follows redirects.
It reports candidate build evidence without making a patch-status verdict.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import ssl

from citrixscan import (RDX_EN_STAMP_TO_VERSION, format_version,
                        parse_netscaler_version, version_branch)
from vhost_probe import probe_vhost


PROBE_PATHS = (
    "/vpn/index.html",
    "/nitro/v1/config/nsversion",
    "/vpn/js/rdx/core/lang/rdx_en.json.gz",
)
MAX_HOSTNAMES = 2
MAX_BODY = 16384
MAX_THREADS = 4
MAX_TIMEOUT = 15
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_NITRO_VERSION = re.compile(
    r"\bNS\d{2}\.\d\s*:\s*Build\s+\d+\.\d+\b|"
    r"\b(?:NetScaler|Citrix\s+ADC)\s+Release\s+\d{2}\.\d\s+Build\s+\d+\.\d+\b",
    re.IGNORECASE,
)
_GUI_TOKEN = re.compile(rb"[?&]v=([0-9a-fA-F]{32})(?![0-9a-fA-F])")


def _endpoint(ip, port):
    if not isinstance(ip, str) or isinstance(port, bool) or not isinstance(port, int):
        return None
    if not 1 <= port <= 65535:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if getattr(address, "scope_id", None) is not None:
        return None
    return str(address), port


def _fqdn(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return None
    if value.count(".") < 1 or any(not _LABEL.fullmatch(label)
                                 for label in value.split(".")):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    return None


def load_approved_hostnames(path):
    """Read explicit IP,port,hostname CSV approvals; reject an empty file."""
    approved = set()
    with open(path, newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ["ip", "port", "hostname"]:
            raise ValueError("approved hostnames CSV needs ip,port,hostname columns")
        for number, row in enumerate(reader, 2):
            port_text = row.get("port")
            if (None in row or not isinstance(port_text, str) or
                    not re.fullmatch(r"[0-9]{1,5}", port_text)):
                raise ValueError(f"approved hostnames CSV line {number} is invalid")
            key = _endpoint(row.get("ip"), int(port_text))
            hostname = _fqdn(row.get("hostname"))
            if key is None or hostname is None:
                raise ValueError(f"approved hostnames CSV line {number} is invalid")
            approved.add((key[0], key[1], hostname))
    if not approved:
        raise ValueError("approved hostnames CSV is empty")
    return approved


def load_targets(shodan_path, live_report_path, *, approved_hostnames):
    """Intersect Shodan FQDNs with exact approvals for unresolved endpoints."""
    if not approved_hostnames:
        raise ValueError("explicit approved hostnames are required")
    candidates = {}
    with open(shodan_path, encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Shodan JSONL line {number} is invalid") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Shodan JSONL line {number} is not an object")
            key = _endpoint(record.get("ip_str"), record.get("port"))
            if key is None:
                raise ValueError(f"Shodan JSONL line {number} has an invalid endpoint")
            names = candidates.setdefault(key, [])
            http = record.get("http")
            values = [http.get("host")] if isinstance(http, dict) else []
            hostnames = record.get("hostnames")
            if isinstance(hostnames, list):
                values.extend(hostnames)
            for value in values:
                name = _fqdn(value)
                if (name and (key[0], key[1], name) in approved_hostnames
                        and name not in names and len(names) < MAX_HOSTNAMES):
                    names.append(name)

    with open(live_report_path, encoding="utf-8") as source:
        report = json.load(source)
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ValueError("live report must be a JSON object with a results list")

    selected = []
    seen = set()
    for result in report["results"]:
        if not isinstance(result, dict):
            raise ValueError("live report contains a non-object result")
        key = _endpoint(result.get("ip"), result.get("port"))
        if key is None:
            raise ValueError("live report contains an invalid endpoint")
        if key in seen:
            continue
        scheme = result.get("http_scheme", "https")
        if scheme not in ("http", "https"):
            raise ValueError("live report contains an invalid HTTP scheme")
        reliable_version = (bool(result.get("version_parsed") or
                                 result.get("version_display")) and
                            str(result.get("version_confidence", "")).upper() == "HIGH")
        if (result.get("reachable") is True and result.get("is_netscaler") is True
                and not reliable_version and candidates.get(key)):
            selected.append({"ip": key[0], "port": key[1], "scheme": scheme,
                             "hostnames": list(candidates[key])})
            seen.add(key)
    return selected


def parse_nitro_build(data):
    """Accept only a successful NITRO nsversion object's firmware field."""
    try:
        obj = json.loads(data)
    except (TypeError, ValueError, UnicodeError):
        return None
    if not isinstance(obj, dict) or type(obj.get("errorcode")) is not int or obj["errorcode"] != 0:
        return None
    rows = obj.get("nsversion")
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("version"), str):
            continue
        raw = row["version"]
        if not _NITRO_VERSION.search(raw):
            continue
        parsed = parse_netscaler_version(raw)
        if parsed is None:
            continue
        build = format_version(parsed)
        branch = version_branch(parsed, raw)
        if branch.endswith("-FIPS"):
            build += " FIPS"
        elif branch.endswith("-NDcPP"):
            build += " NDcPP"
        return build
    return None


def parse_gzip_stamp(data):
    """Return a validated GZIP MTIME and any exact known-build lookup."""
    if (not isinstance(data, bytes) or len(data) < 10 or
            data[:3] != b"\x1f\x8b\x08" or data[3] & 0xe0):
        return None, None
    stamp = int.from_bytes(data[4:8], "little")
    raw = RDX_EN_STAMP_TO_VERSION.get(stamp)
    parsed = parse_netscaler_version(raw) if isinstance(raw, str) else None
    return stamp, format_version(parsed) if parsed else None


def _cache_flags(headers):
    lower = {str(key).lower(): str(value).lower() for key, value in headers.items()}
    control = lower.get("cache-control", "")
    x_cache = lower.get("x-cache", "")
    age = lower.get("age", "")
    return {
        "cache_control_present": bool(control),
        "no_cache": "no-cache" in control,
        "no_store": "no-store" in control,
        "age_positive": age.isdecimal() and int(age) > 0,
        "via_present": bool(lower.get("via")),
        "cache_hit": "hit" in x_cache,
        "etag_present": bool(lower.get("etag")),
        "last_modified_present": bool(lower.get("last-modified")),
    }


def _observation(path, response):
    data = response.get("data")
    if not isinstance(data, bytes):
        body = response.get("body")
        data = body.encode("utf-8", errors="replace") if isinstance(body, str) else b""
    data = data[:MAX_BODY]
    headers = response.get("headers")
    headers = headers if isinstance(headers, dict) else {}
    status = response.get("status")
    item = {
        "path": path,
        "status": status if isinstance(status, int) and 100 <= status <= 599 else None,
        "body_sha256": hashlib.sha256(data).hexdigest() if data else None,
        "body_bytes": len(data),
        "truncated": response.get("truncated") is True,
        "cache_flags": _cache_flags(headers),
    }
    if response.get("error"):
        item["request_error"] = True
    if item["status"] != 200:
        return item
    if path == PROBE_PATHS[0]:
        token = _GUI_TOKEN.search(data)
        if token:
            item["gui_version_token"] = token.group(1).decode("ascii").lower()
    elif path == PROBE_PATHS[1]:
        build = parse_nitro_build(data)
        if build:
            item["nitro_build"] = build
    elif path == PROBE_PATHS[2]:
        stamp, build = parse_gzip_stamp(data)
        if stamp is not None:
            item["gzip_mtime"] = stamp
        if build:
            item["gzip_lookup_build"] = build
    return item


def _scan_one(target, timeout, probe_func):
    context = None
    if target["scheme"] == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    hosts = []
    builds = set()
    for hostname in target["hostnames"][:MAX_HOSTNAMES]:
        observations = []
        for path in PROBE_PATHS:
            try:
                response = probe_func(target["ip"], target["port"], hostname, path,
                                      scheme=target["scheme"], method="GET", timeout=timeout,
                                      max_body=MAX_BODY, context=context)
            except Exception:
                response = {"status": None, "headers": {}, "data": b"",
                            "truncated": False, "error": "request_failed"}
            observation = _observation(path, response)
            observations.append(observation)
            for name in ("nitro_build", "gzip_lookup_build"):
                if name in observation:
                    builds.add(observation[name])
        hosts.append({"hostname": hostname, "observations": observations})
    status = "unknown" if not builds else "conflict" if len(builds) > 1 else "single_candidate"
    return {"ip": target["ip"], "port": target["port"],
            "scheme": target["scheme"], "version_status": status,
            "candidate_builds": sorted(builds), "hosts": hosts}


def collect_followup(targets, *, approved_hostnames=None, timeout=5,
                     threads=2, probe_func=None):
    """Run bounded pinned probes and return a JSON-safe evidence report."""
    if not approved_hostnames:
        raise ValueError("explicit approved hostnames are required")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT):
        raise ValueError("timeout must be greater than zero and at most 15 seconds")
    if isinstance(threads, bool) or not isinstance(threads, int) or not 1 <= threads <= MAX_THREADS:
        raise ValueError("threads must be between 1 and 4")
    filtered_targets = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("target must be an object")
        key = _endpoint(target.get("ip"), target.get("port"))
        names = target.get("hostnames")
        scheme = target.get("scheme", "https")
        if key is None or not isinstance(names, list) or scheme not in ("http", "https"):
            raise ValueError("target needs an IP, port, and hostname list")
        filtered = []
        for raw in names:
            name = _fqdn(raw)
            if (name and (key[0], key[1], name) in approved_hostnames
                    and name not in filtered and len(filtered) < MAX_HOSTNAMES):
                filtered.append(name)
        if filtered:
            filtered_targets.append({"ip": key[0], "port": key[1],
                                     "scheme": scheme, "hostnames": filtered})
    probe = probe_func if probe_func is not None else probe_vhost
    with ThreadPoolExecutor(max_workers=threads) as executor:
        endpoints = list(executor.map(lambda target: _scan_one(target, timeout, probe),
                                      filtered_targets))
    return {
        "mode": "live_vhost_followup",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "transport": "HTTP/HTTPS with TCP IP and port pinned; TLS certificate validation disabled for HTTPS",
        "patch_status": "not_assessed",
        "summary": {
            "selected_endpoints": len(filtered_targets),
            "candidate_hostnames": sum(len(target["hostnames"])
                                       for target in filtered_targets),
            "requests": sum(len(host["observations"]) for endpoint in endpoints
                            for host in endpoint["hosts"]),
            "build_conflicts": sum(endpoint["version_status"] == "conflict"
                                   for endpoint in endpoints),
            "unknown_builds": sum(endpoint["version_status"] == "unknown"
                                  for endpoint in endpoints),
        },
        "endpoints": endpoints,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Collect sanitized Host/SNI evidence on already authorized live endpoints")
    parser.add_argument("--shodan-export", required=True, type=Path,
                        help="Shodan JSONL file providing candidate hostnames")
    parser.add_argument("--live-report", required=True, type=Path,
                        help="Existing CitrixScan live JSON report")
    parser.add_argument("--approved-hostnames", required=True, type=Path,
                        help="Explicit CSV allowlist with ip,port,hostname columns")
    parser.add_argument("--output-json", required=True, type=Path,
                        help="Write sanitized evidence JSON")
    parser.add_argument("--timeout", type=float, default=5,
                        help="Per-request timeout in seconds, maximum 15")
    parser.add_argument("--threads", type=int, default=2,
                        help="Concurrent endpoints, maximum 4")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= MAX_TIMEOUT:
        parser.error("--timeout must be greater than zero and at most 15")
    if not 1 <= args.threads <= MAX_THREADS:
        parser.error("--threads must be between 1 and 4")
    for input_path in (args.shodan_export, args.live_report, args.approved_hostnames):
        if (args.output_json.resolve() == input_path.resolve() or
                (args.output_json.exists() and input_path.exists() and
                 args.output_json.samefile(input_path))):
            parser.error("--output-json must differ from every input file")
    try:
        approved = load_approved_hostnames(args.approved_hostnames)
        targets = load_targets(args.shodan_export, args.live_report,
                               approved_hostnames=approved)
        report = collect_followup(targets, approved_hostnames=approved,
                                  timeout=args.timeout, threads=args.threads)
        with open(args.output_json, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Follow-up evidence for {len(targets)} endpoints written to {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
