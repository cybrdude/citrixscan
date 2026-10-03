# CitrixScan

**External security scanner for Citrix NetScaler ADC and NetScaler Gateway appliances.**
---

## What It Does

CitrixScan performs a non-exploitative security assessment of internet-facing Citrix NetScaler appliances. It attempts to identify the firmware version, maps it against 26 known CVEs spanning 2019–2026, screens detectable configurations and selected indicators of compromise (IoCs), and audits TLS and security headers — all without appliance authentication. External results need confirmation on the appliance, especially when the version or edition is unknown.

### Scan Modules

| Module | What It Checks |
|---|---|
| **Version Fingerprinting** | 10 detection vectors including GZIP timestamp extraction (Fox-IT technique), NITRO API probing, EPA binary PE analysis, HTTP header parsing, and static resource hashing |
| **CVE Assessment** | 26 CVEs with version-to-fix mapping, configuration prerequisite validation, in-the-wild exploitation tracking, and public PoC status |
| **IoC Detection** | 15 paths associated with webshell activity, primarily from CVE-2023-3519 campaigns and CISA AA23-201A; content checks help prioritize investigation, but cannot prove or rule out compromise |
| **Misconfiguration Audit** | 12 paths checked for exposed management interfaces, unauthenticated NITRO API access, configuration file exposure, and diagnostic data leaks — with login-page false positive filtering |
| **TLS Audit** | Protocol version, cipher strength, deprecated cipher detection, certificate expiry |
| **Security Headers** | HSTS, X-Frame-Options, CSP, X-Content-Type-Options, server version disclosure |
| **Configuration Detection** | SAML IDP, SAML SP, Gateway/VPN, AAA vServer, management interface exposure |

---

## Quick Start

```bash
# Scan a single target
python3 citrixscan.py 10.0.0.1

# Multiple targets with full reporting
python3 citrixscan.py 10.0.0.1 10.0.0.2 10.0.0.3 \
  -v -o report.json --csv report.csv --markdown report.md

# Bulk scan from file
python3 citrixscan.py -f targets.txt --threads 10 -o results.json

# List all CVEs in the database
python3 citrixscan.py --list-cves

# Skip EPA binary download (faster scan)
python3 citrixscan.py 10.0.0.1 --no-deep -v

# Alert an automation when a target reaches HIGH or CRITICAL risk
python3 citrixscan.py 10.0.0.1 --fail-on-risk high -o report.json

# Screen a local ns.conf for the separate NetScaler SAML advisory
python3 citrixscan.py 10.0.0.1 --saml-config /path/to/ns.conf --fail-on-saml-match
```

### Requirements

- **Python 3.8+**
- **No external dependencies** — stdlib only
- Network access to target(s) on HTTPS port

---

## Version Fingerprinting

Identifying the firmware version is the foundation of vulnerability assessment. CitrixScan uses 10 detection vectors, tried in priority order:

### 1. GZIP Timestamp Extraction (Primary — Highest Accuracy)

The most reliable unauthenticated fingerprinting technique available. Every NetScaler build ships a compressed language resource file at `/vpn/js/rdx/core/lang/rdx_en.json.gz`. The GZIP file format (RFC 1952) stores a modification timestamp in bytes 4-8 of the header (`MTIME` field). This timestamp is set during firmware compilation and uniquely identifies the build.

CitrixScan embeds a **228-entry lookup table** mapping known timestamps to exact firmware versions, covering every release from 12.1-49.23 (August 2018) through 14.1-66.59 (November 2025).

Credit: [Fox-IT Security Research Team](https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/)

**Known limitation:** Some builds compress this file with `gzip -n`, which zeroes out the MTIME field. In those cases, the scanner falls through to other detection vectors.
An MTIME that is absent from the lookup table also falls through to other version sources. If no source identifies the build, the report keeps the version unknown and asks for appliance verification.

### 2. NITRO API

Probes `/nitro/v1/config/nsversion` and `/nsversion`. Some appliances return the version in JSON without authentication. Includes login-page false positive filtering — if the response is an HTML login portal instead of JSON, it's correctly rejected.

### 3. HTTP Response Headers

Scans `Server`, `X-NS-version`, `X-Citrix-Version`, `Via`, and `X-NS-Build` headers across all probed endpoints.

### 4. Response Body Firmware Patterns

Regex-scans HTML, JavaScript, and XML responses for firmware-specific strings like `NS14.1: Build 65.11`.

### 5. EPA Binary PE Analysis

Downloads the Endpoint Analysis client (`nsepa_setup.exe`) and scans the PE binary for embedded NetScaler firmware version strings. Includes strict validation to reject Windows build numbers (e.g., `11.0.20348.1`) that are present in the PE metadata but represent the Windows SDK version, not NetScaler firmware.

### 6-10. Additional Vectors

Content-Length fingerprinting, ETag correlation, login page hash mapping, TLS certificate CN/SAN analysis, and plugin version filtering (to reject VPN client versions like `25.5.x.x` that appear in `pluginlist.xml`).

### What If Version Can't Be Determined?

Some hardened appliances gate every resource path (including static files) behind authentication. When this happens, CitrixScan provides detailed diagnostics explaining exactly which paths were tried and what each returned, along with actionable guidance:

```
VERSION UNKNOWN: Authenticate and run 'show ns version' to confirm patch status.
  → Fingerprint diagnostic: rdx_en.json.gz — GZIP valid but MTIME=0 (timestamp stripped)
  → Vulnerable config detected. ASSUME VULNERABLE until version confirmed.
  → EPA binary downloadable. Download nsepa_setup.exe and check file properties.
  → Or use NITRO API with credentials: curl -k -u nsroot:pass https://<IP>/nitro/v1/config/nsversion
```

---

## CVE Database

26 CVEs spanning 2019–2026. Each entry includes CVSS score, affected version ranges, fixed versions per branch, configuration prerequisites, in-the-wild exploitation status, and public PoC availability.

| CVE | CVSS | Severity | Name | ITW | PoC |
|---|---|---|---|---|---|
| CVE-2019-19781 | 9.8 | CRITICAL | Path Traversal RCE (Shitrix) | 🔥 | ⚡ |
| CVE-2022-27510 | 9.8 | CRITICAL | Authentication Bypass | 🔥 | ⚡ |
| CVE-2022-27518 | 9.8 | CRITICAL | Unauthenticated RCE (SAML) | 🔥 | ⚡ |
| CVE-2023-3519 | 9.8 | CRITICAL | Unauthenticated RCE (Stack Overflow) | 🔥 | ⚡ |
| CVE-2026-88771 | 9.5 | CRITICAL | Unauthenticated RCE (Improper Input Validation) | 🔥 | |
| CVE-2023-4966 | 9.4 | CRITICAL | CitrixBleed | 🔥 | ⚡ |
| CVE-2025-5777 | 9.3 | CRITICAL | CitrixBleed 2 | 🔥 | ⚡ |
| CVE-2026-3055 | 9.3 | CRITICAL | Memory Overread (SAML IDP) | | |
| CVE-2025-7775 | 9.2 | CRITICAL | CitrixBleed 3 (RCE/DoS) | 🔥 | ⚡ |
| CVE-2025-6543 | 9.2 | CRITICAL | Memory Overflow (Gateway) | 🔥 | |
| CVE-2025-7776 | 8.8 | HIGH | Memory Overflow (PCoIP) | | |
| CVE-2025-8424 | 8.7 | HIGH | Management Interface Access Control | | |
| CVE-2024-8534 | 8.4 | HIGH | Memory Safety Violation (DoS) | | |
| CVE-2023-3466 | 8.3 | HIGH | Reflected XSS | | ⚡ |
| CVE-2023-6549 | 8.2 | HIGH | Buffer Overflow DoS (Zero-Day) | 🔥 | ⚡ |
| CVE-2023-3467 | 8.0 | HIGH | Privilege Escalation to Root | | ⚡ |
| CVE-2026-4368 | 7.7 | HIGH | Race Condition Session Mixup | | |
| CVE-2023-4967 | 7.5 | HIGH | Denial of Service | | |
| CVE-2021-22927 | 7.5 | HIGH | Session Fixation (SAML) | | |
| CVE-2024-5491 | 7.1 | HIGH | Unauthenticated DoS | | |
| CVE-2020-8300 | 6.5 | MEDIUM | SAML Authentication Hijack | | |
| CVE-2024-8535 | 5.8 | MEDIUM | Privilege Escalation | | |
| CVE-2023-6548 | 5.5 | MEDIUM | Authenticated RCE (Mgmt Interface) | 🔥 | |
| CVE-2025-12101 | 5.1 | MEDIUM | Information Disclosure | | |
| CVE-2025-5349 | 5.1 | MEDIUM | Management Interface Access Control | | |
| CVE-2024-5492 | 5.1 | MEDIUM | Open Redirect | | |

**🔥** Exploited in the wild &ensp; **⚡** Public PoC available

Run `python3 citrixscan.py --list-cves` for the full interactive table.

### CVE-2026-88771: fixed builds

[Citrix bulletin CTX697096](https://support.citrix.com/external/article/CTX697096/netscaler-adc-and-netscaler-gateway-secu.html) reports that CVE-2026-88771 permits unauthenticated remote code execution and that exploitation of unmitigated deployments has been observed. All affected customer-managed NetScaler ADC and NetScaler Gateway deployments are exposed, including default configurations; no additional feature needs to be enabled.

| Product and edition | First fixed build |
|---|---|
| NetScaler ADC and NetScaler Gateway 14.1 | 14.1-73.37 |
| NetScaler ADC and NetScaler Gateway 13.1 | 13.1-64.23 |
| NetScaler ADC 14.1-FIPS | 14.1-73.37 FIPS |
| NetScaler ADC 13.1-FIPS and 13.1-NDcPP | 13.1-37.279 |

If the scanner cannot identify the firmware build or distinguish a FIPS/NDcPP edition, verify both on the appliance with `show ns version` before deciding whether it is patched. Compare the result with the corresponding edition and branch in Citrix's bulletin.
When the 13.1 standard and FIPS/NDcPP thresholds would give different answers for an unlabelled build, CitrixScan lists CVE-2026-88771 as unassessed until the edition is confirmed. It does not count that case as a confirmed vulnerability or a confirmed fix.
For a known FIPS/NDcPP edition, older database entries without an edition-specific fix are listed as unassessed. The scanner does not substitute standard-release patch thresholds for those entries.

### Separate NetScaler SAML advisory (October 2, 2026)

Citrix issued [security update guidance for NetScaler SAML authentication deployments](https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/) separately from bulletin CTX697096 and CVE-2026-88771. No CVE identifier or fixed-build thresholds were available for this SAML guidance at the time of this update, so CitrixScan does not label a build vulnerable or patched for it.

Use `--saml-config FILE` with exactly one target to screen a **local** NetScaler `ns.conf` export. The screen looks for a SAML action (`samlAction`) or SAML identity provider profile (`samlIdPProfile`) together with a Gateway or AAA virtual server. A match signals a deployment that should be reviewed against Citrix's guidance; it does not establish that the configuration is exploitable. Confirm the effective configuration and remediation on the appliance. The file is not sent to the target and its contents are not included in scanner reports. Treat the export as sensitive and follow your organization's handling rules.

The external scan's SAML heuristics are separate from this local configuration screen. An absent external SAML signal cannot clear a deployment under the new guidance.

### CVE Applicability Logic

Some CVEs have configuration prerequisites. For example, CVE-2026-3055 requires SAML IDP configuration and CVE-2026-4368 requires Gateway or AAA vServer configuration. CVE-2026-88771 applies to affected builds in the default configuration. CitrixScan reports whether detectable prerequisites are confirmed or unconfirmed (requires CLI verification):

```
CVE-2026-3055  CVSS  9.3 CRITICAL  [SAML IDP] ✓ config confirmed
CVE-2026-4368  CVSS  7.7 HIGH      [Gateway]  ✓ config confirmed
CVE-2025-12101 CVSS  5.1 MEDIUM               ? config unconfirmed
```

---

## IoC Detection

Probes 15 paths associated with known post-exploitation activity, primarily from CVE-2023-3519 campaigns documented in [CISA Advisory AA23-201A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a).

These are selected external HTTP checks, not a forensic assessment or a complete IoC set for CVE-2026-88771. A path or content match requires analyst validation; a clean result does not establish that the appliance was never compromised. Patching closes a known vulnerability but does not remove an implant or undo access gained earlier. [CISA's 2026 alert](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465) urges organizations to check for compromise before patching where possible and preserve evidence because updates may reduce forensic visibility. For suspected compromise, follow [Citrix's recovery guidance](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html) with your incident response team.

### Content-Based Analysis

The scanner distinguishes between:

- **Stock NetScaler files** (e.g., `newbm.pl`, `rmbm.pl`) — legitimate bookmark management scripts that ship with every Gateway install. These are not flagged.
- **Stock files with suspicious content** — Stock paths containing webshell indicators (PHP eval, system calls, etc.). Flagged as CRITICAL for investigation.
- **Unexpected files at checked paths** — Non-stock paths with suspicious content. Flagged as CRITICAL with content preview for investigation.
- **Modified stock files** — Stock paths with unexpected content not matching legitimate signatures. Flagged as HIGH.

Each finding includes a short content preview to help analysts triage it. Confirm suspicious files and activity through authenticated appliance and log review.

---

## Misconfiguration Detection

Probes 12 paths for security misconfigurations:

| Category | Paths Checked | Severity |
|---|---|---|
| NITRO API exposure | `/nitro/v1/config/nsconfig`, `/nsip`, `/sslcertkey`, `/nshardware`, `/stat/system` | CRITICAL / HIGH |
| Management interface | `/menu/neo`, `/menu/ss`, `/gui/` | CRITICAL |
| Configuration files | `/nsconfig/ns.conf` | CRITICAL |
| Log files | `/var/log/ns.log` | CRITICAL |
| Diagnostic data | `/var/nslog/newnslog`, `/var/nstrace/` | HIGH |

### Login Page False Positive Filtering

Many NetScaler appliances return the login portal HTML with `200 OK` for any unauthenticated request path. CitrixScan detects this pattern using 20+ login page markers (including `logonpoint`, `receiver.appcache`, `visibility: hidden`, `noindex, nofollow`) and only flags endpoints that return actual content — JSON API responses, configuration file syntax, log data, or real management UI HTML.

---

## Risk Rating

| Rating | Criteria |
|---|---|
| **CRITICAL** | Critical potential IoC, EOL branch, critical CVE, known exploited applicable CVE, or critical misconfiguration |
| **HIGH** | High-severity potential IoC, high-severity CVE, unassessed CVEs for an edition, high-severity TLS finding, or unknown version with a detectable configuration prerequisite |
| **MEDIUM** | Medium-severity potential IoC, other applicable CVEs, or identified NetScaler with unknown version |
| **LOW** | Identified NetScaler with a version and no modeled findings in the selected modules; this does not prove patch or compromise status |
| **INFO** | Not identified as NetScaler or not reachable; review reachability and identification errors separately |

---

## Output Formats

| Format | Flag | Best For |
|---|---|---|
| **JSON** | `-o report.json` | SIEM ingestion, programmatic processing |
| **CSV** | `--csv report.csv` | Spreadsheets, ticketing systems; includes detected CVE IDs |
| **Markdown** | `--markdown report.md` | Executive reporting, wiki, Slack/Teams |
| **Terminal** | (default) | Interactive use. Add `-v` for verbose. |

### Automation exit codes

Use `--fail-on-risk {medium,high,critical}` to alert when any target reaches the selected rating or higher. Use `--fail-on-saml-match` with `--saml-config FILE` to alert when the local configuration screen matches. Exit codes are **0** for a completed scan without selected findings, **1** for input or report errors, **2** for selected findings, **3** for an incomplete scan, and **4** when both a finding and incomplete coverage occur. Treat **2 or 4** as a finding and **3 or 4** as incomplete coverage. These flags set process status for a scheduler or SIEM collector; CitrixScan does not send messages itself. Preserve the JSON, CSV, or Markdown report for investigation.

---

## CLI Reference

```
usage: citrixscan.py [-h] [-f FILE] [-p PORT] [-t TIMEOUT] [--threads N]
                     [-o JSON] [--csv CSV] [--markdown MD] [-v]
                     [--modules MODULES] [--no-deep] [--saml-config FILE]
                     [--fail-on-risk {medium,high,critical}]
                     [--fail-on-saml-match] [--list-cves] [--version]
                     [targets ...]
```

| Flag | Description | Default |
|---|---|---|
| `targets` | Target IPs or hostnames (space-separated) | — |
| `-f FILE` | Target list file (one per line, `#` for comments) | — |
| `-p PORT` | HTTPS port | 443 |
| `-t SEC` | Timeout per request (seconds) | 15 |
| `--threads N` | Concurrent scan threads | 5 |
| `-o FILE` | JSON report output path | — |
| `--csv FILE` | CSV report output path | — |
| `--markdown FILE` | Markdown report output path | — |
| `-v` | Verbose (paths, ETags, headers, TLS) | off |
| `--modules LIST` | `all`, `cve`, `ioc`, `misconfig`, `tls`, `headers` | `all` |
| `--no-deep` | Skip EPA binary GET/download; retain HEAD/size and other version probes | off |
| `--saml-config FILE` | Screen a local `ns.conf` for SAML action or IdP profile plus Gateway/AAA vServer; requires one target | — |
| `--fail-on-risk LEVEL` | Set finding status if any target's risk is at least `medium`, `high`, or `critical` | — |
| `--fail-on-saml-match` | Set finding status when `--saml-config` finds the SAML deployment pattern | off |
| `--list-cves` | Print CVE database and exit | — |
| `--version` | Print version and exit | — |

---

## Architecture

Single Python file (~2,100 lines), zero external dependencies, stdlib only.

### Scan Phases

```
Phase 1: Standard Fingerprinting
  ├── 7 well-known NetScaler endpoints
  ├── Product detection (signal scoring)
  ├── Configuration detection (SAML IDP, Gateway, AAA)
  └── ETag collection

Phase 2: Extended Probing
  ├── GZIP timestamp extraction (rdx_en.json.gz)
  ├── NITRO API / nsversion endpoints
  ├── JavaScript/CSS resource probing
  └── Version pattern matching

Phase 3: Deep Analysis
  ├── EPA binary download + PE string scan
  ├── Content-Length fingerprinting
  └── Login page hash fingerprinting

Phase 4: Security Assessment
  ├── CVE mapping (26-entry database)
  ├── IoC detection (15 paths, content analysis)
  ├── Misconfiguration checks (12 paths, login-page filtering)
  ├── TLS audit
  └── Security header checks
```

---

## Contributing

Contributions welcome via pull request:

- **GZIP timestamp mappings** — New `stamp → version` entries for the `RDX_EN_STAMP_TO_VERSION` dict
- **CVE entries** — New CVEs following the `CVEEntry` dataclass format
- **IoC paths** — Webshell/backdoor paths from incident response engagements
- **EPA size mappings** — Known EPA binary sizes for the `EPA_SIZE_MAP` dict
- **Page hash mappings** — Login page SHA256 hashes for `KNOWN_PAGE_HASHES`

---

## Acknowledgments

- [**Fox-IT Security Research Team**](https://github.com/fox-it/citrix-netscaler-triage) — GZIP timestamp fingerprinting technique and version lookup table
- [**CISA**](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a) — IoC indicators from Advisory AA23-201A
- **Rapid7**, **Arctic Wolf**, **watchTowr** — CVE analysis and advisory context
- [**tijldeneut**](https://github.com/tijldeneut/Security/blob/master/Fingerprinters/CitrixNS-fingerprinter.py) — Citrix NetScaler fingerprinting script
---

## Disclaimer

This tool is intended for **authorized security assessments only**. Obtain proper written authorization before scanning systems you do not own. The authors assume no liability for unauthorized use.

## License

[MIT](LICENSE)

## Author

**NetGuard 24/7 LLC** — [netguard24-7.com](https://netguard24-7.com)
