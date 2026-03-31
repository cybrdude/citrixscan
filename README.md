# CitrixScan

**Full-scope external security scanner for Citrix NetScaler ADC and NetScaler Gateway appliances.**
---

## What It Does

CitrixScan performs a comprehensive, non-exploitative security assessment of internet-facing Citrix NetScaler appliances. It identifies the firmware version, maps it against 25 known CVEs spanning 2019–2026, detects vulnerable configurations, checks for indicators of compromise, and audits TLS and security headers — all without authentication.

### Scan Modules

| Module | What It Checks |
|---|---|
| **Version Fingerprinting** | 10 detection vectors including GZIP timestamp extraction (Fox-IT technique), NITRO API probing, EPA binary PE analysis, HTTP header parsing, and static resource hashing |
| **CVE Assessment** | 25 CVEs with version-to-fix mapping, configuration prerequisite validation, in-the-wild exploitation tracking, and public PoC status |
| **IoC Detection** | 15 known webshell/backdoor paths from CVE-2023-3519 campaigns, CISA AA23-201A indicators, with content-based analysis that distinguishes stock NetScaler files from actual implants |
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

25 CVEs spanning 2019–2026. Each entry includes CVSS score, affected version ranges, fixed versions per branch, configuration prerequisites, in-the-wild exploitation status, and public PoC availability.

| CVE | CVSS | Severity | Name | ITW | PoC |
|---|---|---|---|---|---|
| CVE-2019-19781 | 9.8 | CRITICAL | Path Traversal RCE (Shitrix) | 🔥 | ⚡ |
| CVE-2022-27510 | 9.8 | CRITICAL | Authentication Bypass | 🔥 | ⚡ |
| CVE-2022-27518 | 9.8 | CRITICAL | Unauthenticated RCE (SAML) | 🔥 | ⚡ |
| CVE-2023-3519 | 9.8 | CRITICAL | Unauthenticated RCE (Stack Overflow) | 🔥 | ⚡ |
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

### CVE Applicability Logic

Each CVE has defined configuration prerequisites. For example, CVE-2026-3055 requires SAML IDP configuration and CVE-2026-4368 requires Gateway or AAA vServer configuration. CitrixScan detects these configurations externally and reports whether the vulnerability is confirmed applicable or unconfirmed (requires CLI verification):

```
CVE-2026-3055  CVSS  9.3 CRITICAL  [SAML IDP] ✓ config confirmed
CVE-2026-4368  CVSS  7.7 HIGH      [Gateway]  ✓ config confirmed
CVE-2025-12101 CVSS  5.1 MEDIUM               ? config unconfirmed
```

---

## IoC Detection

Probes 15 paths associated with known post-exploitation activity, primarily from CVE-2023-3519 campaigns documented in [CISA Advisory AA23-201A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a).

### Content-Based Analysis

The scanner distinguishes between:

- **Stock NetScaler files** (e.g., `newbm.pl`, `rmbm.pl`) — legitimate bookmark management scripts that ship with every Gateway install. These are not flagged.
- **Trojaned stock files** — Stock paths containing webshell indicators (PHP eval, system calls, etc.). Flagged as CRITICAL.
- **Non-stock webshells** — Files at IoC paths with malicious content. Flagged as CRITICAL with content preview.
- **Modified stock files** — Stock paths with unexpected content not matching legitimate signatures. Flagged as HIGH.

Each finding includes a content preview (first 150 characters) so analysts can validate without manual investigation.

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
| **CRITICAL** | IoC detected, EOL software, in-the-wild exploited CVE, or critical misconfiguration |
| **HIGH** | Critical-severity CVE (no ITW), or unknown version with vulnerable config detected |
| **MEDIUM** | High-severity CVEs, or NetScaler with unknown version |
| **LOW** | Fully patched, no findings |
| **INFO** | Not a NetScaler or not reachable |

---

## Output Formats

| Format | Flag | Best For |
|---|---|---|
| **JSON** | `-o report.json` | SIEM ingestion, programmatic processing |
| **CSV** | `--csv report.csv` | Spreadsheets, ticketing systems |
| **Markdown** | `--markdown report.md` | Executive reporting, wiki, Slack/Teams |
| **Terminal** | (default) | Interactive use. Add `-v` for verbose. |

---

## CLI Reference

```
usage: citrixscan.py [-h] [-f FILE] [-p PORT] [-t TIMEOUT] [--threads N]
                     [-o JSON] [--csv CSV] [--markdown MD] [-v]
                     [--modules MODULES] [--no-deep] [--list-cves] [--version]
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
| `--no-deep` | Skip EPA binary download | off |
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
  ├── CVE mapping (25-entry database)
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
