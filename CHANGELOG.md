# Changelog

All notable changes to CitrixScan will be documented in this file.

## [1.0.0] - 2026-03-25

### Initial Release

**Version Fingerprinting (10 vectors)**
- GZIP timestamp extraction from `rdx_en.json.gz` (Fox-IT technique) with 228-entry lookup table
- NITRO API `/nitro/v1/config/nsversion` and `/nsversion` probing with login-page filtering
- HTTP response header analysis (`Server`, `X-NS-version`, `Via`, `X-NS-Build`)
- Response body firmware pattern matching (HTML, JS, XML)
- EPA binary (`nsepa_setup.exe`) PE string scan with Windows build number rejection
- EPA Content-Length fingerprinting
- ETag header correlation
- Login page hash fingerprinting
- TLS certificate CN/SAN analysis
- Plugin version filtering (rejects VPN client versions 20.x+ from `pluginlist.xml`)

**CVE Database (25 entries, 2019–2026)**
- 9 CRITICAL, 10 HIGH, 6 MEDIUM severity
- 10 CVEs with known in-the-wild exploitation
- 10 CVEs with public proof-of-concept
- Per-CVE configuration prerequisite mapping (SAML IDP, Gateway, AAA, Management)
- Version-to-fix mapping across all supported branches (14.1, 13.1, 13.1-FIPS, 13.0, 12.1)

**IoC Detection**
- 15 known webshell/backdoor paths from CVE-2023-3519 campaigns and CISA AA23-201A
- Content-based analysis distinguishing stock files from webshells
- Stock NetScaler file allowlist (`newbm.pl`, `rmbm.pl`, `ns_gui.pl`)
- Content preview for all findings

**Misconfiguration Audit**
- 12 sensitive path checks (NITRO API, management UI, config files, logs, diagnostics)
- Login page false positive filtering (20+ markers)

**TLS Audit**
- Protocol version check (TLSv1.0/1.1 flagged)
- Cipher strength analysis (weak/deprecated cipher detection)
- Certificate expiry monitoring

**Security Headers**
- HSTS, X-Frame-Options, CSP, X-Content-Type-Options
- Server version disclosure detection

**Output**
- JSON structured reports
- CSV flat exports (UTF-8)
- Markdown reports with tables and risk indicators
- Color-coded terminal output with content previews

**Infrastructure**
- Single file, zero external dependencies (Python 3.8+ stdlib only)
- Multi-threaded concurrent scanning
- Non-exploitative, production-safe
