# Changelog

All notable changes to CitrixScan will be documented in this file.

## 2026-10-02

### Defender alerts and post-patch review

- Added a local `ns.conf` screen for the separate [NetScaler SAML authentication guidance](https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/). It identifies a SAML action or IdP profile alongside a Gateway/AAA virtual server without placing configuration contents in reports; it does not assert a CVE or fixed build.
- Added `--fail-on-risk` and `--fail-on-saml-match` for automation, with distinct finding and incomplete-scan exit codes.
- Clarified that selected external IoC checks cannot rule out pre-patch compromise. Linked [CISA's advisory](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465) and [Citrix's response steps](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html) for evidence preservation and investigation.
- Corrected LOW/INFO risk descriptions and documented that `--no-deep` skips EPA binary downloads while retaining other version probes.
- Classified edition-ambiguous 13.1 builds as unassessed, corrected stock-path and content matching in IoC checks, kept redirects on the requested HTTPS host, and marked missing HTTPS responses and failed targets as incomplete scans.

## 2026-10-01

### CVE-2026-88771

- Added version-based detection for the unauthenticated remote code execution vulnerability in customer-managed NetScaler ADC and NetScaler Gateway, including default configurations.
- Added fixed-build thresholds for 14.1, 13.1, 14.1-FIPS, and 13.1-FIPS/NDcPP, with a reminder to verify the appliance edition when an external scan cannot identify it.
- Marked the CVE as exploited in the wild, as reported in [Citrix bulletin CTX697096](https://support.citrix.com/external/article/CTX697096/netscaler-adc-and-netscaler-gateway-secu.html).
- Continued version checks after an unrecognized GZIP timestamp and retained FIPS/NDcPP edition markers in version responses.
- Included detected CVE IDs in CSV reports and flagged edition uncertainty when build thresholds differ.
- Listed older CVEs without FIPS/NDcPP fix mappings as unassessed instead of applying standard-release thresholds.

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
