# Contributing to CitrixScan

Thank you for your interest in contributing. CitrixScan benefits directly from community intelligence — every new fingerprint, CVE entry, and IoC path improves detection accuracy for everyone.

## How to Contribute

### 1. GZIP Timestamp Fingerprints (Highest Impact)

If you manage NetScaler appliances and can correlate the `rdx_en.json.gz` GZIP timestamp with a known firmware version:

```bash
# On your NetScaler CLI:
show ns version

# Then scan it:
python3 citrixscan.py <your-netscaler-ip> -v
# Look for: "GZIP timestamp ... (not in lookup table)"
```

Submit the `stamp → version` mapping via a [New Fingerprint issue](../../issues/new?template=new-fingerprint.md) or PR adding the entry to `RDX_EN_STAMP_TO_VERSION`.

### 2. New CVEs

When Citrix publishes a new security advisory:

1. Create a `CVEEntry` following the existing format in `CVE_DATABASE`
2. Include all affected version ranges and fixed versions
3. Document the configuration prerequisites
4. Submit a PR or [New CVE issue](../../issues/new?template=new-cve.md)

### 3. IoC Paths

From incident response engagements on compromised NetScaler devices:

1. Document the path, content type, and which campaign it's associated with
2. Note if there's a legitimate stock file at the same path (to add to the allowlist)
3. Submit via [New IoC issue](../../issues/new?template=new-ioc.md)

### 4. EPA Content-Length and Page Hash Mappings

If you can correlate an EPA binary file size or login page hash with a known version, add entries to `EPA_SIZE_MAP` or `KNOWN_PAGE_HASHES`.

## Code Guidelines

- **Zero dependencies** — CitrixScan uses Python stdlib only. Do not add external package requirements.
- **Single file** — All code stays in `citrixscan.py`. This is a design decision for portability.
- **Non-exploitative** — No payloads, no authentication bypass, no active exploitation. Standard HTTP GET/HEAD only.
- **Test your changes** — Run against known-version appliances before submitting.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b add-cve-2026-xxxx`)
3. Make your changes
4. Test against at least one real NetScaler appliance (or describe your test methodology)
5. Submit the PR with a clear description of what was added/changed

## Code of Conduct

Be professional. This is a security tool used by defenders. Contributions that enable offensive exploitation or target specific organizations will be rejected.
