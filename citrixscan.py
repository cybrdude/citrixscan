#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CitrixScan - NetScaler Security Scanner                   ║
║                                                                              ║
║  Comprehensive external security assessment for Citrix NetScaler ADC         ║
║  and NetScaler Gateway appliances.                                           ║
║                                                                              ║
║  Author  : NetGuard 24/7 LLC (netguard24-7.com) & Contributors               ║
║  License : MIT                                                               ║
║  Version : 1.0.1                                                             ║
║  Date    : 2026-03-30                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

CAPABILITIES:
  ▸ Multi-vector version fingerprinting (9 detection methods)
  ▸ Comprehensive CVE database (2019-2026, 25+ CVEs with fix versions)
  ▸ Configuration exposure detection (SAML IDP, Gateway, AAA, GSLB, mgmt)
  ▸ TLS/SSL security audit (protocols, cipher strength, cert validity)
  ▸ Indicator of Compromise (IoC) detection (webshells, backdoors)
  ▸ Security misconfiguration checks (exposed mgmt, info leaks, headers)
  ▸ Post-exploitation artifact detection
  ▸ JSON, CSV, and Markdown report export
  ▸ Multi-threaded concurrent scanning
  ▸ OPSEC-safe: non-exploitative, no auth required, production-safe

USAGE:
  python3 citrixscan.py <targets> [options]
  python3 citrixscan.py -f targets.txt -o report.json --csv report.csv -v
  python3 citrixscan.py 10.0.0.1 10.0.0.2 --modules all --threads 10

DETECTION METHOD:
  All checks are non-exploitative. The scanner uses HTTP response analysis,
  version fingerprinting, TLS inspection, and path probing. No authentication
  credentials are required or used. No payloads are sent. Safe for production.

DISCLAIMER:
  This tool is intended for authorized security assessments only. Ensure you
  have proper authorization before scanning any systems. The authors assume
  no liability for misuse.
"""

__version__ = "1.0.1"
__author__ = "NetGuard 24/7 LLC & Contributors"
__license__ = "MIT"

import argparse
import csv
import hashlib
import json
import re
import ssl
import socket
import struct
import sys
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum


# ══════════════════════════════════════════════════════════════════════════════
#  CVE DATABASE
# ══════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CVEEntry:
    cve_id: str
    cvss: float
    severity: str
    title: str
    description: str
    advisory: str                      # Citrix CTX article number
    affected_config: List[str]         # Config prerequisites (e.g., ["SAML IDP"])
    affected_versions: Dict[str, str]  # branch -> "before X.Y.Z.W"
    fixed_versions: Dict[str, tuple]   # branch -> (major, minor, build, patch)
    exploited_in_wild: bool
    public_poc: bool
    cwe: str
    references: List[str]


# Comprehensive CVE database for NetScaler ADC and Gateway (2019-2026)
# Each entry maps version ranges to vulnerability status
CVE_DATABASE: List[CVEEntry] = [
    # ── 2026 ──
    CVEEntry(
        cve_id="CVE-2026-3055",
        cvss=9.3, severity="CRITICAL",
        title="Memory Overread via Insufficient Input Validation",
        description="Unauthenticated OOB read leaking sensitive memory (session tokens). Requires SAML IDP configuration.",
        advisory="CTX696300",
        affected_config=["SAML IDP"],
        affected_versions={"14.1": "< 14.1-66.59", "13.1": "< 13.1-62.23", "13.1-FIPS": "< 13.1-37.262"},
        fixed_versions={"14.1": (14,1,66,59), "13.1": (13,1,62,23), "13.1-FIPS": (13,1,37,262)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-125", references=["https://support.citrix.com/article/CTX696300"],
    ),
    CVEEntry(
        cve_id="CVE-2026-4368",
        cvss=7.7, severity="HIGH",
        title="Race Condition Leading to User Session Mixup",
        description="Race condition causes session mixup exposing one user's session to another. Requires Gateway or AAA vServer config.",
        advisory="CTX696300",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-66.59", "13.1": "< 13.1-62.23", "13.1-FIPS": "< 13.1-37.262"},
        fixed_versions={"14.1": (14,1,66,59), "13.1": (13,1,62,23), "13.1-FIPS": (13,1,37,262)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-362", references=["https://support.citrix.com/article/CTX696300"],
    ),
    # ── 2025 ──
    CVEEntry(
        cve_id="CVE-2025-12101",
        cvss=5.1, severity="MEDIUM",
        title="Authenticated User Information Disclosure",
        description="Authenticated information disclosure in NetScaler Console.",
        advisory="CTX694844",
        affected_config=[],
        affected_versions={"14.1": "< 14.1-62.16", "13.1": "< 13.1-55.34"},
        fixed_versions={"14.1": (14,1,62,16), "13.1": (13,1,55,34)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-200", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2025-8424",
        cvss=8.7, severity="HIGH",
        title="Management Interface Improper Access Control",
        description="Improper access control in the NetScaler management interface (NSIP/CLIP/GSLB site IP).",
        advisory="CTX691702",
        affected_config=["Management Interface"],
        affected_versions={"14.1": "< 14.1-47.48", "13.1": "< 13.1-55.34", "13.1-FIPS": "< 13.1-37.226"},
        fixed_versions={"14.1": (14,1,47,48), "13.1": (13,1,55,34), "13.1-FIPS": (13,1,37,226)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-284", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2025-7775",
        cvss=9.2, severity="CRITICAL",
        title="Memory Overflow - RCE/DoS (CitrixBleed 3)",
        description="Memory overflow allowing RCE and/or DoS in various Gateway configurations. Exploited in the wild.",
        advisory="CTX691702",
        affected_config=["Gateway"],
        affected_versions={"14.1": "< 14.1-47.48", "13.1": "< 13.1-55.34", "13.1-FIPS": "< 13.1-37.226"},
        fixed_versions={"14.1": (14,1,47,48), "13.1": (13,1,55,34), "13.1-FIPS": (13,1,37,226)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-119", references=["https://www.vulncheck.com/blog/new-citrix-netscaler-zero-day-vulnerability-exploited-in-the-wild"],
    ),
    CVEEntry(
        cve_id="CVE-2025-7776",
        cvss=8.8, severity="HIGH",
        title="Memory Overflow - DoS via PCoIP Profiles",
        description="Memory overflow causing DoS when Gateway is configured with PCoIP Profiles.",
        advisory="CTX691702",
        affected_config=["Gateway", "PCoIP"],
        affected_versions={"14.1": "< 14.1-47.48", "13.1": "< 13.1-55.34"},
        fixed_versions={"14.1": (14,1,47,48), "13.1": (13,1,55,34)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-119", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2025-6543",
        cvss=9.2, severity="CRITICAL",
        title="Memory Overflow - Unintended Control Flow (CitrixBleed 2.5)",
        description="Unauthenticated memory overflow in Gateway/AAA mode causing unintended control flow or DoS. Actively exploited.",
        advisory="CTX689025",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-38.32", "13.1": "< 13.1-55.27", "13.1-FIPS": "< 13.1-37.220"},
        fixed_versions={"14.1": (14,1,38,32), "13.1": (13,1,55,27), "13.1-FIPS": (13,1,37,220)},
        exploited_in_wild=True, public_poc=False,
        cwe="CWE-119", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2025-5777",
        cvss=9.3, severity="CRITICAL",
        title="Insufficient Input Validation - Memory Overread (CitrixBleed 2)",
        description="Unauthenticated memory leak via uninitialized variable in authentication logic. Leaks session tokens. Widely exploited.",
        advisory="CTX686543",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-29.72", "13.1": "< 13.1-55.18", "13.1-FIPS": "< 13.1-37.211"},
        fixed_versions={"14.1": (14,1,29,72), "13.1": (13,1,55,18), "13.1-FIPS": (13,1,37,211)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-125", references=["https://www.akamai.com/blog/security-research/mitigating-citrixbleed-memory-vulnerability-ase"],
    ),
    CVEEntry(
        cve_id="CVE-2025-5349",
        cvss=5.1, severity="MEDIUM",
        title="Management Interface Improper Access Control",
        description="Improper access control in NetScaler management interface.",
        advisory="CTX686543",
        affected_config=["Management Interface"],
        affected_versions={"14.1": "< 14.1-29.72", "13.1": "< 13.1-55.18"},
        fixed_versions={"14.1": (14,1,29,72), "13.1": (13,1,55,18)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-284", references=[],
    ),
    # ── 2024 ──
    CVEEntry(
        cve_id="CVE-2024-8535",
        cvss=5.8, severity="MEDIUM",
        title="Authenticated User Privilege Escalation",
        description="Authenticated user can access unintended capabilities when NetScaler is configured as Gateway.",
        advisory="CTX691608",
        affected_config=["Gateway"],
        affected_versions={"14.1": "< 14.1-29.72", "13.1": "< 13.1-55.18"},
        fixed_versions={"14.1": (14,1,29,72), "13.1": (13,1,55,18)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-269", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2024-8534",
        cvss=8.4, severity="HIGH",
        title="Memory Safety Violation - DoS",
        description="Memory safety violation causing corruption and DoS on affected configurations.",
        advisory="CTX691608",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-29.72", "13.1": "< 13.1-55.18"},
        fixed_versions={"14.1": (14,1,29,72), "13.1": (13,1,55,18)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-119", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2024-5491",
        cvss=7.1, severity="HIGH",
        title="Unauthenticated Denial of Service",
        description="DoS vulnerability in NetScaler ADC and Gateway.",
        advisory="CTX677888",
        affected_config=[],
        affected_versions={"14.1": "< 14.1-25.53", "13.1": "< 13.1-51.15", "13.0": "< 13.0-92.31"},
        fixed_versions={"14.1": (14,1,25,53), "13.1": (13,1,51,15), "13.0": (13,0,92,31)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-400", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2024-5492",
        cvss=5.1, severity="MEDIUM",
        title="Open Redirect Vulnerability",
        description="Open redirect via crafted URL allowing phishing attacks.",
        advisory="CTX677888",
        affected_config=[],
        affected_versions={"14.1": "< 14.1-25.53", "13.1": "< 13.1-51.15", "13.0": "< 13.0-92.31"},
        fixed_versions={"14.1": (14,1,25,53), "13.1": (13,1,51,15), "13.0": (13,0,92,31)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-601", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2023-6549",
        cvss=8.2, severity="HIGH",
        title="Buffer Overflow - DoS (Zero-Day)",
        description="Unauthenticated buffer overflow causing DoS when configured as Gateway or AAA vServer. Exploited as zero-day.",
        advisory="CTX584986",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-12.35", "13.1": "< 13.1-51.15", "13.0": "< 13.0-92.21"},
        fixed_versions={"14.1": (14,1,12,35), "13.1": (13,1,51,15), "13.0": (13,0,92,21)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-119", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2023-6548",
        cvss=5.5, severity="MEDIUM",
        title="Authenticated RCE on Management Interface",
        description="Authenticated RCE on the management interface (NSIP/CLIP/SNIP). Exploited as zero-day.",
        advisory="CTX584986",
        affected_config=["Management Interface"],
        affected_versions={"14.1": "< 14.1-12.35", "13.1": "< 13.1-51.15", "13.0": "< 13.0-92.21"},
        fixed_versions={"14.1": (14,1,12,35), "13.1": (13,1,51,15), "13.0": (13,0,92,21)},
        exploited_in_wild=True, public_poc=False,
        cwe="CWE-94", references=[],
    ),
    # ── 2023 (Historic but critical — many still unpatched) ──
    CVEEntry(
        cve_id="CVE-2023-4966",
        cvss=9.4, severity="CRITICAL",
        title="Sensitive Information Disclosure (CitrixBleed)",
        description="Unauthenticated buffer-related vulnerability leaking session tokens. Massively exploited by LockBit, BlackCat, and others.",
        advisory="CTX579459",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-8.50", "13.1": "< 13.1-49.15", "13.0": "< 13.0-92.19"},
        fixed_versions={"14.1": (14,1,8,50), "13.1": (13,1,49,15), "13.0": (13,0,92,19)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-119", references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    ),
    CVEEntry(
        cve_id="CVE-2023-4967",
        cvss=7.5, severity="HIGH",
        title="Denial of Service",
        description="DoS vulnerability when configured as Gateway or AAA vServer.",
        advisory="CTX579459",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"14.1": "< 14.1-8.50", "13.1": "< 13.1-49.15", "13.0": "< 13.0-92.19"},
        fixed_versions={"14.1": (14,1,8,50), "13.1": (13,1,49,15), "13.0": (13,0,92,19)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-119", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2023-3519",
        cvss=9.8, severity="CRITICAL",
        title="Unauthenticated RCE via Stack Buffer Overflow",
        description="Stack buffer overflow in nsppe process enabling unauthenticated RCE as root. Requires Gateway/AAA config. Massively exploited; webshell implants widespread.",
        advisory="CTX561482",
        affected_config=["Gateway", "AAA vServer"],
        affected_versions={"13.1": "< 13.1-49.13", "13.0": "< 13.0-91.13", "12.1": "< 12.1-65.35"},
        fixed_versions={"13.1": (13,1,49,13), "13.0": (13,0,91,13), "12.1": (12,1,65,35)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-121", references=["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a"],
    ),
    CVEEntry(
        cve_id="CVE-2023-3466",
        cvss=8.3, severity="HIGH",
        title="Reflected Cross-Site Scripting (XSS)",
        description="Reflected XSS requiring victim on the same network.",
        advisory="CTX561482",
        affected_config=[],
        affected_versions={"13.1": "< 13.1-49.13", "13.0": "< 13.0-91.13", "12.1": "< 12.1-65.35"},
        fixed_versions={"13.1": (13,1,49,13), "13.0": (13,0,91,13), "12.1": (12,1,65,35)},
        exploited_in_wild=False, public_poc=True,
        cwe="CWE-79", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2023-3467",
        cvss=8.0, severity="HIGH",
        title="Privilege Escalation to Root",
        description="Authenticated privilege escalation to root administrator (nsroot).",
        advisory="CTX561482",
        affected_config=[],
        affected_versions={"13.1": "< 13.1-49.13", "13.0": "< 13.0-91.13", "12.1": "< 12.1-65.35"},
        fixed_versions={"13.1": (13,1,49,13), "13.0": (13,0,91,13), "12.1": (12,1,65,35)},
        exploited_in_wild=False, public_poc=True,
        cwe="CWE-269", references=[],
    ),
    # ── 2022 ──
    CVEEntry(
        cve_id="CVE-2022-27518",
        cvss=9.8, severity="CRITICAL",
        title="Unauthenticated RCE (SAML SP/IDP)",
        description="Unauthenticated RCE when configured as SAML SP or SAML IDP. Exploited by APT5/UNC3886.",
        advisory="CTX474995",
        affected_config=["SAML SP", "SAML IDP"],
        affected_versions={"13.0": "< 13.0-58.32", "12.1": "< 12.1-65.25"},
        fixed_versions={"13.0": (13,0,58,32), "12.1": (12,1,65,25)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-119", references=["https://www.mandiant.com/resources/blog/apt5-citrix-adc-backstory"],
    ),
    CVEEntry(
        cve_id="CVE-2022-27510",
        cvss=9.8, severity="CRITICAL",
        title="Authentication Bypass for Gateway User Capabilities",
        description="Unauthorized access to Gateway user capabilities when configured as Gateway.",
        advisory="CTX463706",
        affected_config=["Gateway"],
        affected_versions={"13.1": "< 13.1-33.47", "13.0": "< 13.0-88.12", "12.1": "< 12.1-65.21"},
        fixed_versions={"13.1": (13,1,33,47), "13.0": (13,0,88,12), "12.1": (12,1,65,21)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-288", references=[],
    ),
    # ── 2019-2021 (legacy but still found in the wild) ──
    CVEEntry(
        cve_id="CVE-2019-19781",
        cvss=9.8, severity="CRITICAL",
        title="Path Traversal - Unauthenticated RCE (Shitrix)",
        description="Directory traversal enabling unauthenticated RCE. Massively exploited. One of the most impactful Citrix vulns ever.",
        advisory="CTX267027",
        affected_config=[],
        affected_versions={"13.0": "< 13.0-47.24", "12.1": "< 12.1-55.18", "12.0": "< 12.0-63.13", "11.1": "< 11.1-63.15", "10.5": "< 10.5-70.12"},
        fixed_versions={"13.0": (13,0,47,24), "12.1": (12,1,55,18), "12.0": (12,0,63,13), "11.1": (11,1,63,15), "10.5": (10,5,70,12)},
        exploited_in_wild=True, public_poc=True,
        cwe="CWE-22", references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    ),
    CVEEntry(
        cve_id="CVE-2020-8300",
        cvss=6.5, severity="MEDIUM",
        title="SAML Authentication Hijack",
        description="Phishing of SAML authentication credentials via crafted link when configured as SAML SP.",
        advisory="CTX316577",
        affected_config=["SAML SP"],
        affected_versions={"13.0": "< 13.0-82.45", "12.1": "< 12.1-62.23"},
        fixed_versions={"13.0": (13,0,82,45), "12.1": (12,1,62,23)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-287", references=[],
    ),
    CVEEntry(
        cve_id="CVE-2021-22927",
        cvss=7.5, severity="HIGH",
        title="Session Fixation via SAML Logout",
        description="Session fixation vulnerability related to SAML authentication.",
        advisory="CTX319135",
        affected_config=["SAML SP"],
        affected_versions={"13.0": "< 13.0-82.45", "12.1": "< 12.1-62.23"},
        fixed_versions={"13.0": (13,0,82,45), "12.1": (12,1,62,23)},
        exploited_in_wild=False, public_poc=False,
        cwe="CWE-384", references=[],
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION LOGIC
# ══════════════════════════════════════════════════════════════════════════════

# EOL branches (no patches available — inherently vulnerable to everything)
EOL_BRANCHES = {"10.5", "11.1", "12.0", "12.1", "13.0"}

# Currently supported branches
SUPPORTED_BRANCHES = {"13.1", "14.1"}


def parse_netscaler_version(version_str: str) -> Optional[tuple]:
    """Parse NetScaler firmware version. Returns (major, minor, build, patch) or None.

    Validates:
      - Major version: 10-15 (NetScaler firmware range)
      - Build number: < 500 (NetScaler builds are typically < 200;
        Windows builds like 20348, 19041, 22631 are rejected)
    """
    patterns = [
        r'NS(\d+)\.(\d+):\s*Build\s+(\d+)\.(\d+)',
        r'(?:NetScaler|Citrix[-_]?(?:ADC|Gateway))[-_\s/]*(\d+)\.(\d+)[-_.\s]+(?:Build\s+)?(\d+)\.(\d+)',
        r'(\d+)\.(\d+)\s+Build\s+(\d+)\.(\d+)',
        r'(\d+),\s*(\d+),\s*(\d+),\s*(\d+)',
        r'(\d+)\.(\d+)[-.](\d+)\.(\d+)',
    ]
    for pat in patterns:
        m = re.search(pat, version_str, re.IGNORECASE)
        if m:
            ver = tuple(int(x) for x in m.groups())
            # Major 10-15, build < 500 (rejects Windows build numbers like 20348)
            if 10 <= ver[0] <= 15 and ver[2] < 500:
                return ver
    return None


def is_plugin_version(version_str: str) -> bool:
    """Detect VPN/EPA client plugin versions (20+), not firmware."""
    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', version_str)
    if m and int(m.group(1)) >= 20:
        return True
    return False


def format_version(ver: tuple) -> str:
    return f"{ver[0]}.{ver[1]}-{ver[2]}.{ver[3]}"


def check_cve_applicability(ver: tuple, config_flags: dict, cve: CVEEntry) -> dict:
    """Check if a specific CVE applies to a version + configuration."""
    branch = f"{ver[0]}.{ver[1]}"
    result = {
        "cve_id": cve.cve_id,
        "vulnerable": False,
        "config_applicable": True,
        "branch_match": False,
        "fixed_version": None,
    }

    # Check branch match
    if branch in cve.fixed_versions:
        result["branch_match"] = True
        fixed = cve.fixed_versions[branch]
        result["fixed_version"] = format_version(fixed)
        if ver < fixed:
            result["vulnerable"] = True
    elif branch in EOL_BRANCHES:
        # EOL branches — check if any fixed version exists for older branches
        for fb in cve.fixed_versions:
            fb_parts = fb.replace("-FIPS", "").split(".")
            if len(fb_parts) == 2:
                fb_major, fb_minor = int(fb_parts[0]), int(fb_parts[1])
                if (ver[0], ver[1]) <= (fb_major, fb_minor):
                    result["branch_match"] = True
                    result["vulnerable"] = True
                    result["fixed_version"] = f"EOL — upgrade to {format_version(list(cve.fixed_versions.values())[-1])}"
                    break

    # Check config prerequisites
    if cve.affected_config and result["vulnerable"]:
        config_met = False
        for req in cve.affected_config:
            req_lower = req.lower()
            if "saml idp" in req_lower and config_flags.get("saml_idp"):
                config_met = True
            elif "saml sp" in req_lower and config_flags.get("saml_sp"):
                config_met = True
            elif "gateway" in req_lower and config_flags.get("gateway"):
                config_met = True
            elif "aaa" in req_lower and config_flags.get("aaa"):
                config_met = True
            elif "management" in req_lower and config_flags.get("mgmt_exposed"):
                config_met = True
            elif "pcoip" in req_lower and config_flags.get("pcoip"):
                config_met = True
        # If we can't confirm config externally, still flag as potentially vulnerable
        result["config_applicable"] = config_met if config_flags else None

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK & TLS
# ══════════════════════════════════════════════════════════════════════════════

def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def get_tls_info(host: str, port: int, ctx: ssl.SSLContext) -> dict:
    info = {"cn": "", "san": "", "issuer": "", "not_after": "", "not_before": "",
            "serial": "", "version": 0, "protocol": "", "cipher": "", "bits": 0}
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["protocol"] = ssock.version() or ""
                cipher_info = ssock.cipher()
                if cipher_info:
                    info["cipher"] = cipher_info[0]
                    info["bits"] = cipher_info[2] if len(cipher_info) > 2 else 0
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    for rdn in cert.get("subject", ()):
                        for attr, val in rdn:
                            if attr == "commonName":
                                info["cn"] = val
                    sans = cert.get("subjectAltName", ())
                    info["san"] = ", ".join(f"{t}:{v}" for t, v in sans)
                    for rdn in cert.get("issuer", ()):
                        for attr, val in rdn:
                            if attr in ("commonName", "organizationName"):
                                info["issuer"] += f"{val} "
                    info["issuer"] = info["issuer"].strip()
                    info["not_after"] = cert.get("notAfter", "")
                    info["not_before"] = cert.get("notBefore", "")
                    info["serial"] = cert.get("serialNumber", "")
                    info["version"] = cert.get("version", 0)
    except Exception:
        pass
    return info


def audit_tls(tls_info: dict) -> List[dict]:
    """Audit TLS configuration for security issues."""
    findings = []
    proto = tls_info.get("protocol", "")
    cipher = tls_info.get("cipher", "")
    bits = tls_info.get("bits", 0)
    not_after = tls_info.get("not_after", "")

    if proto and proto in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        findings.append({"check": "TLS Protocol", "severity": "HIGH",
                         "detail": f"Deprecated protocol: {proto}. Upgrade to TLSv1.2+."})
    if bits and bits < 128:
        findings.append({"check": "Cipher Strength", "severity": "HIGH",
                         "detail": f"Weak cipher: {cipher} ({bits}-bit). Use 128-bit+ ciphers."})
    if cipher and any(w in cipher.upper() for w in ["RC4", "DES", "NULL", "EXPORT", "anon"]):
        findings.append({"check": "Weak Cipher", "severity": "HIGH",
                         "detail": f"Insecure cipher suite: {cipher}"})
    if not_after:
        try:
            from email.utils import parsedate_to_datetime
            exp = parsedate_to_datetime(not_after)
            now = datetime.now(timezone.utc)
            if exp < now:
                findings.append({"check": "Certificate Expired", "severity": "CRITICAL",
                                 "detail": f"Certificate expired: {not_after}"})
            elif (exp - now).days < 30:
                findings.append({"check": "Certificate Expiring", "severity": "MEDIUM",
                                 "detail": f"Certificate expires in {(exp - now).days} days: {not_after}"})
        except Exception:
            pass

    if not findings:
        findings.append({"check": "TLS Configuration", "severity": "INFO",
                         "detail": f"Protocol: {proto}, Cipher: {cipher} ({bits}-bit)"})
    return findings


def http_get(host, port, path, ctx, timeout=15, method="GET", max_body=8192):
    url = f"https://{host}:{port}{path}"
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "CitrixScan/1.0 (Security Assessment)",
        "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    })
    try:
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler)
        resp = opener.open(req, timeout=timeout)
        headers = dict(resp.headers)
        body = resp.read(max_body).decode("utf-8", errors="replace") if method == "GET" else ""
        return {"status": resp.status, "headers": headers, "body": body, "url": url}
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "headers": headers, "body": body, "url": url}
    except Exception:
        return None


def http_get_binary(host, port, path, ctx, timeout=30, max_bytes=20*1024*1024):
    url = f"https://{host}:{port}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "CitrixScan/1.0 (Security Assessment)",
        "Accept": "application/octet-stream,*/*", "Connection": "close",
    })
    try:
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler)
        resp = opener.open(req, timeout=timeout)
        data = resp.read(max_bytes)
        return {"status": resp.status, "headers": dict(resp.headers), "data": data, "size": len(data)}
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  VERSION FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

FINGERPRINT_PATHS = [
    "/vpn/index.html", "/logon/LogonPoint/index.html", "/cgi/login",
    "/nf/auth/doAuthentication.do", "/oauth/idp/.well-known/openid-configuration",
    "/saml/login", "/metadata/saml/idp",
]

EXTENDED_PATHS = [
    "/nitro/v1/config/nsversion", "/vpn/pluginlist.xml",
    "/vpn/js/gateway_login_view.js", "/logon/LogonPoint/custom/strings.en.js",
    "/epatype", "/nsversion", "/vpn/versioninfo.xml",
    "/vpn/js/rdx/core/lang/rdx_en.json.gz",  # GZIP timestamp fingerprinting
]

EPA_PATHS = ["/epa/scripts/win/nsepa_setup.exe", "/epa/scripts/win/nsepa_setup64.exe"]

# IoC / post-exploitation artifact paths
IOC_PATHS = [
    # Known webshell locations from CVE-2023-3519 campaigns
    "/vpn/../vpns/portal/scripts/newbm.pl",
    "/vpn/../vpns/portal/scripts/rmbm.pl",
    "/vpns/portal/scripts/newbm.pl",
    "/vpns/portal/scripts/rmbm.pl",
    # China Chopper / generic PHP/Perl shells
    "/vpn/media/logo.png.php",
    "/vpn/media/ns_gui/vpn/media/MediaServlet",
    "/vpn/media/test.html",
    "/vpns/portal/scripts/test.pl",
    "/vpns/portal/scripts/ns_gui.pl",
    # CISA-identified IoCs from AA23-201A
    "/logon/LogonPoint/custom/login.php",
    "/logon/LogonPoint/custom/config.php",
    "/logon/LogonPoint/Resources/skin/skin.php",
    # Suspicious XML/PHP in non-standard locations
    "/vpn/js/info.php",
    "/vpn/js/cmd.php",
    "/vpn/themes/default/info.php",
]

# Security misconfiguration check paths
MISCONFIG_PATHS = [
    # NITRO API (should not be externally accessible without auth)
    "/nitro/v1/config/nsconfig",
    "/nitro/v1/config/nshardware",
    "/nitro/v1/config/nsip",
    "/nitro/v1/config/sslcertkey",
    "/nitro/v1/stat/system",
    # Management interfaces (should never be externally exposed)
    "/menu/neo",
    "/menu/ss",
    "/gui/",
    # Diagnostic / debug endpoints
    "/nsconfig/ns.conf",
    "/var/log/ns.log",
    "/var/nslog/newnslog",
    "/var/nstrace/",
]

FIRMWARE_PATTERNS = [
    r'NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)',
    r'NetScaler\s+NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)',
    r'(?:NetScaler|Citrix\s+ADC|Citrix\s+Gateway)\s+NS(\d+\.\d+):\s+Build\s+(\d+\.\d+)',
    r'"version"\s*:\s*"[^"]*NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)[^"]*"',
]

HEADER_PATTERNS = [
    r'NS(\d+\.\d+)\s*:\s*Build\s+(\d+\.\d+)',
    r'Citrix[-_]?(?:ADC|Gateway)[-_/](\d+\.\d+[-_]\d+\.\d+)',
]


def extract_pe_version(data: bytes) -> Optional[str]:
    """Extract NetScaler firmware version from EPA PE binary.

    The EPA installer (nsepa_setup.exe) is a Windows executable. Its
    VS_FIXEDFILEINFO contains the *Windows binary* version (e.g., 11.0.20348.1
    for a binary built on Server 2022), NOT the NetScaler firmware version.

    Strategy:
      1. String-scan the binary for NetScaler-specific version patterns
         (e.g., "NS14.1: Build 65.11", "Citrix ADC 13.1-62.23")
      2. Scan FileVersion/ProductVersion resource strings for firmware-range versions
      3. VS_FIXEDFILEINFO as last resort with strict validation
    """
    if not data or len(data) < 1024:
        return None

    # Method 1 (best): ASCII string scan for NetScaler firmware patterns
    # These patterns are unique to Citrix/NetScaler and won't match Windows versions
    ascii_text = data.decode('ascii', errors='replace')
    ns_patterns = [
        r'NS(\d{2})\.(\d)\s*[.:]\s*Build\s+(\d+)\.(\d+)',
        r'(?:NetScaler|Citrix[-_]?(?:ADC|Gateway))[-_\s/]+(\d{2})\.(\d)[-_.](\d+)\.(\d+)',
    ]
    for pat in ns_patterns:
        m = re.search(pat, ascii_text, re.IGNORECASE)
        if m:
            major = int(m.group(1))
            if 10 <= major <= 15:
                return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"

    # Method 2: UTF-16LE resource strings (FileVersion / ProductVersion)
    for marker in [b'F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n',
                   b'P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n']:
        pos = data.find(marker)
        if pos > 0:
            region = data[pos + len(marker):pos + len(marker) + 200]
            try:
                decoded = region.decode('utf-16-le', errors='replace')
                m = re.search(r'(\d+)[.,]\s*(\d+)[.,]\s*(\d+)[.,]\s*(\d+)', decoded)
                if m:
                    major, minor = int(m.group(1)), int(m.group(2))
                    build, patch = int(m.group(3)), int(m.group(4))
                    # NetScaler firmware: major 10-15, build < 200
                    # Windows builds: build > 10000 (e.g., 20348, 19041)
                    if 10 <= major <= 15 and build < 500:
                        return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
            except Exception:
                pass

    # Method 3: VS_FIXEDFILEINFO (last resort, strict validation)
    sig = b'\xBD\x04\xEF\xFE'
    idx = data.find(sig)
    if idx > 0 and idx + 52 <= len(data):
        try:
            ms = struct.unpack_from('<I', data, idx + 8)[0]
            ls = struct.unpack_from('<I', data, idx + 12)[0]
            major, minor = (ms >> 16) & 0xFFFF, ms & 0xFFFF
            build, patch = (ls >> 16) & 0xFFFF, ls & 0xFFFF
            # Strict: NetScaler firmware builds are < 200; Windows builds are 10000+
            if 10 <= major <= 15 and build < 500:
                return f"{major}.{minor}.{build}.{patch}"
        except Exception:
            pass

    return None


def extract_nitro_version(resp):
    """Extract firmware version from NITRO or /nsversion responses.

    These endpoints can return:
      - JSON: {"nsversion": [{"version": "NetScaler NS14.1: Build 65.11.nc ..."}]}
      - JSON: {"version": "NS14.1: Build 65.11"}
      - HTML page with version embedded
      - Plain text with version string
      - JSON with errorcode (auth required) but version leaked in headers/body
    """
    if not resp or resp["status"] not in (200, 401, 403):
        return None
    body = resp.get("body", "")
    if not body:
        return None

    # IMPORTANT: If body is just a login page, don't scan it for version strings
    # (login pages are returned for ALL unauthenticated paths on locked-down appliances)
    if is_login_page(body):
        # Still check headers — version can leak there even when body is login page
        for hdr in ("X-NS-version", "Server", "Via", "X-Citrix-Version"):
            val = resp.get("headers", {}).get(hdr, "")
            if val:
                m = re.search(r'NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)', val)
                if m:
                    return f"NS{m.group(1)}: Build {m.group(2)}"
        return None

    # Method 1: JSON parse
    try:
        data = json.loads(body)
        # Walk all string values looking for NS version pattern
        def _walk_json(obj):
            if isinstance(obj, str):
                if re.search(r'NS\d+\.\d+', obj):
                    return obj
            elif isinstance(obj, dict):
                for v in obj.values():
                    r = _walk_json(v)
                    if r:
                        return r
            elif isinstance(obj, list):
                for item in obj:
                    r = _walk_json(item)
                    if r:
                        return r
            return None
        json_ver = _walk_json(data)
        if json_ver:
            return json_ver
    except (json.JSONDecodeError, TypeError):
        pass

    # Method 2: Regex scan raw body for firmware patterns (works on HTML, text, partial JSON)
    for pat in FIRMWARE_PATTERNS:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            return f"NS{m.group(1)}: Build {m.group(2)}"

    # Method 3: Broader pattern - catches "14.1, Build 65.11" and similar variants
    m = re.search(r'(?:version|build|firmware)[^:]*?(\d{2}\.\d)[^:]*?build\s*(\d+\.\d+)',
                  body, re.IGNORECASE)
    if m:
        candidate = f"NS{m.group(1)}: Build {m.group(2)}"
        if parse_netscaler_version(candidate):
            return candidate

    # Method 4: Check response headers for version leak
    for hdr in ("X-NS-version", "Server", "Via", "X-Citrix-Version"):
        val = resp.get("headers", {}).get(hdr, "")
        if val:
            m = re.search(r'NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)', val)
            if m:
                return f"NS{m.group(1)}: Build {m.group(2)}"

    return None


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN RESULT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanResult:
    target: str
    ip: str
    port: int
    timestamp: str
    reachable: bool = False
    is_netscaler: bool = False
    version_raw: str = ""
    version_parsed: Optional[tuple] = None
    version_display: str = ""
    version_source: str = ""
    version_confidence: str = ""
    rdx_en_status: str = ""  # Diagnostic: what rdx_en.json.gz returned
    branch: str = ""
    eol: bool = False
    # TLS
    tls_protocol: str = ""
    tls_cipher: str = ""
    tls_bits: int = 0
    tls_cn: str = ""
    tls_san: str = ""
    tls_issuer: str = ""
    tls_expiry: str = ""
    tls_findings: list = field(default_factory=list)
    # Config detection
    saml_idp_detected: bool = False
    saml_sp_detected: bool = False
    gateway_detected: bool = False
    aaa_detected: bool = False
    mgmt_exposed: bool = False
    epa_available: bool = False
    nitro_accessible: bool = False
    server_header: str = ""
    # CVE results
    cve_results: list = field(default_factory=list)
    critical_cves: int = 0
    high_cves: int = 0
    total_vulns: int = 0
    exploited_itw_vulns: int = 0
    # IoC detection
    ioc_findings: list = field(default_factory=list)
    # Misconfig
    misconfig_findings: list = field(default_factory=list)
    # Security headers
    header_findings: list = field(default_factory=list)
    # Meta
    risk_rating: str = "UNKNOWN"
    accessible_paths: list = field(default_factory=list)
    etag_values: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    scan_duration: float = 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION MODULES
# ══════════════════════════════════════════════════════════════════════════════

def detect_product(responses: list, tls_info: dict) -> bool:
    signals = 0
    for resp in responses:
        if not resp:
            continue
        combined = json.dumps(resp["headers"]) + resp.get("body", "")
        lower = combined.lower()
        if any(kw in lower for kw in ["netscaler", "citrix gateway", "citrix adc",
                                       "logonpoint", "ns_vpn", "nsvpx", "ctxs_gateway",
                                       "/vpn/js/", "/logon/logonpoint/", "cgi/login"]):
            signals += 2
        if any(kw in lower for kw in ["citrix", "x-citrix", "nsc_"]):
            signals += 1
        cookies = resp["headers"].get("Set-Cookie", "")
        if "NSC_" in cookies or "ns_vpn" in cookies.lower():
            signals += 2
    tls_combined = f"{tls_info.get('cn','')} {tls_info.get('san','')} {tls_info.get('issuer','')}".lower()
    if any(kw in tls_combined for kw in ["netscaler", "citrix", "ns."]):
        signals += 1
    return signals >= 2


def detect_config(responses: list, paths_tried: dict) -> dict:
    """Detect appliance configuration from accessible endpoints."""
    config = {
        "saml_idp": False, "saml_sp": False, "gateway": False,
        "aaa": False, "mgmt_exposed": False, "pcoip": False,
    }
    saml_idp_paths = ["/saml/login", "/metadata/saml/idp",
                      "/oauth/idp/.well-known/openid-configuration", "/cgi/samlauth"]
    gw_paths = ["/vpn/index.html", "/logon/LogonPoint/index.html", "/cgi/login",
                "/nf/auth/doAuthentication.do", "/vpn/tmindex.html"]
    mgmt_paths = ["/menu/neo", "/menu/ss", "/gui/",
                  "/nitro/v1/config/nsconfig", "/nitro/v1/config/nshardware"]

    for p in saml_idp_paths:
        resp = paths_tried.get(p)
        if resp and resp["status"] in (200, 301, 302, 307, 401, 403):
            config["saml_idp"] = True
            break
    for p in gw_paths:
        resp = paths_tried.get(p)
        if resp and resp["status"] in (200, 301, 302, 307, 401):
            config["gateway"] = True
            break
    for p in mgmt_paths:
        resp = paths_tried.get(p)
        if resp and resp["status"] in (200, 301, 302):
            body = resp.get("body", "")
            if not is_login_page(body):
                config["mgmt_exposed"] = True
                break

    # Body scan for additional config indicators
    for resp in responses:
        if not resp:
            continue
        body = resp.get("body", "").lower()
        if any(kw in body for kw in ["samlidpprofile", "saml:idp", "saml2/idp", "samlsso"]):
            config["saml_idp"] = True
        if any(kw in body for kw in ["samlspprofile", "saml:sp", "saml_sp"]):
            config["saml_sp"] = True
        if any(kw in body for kw in ["ssl vpn", "ica proxy", "rdp proxy", "cvpn",
                                      "storefront", "nsepa", "gateway_login"]):
            config["gateway"] = True
        if any(kw in body for kw in ["aaa vserver", "add authentication vserver"]):
            config["aaa"] = True
        if "pcoip" in body:
            config["pcoip"] = True
    return config


# ══════════════════════════════════════════════════════════════════════════════
#  GZIP TIMESTAMP → VERSION MAPPING (Fox-IT technique)
#  Sources:
#    https://github.com/fox-it/citrix-netscaler-triage
#    https://github.com/tijldeneut/Security/blob/master/Fingerprinters/CitrixNS-fingerprinter.py
#  Blog: https://blog.fox-it.com/2022/12/28/cve-2022-27510-cve-2022-27518-measuring-citrix-adc-gateway-version-adoption-on-the-internet/
#
#  The file /vpn/js/rdx/core/lang/rdx_en.json.gz contains a GZIP MTIME
#  timestamp (bytes 4-8, little-endian) set during firmware compilation.
#  This timestamp uniquely identifies the NetScaler build version.
# ══════════════════════════════════════════════════════════════════════════════

RDX_EN_STAMP_TO_VERSION = {
    1535167752: "12.1-49.23", 1539712460: "12.1-49.37", 1543395386: "12.1-50.28",
    1547833294: "12.1-50.31", 1551259802: "12.1-51.16", 1553553428: "12.1-51.19",
    1557769307: "13.0-36.27", 1568102085: "13.0-41.20", 1570800276: "13.0-41.28",
    1572931127: "12.1-55.13", 1574967982: "13.0-47.22", 1579181764: "11.1-63.15",
    1579524387: "12.1-55.18", 1579525745: "13.0-47.24", 1582900076: "12.1-55.24",
    1584639643: "13.0-52.24", 1585473032: "12.1-56.22", 1590994121: "13.0-58.30",
    1591024587: "12.0-63.21", 1591064853: "11.1-64.14", 1591729615: "12.1-57.18",
    1593707893: "13.0-58.32", 1595447367: "13.0-61.48", 1596099904: "13.0-61.48",
    1597416844: "12.1-58.14", 1598960821: "12.1-58.15", 1598976896: "13.0-64.35",
    1599733618: "11.1-65.12", 1600737705: "12.1-59.16", 1602086829: "13.0-67.39",
    1602147782: "12.1-55.190", 1604484881: "12.1-60.16", 1605272190: "13.0-67.43",
    1606224413: "13.0-67.43", 1606972406: "13.0-71.40", 1609009448: "13.0-71.44",
    1609011565: "12.1-60.19", 1609729665: "12.1-55.210", 1612272966: "12.1-61.18",
    1613673469: "13.0-76.29", 1615224221: "12.1-61.19", 1615281639: "13.0-76.31",
    1615477570: "12.1-61.19", 1617632002: "13.0-79.64", 1620657482: "12.1-62.21",
    1621266971: "12.1-62.23", 1622313211: "11.1-65.20", 1622469918: "13.0-82.41",
    1623352880: "13.0-82.42", 1623368345: "12.1-62.25", 1625590978: "12.1-62.27",
    1625622338: "12.1-62.27", 1625638831: "11.1-65.22", 1626453956: "13.0-82.45",
    1631259090: "13.1-4.43", 1632751280: "13.0-83.27", 1633526754: "13.1-9.52",
    1634064549: "11.1-65.23", 1634113449: "12.1-63.22", 1636641773: "13.1-4.44",
    1636650155: "13.0-83.29", 1636661207: "12.1-63.23", 1637163803: "13.1-9.60",
    1637905276: "13.1-9.107", 1638969245: "13.1-9.112", 1639153035: "13.1-12.50",
    1639162109: "13.0-84.10", 1639730895: "13.1-12.103", 1640166898: "12.1-63.24",
    1640186329: "13.0-84.11", 1640248123: "13.1-12.51", 1642646201: "12.1-64.16",
    1643350935: "12.1-55.265", 1645447769: "13.1-17.42", 1646925462: "13.0-85.15",
    1648241342: "13.1-12.117", 1648963108: "12.1-55.276", 1649311904: "13.1-21.50",
    1650526474: "12.1-55.278", 1650537528: "12.1-64.17", 1650655111: "12.1-65.15",
    1652100881: "13.1-12.130", 1652947813: "13.0-85.19", 1653569469: "13.1-24.38",
    1655226228: "13.0-86.17", 1656510368: "12.1-65.17", 1657097682: "12.1-55.282",
    1657104103: "13.1-27.59", 1657655579: "13.1-12.131", 1659116392: "13.0-87.9",
    1661353021: "13.1-30.52", 1662371872: "13.1-30.103", 1662553033: "13.1-30.105",
    1663959215: "13.1-33.47", 1664281882: "13.1-30.108", 1664513221: "13.1-30.109",
    1664885015: "13.1-30.111", 1664899863: "12.1-65.21", 1665559544: "12.1-55.289",
    1665594088: "13.1-33.49", 1665767445: "13.0-88.12", 1667231699: "13.0-88.13",
    1667233903: "13.1-33.51", 1667452925: "13.0-88.14", 1667453909: "13.1-33.52",
    1668678940: "13.1-33.54", 1668681438: "13.0-88.16", 1669203751: "13.1-37.38",
    1669636505: "12.1-55.291", 1669808545: "12.1-65.25", 1669891705: "13.1-30.114",
    1671033279: "13.0-89.7", 1674582275: "13.0-90.7", 1677072689: "13.1-42.47",
    1680677853: "12.1-55.296", 1681286714: "13.1-45.61", 1681754964: "13.1-37.150",
    1681918478: "13.0-90.11", 1682509375: "13.1-45.62", 1682714340: "12.1-65.35",
    1682844871: "13.1-45.63", 1683866996: "13.0-91.12", 1683876838: "13.1-45.64",
    1684146224: "13.0-90.12", 1685777750: "13.1-48.47", 1688743976: "13.0-91.13",
    1688746627: "13.1-37.159", 1688747367: "12.1-55.297", 1688954279: "13.1-49.101",
    1689014191: "13.1-49.13", 1689059677: "13.1-49.102", 1689827785: "13.1-49.106",
    1690503901: "14.1-4.42", 1693379034: "13.0-92.18", 1694760036: "14.1-8.50",
    1695273924: "13.0-92.19", 1695277021: "13.1-49.15", 1695284102: "12.1-65.37",
    1695316368: "12.1-55.300", 1695817672: "13.1-37.164", 1697614024: "13.1-50.23",
    1700677179: "14.1-12.30", 1701886543: "14.1-8.120", 1702035068: "14.1-12.34",
    1702062640: "13.1-51.14", 1702548756: "13.0-92.21", 1702625218: "13.1-51.15",
    1702631914: "14.1-12.35", 1702886392: "12.1-55.302", 1702908964: "12.1-65.39",
    1704194696: "14.1-8.122", 1704428153: "13.1-37.176", 1707370491: "14.1-17.38",
    1709227868: "13.1-52.19", 1713474810: "14.1-21.57", 1714132594: "12.1-55.304",
    1714542524: "12.1-55.304", 1715618728: "13.1-53.17", 1715691351: "13.1-37.183",
    1717831730: "14.1-25.53", 1718215257: "12.1-55.307", 1718362054: "13.1-37.188",
    1719233060: "14.1-25.107", 1720089675: "13.0-92.31", 1720103560: "13.1-53.24",
    1720110688: "14.1-25.56", 1720111773: "13.1-37.190", 1720159658: "14.1-25.108",
    1720464791: "13.0-92.31", 1720473719: "12.1-55.309", 1721238815: "13.1-54.29",
    1723114781: "14.1-29.63", 1723549420: "13.1-37.199", 1726488799: "13.1-55.29",
    1728331888: "13.1-37.207", 1728334533: "12.1-55.321", 1728642184: "14.1-29.72",
    1729543935: "12.1-55.321", 1729561034: "14.1-34.42", 1729777429: "13.1-55.34",
    1730184925: "14.1-34.101", 1730996230: "13.1-56.18", 1732875663: "13.1-37.219",
    1734369608: "14.1-38.53", 1737799969: "13.1-57.26", 1739236765: "12.1-55.325",
    1739840877: "12.1-55.325", 1740156084: "14.1-43.50", 1741267150: "14.1-34.105",
    1741944779: "14.1-34.107", 1743497009: "13.1-37.232", 1744121299: "13.1-58.21",
    1744185164: "14.1-43.109", 1747159096: "14.1-47.40", 1747727322: "14.1-47.43",
    1747814734: "14.1-47.44", 1749304395: "14.1-47.46", 1749552827: "14.1-43.56",
    1749564145: "12.1-55.328", 1749572802: "13.1-37.235", 1749588747: "13.1-58.32",
    1750134083: "12.1-55.328", 1750251851: "13.1-59.19", 1755692465: "12.1-55.330",
    1755692615: "14.1-47.48", 1755693334: "13.1-37.241", 1755693886: "13.1-59.22",
    1756174950: "12.1-55.330", 1756797107: "14.1-51.72", 1756913056: "13.1-60.26",
    1757152960: "14.1-51.80", 1758266399: "13.1-37.247", 1758461041: "14.1-55.19",
    1758481087: "13.1-60.29", 1758572828: "14.1-51.80", 1758807975: "13.1-60.29",
    1760420084: "14.1-55.23", 1760504854: "14.1-51.83", 1760549260: "14.1-56.71",
    1760855527: "13.1-60.30", 1761072485: "13.1-37.259", 1761086178: "14.1-55.80",
    1761126430: "13.1-62.16", 1761218816: "14.1-62.16", 1761741652: "13.1-37.262",
    1761746770: "14.1-62.20", 1761935980: "13.1-60.32", 1762297523: "13.1-62.23",
    1762299316: "14.1-66.59", 1762655407: "14.1-56.74", 1762663520: "13.1-61.23",
    1762830097: "12.1-55.333", 1764257490: "13.1-61.25", 1764788389: "14.1-60.52",
    1768287554: "14.1-60.57", 1768297927: "13.1-61.26", 1771909221: "14.1-66.54",
    1773036148: "13.1-62.23", 1773588193: "14.1-60.58", 1773758251: "14.1-66.59",
}


def extract_version(responses, extended_responses, paths_tried, ctx, host, port, timeout) -> Tuple[str, str, str, str]:
    """Multi-vector version extraction. Returns (raw, source, confidence, diagnostic).

    Priority order:
      1. GZIP timestamp from rdx_en.json.gz (Fox-IT technique — highest accuracy)
      2. NITRO API / nsversion endpoints
      3. HTTP headers
      4. Body firmware patterns
      5. EPA binary PE string scan
      6. Content-Length / hash fingerprints
    """
    diagnostic = ""

    # 1. GZIP timestamp from resource files (Fox-IT technique)
    # The GZIP MTIME field (bytes 4-8) contains the build compilation timestamp.
    # Credit: Fox-IT Security Research Team
    # Try multiple known GZIP resource paths — different builds serve from different locations
    gzip_paths = [
        "/vpn/js/rdx/core/lang/rdx_en.json.gz",
        "/vpn/js/rdx/core/lang-ext/rdx_en.json.gz",
        "/vpn/js/rdx/core/lang/rdx_en.json",  # Some builds serve uncompressed with GZIP encoding
    ]
    rdx_stamp = None

    all_diags = []

    for gzip_path in gzip_paths:
        rdx_resp = http_get_binary(host, port, gzip_path, ctx, timeout, max_bytes=4096)
        if not rdx_resp:
            all_diags.append(f"{gzip_path} — connection failed")
            continue
        if rdx_resp["status"] != 200:
            all_diags.append(f"{gzip_path} — HTTP {rdx_resp['status']}")
            continue

        data = rdx_resp.get("data", b"")
        if not data:
            all_diags.append(f"{gzip_path} — empty response")
            continue

        # Check for GZIP magic bytes
        if len(data) >= 20 and data[0:2] == b"\x1f\x8b":
            stamp = int.from_bytes(data[4:8], "little")
            if 1500000000 < stamp < 2000000000:
                rdx_stamp = stamp
                version = RDX_EN_STAMP_TO_VERSION.get(stamp)
                if version and version != "unknown":
                    dt_str = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    return (version, f"GZIP timestamp {gzip_path} (stamp={stamp}, {dt_str})", "HIGH", "")
                else:
                    dt_str = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    return (f"unknown (stamp={stamp}, {dt_str})",
                            f"GZIP timestamp {gzip_path} (not in lookup table)", "MEDIUM",
                            f"rdx_en stamp={stamp} dt={dt_str} — not in {len(RDX_EN_STAMP_TO_VERSION)}-entry lookup table")
            elif stamp == 0:
                all_diags.append(f"{gzip_path} — GZIP valid but MTIME=0 (timestamp stripped, likely gzip -n / reproducible build)")
                # Don't break — try other paths which may have a real timestamp
            else:
                all_diags.append(f"{gzip_path} — GZIP valid but MTIME out of range: {stamp}")
        else:
            # Not GZIP — check what we got
            try:
                text_preview = data[:80].decode("utf-8", errors="replace").replace("\n", " ")
            except Exception:
                text_preview = f"<binary {len(data)} bytes, magic={data[:4].hex()}>"
            if b"<html" in data.lower()[:200] or b"<!doctype" in data.lower()[:200]:
                all_diags.append(f"{gzip_path} — login page redirect (HTML, not GZIP)")
            elif b"{" in data[:10]:
                all_diags.append(f"{gzip_path} — JSON response (not GZIP compressed)")
            else:
                all_diags.append(f"{gzip_path} — unexpected content: {text_preview[:60]}")

    diagnostic = " | ".join(all_diags) if all_diags else "rdx_en: no paths accessible"

    # 2. NITRO / nsversion endpoints
    for ep in ["/nitro/v1/config/nsversion", "/nsversion"]:
        resp = paths_tried.get(ep)
        if resp:
            nv = extract_nitro_version(resp)
            if nv and parse_netscaler_version(nv):
                src = "NITRO API" if "nitro" in ep else "/nsversion endpoint"
                return (nv, src, "HIGH", diagnostic)

    # 2. HTTP headers across all responses
    all_resp = responses + (extended_responses or [])
    for resp in all_resp:
        if not resp:
            continue
        for hdr in ("Server", "X-NS-version", "X-Citrix-Version", "Via", "X-NS-Build"):
            val = resp["headers"].get(hdr, "")
            if val:
                for pat in HEADER_PATTERNS:
                    m = re.search(pat, val, re.IGNORECASE)
                    if m and not is_plugin_version(val):
                        if parse_netscaler_version(val):
                            return (val.strip(), f"HTTP header ({hdr})", "HIGH", diagnostic)

    # 3. Body firmware patterns (skip pluginlist.xml)
    for resp in all_resp:
        if not resp:
            continue
        if "pluginlist.xml" in resp.get("url", ""):
            continue
        body = resp.get("body", "")
        for pat in FIRMWARE_PATTERNS:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                ver_str = f"NS{m.group(1)}: Build {m.group(2)}"
                if parse_netscaler_version(ver_str):
                    return (ver_str, f"Response body ({resp.get('url','')})", "MEDIUM", diagnostic)

    # 4. EPA binary analysis (PE extraction + Content-Length fingerprint)
    epa_info = {}
    for epa_path in EPA_PATHS:
        head = http_get(host, port, epa_path, ctx, timeout, method="HEAD")
        if head and head["status"] == 200:
            cl = head["headers"].get("Content-Length", "0")
            try:
                size = int(cl)
            except ValueError:
                size = 0
            epa_info["available"] = True
            epa_info["size"] = size
            epa_info["path"] = epa_path

            # 4a. Content-Length fingerprint (known EPA sizes → firmware builds)
            # EPA binary sizes are unique per NetScaler release. This mapping can
            # be populated from your fleet baselines. Format: size_bytes → "NS version string"
            # Example: EPA_SIZE_MAP = {14432360: "NS14.1: Build 65.11", ...}
            EPA_SIZE_MAP = {
                # Add known mappings from your fleet here:
                # 14432360: "NS14.1: Build 65.11",
            }
            if size in EPA_SIZE_MAP:
                ver_str = EPA_SIZE_MAP[size]
                if parse_netscaler_version(ver_str):
                    return (ver_str, f"EPA Content-Length fingerprint ({size} bytes)", "MEDIUM", diagnostic)

            # 4b. PE binary deep scan — download and search for firmware strings
            if 0 < size <= 20 * 1024 * 1024:
                bin_resp = http_get_binary(host, port, epa_path, ctx, timeout)
                if bin_resp and bin_resp["status"] == 200 and bin_resp["data"]:
                    epa_ver = extract_pe_version(bin_resp["data"])
                    if epa_ver and parse_netscaler_version(epa_ver):
                        return (epa_ver, f"EPA binary PE ({epa_path}, {len(bin_resp['data'])} bytes)", "HIGH", diagnostic)
            break  # Only try first available EPA path

    # 5. Login page / static resource hash fingerprint
    # The login page HTML and JS content changes with each build. Hash them
    # and compare against known build fingerprints.
    # Populate KNOWN_PAGE_HASHES from fleet baselines.
    KNOWN_PAGE_HASHES = {
        # "sha256_prefix": "NS version string"
        # Populated during fleet baseline scans
    }
    hashable_paths = ["/vpn/index.html", "/logon/LogonPoint/index.html",
                      "/vpn/js/gateway_login_view.js"]
    for hp in hashable_paths:
        resp = paths_tried.get(hp)
        if resp and resp["status"] == 200 and resp.get("body"):
            body = resp["body"]
            if not is_login_page(body):
                continue  # Only hash actual login/resource pages, not error pages
            h = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]
            if h in KNOWN_PAGE_HASHES:
                ver_str = KNOWN_PAGE_HASHES[h]
                if parse_netscaler_version(ver_str):
                    return (ver_str, f"Page hash fingerprint ({hp}: {h})", "MEDIUM", diagnostic)

    return ("", "", "", diagnostic)


def check_security_headers(responses: list) -> list:
    """Audit HTTP security headers."""
    findings = []
    checked_headers = {
        "Strict-Transport-Security": ("HSTS not set. Appliance should enforce HTTPS.", "MEDIUM"),
        "X-Content-Type-Options": ("X-Content-Type-Options not set.", "LOW"),
        "X-Frame-Options": ("X-Frame-Options not set. May be vulnerable to clickjacking.", "MEDIUM"),
        "Content-Security-Policy": ("No Content-Security-Policy header.", "LOW"),
    }
    # Use the first 200 response
    for resp in responses:
        if resp and resp["status"] == 200:
            for hdr, (msg, sev) in checked_headers.items():
                if hdr not in resp["headers"]:
                    findings.append({"check": hdr, "severity": sev, "detail": msg})
            # Check for server version disclosure
            srv = resp["headers"].get("Server", "")
            if srv and any(kw in srv.lower() for kw in ["apache", "nginx", "netscaler", "ns-"]):
                findings.append({"check": "Server Header Disclosure", "severity": "LOW",
                                 "detail": f"Server header reveals software: {srv}"})
            break
    return findings


# Stock NetScaler files that are NOT IoCs — these ship with every Gateway install
STOCK_NETSCALER_FILES = {
    "/vpns/portal/scripts/newbm.pl",     # Bookmark management - add
    "/vpns/portal/scripts/rmbm.pl",      # Bookmark management - remove
    "/vpns/portal/scripts/ns_gui.pl",    # Portal GUI script
}

# Webshell indicators in file content
WEBSHELL_INDICATORS = [
    "<?php", "eval(", "base64_decode(", "system(", "exec(",
    "passthru(", "shell_exec(", "popen(", "proc_open(",
    "assert(", "preg_replace.*e", "create_function(",
    "#!/usr/bin/perl", "#!/bin/sh", "#!/bin/bash",
    "`$_", "$_GET", "$_POST", "$_REQUEST", "$_FILES",
    "cmd.exe", "/bin/sh -c", "wget ", "curl ",
    "nc -e", "reverse", "bind_shell", "backdoor",
]

# Legitimate NetScaler content signatures (used to confirm stock files)
STOCK_CONTENT_SIGNATURES = [
    "citrix", "netscaler", "ns_gui", "bookmark", "vpnbookmark",
    "nsapi", "ns_portal", "logonpoint", "nsc_",
]


def check_iocs(host, port, ctx, timeout) -> list:
    """Probe for known IoC paths with content-based analysis.

    Distinguishes:
      - Stock NetScaler scripts (legitimate, not flagged)
      - Confirmed webshells (CRITICAL - known malicious patterns)
      - Modified stock files (HIGH - stock file with injected code)
      - Suspicious non-stock files (MEDIUM - unexpected content at IoC path)
    """
    findings = []
    for path in IOC_PATHS:
        resp = http_get(host, port, path, ctx, timeout)
        if not resp or resp["status"] != 200:
            continue

        body_raw = resp.get("body", "")
        body = body_raw.lower()
        body_len = len(body_raw)

        # Skip empty or trivially small responses
        if body_len < 10:
            continue

        # Skip if it's just a login page redirect
        if any(skip in body for skip in ["<html", "login", "logon", "<!doctype"]):
            if not any(ind in body for ind in WEBSHELL_INDICATORS):
                continue

        # Check if this is a known stock NetScaler file
        is_stock_path = path in STOCK_NETSCALER_FILES
        has_stock_content = any(sig in body for sig in STOCK_CONTENT_SIGNATURES)
        has_webshell_code = any(ind in body for ind in WEBSHELL_INDICATORS)

        # Content preview (first 200 chars, sanitized)
        preview = body_raw[:200].replace("\n", " ").replace("\r", "").strip()
        if len(body_raw) > 200:
            preview += "..."

        if has_webshell_code:
            if is_stock_path and has_stock_content:
                # Stock file with injected malicious code — potentially trojaned
                findings.append({
                    "severity": "CRITICAL",
                    "path": path,
                    "detail": f"POTENTIALLY TROJANED stock file at {path} — contains webshell indicators.",
                    "type": "trojaned_stock_file",
                    "content_preview": preview,
                    "content_size": body_len,
                })
            else:
                # Non-stock path with webshell code
                findings.append({
                    "severity": "CRITICAL",
                    "path": path,
                    "detail": f"WEBSHELL DETECTED at {path}. Investigate immediately.",
                    "type": "webshell",
                    "content_preview": preview,
                    "content_size": body_len,
                })
        elif is_stock_path and has_stock_content:
            # Stock NetScaler file, legitimate content — NOT an IoC
            continue
        elif is_stock_path and not has_stock_content:
            # Stock path but content doesn't match expected signatures — suspicious replacement
            findings.append({
                "severity": "HIGH",
                "path": path,
                "detail": f"Stock file at {path} has unexpected content — possible replacement.",
                "type": "modified_stock_file",
                "content_preview": preview,
                "content_size": body_len,
            })
        else:
            # Non-stock IoC path with non-trivial content
            findings.append({
                "severity": "MEDIUM",
                "path": path,
                "detail": f"Unexpected file at known IoC path {path} ({body_len} bytes). Review content.",
                "type": "suspicious_file",
                "content_preview": preview,
                "content_size": body_len,
            })

    return findings


def is_login_page(body: str) -> bool:
    """Detect if a response body is a NetScaler login/portal page rather than actual content.

    NetScaler appliances often return a 200 with the login portal HTML for ANY
    unauthenticated request path, making it look like sensitive files are exposed
    when they're actually behind auth. This function detects that pattern.
    """
    if not body or len(body) < 50:
        return False
    lower = body.lower()
    # Login page indicators — these appear in NetScaler login portals
    login_signals = 0
    login_markers = [
        "logonpoint", "login", "logon", "sign in", "sign-in",
        "authentication", "username", "password", "credentials",
        "receiver.appcache", "citrix workspace", "storefront",
        "ns_gui", "visibility: hidden", "nsc_tmaa", "nsc_tmas",
        "/vpn/js/", "gateway_login", "ctxs.login",
        "noindex, nofollow", "receiver",
    ]
    for marker in login_markers:
        if marker in lower:
            login_signals += 1

    # If it's HTML with 3+ login markers, it's a login page
    if login_signals >= 2 and ("<html" in lower or "<!doctype" in lower):
        return True

    # Specific NetScaler login page pattern: visibility:hidden JS redirect
    if "visibility: hidden" in lower and "<script" in lower:
        return True

    return False


def is_actual_api_response(body: str, expected_type: str = "json") -> bool:
    """Check if response body is actual API data vs a login page redirect."""
    if not body:
        return False
    if is_login_page(body):
        return False
    if expected_type == "json":
        try:
            json.loads(body)
            return True
        except (json.JSONDecodeError, TypeError):
            return False
    if expected_type == "config":
        # ns.conf starts with #, set, add, bind commands
        lower = body.lower().strip()
        return any(lower.startswith(kw) for kw in ["#", "set ", "add ", "bind ", "enable ", "disable "])
    if expected_type == "log":
        # Log files contain timestamps, daemon names
        return bool(re.search(r'\d{4}[-/]\d{2}[-/]\d{2}|\w+\[\d+\]:', body[:500]))
    if expected_type == "xml":
        return body.strip().startswith("<?xml") or body.strip().startswith("<")
    return not is_login_page(body)


def check_misconfigs(host, port, ctx, timeout, paths_tried) -> list:
    """Check for security misconfigurations with login page false positive filtering."""
    findings = []
    for path in MISCONFIG_PATHS:
        if path in paths_tried:
            resp = paths_tried[path]
        else:
            resp = http_get(host, port, path, ctx, timeout)
        if resp and resp["status"] == 200:
            body_raw = resp.get("body", "")
            body = body_raw.lower()

            # CRITICAL: Filter out login page redirects masquerading as 200 OK
            if is_login_page(body_raw):
                continue  # Not actually accessible — just the login portal

            # Content preview (sanitized, first 300 chars)
            preview = body_raw[:300].replace("\n", " ").replace("\r", "").strip()
            if len(body_raw) > 300:
                preview += "..."

            if path.startswith("/nitro/"):
                # Verify it's actual JSON API response, not login page
                if is_actual_api_response(body_raw, "json"):
                    if "errorcode" not in body or '"errorcode": 0' in body.replace(" ", "").replace("'", '"'):
                        findings.append({
                            "severity": "CRITICAL" if "nsconfig" in path or "nsip" in path else "HIGH",
                            "path": path,
                            "detail": f"NITRO API endpoint accessible without authentication: {path}",
                            "content_preview": preview[:200] if "nsconfig" in path or "nsip" in path else "",
                        })
            elif path in ("/menu/neo", "/menu/ss", "/gui/"):
                # Verify actual management UI, not login redirect
                if any(kw in body for kw in ["menu", "configuration", "dashboard", "system",
                                              "networking", "appexpert", "traffic"]):
                    findings.append({
                        "severity": "CRITICAL",
                        "path": path,
                        "detail": f"Management interface externally exposed: {path}. Restrict to NSIP only.",
                    })
            elif "ns.conf" in path:
                if is_actual_api_response(body_raw, "config"):
                    findings.append({
                        "severity": "CRITICAL",
                        "path": path,
                        "detail": f"Configuration file accessible: {path}. Contains credentials.",
                        "content_preview": preview,
                    })
            elif "ns.log" in path:
                if is_actual_api_response(body_raw, "log"):
                    findings.append({
                        "severity": "CRITICAL",
                        "path": path,
                        "detail": f"Log file accessible: {path}. May contain session data.",
                        "content_preview": preview,
                    })
            elif "nstrace" in path or "nslog" in path:
                findings.append({
                    "severity": "HIGH",
                    "path": path,
                    "detail": f"Diagnostic data exposed: {path}.",
                })
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  RISK CALCULATION & RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════

def calculate_risk(result: ScanResult) -> str:
    if result.ioc_findings:
        return "CRITICAL"
    if result.eol:
        return "CRITICAL"
    if result.exploited_itw_vulns > 0:
        return "CRITICAL"
    if result.critical_cves > 0:
        return "CRITICAL"
    if any(f.get("severity") == "CRITICAL" for f in result.misconfig_findings):
        return "CRITICAL"
    if result.high_cves > 0:
        return "HIGH"
    if result.is_netscaler and not result.version_raw:
        if result.saml_idp_detected or result.gateway_detected:
            return "HIGH"
        return "MEDIUM"
    if any(f.get("severity") == "HIGH" for f in result.tls_findings):
        return "HIGH"
    if result.total_vulns > 0:
        return "MEDIUM"
    if result.is_netscaler and result.version_raw:
        return "LOW"
    return "INFO"


def build_recommendations(result: ScanResult) -> list:
    recs = []
    if result.ioc_findings:
        recs.append("🚨 COMPROMISE INDICATORS DETECTED. Initiate incident response immediately.")
        recs.append("  → Isolate affected appliance from network.")
        recs.append("  → Preserve forensic evidence (snapshot, memory dump, logs).")
        recs.append("  → Engage DFIR team. Do NOT simply patch — full investigation required.")
    if result.eol:
        recs.append(f"URGENT: Branch {result.branch} is End-of-Life. Upgrade to 14.1-66.59+ immediately.")
    if result.exploited_itw_vulns > 0:
        itw_cves = [c["cve_id"] for c in result.cve_results if c.get("vulnerable") and c.get("exploited_itw")]
        recs.append(f"CRITICAL: {len(itw_cves)} CVE(s) with known in-the-wild exploitation: {', '.join(itw_cves)}")
        recs.append("  → Assume compromise until proven otherwise. Check for IoCs.")
    if result.critical_cves > 0 or result.high_cves > 0:
        vuln_cves = [c["cve_id"] for c in result.cve_results if c.get("vulnerable")]
        if vuln_cves:
            recs.append(f"PATCH: {len(vuln_cves)} CVE(s) applicable: {', '.join(vuln_cves[:10])}")
            # Find the highest fixed version needed
            max_fix = None
            for c in result.cve_results:
                if c.get("vulnerable") and c.get("fixed_version") and "EOL" not in (c["fixed_version"] or ""):
                    fv = parse_netscaler_version(c["fixed_version"])
                    if fv and (not max_fix or fv > max_fix):
                        max_fix = fv
            if max_fix:
                recs.append(f"  → Minimum target version: {format_version(max_fix)}")
    if any(f.get("severity") == "CRITICAL" for f in result.misconfig_findings):
        recs.append("MISCONFIG: Critical security misconfiguration(s) detected.")
        for f in result.misconfig_findings:
            if f.get("severity") == "CRITICAL":
                recs.append(f"  → {f['detail']}")
    if result.mgmt_exposed:
        recs.append("RESTRICT: Management interface is externally accessible. Bind to NSIP only.")
    if result.cve_results and any(c.get("vulnerable") for c in result.cve_results):
        recs.append("POST-PATCH: Kill all sessions after patching:")
        recs.append("  kill aaa session -all && kill icaconnection -all && kill rdp connection -all")
        recs.append("  kill pcoipConnection -all && clear lb persistentSessions")
        recs.append("FORENSICS: Snapshot appliance BEFORE patching for investigation.")
    if result.is_netscaler and not result.version_raw:
        recs.append("VERSION UNKNOWN: Authenticate and run 'show ns version' to confirm patch status.")
        if result.rdx_en_status:
            recs.append(f"  → Fingerprint diagnostic: {result.rdx_en_status}")
        if result.saml_idp_detected or result.gateway_detected:
            recs.append("  → Vulnerable config detected. ASSUME VULNERABLE until version confirmed.")
        if result.epa_available:
            recs.append("  → EPA binary downloadable. Download nsepa_setup.exe and check file properties for version.")
        recs.append("  → Or use NITRO API with credentials: curl -k -u nsroot:pass https://<IP>/nitro/v1/config/nsversion")
        if result.etag_values:
            recs.append(f"  → ETag fingerprints collected ({len(result.etag_values)} paths) — compare against known builds for identification.")
    if not result.is_netscaler and result.reachable:
        recs.append("Target is reachable but not identified as NetScaler. Verify asset inventory.")
    return recs


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER CORE
# ══════════════════════════════════════════════════════════════════════════════

def scan_target(target: str, port: int = 443, timeout: int = 15,
                modules: str = "all", deep_scan: bool = True) -> ScanResult:
    """Full-scope security scan of a single target."""
    start_time = datetime.now(timezone.utc)
    result = ScanResult(
        target=target, ip=target, port=port,
        timestamp=start_time.isoformat(),
    )
    ctx = create_ssl_context()

    # ── DNS ──
    try:
        result.ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        result.errors.append(f"DNS resolution failed: {e}")
        result.recommendations = build_recommendations(result)
        return result

    # ── TCP ──
    try:
        with socket.create_connection((target, port), timeout=timeout):
            result.reachable = True
    except Exception as e:
        result.errors.append(f"TCP/{port} unreachable: {e}")
        result.recommendations = build_recommendations(result)
        return result

    # ── TLS ──
    tls_info = get_tls_info(target, port, ctx)
    result.tls_protocol = tls_info["protocol"]
    result.tls_cipher = tls_info["cipher"]
    result.tls_bits = tls_info["bits"]
    result.tls_cn = tls_info["cn"]
    result.tls_san = tls_info["san"]
    result.tls_issuer = tls_info["issuer"]
    result.tls_expiry = tls_info["not_after"]
    if "tls" in modules or modules == "all":
        result.tls_findings = audit_tls(tls_info)

    # ── Phase 1: Standard Fingerprinting ──
    responses = []
    paths_tried = {}
    for path in FINGERPRINT_PATHS:
        resp = http_get(target, port, path, ctx, timeout)
        responses.append(resp)
        paths_tried[path] = resp
        if resp:
            result.accessible_paths.append(f"{path} [{resp['status']}]")
            if not result.server_header:
                result.server_header = resp["headers"].get("Server", "")
            etag = resp["headers"].get("ETag", "")
            if etag:
                result.etag_values.append(f"{path}: {etag}")

    root_resp = http_get(target, port, "/", ctx, timeout)
    responses.append(root_resp)
    if root_resp:
        result.accessible_paths.append(f"/ [{root_resp['status']}]")

    # Product detection
    result.is_netscaler = detect_product(responses, tls_info)
    if not result.is_netscaler:
        result.risk_rating = calculate_risk(result)
        result.recommendations = build_recommendations(result)
        result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        return result

    # ── Phase 2: Extended Probing ──
    extended_responses = []
    for path in EXTENDED_PATHS:
        resp = http_get(target, port, path, ctx, timeout)
        extended_responses.append(resp)
        paths_tried[path] = resp
        if resp:
            result.accessible_paths.append(f"{path} [{resp['status']}]")
            etag = resp["headers"].get("ETag", "")
            if etag:
                result.etag_values.append(f"{path}: {etag}")
            if "/nitro/v1/config/nsversion" in path and resp["status"] in (200, 401, 403):
                body = resp.get("body", "")
                if resp["status"] in (401, 403):
                    result.nitro_accessible = True  # Auth required = real NITRO endpoint
                elif resp["status"] == 200 and not is_login_page(body):
                    result.nitro_accessible = True  # 200 with actual data = accessible

    # Config detection
    config = detect_config(responses + extended_responses, paths_tried)
    result.saml_idp_detected = config["saml_idp"]
    result.saml_sp_detected = config.get("saml_sp", False)
    result.gateway_detected = config["gateway"]
    result.aaa_detected = config.get("aaa", False)
    result.mgmt_exposed = config["mgmt_exposed"]

    # Version extraction
    ver_raw, ver_src, ver_conf, ver_diag = extract_version(
        responses, extended_responses, paths_tried, ctx, target, port, timeout
    )
    result.version_raw = ver_raw
    result.version_source = ver_src
    result.version_confidence = ver_conf
    result.rdx_en_status = ver_diag

    # Check EPA availability (HEAD check if not already done during version extraction)
    for epa_path in EPA_PATHS:
        head = http_get(target, port, epa_path, ctx, timeout, method="HEAD")
        if head and head["status"] == 200:
            result.epa_available = True
            result.accessible_paths.append(f"{epa_path} [200/HEAD]")
            break

    if ver_raw:
        result.version_parsed = parse_netscaler_version(ver_raw)
    if result.version_parsed:
        result.version_display = format_version(result.version_parsed)
        result.branch = f"{result.version_parsed[0]}.{result.version_parsed[1]}"
        result.eol = result.branch in EOL_BRANCHES

    # ── CVE Assessment ──
    if "cve" in modules or modules == "all":
        if result.version_parsed:
            for cve in CVE_DATABASE:
                res = check_cve_applicability(result.version_parsed, config, cve)
                res["cvss"] = cve.cvss
                res["severity"] = cve.severity
                res["title"] = cve.title
                res["exploited_itw"] = cve.exploited_in_wild
                res["public_poc"] = cve.public_poc
                res["advisory"] = cve.advisory
                res["affected_config"] = cve.affected_config
                if res["vulnerable"]:
                    result.cve_results.append(res)
                    result.total_vulns += 1
                    if cve.severity == "CRITICAL":
                        result.critical_cves += 1
                    elif cve.severity == "HIGH":
                        result.high_cves += 1
                    if cve.exploited_in_wild:
                        result.exploited_itw_vulns += 1

    # ── IoC Detection ──
    if "ioc" in modules or modules == "all":
        result.ioc_findings = check_iocs(target, port, ctx, timeout)

    # ── Misconfiguration Checks ──
    if "misconfig" in modules or modules == "all":
        result.misconfig_findings = check_misconfigs(target, port, ctx, timeout, paths_tried)

    # ── Security Headers ──
    if "headers" in modules or modules == "all":
        result.header_findings = check_security_headers(responses)

    # ── Final Assessment ──
    result.risk_rating = calculate_risk(result)
    result.recommendations = build_recommendations(result)
    result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
          "LOW": "\033[92m", "INFO": "\033[94m", "UNKNOWN": "\033[90m"}
R = "\033[0m"
B = "\033[1m"


def print_result(r: ScanResult, verbose: bool = False):
    c = COLORS.get(r.risk_rating, "")
    print(f"\n{'═'*80}")
    print(f"{B} TARGET: {r.target}:{r.port}  ({r.ip}){R}")
    print(f"{'═'*80}")
    print(f"  Scan Time  : {r.timestamp}  ({r.scan_duration:.1f}s)")
    print(f"  Reachable  : {'Yes' if r.reachable else 'No'}")
    print(f"  NetScaler  : {'Yes' if r.is_netscaler else 'No'}")

    if not r.is_netscaler:
        print(f"  {B}Risk: {c}{r.risk_rating}{R}")
        if r.recommendations:
            for rec in r.recommendations:
                print(f"    {rec}")
        return

    print(f"  Version    : {r.version_display or 'UNKNOWN'}", end="")
    if r.version_source:
        print(f"  (via {r.version_source}, {r.version_confidence})", end="")
    print()
    if r.branch:
        eol_tag = f" \033[91m[EOL]{R}" if r.eol else ""
        print(f"  Branch     : {r.branch}{eol_tag}")
    print(f"  Server     : {r.server_header or 'N/A'}")

    # Config
    print(f"\n  {B}Configuration:{R}")
    flags = [
        ("SAML IDP", r.saml_idp_detected), ("Gateway/VPN", r.gateway_detected),
        ("AAA vServer", r.aaa_detected), ("Mgmt Exposed", r.mgmt_exposed),
        ("EPA Available", r.epa_available), ("NITRO API", r.nitro_accessible),
    ]
    for label, val in flags:
        color = "\033[91m" if val and label in ("Mgmt Exposed",) else ("\033[93m" if val else "\033[92m")
        print(f"    {label:16s}: {color}{'DETECTED' if val else 'No'}{R}")

    # TLS
    if r.tls_findings and verbose:
        print(f"\n  {B}TLS Audit:{R}")
        for f in r.tls_findings:
            fc = COLORS.get(f["severity"], "")
            print(f"    [{fc}{f['severity']:8s}{R}] {f['detail']}")

    # CVEs
    if r.cve_results:
        print(f"\n  {B}Vulnerabilities ({r.total_vulns} found):{R}")
        for cv in sorted(r.cve_results, key=lambda x: x["cvss"], reverse=True):
            sc = COLORS.get(cv["severity"], "")
            itw = " 🔥 EXPLOITED-ITW" if cv.get("exploited_itw") else ""
            poc = " ⚡ PUBLIC-POC" if cv.get("public_poc") else ""
            cfg = f" [{', '.join(cv.get('affected_config', []))}]" if cv.get("affected_config") else ""
            conf_met = ""
            if cv.get("config_applicable") is True:
                conf_met = " ✓ config confirmed"
            elif cv.get("config_applicable") is False:
                conf_met = " ? config unconfirmed"
            print(f"    {sc}{cv['cve_id']:18s} CVSS {cv['cvss']:4.1f} {cv['severity']:8s}{R} "
                  f"{cv['title'][:45]}{cfg}{itw}{poc}{conf_met}")
            if cv.get("fixed_version"):
                print(f"      → Fix: {cv['fixed_version']}  ({cv.get('advisory','')})")
    elif r.version_parsed:
        print(f"\n  {B}Vulnerabilities:{R} \033[92mNone found for {r.version_display}{R}")

    # IoCs
    if r.ioc_findings:
        print(f"\n  {B}\033[91m⚠ INDICATORS OF COMPROMISE ({len(r.ioc_findings)}):{R}")
        for ioc in r.ioc_findings:
            sev_c = COLORS.get(ioc['severity'], "")
            print(f"    [{sev_c}{ioc['severity']:8s}{R}] {ioc['detail']}")
            if ioc.get("content_preview"):
                print(f"      Content ({ioc.get('content_size', '?')} bytes): {ioc['content_preview'][:150]}")

    # Misconfigs
    if r.misconfig_findings:
        print(f"\n  {B}Misconfigurations ({len(r.misconfig_findings)}):{R}")
        for mc in r.misconfig_findings:
            mc_c = COLORS.get(mc["severity"], "")
            print(f"    [{mc_c}{mc['severity']:8s}{R}] {mc['detail']}")
            if mc.get("content_preview"):
                print(f"      Content: {mc['content_preview'][:200]}")

    # Risk
    print(f"\n  {B}Overall Risk: {c}{r.risk_rating}{R}")

    # Recommendations
    if r.recommendations:
        print(f"\n  {B}Recommendations:{R}")
        for rec in r.recommendations:
            print(f"    {rec}")

    if verbose:
        if r.accessible_paths:
            print(f"\n  {B}Accessible Paths:{R}")
            for p in r.accessible_paths:
                print(f"    {p}")
        if r.header_findings:
            print(f"\n  {B}Security Headers:{R}")
            for h in r.header_findings:
                print(f"    [{h['severity']:8s}] {h['detail']}")

    if r.errors:
        print(f"\n  Errors:")
        for e in r.errors:
            print(f"    ! {e}")
    print()


def print_summary(results: list):
    total = len(results)
    reachable = sum(1 for r in results if r.reachable)
    ns = sum(1 for r in results if r.is_netscaler)
    ver = sum(1 for r in results if r.version_raw)
    crit = sum(1 for r in results if r.risk_rating == "CRITICAL")
    high = sum(1 for r in results if r.risk_rating == "HIGH")
    med = sum(1 for r in results if r.risk_rating == "MEDIUM")
    ioc = sum(len(r.ioc_findings) for r in results)
    total_cves = sum(r.total_vulns for r in results)
    itw = sum(r.exploited_itw_vulns for r in results)
    eol_count = sum(1 for r in results if r.eol)

    print(f"\n{'═'*80}")
    print(f"{B} EXECUTIVE SUMMARY{R}")
    print(f"{'═'*80}")
    print(f"  Targets Scanned    : {total}")
    print(f"  Reachable          : {reachable}")
    print(f"  NetScaler Detected : {ns}")
    print(f"  Version Identified : {ver}")
    print(f"  EOL Software       : {eol_count}")
    print(f"\n  {COLORS['CRITICAL']}CRITICAL{R}  : {crit}")
    print(f"  {COLORS['HIGH']}HIGH{R}      : {high}")
    print(f"  {COLORS['MEDIUM']}MEDIUM{R}    : {med}")
    print(f"\n  Total CVEs Found   : {total_cves}")
    print(f"  Exploited-ITW CVEs : {itw}")
    print(f"  IoC Detections     : {ioc}")

    if ioc > 0:
        print(f"\n  {B}\033[91m⚠  COMPROMISE INDICATORS FOUND — INITIATE INCIDENT RESPONSE{R}")
    if crit > 0:
        print(f"  {B}\033[91m⚠  CRITICAL FINDINGS REQUIRE IMMEDIATE ACTION{R}")
    print()


def export_json(results: list, filepath: str):
    export = []
    for r in results:
        d = asdict(r)
        d["version_parsed"] = list(r.version_parsed) if r.version_parsed else None
        export.append(d)
    with open(filepath, "w") as f:
        json.dump({
            "scan_metadata": {
                "tool": "CitrixScan", "version": __version__, "author": __author__,
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "cve_database_size": len(CVE_DATABASE),
                "modules": "version, cve, ioc, misconfig, tls, headers",
            },
            "results": export,
            "summary": {
                "total": len(results),
                "netscaler": sum(1 for r in results if r.is_netscaler),
                "critical": sum(1 for r in results if r.risk_rating == "CRITICAL"),
                "high": sum(1 for r in results if r.risk_rating == "HIGH"),
                "total_cves": sum(r.total_vulns for r in results),
                "iocs": sum(len(r.ioc_findings) for r in results),
            },
        }, f, indent=2, default=str)
    print(f"[+] JSON: {filepath}")


def export_csv(results: list, filepath: str):
    fields = [
        "target", "ip", "port", "reachable", "is_netscaler", "version_display",
        "branch", "eol", "version_source", "version_confidence",
        "saml_idp_detected", "gateway_detected", "aaa_detected", "mgmt_exposed",
        "tls_protocol", "tls_cipher", "tls_bits",
        "total_vulns", "critical_cves", "high_cves", "exploited_itw_vulns",
        "ioc_count", "misconfig_count", "risk_rating", "recommendations",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = {k: getattr(r, k, "") for k in fields}
            row["ioc_count"] = len(r.ioc_findings)
            row["misconfig_count"] = len(r.misconfig_findings)
            row["recommendations"] = " | ".join(r.recommendations)
            w.writerow(row)
    print(f"[+] CSV: {filepath}")


def export_markdown(results: list, filepath: str):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# CitrixScan Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        f.write(f"**Tool:** CitrixScan v{__version__} by {__author__}  \n")
        f.write(f"**Targets:** {len(results)}  \n\n")

        # Summary table
        f.write("## Summary\n\n")
        f.write("| Metric | Count |\n|---|---|\n")
        f.write(f"| Targets Scanned | {len(results)} |\n")
        f.write(f"| NetScaler Detected | {sum(1 for r in results if r.is_netscaler)} |\n")
        f.write(f"| CRITICAL | {sum(1 for r in results if r.risk_rating == 'CRITICAL')} |\n")
        f.write(f"| HIGH | {sum(1 for r in results if r.risk_rating == 'HIGH')} |\n")
        f.write(f"| Total CVEs | {sum(r.total_vulns for r in results)} |\n")
        f.write(f"| IoC Detections | {sum(len(r.ioc_findings) for r in results)} |\n\n")

        # Per-target details
        f.write("## Findings\n\n")
        for r in results:
            risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r.risk_rating, "⚪")
            f.write(f"### {risk_emoji} {r.target}:{r.port}\n\n")
            f.write(f"- **Risk:** {r.risk_rating}\n")
            f.write(f"- **Version:** {r.version_display or 'Unknown'}\n")
            f.write(f"- **Branch:** {r.branch or 'N/A'} {'(EOL)' if r.eol else ''}\n")
            f.write(f"- **SAML IDP:** {'Yes' if r.saml_idp_detected else 'No'}\n")
            f.write(f"- **Gateway:** {'Yes' if r.gateway_detected else 'No'}\n")
            f.write(f"- **CVEs:** {r.total_vulns} ({r.critical_cves} critical, {r.exploited_itw_vulns} exploited-ITW)\n\n")

            if r.cve_results:
                f.write("| CVE | CVSS | Severity | Title | Fix |\n|---|---|---|---|---|\n")
                for cv in sorted(r.cve_results, key=lambda x: x["cvss"], reverse=True):
                    itw = " 🔥" if cv.get("exploited_itw") else ""
                    f.write(f"| {cv['cve_id']}{itw} | {cv['cvss']} | {cv['severity']} | "
                            f"{cv['title'][:50]} | {cv.get('fixed_version', 'N/A')} |\n")
                f.write("\n")

            if r.recommendations:
                f.write("**Recommendations:**\n\n")
                for rec in r.recommendations:
                    f.write(f"- {rec}\n")
                f.write("\n")

    print(f"[+] Markdown: {filepath}")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{B}  ░█▀▀░▀█▀░▀█▀░█▀▄░▀█▀░█░█░█▀▀░█▀▀░█▀█░█▀█
  ░█░░░░█░░░█░░█▀▄░░█░░▄▀▄░▀▀█░█░░░█▀█░█░█   v{__version__}
  ░▀▀▀░▀▀▀░░▀░░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀░▀

  NetScaler Security Scanner     {__author__}
  {len(CVE_DATABASE)} CVEs  |  10 Fingerprint Vectors  |  IoC Detection{R}
"""


def main():
    parser = argparse.ArgumentParser(
        description="CitrixScan - Full-Scope NetScaler Security Scanner",
        epilog="Non-exploitative. Production-safe. Authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="Target IPs or hostnames")
    parser.add_argument("-f", "--file", help="Target list file (one per line)")
    parser.add_argument("-p", "--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Timeout per request (default: 15s)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    parser.add_argument("-o", "--output-json", help="JSON report output path")
    parser.add_argument("--csv", dest="output_csv", help="CSV report output path")
    parser.add_argument("--markdown", dest="output_md", help="Markdown report output path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--modules", default="all",
                        help="Scan modules: all, cve, ioc, misconfig, tls, headers (comma-separated)")
    parser.add_argument("--no-deep", action="store_true", help="Skip EPA binary download")
    parser.add_argument("--list-cves", action="store_true", help="List all CVEs in database and exit")
    parser.add_argument("--version", action="version", version=f"CitrixScan v{__version__}")

    args = parser.parse_args()

    if args.list_cves:
        print(f"\n{B}CitrixScan CVE Database ({len(CVE_DATABASE)} entries):{R}\n")
        print(f"{'CVE ID':20s} {'CVSS':5s} {'Severity':9s} {'ITW':4s} {'PoC':4s} {'Title'}")
        print("─" * 100)
        for cve in sorted(CVE_DATABASE, key=lambda c: c.cvss, reverse=True):
            itw = "🔥" if cve.exploited_in_wild else "  "
            poc = "⚡" if cve.public_poc else "  "
            print(f"{cve.cve_id:20s} {cve.cvss:5.1f} {cve.severity:9s} {itw:4s} {poc:4s} {cve.title}")
        print(f"\n{B}Legend:{R} 🔥 = Exploited in the wild  ⚡ = Public PoC available\n")
        sys.exit(0)

    targets = list(args.targets) if args.targets else []
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    targets = list(dict.fromkeys(targets))

    print(BANNER)
    print(f"  Targets: {len(targets)} │ Port: {args.port} │ Threads: {args.threads}")
    print(f"  Modules: {args.modules} │ CVE DB: {len(CVE_DATABASE)} entries")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'─'*80}")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_target, t, args.port, args.timeout, args.modules, not args.no_deep): t
            for t in targets
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
                print_result(result, verbose=args.verbose)
            except Exception as e:
                print(f"[!] Error scanning {futures[future]}: {e}", file=sys.stderr)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    results.sort(key=lambda r: risk_order.get(r.risk_rating, 5))

    print_summary(results)

    if args.output_json:
        export_json(results, args.output_json)
    if args.output_csv:
        export_csv(results, args.output_csv)
    if args.output_md:
        export_markdown(results, args.output_md)


if __name__ == "__main__":
    main()
