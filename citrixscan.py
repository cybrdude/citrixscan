#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CitrixScan - NetScaler Security Scanner                   ║
║                                                                              ║
║  Comprehensive external security assessment for Citrix NetScaler ADC         ║
║  and NetScaler Gateway appliances.                                           ║
║                                                                              ║
║  Author  : NetGuard 24/7 LLC (netguard24-7.com) & Open Source Contributors   ║
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
__author__ = "NetGuard 24/7 LLC & Open Source Contributors"
__license__ = "MIT"

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import ssl
import socket
import struct
import sys
import os
import tempfile
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlsplit
import posixpath
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum


SAML_SECURITY_NOTICE = {
    "id": "CITRIX-SAML-2026-10-02",
    "title": "Citrix NetScaler SAML authentication security notice",
    "published": "2026-10-02",
    "source": "https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/",
    "status": "No CVE or fixed build published in the October 2 notice",
    "scope": "Customer-managed NetScaler using SAML with Gateway or AAA",
    "relationship": "Independent of CTX697096 and CVE-2026-88771 through CVE-2026-88778",
    "action": "Inspect the local configuration for SAML actions or IdP profiles and Gateway/AAA virtual servers; follow Citrix updates and contact Citrix Support if experiencing impact.",
}


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
    assume_eol_affected: bool = True


# Comprehensive CVE database for NetScaler ADC and Gateway (2019-2026)
# Each entry maps version ranges to vulnerability status
CVE_DATABASE: List[CVEEntry] = [
    # ── 2026 ──
    CVEEntry(
        cve_id="CVE-2026-88771",
        cvss=9.5, severity="CRITICAL",
        title="Unauthenticated Remote Code Execution",
        description="Improper input validation permits unauthenticated command execution on NetScaler ADC and Gateway in the default configuration.",
        advisory="CTX697096",
        affected_config=[],
        affected_versions={
            "14.1": "< 14.1-73.37", "13.1": "< 13.1-64.23",
            "14.1-FIPS": "< 14.1-73.37", "13.1-FIPS": "< 13.1-37.279",
            "13.1-NDcPP": "< 13.1-37.279",
        },
        fixed_versions={
            "14.1": (14, 1, 73, 37), "13.1": (13, 1, 64, 23),
            "14.1-FIPS": (14, 1, 73, 37), "13.1-FIPS": (13, 1, 37, 279),
            "13.1-NDcPP": (13, 1, 37, 279),
        },
        exploited_in_wild=True, public_poc=False,
        cwe="CWE-20",
        references=["https://support.citrix.com/external/article/CTX697096/netscaler-adc-and-netscaler-gateway-secu.html"],
        assume_eol_affected=False,
    ),
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


def version_branch(ver: tuple, version_raw: str = "") -> str:
    """Keep an explicitly identified FIPS or NDcPP edition with its build."""
    branch = f"{ver[0]}.{ver[1]}"
    if re.search(r"\bNDcPP\b", version_raw, re.IGNORECASE):
        return f"{branch}-NDcPP"
    if re.search(r"\bFIPS\b", version_raw, re.IGNORECASE):
        return f"{branch}-FIPS"
    return branch


def check_cve_applicability(ver: tuple, config_flags: dict, cve: CVEEntry,
                            version_raw: str = "") -> dict:
    """Check if a specific CVE applies to a version + configuration."""
    base_branch = f"{ver[0]}.{ver[1]}"
    branch = version_branch(ver, version_raw)
    result = {
        "cve_id": cve.cve_id,
        "vulnerable": False,
        "config_applicable": True,
        "branch_match": False,
        "fixed_version": None,
        "edition_unconfirmed": False,
        "possible_vulnerability": False,
    }
    if branch != base_branch and branch not in cve.fixed_versions:
        # A standard-release fix is not evidence of the FIPS/NDcPP fix build.
        result["edition_unconfirmed"] = base_branch in cve.fixed_versions
        return result

    # Check branch match
    if branch in cve.fixed_versions:
        result["branch_match"] = True
        fixed = cve.fixed_versions[branch]
        result["fixed_version"] = format_version(fixed)
        if ver < fixed:
            result["vulnerable"] = True
        if branch == base_branch:
            alternate_fixes = (
                alt_fix for alt_branch, alt_fix in cve.fixed_versions.items()
                if alt_branch.startswith(f"{base_branch}-")
            )
            result["edition_unconfirmed"] = any(
                (ver < fixed) != (ver < alt_fix)
                for alt_fix in alternate_fixes
            )
            if result["edition_unconfirmed"]:
                # The same numeric build can be patched in one edition and
                # unpatched in another. Do not count it as a confirmed CVE.
                result["possible_vulnerability"] = True
                result["vulnerable"] = False
    elif branch in EOL_BRANCHES and cve.assume_eol_affected:
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


def decode_der_certificate(der: bytes) -> dict:
    """Best-effort certificate metadata under CERT_NONE, using CPython SSL."""
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if not der or decoder is None:
        return {}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.TemporaryDirectory(prefix="citrixscan-cert-") as directory:
            path = os.path.join(directory, "peer.pem")
            with open(path, "w", encoding="ascii") as cert_file:
                cert_file.write(pem)
            return decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}


def get_tls_info(host: str, port: int, ctx: ssl.SSLContext, timeout: int = 10) -> dict:
    info = {"cn": "", "san": "", "issuer": "", "not_after": "", "not_before": "",
            "serial": "", "version": 0, "protocol": "", "cipher": "", "bits": 0}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["protocol"] = ssock.version() or ""
                cipher_info = ssock.cipher()
                if cipher_info:
                    info["cipher"] = cipher_info[0]
                    info["bits"] = cipher_info[2] if len(cipher_info) > 2 else 0
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    cert = decode_der_certificate(ssock.getpeercert(binary_form=True))
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


class TargetRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only to the same scheme, host, and port."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urlsplit(req.full_url)
        new = urlsplit(urljoin(req.full_url, newurl))
        default_port = 443 if old.scheme == "https" else 80
        if (new.scheme != old.scheme or (new.hostname or "").lower() !=
                (old.hostname or "").lower() or (new.port or default_port) !=
                (old.port or default_port)):
            return None
        return super().redirect_request(req, fp, code, msg, headers, new.geturl())


def header_value(headers, name):
    """Read HTTP response headers without depending on server capitalization."""
    return next((value for key, value in (headers or {}).items()
                 if key.lower() == name.lower()), "")


def classified_server_header(value):
    """Retain the server family without exporting an untrusted header value."""
    lower = value.lower()
    for marker, label in (("netscaler", "NetScaler"), ("citrix", "Citrix"),
                          ("apache", "Apache"), ("nginx", "nginx"),
                          ("microsoft-iis", "Microsoft-IIS")):
        if marker in lower:
            return label
    return "present" if value else ""


def response_evidence(resp):
    """Report a response without copying potentially sensitive body content."""
    body = resp.get("body", "")
    encoded = body.encode("utf-8", errors="replace")
    return {"http_status": resp["status"], "content_size": len(encoded),
            "content_sha256": hashlib.sha256(encoded).hexdigest()}


def http_get(host, port, path, ctx, timeout=15, method="GET", max_body=8192,
             scheme="https"):
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    url_host = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{url_host}:{port}{path}"
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": "CitrixScan/1.0 (Security Assessment)",
        "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    })
    try:
        handlers = [urllib.request.ProxyHandler({})]
        if scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers, TargetRedirectHandler())
        resp = opener.open(req, timeout=timeout)
        headers = dict(resp.headers)
        body = resp.read(max_body).decode("utf-8", errors="replace") if method == "GET" else ""
        return {"status": resp.status, "headers": headers, "body": body,
                "url": url, "final_url": resp.geturl()}
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        body = ""
        try:
            body = e.read(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "headers": headers, "body": body,
                "url": url, "final_url": e.geturl()}
    except Exception:
        return None


def http_get_binary(host, port, path, ctx, timeout=30, max_bytes=20*1024*1024,
                    scheme="https"):
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    url_host = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{url_host}:{port}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "CitrixScan/1.0 (Security Assessment)",
        "Accept": "application/octet-stream,*/*", "Connection": "close",
    })
    try:
        handlers = [urllib.request.ProxyHandler({})]
        if scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers, TargetRedirectHandler())
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
    r'(?:NetScaler|Citrix\s+ADC)\s+(?:FIPS|NDcPP)\s+NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)',
    r'(?:NetScaler|Citrix\s+ADC)\s+(?:(?:FIPS|NDcPP)\s+)?Release(?:\s+\([^)]+\))?\s+(\d+\.\d+)\s+Build\s+(\d+\.\d+)',
    r'NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)',
    r'NetScaler\s+NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)',
    r'(?:NetScaler|Citrix\s+ADC|Citrix\s+Gateway)\s+NS(\d+\.\d+):\s+Build\s+(\d+\.\d+)',
    r'"version"\s*:\s*"[^"]*NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)[^"]*"',
]

HEADER_PATTERNS = [
    r'NS(\d+\.\d+)\s*:\s*Build\s+(\d+\.\d+)',
    r'(?:NetScaler|Citrix\s+ADC)\s+(?:(?:FIPS|NDcPP)\s+)?Release(?:\s+\([^)]+\))?\s+\d+\.\d+\s+Build\s+\d+\.\d+',
    r'Citrix[-_]?(?:ADC|Gateway)[-_/](\d+\.\d+[-_]\d+\.\d+)',
]


def matched_firmware_version(match: re.Match, source: str) -> str:
    """Retain an edition marker in the matched name or after its build."""
    version = f"NS{match.group(1)}: Build {match.group(2)}"
    marker = re.search(r"\b(FIPS|NDcPP)\b", match.group(0), re.IGNORECASE)
    if not marker:
        marker = re.match(r"(?:\.nc)?[\s._-]*(FIPS|NDcPP)\b",
                          source[match.end():match.end() + 16], re.IGNORECASE)
    if marker:
        version += " NDcPP" if marker.group(1).lower() == "ndcpp" else " FIPS"
    return version


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


def extract_nitro_version(resp, nitro_path=False):
    """Return a build only from a NITRO version field or direct version text.

    An arbitrary JSON string or a login page can contain a historical build;
    neither identifies the running firmware of the requested endpoint.
    """
    if not resp or resp["status"] != 200:
        return None
    body = resp.get("body", "")
    if nitro_path:
        final_url = resp.get("final_url")
        if final_url:
            final = urlsplit(final_url)
            original = urlsplit(resp.get("url", ""))
            if posixpath.normpath(final.path) != "/nitro/v1/config/nsversion":
                return None
            if original.netloc and (final.scheme != original.scheme or
                                    final.netloc.lower() != original.netloc.lower()):
                return None
        if not body or is_login_page(body):
            return None
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return None
        if (not isinstance(data, dict) or type(data.get("errorcode")) is not int
                or data["errorcode"] != 0 or not isinstance(data.get("nsversion"), list)):
            return None
        for item in data["nsversion"]:
            if isinstance(item, dict) and isinstance(item.get("version"), str):
                if parse_netscaler_version(item["version"]):
                    return item["version"]
        return None
    if body and not is_login_page(body):
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, dict):
            candidates = []
            version_field = data.get("version")
            if isinstance(version_field, str):
                candidates.append(version_field)
            nsversion = data.get("nsversion")
            if isinstance(nsversion, dict):
                nsversion = [nsversion]
            if isinstance(nsversion, list):
                candidates.extend(item.get("version") for item in nsversion
                                  if isinstance(item, dict))
            for candidate in candidates:
                if isinstance(candidate, str) and parse_netscaler_version(candidate):
                    return candidate
        elif data is None and not nitro_path and "<" not in body:
            for pat in FIRMWARE_PATTERNS:
                match = re.search(pat, body, re.IGNORECASE)
                if match:
                    candidate = matched_firmware_version(match, body)
                    if parse_netscaler_version(candidate):
                        return candidate

    # Some appliances include a build in an explicit response header even
    # when authentication prevents access to the body.
    for hdr in ("X-NS-version", "Server", "Via", "X-Citrix-Version"):
        val = header_value(resp.get("headers", {}), hdr)
        if val:
            m = re.search(r'NS(\d+\.\d+):\s*Build\s+(\d+\.\d+)', val)
            if m:
                return matched_firmware_version(m, val)

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
    modules_run: str = "all"
    http_scheme: str = "https"
    reachable: bool = False
    is_netscaler: bool = False
    version_raw: str = ""
    version_parsed: Optional[tuple] = None
    version_display: str = ""
    version_source: str = ""
    version_confidence: str = ""
    patch_status: str = "unverified_external"
    version_evidence: list = field(default_factory=list)
    asset_fingerprints: dict = field(default_factory=dict)
    response_hashes: dict = field(default_factory=dict)
    shared_response_hosts: int = 0
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
    saml_advisory_status: str = "not_assessed"
    saml_advisory_signals: list = field(default_factory=list)
    oauth_idp_detected: bool = False
    gateway_detected: bool = False
    aaa_detected: bool = False
    mgmt_exposed: bool = False
    epa_available: bool = False
    nitro_accessible: bool = False
    server_header: str = ""
    # CVE results
    cve_results: list = field(default_factory=list)
    unassessed_cves: list = field(default_factory=list)
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


def detect_live_product(responses: list, tls_info: dict) -> bool:
    """Require a native response signal, not reflected probe-path text."""
    for resp in responses:
        if not resp:
            continue
        headers = resp.get("headers", {})
        server = header_value(headers, "Server").lower()
        if any(name in server for name in ("netscaler", "citrix adc", "citrix gateway")):
            return True
        cookies = header_value(headers, "Set-Cookie").lower()
        if "nsc_" in cookies or "ns_vpn" in cookies:
            return True
        if any(header_value(headers, name) for name in ("X-NS-version", "X-NS-Build")):
            return True
        body = resp.get("body", "")
        if re.search(r"<title[^>]*>\s*(?:citrix gateway|netscaler(?: gateway| adc)?)\b",
                     body, re.IGNORECASE):
            return True
        if "<html" in body.lower() and "logonpoint" in body.lower() and (
            "citrix" in body.lower() or "netscaler" in body.lower()
        ):
            return True
    return False


def review_saml_config(config_text: str) -> dict:
    """Screen a local ns.conf for Citrix's October 2 SAML notice patterns.

    A pattern match calls for administrator review; it does not establish
    exploitability or compromise. Only signal names, never config text, are
    returned for inclusion in scan reports.
    """
    lines = [line for line in config_text.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    config = "\n".join(lines)
    patterns = {
        "samlAction": r"^\s*add\s+authentication\s+samlAction\b",
        "samlIdPProfile": r"^\s*add\s+authentication\s+samlIdPProfile\b",
        "Gateway vserver": r"^\s*add\s+vpn\s+vserver\b",
        "AAA vserver": r"^\s*add\s+authentication\s+vserver\b",
    }
    signals = [name for name, pattern in patterns.items()
               if re.search(pattern, config, re.IGNORECASE | re.MULTILINE)]
    has_saml = "samlAction" in signals or "samlIdPProfile" in signals
    has_gateway_aaa = "Gateway vserver" in signals or "AAA vserver" in signals
    if has_saml and has_gateway_aaa:
        status = "configuration_match"
    elif has_saml:
        status = "saml_configuration_only"
    else:
        status = "no_pattern_found"
    return {"status": status, "signals": signals}


def detect_config(responses: list, paths_tried: dict) -> dict:
    """Detect appliance configuration from accessible endpoints."""
    config = {
        "saml_idp": False, "saml_sp": False, "gateway": False,
        "aaa": False, "mgmt_exposed": False, "pcoip": False, "oauth_idp": False,
    }
    # SAML IDP indicators — these are SAML-specific endpoints only.
    # NOTE: /oauth/idp/.well-known/openid-configuration is an OAuth/OIDC endpoint,
    # NOT a SAML IDP endpoint. OAuth IdP and SAML IdP are separate configurations
    # on NetScaler. CVE-2026-3055 requires SAML IDP specifically.
    # Credit: tijldeneut for identifying this false positive vector.
    saml_idp_paths = ["/saml/login", "/metadata/saml/idp", "/cgi/samlauth"]
    oauth_idp_paths = ["/oauth/idp/.well-known/openid-configuration"]
    gw_paths = ["/vpn/index.html", "/logon/LogonPoint/index.html", "/cgi/login",
                "/nf/auth/doAuthentication.do", "/vpn/tmindex.html"]
    mgmt_paths = ["/menu/neo", "/menu/ss", "/gui/",
                  "/nitro/v1/config/nsconfig", "/nitro/v1/config/nshardware"]

    for p in saml_idp_paths:
        resp = paths_tried.get(p)
        if resp and resp["status"] in (200, 301, 302, 307, 401, 403):
            body = resp.get("body", "")
            if not is_login_page(body):
                config["saml_idp"] = True
                break
    for p in oauth_idp_paths:
        resp = paths_tried.get(p)
        if resp and resp["status"] == 200:
            body = resp.get("body", "")
            # Verify it's actual OIDC JSON, not a login page redirect
            if not is_login_page(body) and ("issuer" in body or "authorization_endpoint" in body):
                config["oauth_idp"] = True
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


def extract_version(responses, extended_responses, paths_tried, ctx, host, port, timeout,
                    allow_epa_download=True, scheme="https", evidence_out=None,
                    corpus=None
                    ) -> Tuple[str, str, str, str]:
    """Collect live build signals and suppress a verdict when builds conflict.

    Priority order:
      1. GZIP timestamp from rdx_en.json.gz (Fox-IT technique — highest accuracy)
      2. NITRO API / nsversion endpoints
      3. HTTP headers
      4. Body firmware patterns
      5. Stock resource fingerprints when a trusted map is supplied
    """
    diagnostic = ""
    candidates = []
    request_options = {"scheme": scheme} if scheme != "https" else {}

    def record_version(raw, source, confidence):
        parsed = parse_netscaler_version(raw)
        if parsed:
            branch = version_branch(parsed, raw)
            normalized = f"NS{parsed[0]}.{parsed[1]}: Build {parsed[2]}.{parsed[3]}"
            if branch.endswith("-FIPS"):
                normalized += " FIPS"
            elif branch.endswith("-NDcPP"):
                normalized += " NDcPP"
            candidates.append((normalized, source, confidence, parsed, branch))
            if evidence_out is not None:
                item = {"version": format_version(parsed), "edition_branch": branch,
                        "source": source,
                        "confidence": confidence}
                if item not in evidence_out:
                    evidence_out.append(item)

    # 1. GZIP timestamp from resource files (Fox-IT technique)
    # The GZIP MTIME field (bytes 4-8) contains the build compilation timestamp.
    # Credit: Fox-IT Security Research Team
    # Try multiple known GZIP resource paths — different builds serve from different locations
    gzip_paths = [
        "/vpn/js/rdx/core/lang/rdx_en.json.gz",
        "/vpn/js/rdx/core/lang-ext/rdx_en.json.gz",
        "/vpn/js/rdx/core/lang/rdx_en.json",  # Some builds serve uncompressed with GZIP encoding
    ]
    all_diags = []

    for gzip_path in gzip_paths:
        rdx_resp = http_get_binary(host, port, gzip_path, ctx, timeout,
                                   max_bytes=4096, **request_options)
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

        # RFC 1952: magic, DEFLATE method, and no reserved FLG bits.
        if (len(data) >= 10 and data[0:3] == b"\x1f\x8b\x08"
                and data[3] & 0xE0 == 0):
            stamp = int.from_bytes(data[4:8], "little")
            if 1500000000 < stamp < 2000000000:
                version = RDX_EN_STAMP_TO_VERSION.get(stamp)
                if version and version != "unknown":
                    dt_str = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    record_version(version,
                                   f"GZIP timestamp {gzip_path} (stamp={stamp}, {dt_str})",
                                   "MEDIUM")
                else:
                    dt_str = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    all_diags.append(
                        f"{gzip_path} — rdx_en stamp={stamp} dt={dt_str} "
                        f"not in {len(RDX_EN_STAMP_TO_VERSION)}-entry lookup table"
                    )
                if corpus:
                    corpus_matches = (corpus.get("fingerprints", {})
                                      .get("rdx_en_gzip_mtime", {})
                                      .get(str(stamp), []))
                    for match in corpus_matches:
                        if isinstance(match, dict) and isinstance(match.get("build"), str):
                            record_version(match["build"],
                                           f"Firmware corpus GZIP stamp {stamp}", "MEDIUM")
            elif stamp == 0:
                all_diags.append(f"{gzip_path} — GZIP valid but MTIME=0 (timestamp stripped, likely gzip -n / reproducible build)")
                # Don't break — try other paths which may have a real timestamp
            else:
                all_diags.append(f"{gzip_path} — GZIP valid but MTIME out of range: {stamp}")
        else:
            # Not GZIP — check what we got
            if b"<html" in data.lower()[:200] or b"<!doctype" in data.lower()[:200]:
                all_diags.append(f"{gzip_path} — login page redirect (HTML, not GZIP)")
            elif b"{" in data[:10]:
                all_diags.append(f"{gzip_path} — JSON response (not GZIP compressed)")
            else:
                all_diags.append(f"{gzip_path} — unexpected content type (not GZIP)")

    diagnostic = " | ".join(all_diags) if all_diags else "rdx_en: no paths accessible"

    # 2. NITRO / nsversion endpoints
    for ep in ["/nitro/v1/config/nsversion", "/nsversion"]:
        resp = paths_tried.get(ep)
        if resp:
            nv = extract_nitro_version(resp, nitro_path=ep.startswith("/nitro/"))
            if nv and parse_netscaler_version(nv):
                src = "NITRO API" if "nitro" in ep else "/nsversion endpoint"
                record_version(nv, src, "HIGH" if ep.startswith("/nitro/") else "MEDIUM")

    # 2. HTTP headers across all responses
    all_resp = responses + (extended_responses or [])
    for resp in all_resp:
        if not resp:
            continue
        for hdr in ("Server", "X-NS-version", "X-Citrix-Version", "Via", "X-NS-Build"):
            val = header_value(resp.get("headers", {}), hdr)
            if val:
                for pat in HEADER_PATTERNS:
                    m = re.search(pat, val, re.IGNORECASE)
                    if m and not is_plugin_version(val):
                        if parse_netscaler_version(val):
                            actual_name = next((key for key in resp["headers"]
                                                if key.lower() == hdr.lower()), hdr)
                            record_version(val, f"HTTP header ({actual_name})", "MEDIUM")

    # 3. Body firmware patterns (skip pluginlist.xml)
    for resp in all_resp:
        if not resp:
            continue
        if any(path in resp.get("url", "") for path in
               ("pluginlist.xml", "/nitro/", "/nsversion")):
            continue
        body = resp.get("body", "")
        for pat in FIRMWARE_PATTERNS:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                ver_str = matched_firmware_version(m, body)
                if parse_netscaler_version(ver_str):
                    source_path = urlsplit(resp.get("url", "")).path or "response"
                    record_version(ver_str, f"Response body ({source_path})", "MEDIUM")

    # 4. EPA binary analysis (PE extraction + Content-Length fingerprint)
    epa_info = {}
    for epa_path in EPA_PATHS:
        head = http_get(host, port, epa_path, ctx, timeout,
                        method="HEAD", **request_options)
        if head and head["status"] == 200:
            cl = header_value(head.get("headers", {}), "Content-Length") or "0"
            try:
                size = int(cl)
            except ValueError:
                size = 0
            epa_info["available"] = True
            epa_info["size"] = size
            epa_info["path"] = epa_path

            # EPA is a client plugin. Its length and PE FileVersion are useful
            # inventory clues, but do not establish the appliance's running build.
            all_diags.append(f"{epa_path} — EPA client available (size={size})")
            if allow_epa_download and 0 < size <= 20 * 1024 * 1024:
                bin_resp = http_get_binary(host, port, epa_path, ctx, timeout,
                                           **request_options)
                if bin_resp and bin_resp["status"] == 200 and bin_resp["data"]:
                    epa_ver = extract_pe_version(bin_resp["data"])
                    if epa_ver:
                        all_diags.append(f"{epa_path} — EPA client PE version observed")
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
                    record_version(ver_str, f"Page hash fingerprint ({hp}: {h})", "MEDIUM")

    # Fox-IT's stock ?v= cache token can be extracted from the login page.
    # Its build mapping must come from a local firmware corpus, not guesswork.
    index_resp = paths_tried.get("/vpn/index.html")
    if corpus and index_resp and index_resp.get("status") == 200:
        tokens = set(re.findall(r"\?v=([0-9a-f]{32})(?![0-9a-z_])",
                                index_resp.get("body", ""), re.IGNORECASE))
        token_map = corpus.get("fingerprints", {}).get("vpn_index_v", {})
        for token in tokens:
            for match in token_map.get(token.lower(), []):
                if isinstance(match, dict) and isinstance(match.get("build"), str):
                    record_version(match["build"],
                                   f"Firmware corpus VPN asset token {token.lower()}",
                                   "MEDIUM")

    diagnostic = " | ".join(all_diags) if all_diags else diagnostic
    unique_builds = {(item[3], item[4]) for item in candidates}
    if len(unique_builds) > 1:
        versions = ", ".join(sorted(
            f"{format_version(build)} ({branch})" for build, branch in unique_builds
        ))
        return ("", "", "", f"Live build conflict: {versions}. {diagnostic}".strip())
    if candidates:
        selected = next((item for item in candidates if item[2] == "HIGH"),
                        candidates[0])
        return (selected[0], selected[1], selected[2], diagnostic)
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
            srv = header_value(resp["headers"], "Server")
            if srv and any(kw in srv.lower() for kw in ["apache", "nginx", "netscaler", "ns-"]):
                findings.append({"check": "Server Header Disclosure", "severity": "LOW",
                                 "detail": f"Server header reveals software: {classified_server_header(srv)}"})
            break
    return findings


# Stock NetScaler files that are NOT IoCs — these ship with every Gateway install
STOCK_NETSCALER_FILES = {
    "/vpns/portal/scripts/newbm.pl",     # Bookmark management - add
    "/vpns/portal/scripts/rmbm.pl",      # Bookmark management - remove
    "/vpns/portal/scripts/ns_gui.pl",    # Portal GUI script
}

# Strong indicators can identify suspicious content on their own. Generic
# process calls need corroboration because legitimate stock scripts use them.
WEBSHELL_INDICATORS = [
    "<?php", "base64_decode(", "passthru(", "shell_exec(",
    "$_get", "$_post", "$_request", "$_files",
    "#!/bin/sh", "#!/bin/bash", "/bin/sh -c", "nc -e",
]
WEBSHELL_SUPPORTING_INDICATORS = [
    "eval(", "system(", "exec(", "popen(", "proc_open(",
    "assert(", "create_function(", "wget ", "curl ",
]

# Legitimate NetScaler content signatures (used to confirm stock files)
STOCK_CONTENT_SIGNATURES = [
    "citrix", "netscaler", "ns_gui", "bookmark", "vpnbookmark",
    "nsapi", "ns_portal", "logonpoint", "nsc_",
]


def check_iocs(host, port, ctx, timeout, scheme="https") -> list:
    """Probe for known IoC paths with content-based analysis.

    Distinguishes:
      - Stock NetScaler scripts (legitimate, not flagged)
      - Confirmed webshells (CRITICAL - known malicious patterns)
      - Modified stock files (HIGH - stock file with injected code)
      - Suspicious non-stock files (MEDIUM - unexpected content at IoC path)
    """
    findings = []
    for path in IOC_PATHS:
        request_options = {"scheme": scheme} if scheme != "https" else {}
        resp = http_get(host, port, path, ctx, timeout, max_body=65536,
                        **request_options)
        if not resp or resp["status"] != 200:
            continue

        # Redirected login pages and other hosts are not evidence that the
        # requested appliance path exists.
        final_url = resp.get("final_url")
        if final_url:
            final = urlsplit(final_url)
            default_port = 443 if scheme == "https" else 80
            if ((final.hostname or "").lower() != host.lower()
                    or (final.port or default_port) != port):
                continue
            if posixpath.normpath(final.path) != posixpath.normpath(path):
                continue

        body_raw = resp.get("body", "")
        body = body_raw.lower()
        body_len = len(body_raw)

        # Skip empty or trivially small responses
        if body_len < 10:
            continue

        strong_match = any(ind in body for ind in WEBSHELL_INDICATORS)
        if is_login_page(body_raw) and not strong_match:
            continue

        # Check if this is a known stock NetScaler file
        is_stock_path = posixpath.normpath(path) in STOCK_NETSCALER_FILES
        has_stock_content = any(sig in body for sig in STOCK_CONTENT_SIGNATURES)
        supporting_matches = sum(ind in body for ind in WEBSHELL_SUPPORTING_INDICATORS)
        legacy_preg_replace = bool(re.search(
            r"preg_replace\s*\(\s*['\"][^'\"]*/[a-z]*e", body
        ))
        has_webshell_code = strong_match or supporting_matches >= 2 or legacy_preg_replace

        first_finding = len(findings)
        if has_webshell_code:
            if is_stock_path and has_stock_content:
                # Stock file with injected malicious code — potentially trojaned
                findings.append({
                    "severity": "CRITICAL",
                    "path": path,
                    "detail": f"POSSIBLY TROJANED stock file at {path} — contains suspicious code indicators. Validate on the appliance.",
                    "type": "trojaned_stock_file",
                })
            else:
                # Non-stock path with webshell code
                findings.append({
                    "severity": "CRITICAL",
                    "path": path,
                    "detail": f"POSSIBLE WEBSHELL at {path}. Validate on the appliance and investigate immediately.",
                    "type": "webshell",
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
            })
        else:
            # Non-stock IoC path with non-trivial content
            findings.append({
                "severity": "MEDIUM",
                "path": path,
                "detail": f"Unexpected file at known IoC path {path} ({body_len} bytes). Review content.",
                "type": "suspicious_file",
            })

        for finding in findings[first_finding:]:
            finding.update(response_evidence(resp))

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


def check_misconfigs(host, port, ctx, timeout, paths_tried, scheme="https") -> list:
    """Check for security misconfigurations with login page false positive filtering."""
    findings = []
    for path in MISCONFIG_PATHS:
        if path in paths_tried:
            resp = paths_tried[path]
        else:
            request_options = {"scheme": scheme} if scheme != "https" else {}
            resp = http_get(host, port, path, ctx, timeout, **request_options)
        if resp and resp["status"] == 200:
            body_raw = resp.get("body", "")
            body = body_raw.lower()

            # CRITICAL: Filter out login page redirects masquerading as 200 OK
            if is_login_page(body_raw):
                continue  # Not actually accessible — just the login portal

            first_finding = len(findings)
            if path.startswith("/nitro/"):
                # Verify it's actual JSON API response, not login page
                if is_actual_api_response(body_raw, "json"):
                    payload = json.loads(body_raw)
                    if (isinstance(payload, dict)
                            and type(payload.get("errorcode")) is int
                            and payload["errorcode"] == 0):
                        findings.append({
                            "severity": "CRITICAL" if "nsconfig" in path or "nsip" in path else "HIGH",
                            "path": path,
                            "detail": f"NITRO API endpoint accessible without authentication: {path}",
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
                    })
            elif "ns.log" in path:
                if is_actual_api_response(body_raw, "log"):
                    findings.append({
                        "severity": "CRITICAL",
                        "path": path,
                        "detail": f"Log file accessible: {path}. May contain session data.",
                    })
            elif "nstrace" in path or "nslog" in path:
                findings.append({
                    "severity": "HIGH",
                    "path": path,
                    "detail": f"Diagnostic data exposed: {path}.",
                })
            for finding in findings[first_finding:]:
                finding.update(response_evidence(resp))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  RISK CALCULATION & RECOMMENDATIONS
# ══════════════════════════════════════════════════════════════════════════════

def calculate_risk(result: ScanResult) -> str:
    if any(f.get("severity") == "CRITICAL" for f in result.ioc_findings):
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
    if any(f.get("severity") == "HIGH" for f in result.ioc_findings):
        return "HIGH"
    if result.unassessed_cves:
        return "HIGH"
    if result.is_netscaler and not result.version_raw:
        if result.saml_idp_detected or result.gateway_detected:
            return "HIGH"
        return "MEDIUM"
    if any(f.get("severity") == "HIGH" for f in result.tls_findings):
        return "HIGH"
    if result.total_vulns > 0:
        return "MEDIUM"
    if result.ioc_findings:
        return "MEDIUM"
    if result.is_netscaler and result.version_raw:
        return "LOW"
    return "INFO"


def build_recommendations(result: ScanResult) -> list:
    recs = []
    if result.ioc_findings:
        recs.append("SUSPICIOUS PATH CONTENT: Validate these potential IoCs on the appliance and initiate incident response if confirmed.")
        recs.append("  → If confirmed, isolate the affected appliance and engage incident response.")
        recs.append("  → Preserve forensic evidence (snapshot, memory dump, logs) before remediation when compromise is suspected.")
        recs.append("  → Do not rely on patching alone to remove established access.")
    if result.is_netscaler or result.saml_advisory_status != "not_assessed":
        recs.append("SAML NOTICE (2026-10-02): Citrix reports a separate SAML authentication issue, independent of CTX697096. No CVE or fixed build is published in this notice.")
        if result.saml_advisory_status == "configuration_match":
            recs.append("  → Local configuration matches SAML plus Gateway/AAA screening patterns. Verify active bindings and follow Citrix's update guidance.")
        elif result.saml_advisory_status == "saml_configuration_only":
            recs.append("  → Local SAML pattern found; verify whether Gateway or AAA uses it.")
        elif result.saml_advisory_status == "no_pattern_found":
            recs.append("  → No SAML action or IdP profile pattern found in the supplied file. Confirm the file is complete and current.")
        else:
            recs.append("  → Inspect the local NetScaler configuration for 'add authentication samlAction' or 'add authentication samlIdPProfile' and Gateway/AAA use; an external scan cannot confirm this.")
        recs.append(f"  → Citrix guidance: {SAML_SECURITY_NOTICE['source']}")
        recs.append("POST-PATCH: A fixed build does not establish that the appliance was never compromised. Review NetScaler Console IoCs, logs, configuration changes, sessions, and credentials; preserve evidence if compromise is suspected.")
    if result.eol:
        recs.append(f"URGENT: The served build indicates End-of-Life branch {result.branch}. Confirm the running build on each node and plan an immediate supported upgrade.")
        recs.append("  → For CVE-2026-88771, standard editions require at least 14.1-73.37 or 13.1-64.23 on a supported branch; check the Citrix bulletin for edition-specific fixes.")
    if result.exploited_itw_vulns > 0:
        itw_cves = [c["cve_id"] for c in result.cve_results if c.get("vulnerable") and c.get("exploited_itw")]
        recs.append(f"CRITICAL: {len(itw_cves)} CVE(s) with known in-the-wild exploitation: {', '.join(itw_cves)}")
        recs.append("  → Assume compromise until proven otherwise. Check for IoCs.")
    if result.critical_cves > 0 or result.high_cves > 0:
        vuln_cves = [c["cve_id"] for c in result.cve_results if c.get("vulnerable")]
        if vuln_cves:
            recs.append(f"OBSERVED BUILD: {len(vuln_cves)} version-based CVE candidate(s): {', '.join(vuln_cves[:10])}. Confirm the running build on each appliance before stating patch status.")
            # Find the highest fixed version needed
            max_fix = None
            for c in result.cve_results:
                if c.get("vulnerable") and c.get("fixed_version") and "EOL" not in (c["fixed_version"] or ""):
                    fv = parse_netscaler_version(c["fixed_version"])
                    if fv and (not max_fix or fv > max_fix):
                        max_fix = fv
            if max_fix:
                recs.append(f"  → Minimum target version: {format_version(max_fix)}")
    if any(c.get("edition_unconfirmed") for c in result.cve_results):
        recs.append("EDITION UNKNOWN: Confirm FIPS/NDcPP status with 'show ns version' before interpreting the fixed build.")
    if result.version_parsed and result.version_confidence not in ("", "HIGH"):
        recs.append("VERSION CANDIDATE: A served page or asset suggests this build, but the evidence does not establish the running appliance build. Verify with authenticated NITRO or 'show ns version' on every node.")
    if result.unassessed_cves and result.version_confidence == "HIGH":
        recs.append(f"EDITION COVERAGE: {len(result.unassessed_cves)} CVE(s) unassessed for {result.branch}; verify their edition-specific status on the appliance.")
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
        recs.append("  → CVE-2026-88771 patch status is unknown. Verify the build and edition against CTX697096 immediately.")
        if result.rdx_en_status:
            recs.append(f"  → Fingerprint diagnostic: {result.rdx_en_status}")
        if result.saml_idp_detected or result.gateway_detected:
            recs.append("  → Gateway or authentication features are visible; prioritize owner-side version and configuration review.")
        recs.append("  → Confirm the running build and edition on every node with 'show ns version' or authenticated NITRO on the management network.")
        if result.etag_values:
            recs.append(f"  → ETag hashes collected for {len(result.etag_values)} paths; use only as served-content correlation clues.")
    if not result.is_netscaler and result.reachable:
        recs.append("Target is reachable but not identified as NetScaler. Verify asset inventory.")
    return recs


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER CORE
# ══════════════════════════════════════════════════════════════════════════════

def scan_target(target: str, port: int = 443, timeout: int = 15,
                modules: str = "all", deep_scan: bool = True,
                saml_review: Optional[dict] = None, scheme: str = "https",
                corpus: Optional[dict] = None) -> ScanResult:
    """Full-scope security scan of a single target."""
    if scheme not in ("http", "https", "auto"):
        raise ValueError("scheme must be http, https, or auto")
    start_time = datetime.now(timezone.utc)
    result = ScanResult(
        target=target, ip=target, port=port,
        timestamp=start_time.isoformat(), modules_run=modules,
        http_scheme=scheme,
    )
    request_options = {"scheme": scheme} if scheme != "https" else {}
    if saml_review:
        result.saml_advisory_status = saml_review["status"]
        result.saml_advisory_signals = saml_review["signals"]
    ctx = create_ssl_context()

    # ── DNS ──
    try:
        try:
            result.ip = str(ipaddress.ip_address(target))
        except ValueError:
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
    tls_info = (get_tls_info(target, port, ctx, timeout=timeout)
                if scheme in ("https", "auto") else
                {"protocol": "", "cipher": "", "bits": 0, "cn": "", "san": "",
                 "issuer": "", "not_after": ""})
    if scheme == "auto":
        scheme = "https" if tls_info.get("protocol") else "http"
        result.http_scheme = scheme
        request_options = {"scheme": scheme} if scheme != "https" else {}
    result.tls_protocol = tls_info["protocol"]
    result.tls_cipher = tls_info["cipher"]
    result.tls_bits = tls_info["bits"]
    result.tls_cn = tls_info["cn"]
    result.tls_san = tls_info["san"]
    result.tls_issuer = tls_info["issuer"]
    result.tls_expiry = tls_info["not_after"]
    if scheme == "https" and ("tls" in modules or modules == "all"):
        result.tls_findings = audit_tls(tls_info)

    # ── Phase 1: Standard Fingerprinting ──
    responses = []
    paths_tried = {}
    for path in FINGERPRINT_PATHS:
        resp = http_get(target, port, path, ctx, timeout, **request_options)
        responses.append(resp)
        paths_tried[path] = resp
        if resp:
            result.accessible_paths.append(f"{path} [{resp['status']}]")
            if path == "/vpn/index.html" and resp.get("body"):
                result.response_hashes[path] = hashlib.sha256(
                    resp["body"].encode("utf-8", errors="replace")
                ).hexdigest()
                tokens = sorted(set(re.findall(r"\?v=([0-9a-f]{32})(?![0-9a-z_])",
                                               resp["body"], re.IGNORECASE)))
                if tokens:
                    result.asset_fingerprints["vpn_index_v"] = [t.lower() for t in tokens[:8]]
            if not result.server_header:
                result.server_header = classified_server_header(
                    header_value(resp["headers"], "Server"))
            etag = header_value(resp["headers"], "ETag")
            if etag:
                result.etag_values.append(
                    f"{path}: sha256={hashlib.sha256(etag.encode('utf-8', errors='replace')).hexdigest()}")

    root_resp = http_get(target, port, "/", ctx, timeout, **request_options)
    responses.append(root_resp)
    if root_resp:
        result.accessible_paths.append(f"/ [{root_resp['status']}]")
    if not any(resp is not None for resp in responses):
        result.errors.append(f"No {scheme.upper()} response received; product identification and vulnerability assessment are incomplete.")

    # Product detection
    result.is_netscaler = detect_live_product(responses, tls_info)
    if not result.is_netscaler:
        # A generic proxy may hide the portal while exposing a genuine NITRO
        # response. A successful, schema-valid response is a product signal.
        path = "/nitro/v1/config/nsversion"
        nitro_resp = http_get(target, port, path, ctx, timeout, **request_options)
        if extract_nitro_version(nitro_resp, nitro_path=True):
            result.is_netscaler = True
            paths_tried[path] = nitro_resp
            result.accessible_paths.append(f"{path} [{nitro_resp['status']}]")
    if not result.is_netscaler:
        result.risk_rating = calculate_risk(result)
        result.recommendations = build_recommendations(result)
        result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        return result

    # ── Phase 2: Extended Probing ──
    extended_responses = []
    for path in EXTENDED_PATHS:
        resp = paths_tried.get(path)
        if resp is None:
            resp = http_get(target, port, path, ctx, timeout, **request_options)
        extended_responses.append(resp)
        paths_tried[path] = resp
        if resp:
            if f"{path} [{resp['status']}]" not in result.accessible_paths:
                result.accessible_paths.append(f"{path} [{resp['status']}]")
            if path == "/nitro/v1/config/nsversion" and resp.get("body"):
                result.response_hashes[path] = hashlib.sha256(
                    resp["body"].encode("utf-8", errors="replace")
                ).hexdigest()
            etag = header_value(resp["headers"], "ETag")
            if etag:
                result.etag_values.append(
                    f"{path}: sha256={hashlib.sha256(etag.encode('utf-8', errors='replace')).hexdigest()}")
            if "/nitro/v1/config/nsversion" in path and resp["status"] in (200, 401, 403):
                body = resp.get("body", "")
                result.nitro_accessible = bool(
                    extract_nitro_version(resp, nitro_path=True)
                )

    # Config detection
    config = detect_config(responses + extended_responses, paths_tried)
    result.saml_idp_detected = config["saml_idp"]
    result.saml_sp_detected = config.get("saml_sp", False)
    result.oauth_idp_detected = config.get("oauth_idp", False)
    result.gateway_detected = config["gateway"]
    result.aaa_detected = config.get("aaa", False)
    result.mgmt_exposed = config["mgmt_exposed"]

    # Version extraction
    ver_raw, ver_src, ver_conf, ver_diag = extract_version(
        responses, extended_responses, paths_tried, ctx, target, port, timeout,
        allow_epa_download=deep_scan, scheme=scheme,
        evidence_out=result.version_evidence, corpus=corpus
    )
    result.version_raw = ver_raw
    result.version_source = ver_src
    result.version_confidence = ver_conf
    result.rdx_en_status = ver_diag

    # Check EPA availability (HEAD check if not already done during version extraction)
    for epa_path in EPA_PATHS:
        head = http_get(target, port, epa_path, ctx, timeout,
                        method="HEAD", **request_options)
        if head and head["status"] == 200:
            result.epa_available = True
            result.accessible_paths.append(f"{epa_path} [200/HEAD]")
            break

    if ver_raw:
        result.version_parsed = parse_netscaler_version(ver_raw)
    if result.version_parsed:
        result.version_display = format_version(result.version_parsed)
        result.branch = version_branch(result.version_parsed, result.version_raw)
        if result.branch.endswith("-FIPS"):
            result.version_display += " FIPS"
        elif result.branch.endswith("-NDcPP"):
            result.version_display += " NDcPP"
        result.eol = (result.version_confidence == "HIGH" and
                      f"{result.version_parsed[0]}.{result.version_parsed[1]}" in EOL_BRANCHES)

    # ── CVE Assessment ──
    if "cve" in modules or modules == "all":
        if not result.version_parsed or result.version_confidence != "HIGH":
            result.unassessed_cves.append("CVE-2026-88771")
        if result.version_parsed and result.version_confidence == "HIGH":
            for cve in CVE_DATABASE:
                res = check_cve_applicability(result.version_parsed, config, cve,
                                              version_raw=result.version_raw)
                if res["edition_unconfirmed"] and (
                    not res["branch_match"] or res["possible_vulnerability"]
                ):
                    result.unassessed_cves.append(cve.cve_id)
                res["cvss"] = cve.cvss
                res["severity"] = cve.severity
                res["title"] = cve.title
                res["exploited_itw"] = cve.exploited_in_wild
                res["public_poc"] = cve.public_poc
                res["advisory"] = cve.advisory
                res["affected_config"] = cve.affected_config
                res["evidence_scope"] = "served_build_only"
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
        result.ioc_findings = check_iocs(target, port, ctx, timeout, scheme=scheme)

    # ── Misconfiguration Checks ──
    if "misconfig" in modules or modules == "all":
        result.misconfig_findings = check_misconfigs(target, port, ctx, timeout,
                                                     paths_tried, scheme=scheme)

    # ── Security Headers ──
    if "headers" in modules or modules == "all":
        result.header_findings = check_security_headers(responses)

    # ── Final Assessment ──
    result.risk_rating = calculate_risk(result)
    result.recommendations = build_recommendations(result)
    result.scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    return result


def mark_repeated_content(results: list) -> None:
    """Annotate cross-host identical content without erasing build evidence.

    Identical login and NITRO bodies on at least three distinct IPs may be a
    shared backend, proxy, cache, or a fleet on the same build. Equality alone
    cannot decide which explanation is correct, so version-based CVE candidates
    remain visible while per-node patch status remains unverified.
    """
    cohorts = {}
    for result in results:
        hashes = result.response_hashes
        login_hash = hashes.get("/vpn/index.html")
        nitro_hash = hashes.get("/nitro/v1/config/nsversion")
        if login_hash and nitro_hash:
            cohorts.setdefault((login_hash, nitro_hash), []).append(result)
    for cohort in cohorts.values():
        host_count = len({result.ip for result in cohort})
        if host_count < 3:
            continue
        for result in cohort:
            result.shared_response_hosts = host_count
            result.patch_status = "unverified_shared_response"
            result.recommendations.append(
                f"TRIAGE: Two live response bodies were identical across {host_count} "
                "different IPs. This may reflect a fleet on one build or shared "
                "upstream content; verify each appliance's running version and HA peers."
            )


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
        if r.saml_advisory_status != "not_assessed":
            print(f"  Local October 2 SAML review: {r.saml_advisory_status} (remote product identification unverified)")
            if r.saml_advisory_signals:
                print(f"  Local config signals: {', '.join(r.saml_advisory_signals)}")
        if r.recommendations:
            for rec in r.recommendations:
                print(f"    {rec}")
        if r.errors:
            for error in r.errors:
                print(f"  Scan incomplete: {error}")
        return

    print(f"  Version    : {r.version_display or 'UNKNOWN'}", end="")
    if r.version_source:
        print(f"  (via {r.version_source}, {r.version_confidence})", end="")
    print()
    if r.branch:
        eol_tag = f" \033[91m[EOL]{R}" if r.eol else ""
        print(f"  Branch     : {r.branch}{eol_tag}")
    print(f"  Server     : {classified_server_header(r.server_header) or 'N/A'}")
    print(f"  Patch status: {r.patch_status}; confirm the running build on every node")

    # Config
    print(f"\n  {B}Configuration:{R}")
    flags = [
        ("SAML IDP", r.saml_idp_detected), ("OAuth IdP", r.oauth_idp_detected),
        ("Gateway/VPN", r.gateway_detected),
        ("AAA vServer", r.aaa_detected), ("Mgmt Exposed", r.mgmt_exposed),
        ("EPA Available", r.epa_available), ("NITRO API", r.nitro_accessible),
    ]
    for label, val in flags:
        color = "\033[91m" if val and label in ("Mgmt Exposed",) else ("\033[93m" if val else "\033[92m")
        print(f"    {label:16s}: {color}{'DETECTED' if val else 'No'}{R}")
    print(f"    Oct 2 SAML notice: {r.saml_advisory_status}")
    if r.saml_advisory_signals:
        print(f"    Local config signals: {', '.join(r.saml_advisory_signals)}")

    # TLS
    if r.tls_findings and verbose:
        print(f"\n  {B}TLS Audit:{R}")
        for f in r.tls_findings:
            fc = COLORS.get(f["severity"], "")
            print(f"    [{fc}{f['severity']:8s}{R}] {f['detail']}")

    # CVEs
    if r.cve_results:
        print(f"\n  {B}Served-build CVE candidates ({r.total_vulns}):{R}")
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
            if cv.get("edition_unconfirmed"):
                conf_met += " ? edition unconfirmed"
            print(f"    {sc}{cv['cve_id']:18s} CVSS {cv['cvss']:4.1f} {cv['severity']:8s}{R} "
                  f"{cv['title'][:45]}{cfg}{itw}{poc}{conf_met}")
            if cv.get("fixed_version"):
                print(f"      → Fix: {cv['fixed_version']}  ({cv.get('advisory','')})")
    elif r.version_parsed and (r.modules_run == "all" or "cve" in r.modules_run):
        if r.unassessed_cves:
            print(f"\n  {B}Vulnerabilities:{R} {len(r.unassessed_cves)} CVE(s) unassessed for {r.branch or 'unknown build'}")
        else:
            print(f"\n  {B}Vulnerabilities:{R} No modeled CVE candidates for served build {r.version_display}; patch state unverified")
    elif r.version_parsed:
        print(f"\n  {B}Vulnerabilities:{R} CVE module not run")
    if r.unassessed_cves:
        print(f"  Unassessed CVEs: {', '.join(r.unassessed_cves)}")

    # IoCs
    if r.ioc_findings:
        print(f"\n  {B}\033[91m⚠ POTENTIAL INDICATORS OF COMPROMISE ({len(r.ioc_findings)}):{R}")
        for ioc in r.ioc_findings:
            sev_c = COLORS.get(ioc['severity'], "")
            print(f"    [{sev_c}{ioc['severity']:8s}{R}] {ioc['detail']}")
            if ioc.get("content_sha256"):
                print(f"      Response: HTTP {ioc.get('http_status', '?')}, "
                      f"{ioc.get('content_size', '?')} bytes, SHA256 {ioc['content_sha256']}")

    # Misconfigs
    if r.misconfig_findings:
        print(f"\n  {B}Misconfigurations ({len(r.misconfig_findings)}):{R}")
        for mc in r.misconfig_findings:
            mc_c = COLORS.get(mc["severity"], "")
            print(f"    [{mc_c}{mc['severity']:8s}{R}] {mc['detail']}")
            if mc.get("content_sha256"):
                print(f"      Response: HTTP {mc.get('http_status', '?')}, "
                      f"{mc.get('content_size', '?')} bytes, SHA256 {mc['content_sha256']}")

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


def print_summary(results: list, failed_targets=None, requested_targets=None):
    failed_targets = failed_targets or []
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
    unassessed = sum(len(r.unassessed_cves) for r in results)
    unassessed_targets = sum(1 for r in results if r.unassessed_cves)
    eol_count = sum(1 for r in results if r.eol)

    print(f"\n{'═'*80}")
    print(f"{B} EXECUTIVE SUMMARY{R}")
    print(f"{'═'*80}")
    print(f"  Targets Scanned    : {total}")
    if requested_targets is not None:
        print(f"  Targets Requested  : {requested_targets}")
    print(f"  Failed Targets     : {len(failed_targets) + sum(bool(r.errors) for r in results)}")
    print(f"  Reachable          : {reachable}")
    print(f"  NetScaler Detected : {ns}")
    print(f"  Version Identified : {ver}")
    print(f"  EOL Software       : {eol_count}")
    print(f"\n  {COLORS['CRITICAL']}CRITICAL{R}  : {crit}")
    print(f"  {COLORS['HIGH']}HIGH{R}      : {high}")
    print(f"  {COLORS['MEDIUM']}MEDIUM{R}    : {med}")
    print(f"\n  Total CVEs Found   : {total_cves}")
    print(f"  Unassessed CVEs    : {unassessed}")
    print(f"  Targets with Unassessed CVEs : {unassessed_targets}")
    print(f"  Exploited-ITW CVEs : {itw}")
    print(f"  IoC Detections     : {ioc}")

    if ioc > 0:
        print(f"\n  {B}\033[91m⚠  POTENTIAL COMPROMISE INDICATORS FOUND — VALIDATE FINDINGS{R}")
    if crit > 0:
        print(f"  {B}\033[91m⚠  CRITICAL FINDINGS REQUIRE IMMEDIATE ACTION{R}")
    print()


def export_json(results: list, filepath: str, modules="all", failed_targets=None,
                requested_targets=None, saml_review=None):
    failed_targets = failed_targets or []
    export = []
    for r in results:
        d = asdict(r)
        d["version_parsed"] = list(r.version_parsed) if r.version_parsed else None
        d["server_header"] = classified_server_header(r.server_header)
        d["etag_values"] = [
            value if re.fullmatch(r"/[A-Za-z0-9_./-]+: sha256=[0-9a-f]{64}", value)
            else f"sha256={hashlib.sha256(str(value).encode('utf-8', errors='replace')).hexdigest()}"
            for value in r.etag_values
        ]
        allowed_finding_fields = {"severity", "path", "detail", "type",
                                  "http_status", "content_size", "content_sha256"}
        for field_name in ("ioc_findings", "misconfig_findings"):
            d[field_name] = [
                {key: value for key, value in finding.items()
                 if key in allowed_finding_fields}
                for finding in d[field_name]
            ]
        export.append(d)
    with open(filepath, "w") as f:
        json.dump({
            "scan_metadata": {
                "tool": "CitrixScan", "version": __version__, "author": __author__,
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "cve_database_size": len(CVE_DATABASE),
                "modules": modules,
                "requested_targets": requested_targets if requested_targets is not None else len(results),
                "failed_targets": failed_targets,
                "local_saml_review": saml_review,
            },
            "security_notice": SAML_SECURITY_NOTICE,
            "results": export,
            "summary": {
                "total": len(results),
                "failed_targets": len(failed_targets) + sum(bool(r.errors) for r in results),
                "netscaler": sum(1 for r in results if r.is_netscaler),
                "critical": sum(1 for r in results if r.risk_rating == "CRITICAL"),
                "high": sum(1 for r in results if r.risk_rating == "HIGH"),
                "total_cves": sum(r.total_vulns for r in results),
                "unassessed_cves": sum(len(r.unassessed_cves) for r in results),
                "targets_with_unassessed_cves": sum(1 for r in results if r.unassessed_cves),
                "iocs": sum(len(r.ioc_findings) for r in results),
            },
        }, f, indent=2, default=str)
    print(f"[+] JSON: {filepath}")


def export_csv(results: list, filepath: str, failed_targets=None, saml_review=None):
    failed_targets = failed_targets or []
    fields = [
        "target", "scan_status", "errors", "ip", "port", "modules_run", "reachable", "is_netscaler", "version_display",
        "branch", "eol", "version_source", "version_confidence", "patch_status",
        "saml_idp_detected", "oauth_idp_detected", "gateway_detected", "aaa_detected", "mgmt_exposed",
        "saml_advisory_status", "saml_advisory_signals",
        "tls_protocol", "tls_cipher", "tls_bits",
        "total_vulns", "critical_cves", "high_cves", "exploited_itw_vulns", "cve_ids", "unassessed_cve_ids",
        "ioc_count", "misconfig_count", "risk_rating", "recommendations",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = {k: getattr(r, k, "") for k in fields}
            row["scan_status"] = "incomplete" if r.errors else "complete"
            row["errors"] = " | ".join(r.errors)
            row["ioc_count"] = len(r.ioc_findings)
            row["misconfig_count"] = len(r.misconfig_findings)
            row["cve_ids"] = ", ".join(
                c["cve_id"] for c in r.cve_results if c.get("vulnerable")
            )
            row["unassessed_cve_ids"] = ", ".join(r.unassessed_cves)
            row["saml_advisory_signals"] = ", ".join(r.saml_advisory_signals)
            row["recommendations"] = " | ".join(r.recommendations)
            w.writerow(row)
        for target in failed_targets:
            w.writerow({"target": target, "scan_status": "error",
                        "errors": "Scanner exception; see terminal output",
                        "saml_advisory_status": saml_review["status"] if saml_review else "not_assessed",
                        "saml_advisory_signals": ", ".join(saml_review["signals"]) if saml_review else ""})
    print(f"[+] CSV: {filepath}")


def export_markdown(results: list, filepath: str, failed_targets=None,
                    requested_targets=None, saml_review=None):
    failed_targets = failed_targets or []
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# CitrixScan Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
        f.write(f"**Tool:** CitrixScan v{__version__} by {__author__}  \n")
        f.write(f"**Targets:** {len(results)}  \n\n")
        f.write("## Current Citrix notice\n\n")
        f.write(f"**{SAML_SECURITY_NOTICE['title']}** ({SAML_SECURITY_NOTICE['published']}): "
                f"{SAML_SECURITY_NOTICE['relationship']}. "
                f"{SAML_SECURITY_NOTICE['status']}. "
                f"[Citrix guidance]({SAML_SECURITY_NOTICE['source']}).\n\n")
        if saml_review:
            f.write(f"**Local SAML configuration review:** {saml_review['status']} "
                    f"({', '.join(saml_review['signals']) or 'no screening patterns found'}).\n\n")

        # Summary table
        f.write("## Summary\n\n")
        f.write("| Metric | Count |\n|---|---|\n")
        f.write(f"| Targets Scanned | {len(results)} |\n")
        if requested_targets is not None:
            f.write(f"| Targets Requested | {requested_targets} |\n")
        f.write(f"| Failed Targets | {len(failed_targets) + sum(bool(r.errors) for r in results)} |\n")
        f.write(f"| NetScaler Detected | {sum(1 for r in results if r.is_netscaler)} |\n")
        f.write(f"| CRITICAL | {sum(1 for r in results if r.risk_rating == 'CRITICAL')} |\n")
        f.write(f"| HIGH | {sum(1 for r in results if r.risk_rating == 'HIGH')} |\n")
        f.write(f"| Total CVEs | {sum(r.total_vulns for r in results)} |\n")
        f.write(f"| Unassessed CVEs | {sum(len(r.unassessed_cves) for r in results)} |\n")
        f.write(f"| Targets with Unassessed CVEs | {sum(1 for r in results if r.unassessed_cves)} |\n")
        f.write(f"| IoC Detections | {sum(len(r.ioc_findings) for r in results)} |\n\n")
        if failed_targets:
            f.write("**Targets with scanner errors:** " + ", ".join(failed_targets) + "\n\n")

        # Per-target details
        f.write("## Findings\n\n")
        for r in results:
            risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(r.risk_rating, "⚪")
            f.write(f"### {risk_emoji} {r.target}:{r.port}\n\n")
            f.write(f"- **Risk:** {r.risk_rating}\n")
            f.write(f"- **Version:** {r.version_display or 'Unknown'}\n")
            f.write(f"- **Patch status:** {r.patch_status}; confirm the running build on every node\n")
            f.write(f"- **Branch:** {r.branch or 'N/A'} {'(EOL)' if r.eol else ''}\n")
            f.write(f"- **SAML IDP:** {'Yes' if r.saml_idp_detected else 'No'}\n")
            f.write(f"- **October 2 SAML review:** {r.saml_advisory_status}\n")
            f.write(f"- **OAuth IdP:** {'Yes' if r.oauth_idp_detected else 'No'}\n")
            f.write(f"- **Gateway:** {'Yes' if r.gateway_detected else 'No'}\n")
            if r.modules_run == "all" or "cve" in r.modules_run:
                f.write(f"- **Served-build CVE candidates:** {r.total_vulns} ({r.critical_cves} critical, {r.exploited_itw_vulns} exploited-ITW)\n\n")
            else:
                f.write("- **CVEs:** Not assessed (CVE module not run)\n\n")
            if r.unassessed_cves:
                f.write(f"- **Unassessed CVEs for this edition:** {', '.join(r.unassessed_cves)}\n\n")

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


def determine_exit_code(results: list, failed_targets: list,
                        fail_on_risk: Optional[str] = None,
                        fail_on_saml_match: bool = False,
                        saml_review=None) -> int:
    """Return 2 for findings, 3 for incomplete scans, 4 for both, or 0."""
    incomplete = bool(failed_targets) or any(r.errors for r in results)
    risk_levels = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    finding = False
    if fail_on_risk:
        threshold = risk_levels[fail_on_risk.upper()]
        if any(risk_levels.get(r.risk_rating, 0) >= threshold for r in results):
            finding = True
    if fail_on_saml_match and (
        (saml_review and saml_review["status"] == "configuration_match") or
        any(r.saml_advisory_status == "configuration_match" for r in results)
    ):
        finding = True
    if incomplete and finding:
        return 4
    if incomplete:
        return 3
    if finding:
        return 2
    return 0


def analyze_shodan_record(record: dict) -> dict:
    """Triage one cached Shodan service record without contacting its host."""
    if not isinstance(record, dict):
        raise ValueError("record is not a JSON object")
    ip = record.get("ip_str")
    port = record.get("port")
    if not isinstance(ip, str) or not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("record needs an IP address and port")
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("record has an invalid IP address") from exc
    if getattr(parsed_ip, "scope_id", None) is not None:
        raise ValueError("record has an invalid IP address")
    ip = str(parsed_ip)
    if not 1 <= port <= 65535:
        raise ValueError("record has an invalid port")

    http = record.get("http") if isinstance(record.get("http"), dict) else {}
    html = http.get("html") if isinstance(http.get("html"), str) else ""
    raw_headers = http.get("headers") if isinstance(http.get("headers"), dict) else {}
    headers = {
        "-".join(part.capitalize() for part in key.split("-")): value
        for key, value in raw_headers.items()
        if isinstance(key, str) and isinstance(value, str)
    }
    response = {"headers": headers, "body": html}
    product_responses = [response]
    http_server = http.get("server")
    if isinstance(http_server, str):
        product_responses.append({"headers": {"Server": http_server}, "body": ""})
    raw_banner = record.get("data")
    if isinstance(raw_banner, str):
        product_responses.append({"headers": {}, "body": raw_banner})
    product_label = record.get("product", "")
    product_detected = detect_product(product_responses, {}) or (
        isinstance(product_label, str) and "netscaler" in product_label.lower()
    )

    evidence = []
    candidate_versions = []
    seen = set()

    def add_evidence(source: str, raw: str) -> None:
        parsed = parse_netscaler_version(raw)
        if parsed is None:
            return
        edition = version_branch(parsed, raw)
        key = (source, parsed, edition)
        if key in seen:
            return
        seen.add(key)
        entry = {"source": source, "version": format_version(parsed)}
        base_branch = f"{parsed[0]}.{parsed[1]}"
        if edition != base_branch:
            entry["edition"] = edition[len(base_branch) + 1:]
        evidence.append(entry)
        candidate_versions.append((parsed, raw, edition))

    def add_firmware_matches(source: str, text: str) -> None:
        occupied = []
        for pattern in FIRMWARE_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                if any(match.start() < end and match.end() > start
                       for start, end in occupied):
                    continue
                occupied.append(match.span())
                add_evidence(source, matched_firmware_version(match, text))

    shodan_version = record.get("version")
    if isinstance(shodan_version, str):
        add_evidence("shodan_version", shodan_version)
    for name in ("x-ns-version", "x-ns-build", "x-citrix-version", "via", "server"):
        value = next((header_value for header_name, header_value in raw_headers.items()
                      if isinstance(header_name, str) and header_name.lower() == name
                      and isinstance(header_value, str)), None)
        if value and (name != "server" or any(label in value.lower()
                                               for label in ("netscaler", "citrix"))):
            add_evidence(f"http_header:{name}", value)
    add_firmware_matches("http_html", html)
    if isinstance(raw_banner, str):
        add_firmware_matches("raw_banner", raw_banner)

    distinct_versions = {version for version, _, _ in candidate_versions}
    explicit_editions = {
        edition for version, _, edition in candidate_versions
        if edition != f"{version[0]}.{version[1]}"
    }
    if not distinct_versions:
        version_status = "unknown"
    elif len(distinct_versions) > 1 or len(explicit_editions) > 1:
        version_status = "conflict"
    else:
        version_status = "consistent"

    cve = next(item for item in CVE_DATABASE if item.cve_id == "CVE-2026-88771")
    assessed_versions = candidate_versions
    if version_status == "consistent" and explicit_editions:
        assessed_versions = [item for item in candidate_versions
                             if item[2] in explicit_editions]
    checks = [
        check_cve_applicability(version, {}, cve, version_raw=raw)
        for version, raw, _ in assessed_versions
    ]
    fixed_builds = {check["fixed_version"] for check in checks if check["fixed_version"]}
    all_below = product_detected and bool(checks) and all(
        check["vulnerable"] and not check["edition_unconfirmed"] for check in checks
    )
    if not product_detected:
        assessment = "product_unverified"
    elif version_status == "unknown":
        assessment = "unknown_build"
    elif version_status == "conflict":
        assessment = "requires_verification"
    elif any(check["edition_unconfirmed"] or not check["branch_match"] for check in checks):
        assessment = "requires_verification"
    elif all_below:
        assessment = "below_fixed_candidate"
    else:
        assessment = "at_or_above_fixed_candidate"

    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?",
        timestamp,
    ):
        timestamp = None
    else:
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
    return {
        "ip": ip,
        "port": port,
        "timestamp": timestamp,
        "product_detected": product_detected,
        "version_evidence": evidence,
        "version_status": version_status,
        "cve_2026_88771": {
            "assessment": assessment,
            "all_candidates_below_fixed": all_below,
            "fixed_build": next(iter(fixed_builds)) if len(fixed_builds) == 1 else None,
            "advisory": "CTX697096",
        },
    }


def analyze_shodan_export(filepath) -> dict:
    """Read Shodan JSON Lines as untrusted cached evidence."""
    records = []
    errors = []
    with open(filepath, encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                records.append(analyze_shodan_record(json.loads(line)))
            except json.JSONDecodeError:
                errors.append({"line": line_number, "error": "invalid JSON"})
            except ValueError as exc:
                errors.append({"line": line_number, "error": str(exc)})

    assessments = [item["cve_2026_88771"] for item in records]
    summary = {
        "records": len(records),
        "unique_hosts": len({item["ip"] for item in records}),
        "product_candidates": sum(item["product_detected"] for item in records),
        "version_conflicts": sum(item["version_status"] == "conflict" for item in records),
        "conflict_hosts": len({item["ip"] for item in records
                               if item["version_status"] == "conflict"}),
        "unknown_builds": sum(item["version_status"] == "unknown" for item in records),
        "unknown_build_hosts": len({item["ip"] for item in records
                                    if item["version_status"] == "unknown"}),
        "below_fixed_candidates": sum(item["assessment"] == "below_fixed_candidate"
                                      for item in assessments),
        "conflicting_below_fixed_candidates": sum(
            item["version_status"] == "conflict"
            and item["cve_2026_88771"]["all_candidates_below_fixed"] for item in records
        ),
        "invalid_records": len(errors),
    }
    return {
        "mode": "offline_shodan_export",
        "cve": "CVE-2026-88771",
        "advisory": "CTX697096",
        "summary": summary,
        "records": records,
        "errors": errors,
    }


def load_live_shodan_targets(filepath) -> list:
    """Select HTTP services from a JSONL export without trusting its body text.

    The destination is always the validated IP and port in each record.
    Shodan hostnames, redirect URLs, and HTML never become scan destinations.
    """
    targets = {}
    with open(filepath, encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: invalid JSON") from exc
            if not isinstance(item, dict):
                raise ValueError(f"line {line_number}: expected JSON object")
            ip = item.get("ip_str")
            port = item.get("port")
            try:
                parsed = ipaddress.ip_address(ip)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"line {line_number}: invalid IP address") from exc
            if getattr(parsed, "scope_id", None) is not None:
                raise ValueError(f"line {line_number}: scoped IP address is unsupported")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise ValueError(f"line {line_number}: invalid port")
            raw = item.get("data")
            if not isinstance(item.get("http"), dict) and not (
                isinstance(raw, str) and raw.startswith("HTTP/")
            ):
                raise ValueError(f"line {line_number}: not an HTTP service record")
            key = (str(parsed), port)
            # Cached TLS metadata is historical; detect the current transport.
            targets[key] = "auto"
    return [(ip, port, scheme) for (ip, port), scheme in targets.items()]


def load_firmware_corpus(filepath) -> dict:
    """Load an operator-built fingerprint corpus with bounded schema checks."""
    with open(filepath, encoding="utf-8") as source:
        corpus = json.load(source)
    if not isinstance(corpus, dict) or corpus.get("schema_version") != 1:
        raise ValueError("unsupported firmware corpus schema")
    fingerprints = corpus.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise ValueError("firmware corpus has no fingerprints")
    for kind in ("vpn_index_v", "rdx_en_gzip_mtime"):
        entries = fingerprints.get(kind)
        if not isinstance(entries, dict):
            raise ValueError(f"firmware corpus is missing {kind}")
        for key, candidates in entries.items():
            if not isinstance(key, str) or not isinstance(candidates, list):
                raise ValueError(f"invalid {kind} entry")
            if any(not isinstance(candidate, dict) or
                   not isinstance(candidate.get("build"), str) or
                   not parse_netscaler_version(candidate["build"])
                   for candidate in candidates):
                raise ValueError(f"invalid {kind} build candidate")
    return corpus


class ScannerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def main():
    parser = ScannerArgumentParser(
        description="CitrixScan - NetScaler Security Scanner",
        epilog="Non-exploitative. Production-safe. Authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="Target IPs or hostnames")
    parser.add_argument("-f", "--file", help="Target list file (one per line)")
    parser.add_argument("--shodan-export", metavar="FILE",
                        help="Triage Shodan JSON Lines offline without contacting listed hosts")
    parser.add_argument("--live-shodan-export", metavar="FILE",
                        help="Scan each authorized HTTP service IP:port in Shodan JSON Lines")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--scheme", choices=("http", "https"), default="https",
                        help="HTTP protocol for ordinary targets (default: https)")
    parser.add_argument("--firmware-corpus", metavar="FILE",
                        help="Match live stock fingerprints to a local firmware corpus")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Timeout per request (default: 15s)")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads (default: 5)")
    parser.add_argument("-o", "--output-json", help="JSON report output path")
    parser.add_argument("--csv", dest="output_csv", help="CSV report output path")
    parser.add_argument("--markdown", dest="output_md", help="Markdown report output path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--modules", default="all",
                        help="Scan modules: all, cve, ioc, misconfig, tls, headers (comma-separated)")
    parser.add_argument("--no-deep", action="store_true", help="Skip EPA binary download")
    parser.add_argument("--saml-config", metavar="FILE",
                        help="Screen a local NetScaler configuration for the Oct 2 SAML notice (one target only)")
    parser.add_argument("--fail-on-risk", choices=("medium", "high", "critical"),
                        help="Set finding status when a target meets or exceeds this risk")
    parser.add_argument("--fail-on-saml-match", action="store_true",
                        help="Set finding status when --saml-config matches SAML and Gateway/AAA patterns")
    parser.add_argument("--list-cves", action="store_true", help="List all CVEs in database and exit")
    parser.add_argument("--version", action="version", version=f"CitrixScan v{__version__}")

    args = parser.parse_args()
    selected_modules = [name.strip().lower() for name in args.modules.split(",")]
    allowed_modules = {"all", "cve", "ioc", "misconfig", "tls", "headers"}
    if (not selected_modules or any(name not in allowed_modules for name in selected_modules)
            or ("all" in selected_modules and len(selected_modules) > 1)):
        parser.error("--modules must be 'all' or a comma-separated list of cve,ioc,misconfig,tls,headers")
    args.modules = ",".join(dict.fromkeys(selected_modules))

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

    if args.shodan_export:
        if (args.targets or args.file or args.saml_config or args.fail_on_saml_match
                or args.live_shodan_export or args.firmware_corpus):
            parser.error("--shodan-export cannot be combined with live targets, a firmware corpus, or SAML configuration")
        if args.output_csv or args.output_md or args.fail_on_risk:
            parser.error("--shodan-export supports JSON output only; live risk flags do not apply")
        if args.modules not in ("all", "cve"):
            parser.error("--shodan-export assesses cached CVE evidence only")
        try:
            offline_report = analyze_shodan_export(args.shodan_export)
            if args.output_json:
                with open(args.output_json, "w", encoding="utf-8") as output:
                    json.dump(offline_report, output, indent=2)
                    output.write("\n")
        except (OSError, UnicodeError) as exc:
            print(f"[!] Could not process Shodan export: {exc}", file=sys.stderr)
            return 1
        summary = offline_report["summary"]
        print(f"Offline Shodan evidence: {summary['records']} records, "
              f"{summary['unique_hosts']} hosts; "
              f"{summary['version_conflicts']} version conflicts, "
              f"{summary['unknown_builds']} unknown builds, "
              f"{summary['invalid_records']} invalid records.")
        print("Cached banner triage only; verify build and edition on the appliance.")
        return 1 if summary["invalid_records"] or not summary["records"] else 0

    corpus = None
    if args.firmware_corpus:
        try:
            corpus = load_firmware_corpus(args.firmware_corpus)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            print(f"[!] Could not load firmware corpus: {exc}", file=sys.stderr)
            return 1

    if args.live_shodan_export and (args.targets or args.file or args.saml_config):
        parser.error("--live-shodan-export cannot be combined with ordinary targets or SAML configuration")
    if args.live_shodan_export and args.port != 443:
        parser.error("--live-shodan-export uses each record's port; omit --port")

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

    if not targets and not args.live_shodan_export:
        print(BANNER)
        parser.print_help()
        sys.exit(1)

    targets = list(dict.fromkeys(targets))
    if args.live_shodan_export:
        try:
            scan_specs = load_live_shodan_targets(args.live_shodan_export)
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"[!] Could not load live Shodan targets: {exc}", file=sys.stderr)
            return 1
        if not scan_specs:
            print("[!] Shodan export contains no HTTP services", file=sys.stderr)
            return 1
    else:
        scan_specs = [(target, args.port, args.scheme) for target in targets]
    if args.saml_config and len(scan_specs) != 1:
        parser.error("--saml-config requires exactly one target")
    if args.fail_on_saml_match and not args.saml_config:
        parser.error("--fail-on-saml-match requires --saml-config")
    saml_review = None
    if args.saml_config:
        try:
            with open(args.saml_config, encoding="utf-8", errors="replace") as config_file:
                saml_review = review_saml_config(config_file.read())
        except OSError as e:
            print(f"[!] Could not read SAML config: {e}", file=sys.stderr)
            return 1

    print(BANNER)
    print(f"  Targets: {len(scan_specs)} │ Port: {'per record' if args.live_shodan_export else args.port} │ Threads: {args.threads}")
    print(f"  Modules: {args.modules} │ CVE DB: {len(CVE_DATABASE)} entries")
    if saml_review:
        print(f"  Local SAML configuration review: {saml_review['status']}")
    print(f"  Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'─'*80}")

    results = []
    failed_targets = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        def submit_one(ip, port, scheme):
            scan_args = (ip, port, args.timeout, args.modules,
                         not args.no_deep, saml_review)
            if corpus is not None:
                return executor.submit(scan_target, *scan_args, scheme, corpus)
            if scheme != "https":
                return executor.submit(scan_target, *scan_args, scheme)
            return executor.submit(scan_target, *scan_args)

        futures = {
            submit_one(ip, port, scheme):
                (f"{ip}:{port}" if args.live_shodan_export else ip)
            for ip, port, scheme in scan_specs
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                failed_targets.append(futures[future])
                print(f"[!] Error scanning {futures[future]}: {e}", file=sys.stderr)

    mark_repeated_content(results)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    results.sort(key=lambda r: risk_order.get(r.risk_rating, 5))
    for result in results:
        print_result(result, verbose=args.verbose)

    print_summary(results, failed_targets, len(scan_specs))

    try:
        if args.output_json:
            export_json(results, args.output_json, args.modules, failed_targets,
                        len(scan_specs), saml_review)
        if args.output_csv:
            export_csv(results, args.output_csv, failed_targets, saml_review)
        if args.output_md:
            export_markdown(results, args.output_md, failed_targets, len(scan_specs), saml_review)
    except OSError as e:
        print(f"[!] Could not write report: {e}", file=sys.stderr)
        return 1

    return determine_exit_code(results, failed_targets, args.fail_on_risk,
                               args.fail_on_saml_match, saml_review)


if __name__ == "__main__":
    sys.exit(main())
