"""Finding and CVE helpers for WebRaider reports."""
from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

GENERIC_WEAKNESS = {
    "sqli": {"cwe": "CWE-89", "name": "SQL Injection", "severity": "High"},
    "xss": {"cwe": "CWE-79", "name": "Cross-Site Scripting", "severity": "Medium"},
    "lfi": {"cwe": "CWE-22", "name": "Path Traversal / Local File Inclusion", "severity": "High"},
    "ssrf": {"cwe": "CWE-918", "name": "Server-Side Request Forgery", "severity": "High"},
    "default_creds": {"cwe": "CWE-798", "name": "Use of Hard-coded Credentials", "severity": "Critical"},
    "hydra": {"cwe": "CWE-521", "name": "Weak Password Requirements", "severity": "High"},
    "missing_security_header": {"cwe": "CWE-693", "name": "Missing Protection Mechanism", "severity": "Low"},
    "cookie_secure": {"cwe": "CWE-614", "name": "Sensitive Cookie Without Secure Attribute", "severity": "Medium"},
    "cookie_httponly": {"cwe": "CWE-1004", "name": "Sensitive Cookie Without HttpOnly Attribute", "severity": "Medium"},
    "weak_tls": {"cwe": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm", "severity": "Medium"},
    "cert_expired": {"cwe": "CWE-295", "name": "Improper Certificate Validation", "severity": "Medium"},
    "nikto": {"cwe": "CWE-1035", "name": "Vulnerable Third Party Component", "severity": "Medium"},
    "service_cve": {"cwe": "CWE-1104", "name": "Use of Unmaintained Third Party Components", "severity": "High"},
}

KNOWN_SSL_CVES = {
    "heartbleed": ["CVE-2014-0160"],
    "openssl_ccs_injection": ["CVE-2014-0224"],
    "robot": ["CVE-2017-13099"],
    "tls_compression": ["CVE-2012-4929"],
    "ssl_2_0": ["CVE-2016-0800"],
    "ssl_3_0": ["CVE-2014-3566"],
}

SSL_TITLES = {
    "heartbleed": "Heartbleed TLS heartbeat vulnerability",
    "openssl_ccs_injection": "OpenSSL CCS injection vulnerability",
    "robot": "ROBOT RSA padding oracle vulnerability",
    "tls_compression": "TLS compression enabled (CRIME risk)",
    "ssl_2_0": "SSLv2 supported",
    "ssl_3_0": "SSLv3 supported",
    "tls_1_0": "TLS 1.0 supported",
    "tls_1_1": "TLS 1.1 supported",
    "cert_expired": "Expired TLS certificate",
}


def extract_cves(value: Any) -> list[str]:
    """Extract unique CVE IDs from strings, lists, dicts, or nested structures."""
    if value is None:
        return []
    if isinstance(value, dict):
        text = "\n".join(str(k) + " " + str(v) for k, v in value.items())
    elif isinstance(value, (list, tuple, set)):
        text = "\n".join(str(v) for v in value)
    else:
        text = str(value)
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(text)})


def make_finding(
    *,
    module: str,
    category: str,
    title: str | None = None,
    severity: str | None = None,
    cwe: str | None = None,
    cves: list[str] | None = None,
    evidence: str = "",
    url: str = "",
    parameter: str = "",
    payload: str = "",
    port: str = "",
    service: str = "",
    recommendation: str = "",
) -> dict[str, Any]:
    meta = GENERIC_WEAKNESS.get(category, {})
    detected_cves = list(cves or [])
    detected_cves.extend(extract_cves(evidence))
    detected_cves = sorted(set(c.upper() for c in detected_cves if c))
    return {
        "module": module,
        "category": category,
        "title": title or meta.get("name", category),
        "severity": severity or meta.get("severity", "Info"),
        "cves": detected_cves,
        "cve": ", ".join(detected_cves) if detected_cves else "N/A",
        "cwe": cwe or meta.get("cwe", "N/A"),
        "evidence": evidence[:2000] if evidence else "",
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "port": str(port) if port else "",
        "service": service,
        "recommendation": recommendation,
    }


def ssl_finding(kind: str, evidence: str = "", **extra: Any) -> dict[str, Any]:
    cves = KNOWN_SSL_CVES.get(kind, [])
    cwe = "CWE-327" if kind != "cert_expired" else "CWE-295"
    severity = "High" if kind in {"heartbleed", "openssl_ccs_injection", "robot", "ssl_2_0", "ssl_3_0"} else "Medium"
    return make_finding(
        module="sslcheck",
        category="weak_tls" if kind != "cert_expired" else "cert_expired",
        title=SSL_TITLES.get(kind, kind),
        severity=severity,
        cwe=cwe,
        cves=cves,
        evidence=evidence,
        **extra,
    )
