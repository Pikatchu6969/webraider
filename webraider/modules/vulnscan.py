"""Vulnerability scanner: Nikto, SQLi probes, XSS, LFI, SSRF checks."""
from __future__ import annotations

import urllib.parse

import requests
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webraider.config import has_tool
from webraider.utils import info, normalize_target, ok, run_cmd_stream, section_header, warn
from webraider.vulnmeta import extract_cves, make_finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

SQLI_PAYLOADS = [
    "'", "''", "`", '"', "\\",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "1' ORDER BY 1--", "1' ORDER BY 2--",
    "' UNION SELECT NULL--", "admin'--", "' OR 'unusual'='unusual",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../../../etc/passwd", "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd", "..%2f..%2fetc%2fpasswd",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/",
    "http://[::1]/", "http://0.0.0.0/", "http://0177.0.0.1/",
]

DB_ERROR_INDICATORS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
    "unclosed quotation", "syntax error", "warning: mysql",
    "you have an error in your sql", "postgresql", "sqlstate",
]


def _simple_get(url: str, timeout: int = 8) -> tuple[int, str]:
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 WebRaider/1.0"},
            allow_redirects=False,
        )
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


def _append_query_params(parsed, params: dict[str, list[str]]) -> str:
    new_query = urllib.parse.urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def run_nikto(target: str) -> dict:
    section_header("Web Vulnerability Scan (Nikto)", "bold red")
    url = normalize_target(target)
    results = {"tool": "nikto", "items": [], "raw_lines": [], "findings": []}

    if not has_tool("nikto"):
        warn("nikto not found. Install it with: sudo apt install nikto")
        return results

    info(f"Running nikto against [cyan]{url}[/cyan]")
    cmd = ["nikto", "-h", url, "-nointeractive", "-Format", "txt", "-output", "/dev/stdout"]
    rc, lines = run_cmd_stream(cmd, timeout=600)
    results["raw_lines"] = lines

    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("+"):
            continue
        if "OSVDB" in stripped and "CVE-" not in stripped.upper():
            # Keep lower-quality OSVDB-only lines out of the CVE summary.
            continue
        cves = extract_cves(stripped)
        item = {"detail": stripped, "cves": cves}
        results["items"].append(item)
        results["findings"].append(make_finding(
            module="vulnscan",
            category="nikto",
            title="Nikto web server finding",
            severity="Medium" if not cves else "High",
            cves=cves,
            evidence=stripped,
            url=url,
            recommendation="Review the affected component, confirm impact manually, and patch or harden as needed.",
        ))

    if results["items"]:
        ok(f"Nikto produced {len(results['items'])} reportable item(s).")
    else:
        info("Nikto scan complete. No reportable CVE-bearing items parsed.")

    return results


def sqli_probe(target: str) -> dict:
    section_header("SQL Injection Probe", "bold red")
    url = normalize_target(target)
    results = {"vulnerable": [], "tested": 0, "findings": []}

    if has_tool("sqlmap"):
        info("Using sqlmap in light mode (level 1, risk 1, batch).")
        cmd = [
            "sqlmap", "-u", url, "--level=1", "--risk=1", "--batch", "--forms",
            "--crawl=1", "--output-dir=/tmp/sqlmap_wr", "--timeout=10", "--retries=1",
        ]
        rc, lines = run_cmd_stream(cmd, timeout=300)
        results["sqlmap_output"] = lines
        for line in lines:
            lower = line.lower()
            if "is vulnerable" in lower or "[vulnerable]" in lower:
                cves = extract_cves(line)
                item = {"method": "sqlmap", "detail": line, "cves": cves}
                results["vulnerable"].append(item)
                results["findings"].append(make_finding(
                    module="vulnscan",
                    category="sqli",
                    title="SQL injection detected by sqlmap",
                    severity="High",
                    cves=cves,
                    evidence=line,
                    url=url,
                    recommendation="Use parameterized queries, safe ORM APIs, and server-side input validation.",
                ))
        if results["vulnerable"]:
            warn(f"sqlmap detected {len(results['vulnerable'])} SQLi finding(s).")
        return results

    info("Running manual SQLi probes (sqlmap not found).")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    if not query_params:
        query_params = {"id": ["1"]}

    for param, values in query_params.items():
        original = values[0] if values else "1"
        for payload in SQLI_PAYLOADS[:8]:
            test_params = dict(urllib.parse.parse_qs(parsed.query)) or {param: [original]}
            test_params[param] = [original + payload]
            test_url = _append_query_params(parsed, test_params)
            status, body = _simple_get(test_url)
            results["tested"] += 1
            body_lower = body.lower()
            indicator = next((i for i in DB_ERROR_INDICATORS if i in body_lower), "")
            if indicator:
                item = {"param": param, "payload": payload, "indicator": indicator, "url": test_url, "cves": []}
                results["vulnerable"].append(item)
                results["findings"].append(make_finding(
                    module="vulnscan",
                    category="sqli",
                    title="Possible error-based SQL injection",
                    severity="High",
                    evidence=f"Database error indicator found: {indicator}",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    recommendation="Use prepared statements and remove verbose database errors from responses.",
                ))
                warn(f"Possible SQLi in param {param} with payload: {payload}")
                break

    if results["vulnerable"]:
        table = Table(title="SQLi Findings", border_style="red")
        table.add_column("Param", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Indicator", style="red")
        for item in results["vulnerable"]:
            table.add_row(item.get("param", "?"), item.get("payload", "?"), item.get("indicator", "?"))
        console.print(table)
    else:
        ok(f"No obvious SQLi found ({results['tested']} tests performed).")

    return results


def xss_probe(target: str) -> dict:
    section_header("XSS Probe", "bold red")
    url = normalize_target(target)
    results = {"vulnerable": [], "tested": 0, "findings": []}
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query) or {"q": ["test"], "search": ["test"], "id": ["1"]}

    for param in list(query_params.keys())[:3]:
        for payload in XSS_PAYLOADS[:4]:
            test_params = dict(urllib.parse.parse_qs(parsed.query)) or {param: ["test"]}
            test_params[param] = [payload]
            test_url = _append_query_params(parsed, test_params)
            _, body = _simple_get(test_url)
            results["tested"] += 1
            if payload in body:
                item = {"param": param, "payload": payload, "url": test_url, "cves": []}
                results["vulnerable"].append(item)
                results["findings"].append(make_finding(
                    module="vulnscan",
                    category="xss",
                    title="Reflected cross-site scripting",
                    severity="Medium",
                    evidence="Payload was reflected unencoded in the response body.",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    recommendation="Apply context-aware output encoding and a restrictive Content Security Policy.",
                ))
                warn(f"Reflected XSS in param {param}.")

    if results["vulnerable"]:
        for item in results["vulnerable"]:
            console.print(Panel(
                f"Param: {item['param']}\nPayload: {item['payload']}\nURL: {item['url']}",
                title="XSS Finding",
                border_style="red",
            ))
    else:
        ok(f"No reflected XSS found ({results['tested']} tests).")

    return results


def lfi_probe(target: str) -> dict:
    section_header("LFI Probe", "bold red")
    url = normalize_target(target)
    results = {"vulnerable": [], "tested": 0, "findings": []}
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    if not query_params:
        query_params = {p: ["index"] for p in ["file", "page", "path", "include", "template", "doc", "view"]}

    for param in list(query_params.keys())[:4]:
        for payload in LFI_PAYLOADS:
            test_url = _append_query_params(parsed, {param: [payload]})
            _, body = _simple_get(test_url)
            results["tested"] += 1
            if "root:x:0:0" in body or "root:!:" in body:
                item = {"param": param, "payload": payload, "url": test_url, "cves": []}
                results["vulnerable"].append(item)
                results["findings"].append(make_finding(
                    module="vulnscan",
                    category="lfi",
                    title="Local file inclusion / path traversal",
                    severity="High",
                    evidence="Response contained /etc/passwd markers.",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    recommendation="Restrict file includes to allowlisted paths and normalize user-supplied paths.",
                ))
                warn(f"LFI detected in {param}; /etc/passwd appears readable.")
                break

    if not results["vulnerable"]:
        ok(f"No LFI found ({results['tested']} tests).")
    return results


def ssrf_probe(target: str) -> dict:
    section_header("SSRF Probe", "bold red")
    url = normalize_target(target)
    results = {"potential": [], "tested": 0, "findings": []}
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    ssrf_params = list(query_params.keys()) or ["url", "redirect", "next", "dest", "callback", "fetch"]

    for param in ssrf_params[:3]:
        for payload in SSRF_PAYLOADS[:3]:
            test_url = _append_query_params(parsed, {param: [payload]})
            status, body = _simple_get(test_url, timeout=6)
            results["tested"] += 1
            if status in (200, 301, 302):
                item = {"param": param, "payload": payload, "status": status, "url": test_url, "cves": []}
                results["potential"].append(item)
                results["findings"].append(make_finding(
                    module="vulnscan",
                    category="ssrf",
                    title="Potential server-side request forgery",
                    severity="High",
                    evidence=f"Injected internal URL returned HTTP status {status}.",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    recommendation="Block private IP ranges in server-side fetchers and use strict destination allowlists.",
                ))
                warn(f"Potential SSRF in {param} (status {status}).")

    if not results["potential"]:
        ok(f"No obvious SSRF indicators ({results['tested']} tests).")
    return results


def run_vulnscan(target: str, skip_nikto: bool = False) -> dict:
    results: dict = {}
    if not skip_nikto:
        results["nikto"] = run_nikto(target)
    results["sqli"] = sqli_probe(target)
    results["xss"] = xss_probe(target)
    results["lfi"] = lfi_probe(target)
    results["ssrf"] = ssrf_probe(target)

    findings: list[dict] = []
    for section in results.values():
        if isinstance(section, dict):
            findings.extend(section.get("findings", []))
    results["findings"] = findings

    section_header("Vulnerability Scan Summary", "bold red")
    if findings:
        for finding in findings:
            cve_label = ", ".join(finding.get("cves", [])) or f"N/A ({finding.get('cwe', 'no CWE')})"
            console.print(f"  WARN {finding.get('title')} - {cve_label}")
    else:
        ok("No critical vulnerabilities detected in active probes.")

    return results
