"""Reporting module: generates JSON and HTML reports from scan results."""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel

from webraider import __version__
from webraider.utils import ok, safe_filename, section_header
from webraider.vulnmeta import KNOWN_SSL_CVES, extract_cves, make_finding

console = Console()


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def cve_label(finding: dict) -> str:
    cves = finding.get("cves") or extract_cves(finding)
    if cves:
        return ", ".join(cves)
    cwe = finding.get("cwe") or "N/A"
    return f"N/A ({cwe})" if cwe != "N/A" else "N/A"


def _severity_class(severity: str) -> str:
    sev = str(severity or "").lower()
    if sev in {"critical", "high"}:
        return "crit"
    if sev in {"medium", "low"}:
        return "warn"
    return "ok"


def _normalize_existing_finding(item: dict) -> dict:
    cves = item.get("cves") or extract_cves(item)
    item = dict(item)
    item["cves"] = sorted(set(str(c).upper() for c in cves))
    item["cve"] = ", ".join(item["cves"]) if item["cves"] else "N/A"
    item.setdefault("cwe", "N/A")
    item.setdefault("severity", "Info")
    item.setdefault("module", "unknown")
    item.setdefault("title", item.get("category", "Finding"))
    item.setdefault("evidence", "")
    item.setdefault("url", "")
    item.setdefault("recommendation", "")
    return item


def _scan_data(results: dict) -> dict:
    scan = results.get("scan", {})
    if isinstance(scan, list):
        return {"ports": scan, "findings": []}
    if isinstance(scan, dict):
        return scan
    return {"ports": [], "findings": []}


def _collect_legacy_vuln_findings(vs: dict) -> list[dict]:
    findings: list[dict] = []
    if not isinstance(vs, dict):
        return findings

    if isinstance(vs.get("findings"), list):
        findings.extend(_normalize_existing_finding(f) for f in vs["findings"] if isinstance(f, dict))
        return findings

    for category in ["sqli", "xss", "lfi"]:
        data = vs.get(category, {}) or {}
        for item in data.get("vulnerable", []) or []:
            title = {
                "sqli": "Possible SQL injection",
                "xss": "Reflected cross-site scripting",
                "lfi": "Local file inclusion / path traversal",
            }[category]
            findings.append(make_finding(
                module="vulnscan",
                category=category,
                title=title,
                severity="High" if category in {"sqli", "lfi"} else "Medium",
                cves=item.get("cves", []) if isinstance(item, dict) else [],
                evidence=json.dumps(item, default=str)[:1200],
                url=item.get("url", "") if isinstance(item, dict) else "",
                parameter=item.get("param", "") if isinstance(item, dict) else "",
                payload=item.get("payload", "") if isinstance(item, dict) else "",
            ))

    ssrf = vs.get("ssrf", {}) or {}
    for item in ssrf.get("potential", []) or []:
        findings.append(make_finding(
            module="vulnscan",
            category="ssrf",
            title="Potential server-side request forgery",
            severity="High",
            cves=item.get("cves", []) if isinstance(item, dict) else [],
            evidence=json.dumps(item, default=str)[:1200],
            url=item.get("url", "") if isinstance(item, dict) else "",
            parameter=item.get("param", "") if isinstance(item, dict) else "",
            payload=item.get("payload", "") if isinstance(item, dict) else "",
        ))

    nikto = vs.get("nikto", {}) or {}
    raw_items = nikto.get("items") or nikto.get("nikto") or []
    for item in raw_items:
        detail = item.get("detail", "") if isinstance(item, dict) else str(item)
        cves = item.get("cves", []) if isinstance(item, dict) else extract_cves(detail)
        findings.append(make_finding(
            module="vulnscan",
            category="nikto",
            title="Nikto web server finding",
            severity="High" if cves else "Medium",
            cves=cves,
            evidence=detail,
        ))
    return findings


def _collect_auth_findings(auth: dict) -> list[dict]:
    findings: list[dict] = []
    if not isinstance(auth, dict):
        return findings
    if isinstance(auth.get("findings"), list):
        findings.extend(_normalize_existing_finding(f) for f in auth["findings"] if isinstance(f, dict))
        return findings
    dc = auth.get("default_creds", {}) or {}
    for item in dc.get("found", []) or []:
        if isinstance(item, dict):
            username = item.get("username", "")
            password = item.get("password", "")
            url = item.get("url", "")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            username, password = item[0], item[1]
            url = ""
        else:
            username, password, url = str(item), "", ""
        findings.append(make_finding(
            module="authtest",
            category="default_creds",
            title="Default credentials accepted",
            severity="Critical",
            evidence=f"Credential pair {username}:{password} was reported as accepted.",
            url=url,
        ))
    return findings


def collect_findings(results: dict) -> list[dict]:
    findings: list[dict] = []

    scan = _scan_data(results)
    findings.extend(_normalize_existing_finding(f) for f in scan.get("findings", []) if isinstance(f, dict))
    for port in scan.get("ports", []) or []:
        if isinstance(port, dict) and port.get("cves"):
            findings.append(make_finding(
                module="scan",
                category="service_cve",
                title=f"Service CVE detected on port {port.get('port', '')}",
                severity="High",
                cves=port.get("cves", []),
                port=str(port.get("port", "")),
                service=f"{port.get('service', '')} {port.get('product', '')} {port.get('version', '')}".strip(),
                evidence=json.dumps(port.get("scripts", []), default=str)[:1200],
            ))

    for key in ["webfinger", "sslcheck"]:
        section = results.get(key, {}) or {}
        if isinstance(section, dict):
            findings.extend(_normalize_existing_finding(f) for f in section.get("findings", []) if isinstance(f, dict))

    findings.extend(_collect_legacy_vuln_findings(results.get("vulnscan", {}) or {}))
    findings.extend(_collect_auth_findings(results.get("authtest", {}) or {}))

    # De-duplicate while preserving order.
    seen = set()
    deduped: list[dict] = []
    for finding in findings:
        normalized = _normalize_existing_finding(finding)
        key = (
            normalized.get("module"), normalized.get("title"), normalized.get("url"),
            normalized.get("parameter"), normalized.get("payload"), tuple(normalized.get("cves", [])),
            normalized.get("evidence", "")[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)
    return deduped


def _findings_section(findings: list[dict]) -> str:
    if not findings:
        return "<section><h2>Findings and CVE Summary</h2><p class='ok'>No reportable findings were collected.</p></section>"

    critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    cve_count = len({c for f in findings for c in f.get("cves", [])})

    rows = ""
    for idx, finding in enumerate(findings, 1):
        sev = esc(finding.get("severity", "Info"))
        cls = _severity_class(sev)
        evidence = esc(finding.get("evidence", ""))[:600]
        location_parts = [finding.get("url", ""), finding.get("port", ""), finding.get("parameter", "")]
        location = " / ".join(str(p) for p in location_parts if p)
        rows += (
            f"<tr><td>{idx}</td>"
            f"<td>{esc(finding.get('module', ''))}</td>"
            f"<td class='{cls}'>{sev}</td>"
            f"<td>{esc(finding.get('title', ''))}</td>"
            f"<td><strong>{esc(cve_label(finding))}</strong></td>"
            f"<td>{esc(finding.get('cwe', 'N/A'))}</td>"
            f"<td>{esc(location)}</td>"
            f"<td>{evidence}</td></tr>"
        )

    return f"""
<section><h2>Findings and CVE Summary</h2>
<div class="summary-grid">
  <div class="summary-card"><div class="num crit">{len(findings)}</div><div class="desc">Total reportable finding(s)</div></div>
  <div class="summary-card"><div class="num crit">{critical}</div><div class="desc">Critical finding(s)</div></div>
  <div class="summary-card"><div class="num warn">{high}</div><div class="desc">High finding(s)</div></div>
  <div class="summary-card"><div class="num ok">{cve_count}</div><div class="desc">Unique CVE ID(s) extracted</div></div>
</div>
<p class="note">Generic classes such as SQLi, XSS, LFI, SSRF, missing headers, and default credentials do not have one universal CVE. The report shows extracted CVEs where tools provide them, otherwise it shows the CWE weakness ID.</p>
<table><thead><tr><th>#</th><th>Module</th><th>Severity</th><th>Finding</th><th>CVE</th><th>CWE</th><th>Location</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>
</section>
"""


def _ports_table(scan: Any) -> str:
    scan = scan if isinstance(scan, dict) else {"ports": scan if isinstance(scan, list) else []}
    ports = scan.get("ports", []) or []
    if not ports:
        return ""
    rows = ""
    for p in ports:
        if not isinstance(p, dict):
            continue
        version = f"{p.get('product', '')} {p.get('version', '')}".strip() or "-"
        cves = ", ".join(p.get("cves", []) or []) or "-"
        rows += f"<tr><td>{esc(p.get('port', ''))}</td><td>{esc(p.get('protocol', ''))}</td><td>{esc(p.get('service', ''))}</td><td>{esc(version)}</td><td>{esc(cves)}</td></tr>"
    return f"<section><h2>Port Scan</h2><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th><th>CVEs</th></tr></thead><tbody>{rows}</tbody></table></section>"


def _webfinger_table(wf: dict) -> str:
    if not wf:
        return ""
    tech_pills = "".join(f'<span class="tech-pill">{esc(t)}</span>' for t in wf.get("technologies", []))
    sec_rows = ""
    for name, status in (wf.get("security_headers") or {}).items():
        present = bool(status.get("present")) if isinstance(status, dict) else False
        cls = "present" if present else "missing"
        value = status.get("value") if isinstance(status, dict) else ""
        sec_rows += f"<tr><td>{esc(name)}</td><td class='{cls}'>{'Present' if present else 'Missing'}</td><td>{esc(value or '-')}</td><td>{'N/A (CWE-693)' if not present else '-'}</td></tr>"
    return f"""<section><h2>Web Fingerprint</h2>
<p>Status: <strong>{esc(wf.get('status_code', '?'))}</strong> &nbsp; URL: <code>{esc(wf.get('final_url', '?'))}</code></p>
<p><strong>Technologies:</strong> {tech_pills or '-'}</p>
<table><thead><tr><th>Security Header</th><th>Status</th><th>Value</th><th>CVE/CWE</th></tr></thead><tbody>{sec_rows}</tbody></table></section>"""


def _dirscan_table(ds: dict) -> str:
    if not ds or not ds.get("found"):
        return ""
    rows = ""
    for i, item in enumerate(ds.get("found", []), 1):
        if isinstance(item, dict):
            path = item.get("path", "")
            status = item.get("status", "-")
            size = item.get("size", "-")
            url = item.get("url", "")
        else:
            path, status, size, url = str(item), "-", "-", ""
        rows += f"<tr><td>{i}</td><td>{esc(path)}</td><td>{esc(status)}</td><td>{esc(size)}</td><td>{esc(url)}</td></tr>"
    return f"<section><h2>Directory Scan ({len(ds.get('found', []))} paths)</h2><table><thead><tr><th>#</th><th>Path</th><th>Status</th><th>Size</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table></section>"


def _vuln_section(vs: dict) -> str:
    if not vs:
        return ""
    html_out = "<section><h2>Vulnerability Probe Details</h2>"
    for vtype in ["sqli", "xss", "lfi", "ssrf"]:
        data = vs.get(vtype, {}) or {}
        items = data.get("vulnerable") or data.get("potential") or []
        if not items:
            continue
        rows = ""
        for item in items:
            cves = ", ".join(item.get("cves", []) if isinstance(item, dict) else []) or "N/A"
            details = json.dumps(item, default=str) if isinstance(item, dict) else str(item)
            rows += f"<tr><td>{esc(vtype.upper())}</td><td>{esc(cves)}</td><td>{esc(details)}</td></tr>"
        html_out += f"<h3>{esc(vtype.upper())}</h3><table><thead><tr><th>Type</th><th>CVE</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"
    html_out += "</section>"
    return html_out


def _ssl_section(ssl: dict) -> str:
    if not ssl:
        return ""
    cert = ssl.get("certificate", {}) or {}
    days = cert.get("days_remaining", "?")
    expired = cert.get("expired", False)
    proto_rows = ""
    for proto, value in (ssl.get("protocols") or {}).items():
        supported = value.get("supported", value) if isinstance(value, dict) else value
        kind = {
            "ssl.2.0": "ssl_2_0", "ssl.3.0": "ssl_3_0", "SSLv2": "ssl_2_0", "SSLv3": "ssl_3_0",
        }.get(proto)
        cves = ", ".join(KNOWN_SSL_CVES.get(kind, [])) if supported and kind else "-"
        cls = "crit" if supported and kind else ("ok" if supported else "muted")
        proto_rows += f"<tr><td>{esc(proto)}</td><td class='{cls}'>{'YES' if supported else 'NO'}</td><td>{esc(cves)}</td></tr>"
    cert_status = "EXPIRED" if expired else f"Valid ({days} days remaining)"
    return f"""<section><h2>SSL/TLS Analysis</h2>
<p>Certificate: <strong>{esc(cert_status)}</strong> &nbsp; Subject: <code>{esc(cert.get('subject', '?'))}</code></p>
<table><thead><tr><th>Protocol</th><th>Supported</th><th>CVE</th></tr></thead><tbody>{proto_rows}</tbody></table></section>"""


def _recon_section(recon: dict) -> str:
    if not recon:
        return ""
    whois = recon.get("whois", {}) or {}
    subs = recon.get("subdomains", {}) or {}
    rows = ""
    for key in ["domain", "registrar", "creation_date", "expiration_date", "org", "country"]:
        value = whois.get(key, "")
        if value and value != "N/A":
            rows += f"<tr><td>{esc(key.replace('_', ' ').title())}</td><td>{esc(value)}</td></tr>"
    sub_list = "".join(f"<li>{esc(s)}</li>" for s in subs.get("subdomains", [])[:20])
    return f"<section><h2>Recon</h2><table><thead><tr><th>WHOIS Field</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>{'<ul>' + sub_list + '</ul>' if sub_list else ''}</section>"


def _auth_section(auth: dict) -> str:
    if not auth:
        return ""
    dc = auth.get("default_creds", {}) or {}
    found = dc.get("found", []) or []
    if not found:
        return "<section><h2>Auth Testing</h2><p class='ok'>No default credentials found.</p></section>"
    rows = ""
    for item in found:
        if isinstance(item, dict):
            username, password, url = item.get("username", ""), item.get("password", ""), item.get("url", "")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            username, password, url = item[0], item[1], ""
        else:
            username, password, url = str(item), "", ""
        rows += f"<tr class='crit'><td>{esc(username)}</td><td>{esc(password)}</td><td>{esc(url)}</td><td>N/A (CWE-798)</td></tr>"
    return f"<section><h2>Auth Testing</h2><table><thead><tr><th>Username</th><th>Password</th><th>URL</th><th>CVE/CWE</th></tr></thead><tbody>{rows}</tbody></table></section>"


def _html_page(target: str, timestamp: str, results: dict, findings: list[dict]) -> str:
    ports = _scan_data(results).get("ports", [])
    wf = results.get("webfinger", {}) or {}
    ds = results.get("dirscan", {}) or {}
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebRaider Report - {esc(target)}</title>
<style>
:root {{ --bg:#0d1117; --surface:#161b22; --surface2:#21262d; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#ff4757; --green:#3fb950; --yellow:#d29922; --blue:#58a6ff; --red:#f85149; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:var(--bg); color:var(--text); font-family:Segoe UI,system-ui,sans-serif; line-height:1.55; }}
header {{ background:linear-gradient(135deg,#1a0505 0%,#0d1117 60%); border-bottom:2px solid var(--accent); padding:2rem 3rem; }}
header h1 {{ margin:0; font-size:2rem; color:var(--accent); letter-spacing:1px; }} .subtitle {{ color:var(--muted); margin-top:.3rem; }}
.container {{ max-width:1300px; margin:0 auto; padding:2rem 3rem; }} section {{ margin-bottom:2.5rem; }} section h2 {{ color:var(--accent); border-left:3px solid var(--accent); padding-left:.75rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-top:1rem; }}
th {{ background:var(--surface2); color:var(--muted); text-transform:uppercase; font-size:.74rem; letter-spacing:1px; text-align:left; padding:.6rem .8rem; }}
td {{ padding:.55rem .8rem; border-top:1px solid var(--border); font-size:.88rem; vertical-align:top; }} tr:hover td {{ background:rgba(255,255,255,.02); }}
.present,.ok {{ color:var(--green); }} .missing,.crit {{ color:var(--red); }} .warn {{ color:var(--yellow); }} .muted {{ color:var(--muted); }}
.tech-pill {{ display:inline-block; background:rgba(88,166,255,.15); border:1px solid var(--blue); color:var(--blue); border-radius:12px; padding:.15rem .6rem; font-size:.78rem; margin:2px; }}
.summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1rem; margin-bottom:1rem; }} .summary-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.2rem; }} .num {{ font-size:2rem; font-weight:700; }} .desc,.note {{ color:var(--muted); font-size:.86rem; }}
.warning-box {{ background:rgba(210,153,34,.08); border:1px solid var(--yellow); border-radius:8px; padding:1rem 1.5rem; color:var(--yellow); margin-bottom:1.5rem; }} code {{ color:var(--blue); }} footer {{ text-align:center; color:var(--muted); padding:2rem; border-top:1px solid var(--border); }}
</style>
</head>
<body>
<header><h1>WebRaider Pentest Report</h1><div class="subtitle">Target: <strong>{esc(target)}</strong> | {esc(timestamp)} | WebRaider v{esc(__version__)}</div></header>
<div class="container">
<div class="warning-box">This report is intended for authorized security assessments only.</div>
<div class="summary-grid">
  <div class="summary-card"><div class="num ok">{len(ports)}</div><div class="desc">Open ports</div></div>
  <div class="summary-card"><div class="num ok">{len(wf.get('technologies', []))}</div><div class="desc">Technologies</div></div>
  <div class="summary-card"><div class="num ok">{len(ds.get('found', [])) if isinstance(ds, dict) else 0}</div><div class="desc">Paths found</div></div>
  <div class="summary-card"><div class="num crit">{len(findings)}</div><div class="desc">Reportable findings</div></div>
</div>
{_findings_section(findings)}
{_ports_table(results.get('scan', {}))}
{_webfinger_table(wf)}
{_dirscan_table(ds if isinstance(ds, dict) else {})}
{_vuln_section(results.get('vulnscan', {}) or {})}
{_ssl_section(results.get('sslcheck', {}) or {})}
{_recon_section(results.get('recon', {}) or {})}
{_auth_section(results.get('authtest', {}) or {})}
</div><footer>Generated by WebRaider v{esc(__version__)}</footer>
</body></html>
"""


def generate_report(target: str, results: dict, output_dir: str) -> dict:
    """Generate JSON + HTML reports from aggregated scan results."""
    section_header("Generating Report", "bold cyan")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_target = safe_filename(target.replace("://", "_"))
    json_path = out / f"webraider_{safe_target}.json"
    html_path = out / f"webraider_{safe_target}.html"

    findings = collect_findings(results)
    report_data = {
        "target": target,
        "timestamp": timestamp,
        "version": __version__,
        "findings": findings,
        "results": results,
        "notes": {
            "cve_policy": "CVEs are extracted from tool output or known protocol vulnerability checks. Generic flaw classes use CWE IDs because they do not have a single universal CVE.",
        },
    }

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2, default=str)
    ok(f"JSON report: [cyan]{json_path}[/cyan]")

    html_report = _html_page(target, timestamp, results, findings)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_report)
    ok(f"HTML report: [cyan]{html_path}[/cyan]")

    console.print(Panel(
        f"Reports saved to: [cyan]{out}[/cyan]\n"
        f"  JSON -> [dim]{json_path.name}[/dim]\n"
        f"  HTML -> [dim]{html_path.name}[/dim]\n"
        f"  Findings -> [bold]{len(findings)}[/bold]",
        border_style="green",
        title="Report Complete",
    ))

    return {"json": str(json_path), "html": str(html_path), "findings": findings}
