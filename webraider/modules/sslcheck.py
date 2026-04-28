"""SSL/TLS analysis using sslyze or openssl."""
from __future__ import annotations

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table

from webraider.config import has_tool
from webraider.utils import extract_host, info, ok, run_cmd, section_header, spinner_task, warn, err
from webraider.vulnmeta import ssl_finding

console = Console()

INSECURE_PROTOCOLS = {
    "ssl.2.0": "ssl_2_0",
    "ssl.3.0": "ssl_3_0",
    "tls.1.0": "tls_1_0",
    "tls.1.1": "tls_1_1",
    "SSLv2": "ssl_2_0",
    "SSLv3": "ssl_3_0",
    "TLSv1.0": "tls_1_0",
    "TLSv1.1": "tls_1_1",
}


def _status_is_vulnerable(value) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        up = value.upper()
        return "VULNERABLE" in up and "NOT_VULNERABLE" not in up
    return False


def _run_sslyze(host: str, port: int = 443) -> dict:
    results: dict = {}
    with spinner_task(f"Running sslyze on {host}:{port}"):
        rc, out, stderr = run_cmd([
            "sslyze", f"{host}:{int(port)}", "--json_out=-", "--certinfo",
            "--ssl2", "--ssl3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
            "--compression", "--heartbleed", "--openssl_ccs", "--robot",
        ], timeout=120)

    if rc != 0 or not out.strip():
        return {"error": stderr or "sslyze failed"}

    try:
        data = json.loads(out)
        server_scan = data.get("server_scan_results", [{}])[0]
        scan_result = server_scan.get("scan_result", {})
        results["raw"] = scan_result

        protocols = {}
        for proto in [
            "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites",
            "tls_1_1_cipher_suites", "tls_1_2_cipher_suites", "tls_1_3_cipher_suites",
        ]:
            proto_data = scan_result.get(proto, {}) or {}
            result_data = proto_data.get("result", {}) or {}
            accepted = result_data.get("accepted_cipher_suites", []) or []
            key = proto.replace("_cipher_suites", "").replace("_", ".")
            protocols[key] = {
                "supported": len(accepted) > 0,
                "ciphers": [c.get("cipher_suite", {}).get("name", "") for c in accepted[:10]],
            }
        results["protocols"] = protocols

        certinfo = scan_result.get("certificate_info", {}).get("result", {}) or {}
        chain = (certinfo.get("certificate_deployments") or [{}])[0]
        leaf = (chain.get("received_certificate_chain") or [{}])[0]
        subject = leaf.get("subject", {}) or {}
        not_after = leaf.get("not_valid_after", "")
        cert = {
            "subject": subject.get("rfc4514_string", ""),
            "issuer": (leaf.get("issuer", {}) or {}).get("rfc4514_string", ""),
            "not_after": not_after,
            "expired": False,
        }
        if not_after:
            try:
                exp = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                now = datetime.now(exp.tzinfo)
                cert["expired"] = exp < now
                cert["days_remaining"] = (exp - now).days
            except Exception:
                pass
        results["certificate"] = cert

        hb = (scan_result.get("heartbleed", {}).get("result", {}) or {}).get("is_vulnerable_to_heartbleed")
        ccs = (scan_result.get("openssl_ccs_injection", {}).get("result", {}) or {}).get("is_vulnerable_to_ccs_injection")
        robot = (scan_result.get("robot", {}).get("result", {}) or {}).get("robot_result")
        results["vulnerabilities"] = {
            "heartbleed": hb,
            "openssl_ccs_injection": ccs,
            "robot": robot,
        }

        comp = scan_result.get("tls_compression", {}).get("result", {}) or {}
        results["compression"] = bool(comp.get("supports_compression", False))
    except Exception as e:
        results["parse_error"] = str(e)
        results["raw_output"] = out[:2000]

    return results


def _run_openssl_fallback(host: str, port: int = 443) -> dict:
    results: dict = {}
    info("Using openssl s_client as fallback.")

    rc, out, errout = run_cmd([
        "openssl", "s_client", "-connect", f"{host}:{int(port)}", "-servername", host,
    ], input_text="\n", timeout=15)
    results["raw_handshake"] = out + errout

    protocol_cmds = {
        "SSLv3": ["openssl", "s_client", "-ssl3", "-connect", f"{host}:{int(port)}"],
        "TLSv1.0": ["openssl", "s_client", "-tls1", "-connect", f"{host}:{int(port)}"],
        "TLSv1.1": ["openssl", "s_client", "-tls1_1", "-connect", f"{host}:{int(port)}"],
        "TLSv1.2": ["openssl", "s_client", "-tls1_2", "-connect", f"{host}:{int(port)}"],
        "TLSv1.3": ["openssl", "s_client", "-tls1_3", "-connect", f"{host}:{int(port)}"],
    }
    protocols = {}
    for proto, cmd in protocol_cmds.items():
        _, pout, perr = run_cmd(cmd, input_text="\n", timeout=10)
        combined = pout + perr
        protocols[proto] = ("Cipher is" in combined and "Cipher is (NONE)" not in combined) or "Verify return code:" in combined
    results["protocols"] = protocols

    _, cert_out, _ = run_cmd(
        ["openssl", "x509", "-noout", "-enddate", "-subject", "-issuer"],
        input_text=out,
        timeout=10,
    )
    results["certificate_raw"] = cert_out

    cert: dict = {}
    for line in cert_out.splitlines():
        if line.startswith("notAfter="):
            date_str = line.split("=", 1)[1].strip()
            cert["not_after"] = date_str
            try:
                exp = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                cert["days_remaining"] = (exp - datetime.utcnow()).days
                cert["expired"] = cert["days_remaining"] < 0
            except Exception:
                pass
        elif line.startswith("subject="):
            cert["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            cert["issuer"] = line.split("=", 1)[1].strip()
    results["certificate"] = cert

    return results


def _build_findings(data: dict, host: str, port: int) -> list[dict]:
    findings: list[dict] = []
    protocols = data.get("protocols", {}) or {}
    for proto, value in protocols.items():
        supported = value.get("supported", False) if isinstance(value, dict) else bool(value)
        if not supported:
            continue
        kind = INSECURE_PROTOCOLS.get(proto)
        if kind:
            findings.append(ssl_finding(
                kind,
                evidence=f"{proto} is supported on {host}:{port}.",
                port=str(port),
                service="https",
                recommendation="Disable SSLv2/SSLv3/TLS 1.0/TLS 1.1 and allow only TLS 1.2+ with strong cipher suites.",
            ))

    vulns = data.get("vulnerabilities", {}) or {}
    for key, status in vulns.items():
        if _status_is_vulnerable(status):
            findings.append(ssl_finding(
                key,
                evidence=f"sslyze reported {key}: {status}",
                port=str(port),
                service="https",
                recommendation="Patch the TLS stack and disable affected algorithms or key exchanges.",
            ))

    if data.get("compression"):
        findings.append(ssl_finding(
            "tls_compression",
            evidence=f"TLS compression is enabled on {host}:{port}.",
            port=str(port),
            service="https",
            recommendation="Disable TLS compression.",
        ))

    cert = data.get("certificate", {}) or {}
    if cert.get("expired") is True:
        findings.append(ssl_finding(
            "cert_expired",
            evidence=f"Certificate expired at {cert.get('not_after', 'unknown date')}.",
            port=str(port),
            service="https",
            recommendation="Renew and redeploy a valid certificate chain.",
        ))

    return findings


def ssl_check(target: str, port: int = 443) -> dict:
    section_header("SSL/TLS Analysis", "bold cyan")
    host = extract_host(target)
    results: dict = {"host": host, "port": port, "findings": []}

    if has_tool("sslyze"):
        info("Using sslyze for deep SSL analysis.")
        data = _run_sslyze(host, port)
    elif has_tool("openssl"):
        data = _run_openssl_fallback(host, port)
    else:
        err("Neither sslyze nor openssl found.")
        return results

    results.update(data)
    results["findings"] = _build_findings(results, host, port)

    protocols = results.get("protocols", {}) or {}
    if protocols:
        proto_table = Table(title="Protocol Support", border_style="bright_black")
        proto_table.add_column("Protocol", style="cyan", min_width=10)
        proto_table.add_column("Supported", width=12)
        proto_table.add_column("Notes", style="dim")
        proto_table.add_column("CVE", style="red")
        for proto, value in protocols.items():
            supported = value.get("supported", False) if isinstance(value, dict) else bool(value)
            kind = INSECURE_PROTOCOLS.get(proto)
            is_bad = supported and bool(kind)
            cve = ""
            if is_bad and kind in {"ssl_2_0", "ssl_3_0"}:
                cve = ", ".join(ssl_finding(kind).get("cves", []))
            proto_table.add_row(proto, "YES" if supported else "NO", "INSECURE" if is_bad else "OK" if supported else "-", cve or "-")
        console.print(proto_table)

    cert = results.get("certificate", {}) or {}
    if cert:
        days = cert.get("days_remaining")
        expired = cert.get("expired", False)
        cert_table = Table(title="Certificate", border_style="bright_black", show_header=False)
        cert_table.add_column("Field", style="cyan", min_width=15)
        cert_table.add_column("Value", style="white")
        cert_table.add_row("Subject", str(cert.get("subject", "N/A")))
        cert_table.add_row("Issuer", str(cert.get("issuer", "N/A"))[:120])
        cert_table.add_row("Expires", str(cert.get("not_after", "N/A")))
        if days is not None:
            cert_table.add_row("Days Remaining", str(days))
        cert_table.add_row("Status", "EXPIRED" if expired else "VALID")
        console.print(cert_table)

    if results["findings"]:
        for finding in results["findings"]:
            cves = ", ".join(finding.get("cves", [])) or finding.get("cwe", "N/A")
            warn(f"{finding.get('title')} ({cves})")
    else:
        ok("No SSL/TLS vulnerabilities detected by available checks.")

    return results
