"""Nmap port scanner with XML parsing and CVE extraction from NSE output."""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from rich.console import Console
from rich.table import Table

from webraider.utils import extract_host, info, ok, section_header, warn
from webraider.vulnmeta import extract_cves, make_finding

console = Console()


def safe_nmap_cmd(flags: str, ports: str, host: str, xml_path: str) -> list[str]:
    port_args = shlex.split(str(ports))
    if port_args and port_args[0].startswith("--"):
        return ["nmap", *shlex.split(flags), *port_args, "-oX", xml_path, host]
    return ["nmap", *shlex.split(flags), "-p", str(ports), "-oX", xml_path, host]


def _script_outputs(port_el: ET.Element) -> list[dict[str, str]]:
    scripts = []
    for script in port_el.findall("script"):
        scripts.append({
            "id": script.get("id", ""),
            "output": script.get("output", ""),
        })
    return scripts


def _parse_ports(xml_path: str) -> tuple[list[dict], list[dict]]:
    results: list[dict] = []
    findings: list[dict] = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"
        if state != "up":
            warn("Host appears down")
            continue

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            svc = port_el.find("service")
            scripts = _script_outputs(port_el)
            cpes = [cpe.text or "" for cpe in svc.findall("cpe")] if svc is not None else []
            script_text = "\n".join(s.get("output", "") for s in scripts)
            cves = extract_cves(script_text)
            port_id = port_el.get("portid", "")
            protocol = port_el.get("protocol", "")
            service = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""

            item = {
                "port": port_id,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "cpe": cpes,
                "scripts": scripts,
                "cves": cves,
            }
            results.append(item)

            if cves:
                findings.append(make_finding(
                    module="scan",
                    category="service_cve",
                    title=f"Service CVE detected on {port_id}/{protocol}",
                    severity="High",
                    cves=cves,
                    port=port_id,
                    service=f"{service} {product} {version}".strip(),
                    evidence=script_text[:1200],
                    recommendation="Confirm the service version and patch or upgrade the affected package.",
                ))

    return results, findings


def nmap_scan(target: str, ports: str = "1-1000", flags: str = "-sV -T3") -> dict:
    section_header("Nmap Scan", "bold green")
    host = extract_host(target)

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        xml_path = tf.name

    cmd = safe_nmap_cmd(flags, ports, host, xml_path)
    info(f"Running: {' '.join(shlex.quote(part) for part in cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            text=True,
        )
    except subprocess.TimeoutExpired:
        warn("Scan timed out")
        return {"host": host, "ports": [], "findings": [], "error": "timeout"}
    except FileNotFoundError:
        warn("nmap not found. Install it with: sudo apt install nmap")
        return {"host": host, "ports": [], "findings": [], "error": "nmap_missing"}

    if proc.returncode != 0:
        warn(f"Nmap error: {proc.stderr.strip()}")
        if not os.path.exists(xml_path):
            return {"host": host, "ports": [], "findings": [], "error": proc.stderr.strip()}

    if not os.path.exists(xml_path):
        warn("No XML output generated")
        return {"host": host, "ports": [], "findings": [], "error": "no_xml"}

    try:
        results, findings = _parse_ports(xml_path)
    except ET.ParseError as e:
        warn(f"XML parse error: {e}")
        return {"host": host, "ports": [], "findings": [], "error": str(e)}
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass

    table = Table(title="Open Ports", border_style="bright_black")
    table.add_column("Port", style="cyan")
    table.add_column("Proto", style="dim")
    table.add_column("Service", style="white")
    table.add_column("Version", style="yellow")
    table.add_column("CVEs", style="red")

    for item in results:
        version = f"{item['product']} {item['version']}".strip()
        table.add_row(
            item["port"],
            item["protocol"],
            item["service"],
            version or "-",
            ", ".join(item.get("cves", [])) or "-",
        )

    console.print(table)
    ok(f"{len(results)} open ports found")
    if findings:
        warn(f"{len(findings)} service CVE finding(s) extracted from Nmap script output")

    return {"host": host, "ports": results, "findings": findings}


def quick_scan(target: str) -> dict:
    return nmap_scan(target, ports="--top-ports 100", flags="-sV -T3 --open")


def full_scan(target: str) -> dict:
    return nmap_scan(target, ports="1-65535", flags="-sV -sC -T4 --open")
