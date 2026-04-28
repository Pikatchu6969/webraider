"""Recon module: WHOIS, DNS enumeration, and subdomain discovery."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import dns.exception
import dns.resolver
import whois as pywhois

from webraider.config import has_tool
from webraider.utils import extract_host, info, ok, run_cmd, section_header, spinner_task, warn, err

console = Console()


def whois_lookup(target: str) -> dict:
    section_header("WHOIS Lookup", "bold magenta")
    host = extract_host(target)
    result: dict = {}

    with spinner_task(f"Running WHOIS on {host}"):
        try:
            w = pywhois.whois(host)
            result = {
                "domain": str(w.domain_name or host),
                "registrar": str(w.registrar or "N/A"),
                "creation_date": str(w.creation_date or "N/A"),
                "expiration_date": str(w.expiration_date or "N/A"),
                "name_servers": [str(ns) for ns in (w.name_servers or [])],
                "org": str(w.org or "N/A"),
                "country": str(w.country or "N/A"),
                "emails": [str(e) for e in (w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [])],
            }
        except Exception as e:
            err(f"WHOIS failed: {e}")
            result = {"error": str(e)}

    if "error" not in result:
        table = Table(show_header=False, border_style="bright_black", expand=False)
        table.add_column("Field", style="cyan", min_width=20)
        table.add_column("Value", style="white")
        for key, value in result.items():
            val = ", ".join(value) if isinstance(value, list) else str(value)
            table.add_row(key.replace("_", " ").title(), val)
        console.print(table)

    return result


def dns_enum(target: str) -> dict:
    section_header("DNS Enumeration", "bold magenta")
    host = extract_host(target)
    results: dict[str, list[str] | str | None] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    table = Table(title=f"DNS Records - {host}", border_style="bright_black", show_lines=True)
    table.add_column("Type", style="bold cyan", width=8)
    table.add_column("Records", style="white")

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            records = [str(r) for r in answers]
            results[rtype] = records
            table.add_row(rtype, "\n".join(records))
            ok(f"{rtype}: {len(records)} record(s)")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            results[rtype] = []
        except Exception:
            results[rtype] = []

    console.print(table)

    info("Attempting DNS zone transfer (AXFR)...")
    if has_tool("dig"):
        rc, out, _ = run_cmd(["dig", "axfr", host], timeout=15)
        if rc == 0 and out and "Transfer failed" not in out and len(out) > 100:
            warn("Zone transfer may be possible.")
            results["axfr"] = out
            console.print(Panel(out[:2000], title="AXFR Response", border_style="red"))
        else:
            ok("Zone transfer not allowed (expected).")
            results["axfr"] = None
    else:
        warn("dig not found; skipping AXFR check.")
        results["axfr"] = None

    return results


def subdomain_enum(target: str, wordlist: str = "") -> dict:
    section_header("Subdomain Enumeration", "bold magenta")
    host = extract_host(target)
    found: list[str] = []

    if has_tool("subfinder"):
        info("Using subfinder...")
        rc, out, _ = run_cmd(["subfinder", "-d", host, "-silent"], timeout=120)
        if rc == 0 and out.strip():
            found = [s.strip() for s in out.splitlines() if s.strip()]
            ok(f"subfinder found {len(found)} subdomains")
    elif has_tool("amass"):
        info("Using amass passive enumeration...")
        rc, out, _ = run_cmd(["amass", "enum", "-passive", "-d", host], timeout=180)
        if rc == 0 and out.strip():
            found = [s.strip() for s in out.splitlines() if s.strip()]
            ok(f"amass found {len(found)} subdomains")
    elif has_tool("dnsenum"):
        warn("subfinder/amass not found. Using dnsenum fallback...")
        cmd = ["dnsenum", "--noreverse", "--nocolor"]
        if wordlist:
            cmd.extend(["-f", wordlist])
        cmd.append(host)
        rc, out, _ = run_cmd(cmd, timeout=120)
        if rc == 0:
            for line in out.splitlines():
                if host in line and "." in line:
                    sub = line.split()[0].rstrip(".")
                    if sub.endswith(host):
                        found.append(sub)
    else:
        warn("No subdomain enumeration tool available. Install subfinder, amass, or dnsenum.")

    found = sorted(set(found))
    if found:
        table = Table(title=f"Subdomains ({len(found)} found)", border_style="bright_black")
        table.add_column("#", style="dim", width=5)
        table.add_column("Subdomain", style="cyan")
        for i, sub in enumerate(found[:50], 1):
            table.add_row(str(i), sub)
        if len(found) > 50:
            table.add_row("...", f"(+{len(found) - 50} more)")
        console.print(table)
    else:
        warn("No subdomains discovered.")

    return {"host": host, "subdomains": found, "count": len(found)}


def run_recon(target: str, wordlist: str = "") -> dict:
    return {
        "whois": whois_lookup(target),
        "dns": dns_enum(target),
        "subdomains": subdomain_enum(target, wordlist),
    }
