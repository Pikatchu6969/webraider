"""Web fingerprinting: HTTP headers, tech detection, server info."""
from __future__ import annotations

import re

import requests
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webraider.config import has_tool
from webraider.utils import info, normalize_target, ok, run_cmd, section_header, spinner_task, warn, err
from webraider.vulnmeta import make_finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

TECH_PATTERNS = [
    ("Apache", "server", r"apache"),
    ("Nginx", "server", r"nginx"),
    ("IIS", "server", r"microsoft-iis"),
    ("LiteSpeed", "server", r"litespeed"),
    ("Caddy", "server", r"caddy"),
    ("PHP", "x-powered-by", r"php"),
    ("ASP.NET", "x-powered-by", r"asp\.net"),
    ("Express.js", "x-powered-by", r"express"),
    ("WordPress", "body", r"wp-content|wp-includes|wordpress"),
    ("Joomla", "body", r"joomla|/components/com_"),
    ("Drupal", "body", r"drupal|sites/default/files"),
    ("Magento", "body", r"magento|mage-"),
    ("React", "body", r"react\.js|react\.min\.js|__REACT"),
    ("Angular", "body", r"ng-version|angular\.js"),
    ("Vue.js", "body", r"vue\.js|vue\.min\.js"),
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("Imperva/Incapsula", "x-iinfo", r".+"),
    ("ModSecurity", "x-permitted-cross-domain-policies", r".+"),
]

INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
    "x-drupal-cache", "x-pingback", "via", "x-varnish",
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-xss-protection", "x-content-type-options",
    "referrer-policy", "permissions-policy", "access-control-allow-origin",
    "set-cookie", "cf-ray", "x-iinfo", "x-sucuri-id",
]


def _cookie_httponly(cookie: requests.cookies.RequestsCookieJar) -> bool:
    return any(str(k).lower() == "httponly" for k in getattr(cookie, "_rest", {}).keys())


def fingerprint_web(target: str) -> dict:
    section_header("Web Fingerprinting", "bold yellow")
    url = normalize_target(target)
    results = {
        "url": url,
        "headers": {},
        "technologies": [],
        "security_headers": {},
        "cookies": [],
        "findings": [],
    }

    with spinner_task(f"Connecting to {url}"):
        try:
            resp = requests.get(
                url,
                timeout=15,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WebRaider/1.0"},
            )
        except Exception as e:
            err(f"Connection failed: {e}")
            return results

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    results["status_code"] = resp.status_code
    results["final_url"] = resp.url
    results["headers"] = dict(resp.headers)
    results["cookies"] = [
        {
            "name": c.name,
            "value": c.value,
            "secure": c.secure,
            "httponly": _cookie_httponly(c),
        }
        for c in resp.cookies
    ]

    sec_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-xss-protection": "X-XSS-Protection",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    security_status = {}
    for hdr, name in sec_headers.items():
        present = hdr in headers_lower
        security_status[name] = {"present": present, "value": headers_lower.get(hdr)}
        if not present:
            results["findings"].append(make_finding(
                module="webfinger",
                category="missing_security_header",
                title=f"Missing security header: {name}",
                severity="Low",
                evidence=f"HTTP response from {resp.url} did not include {name}",
                url=resp.url,
                recommendation=f"Add a secure {name} policy where appropriate.",
            ))
    results["security_headers"] = security_status

    body = resp.text[:50000]
    detected = set()
    for name, field, pattern in TECH_PATTERNS:
        if field == "body":
            if re.search(pattern, body, re.IGNORECASE):
                detected.add(name)
        else:
            value = headers_lower.get(field, "")
            if re.search(pattern, value, re.IGNORECASE):
                detected.add(name)
    results["technologies"] = sorted(detected)

    info(f"Status: [bold]{resp.status_code}[/bold] -> [cyan]{resp.url}[/cyan]")
    console.print()

    hdr_table = Table(title="HTTP Headers", border_style="bright_black", show_lines=False, expand=False)
    hdr_table.add_column("Header", style="cyan", min_width=28)
    hdr_table.add_column("Value", style="white")
    for key in INTERESTING_HEADERS:
        if key in headers_lower:
            value = headers_lower[key]
            if len(value) > 80:
                value = value[:77] + "..."
            hdr_table.add_row(key, value)
    console.print(hdr_table)
    console.print()

    if results["technologies"]:
        tech_str = "  ".join(f"[bold green]{t}[/bold green]" for t in results["technologies"])
        console.print(Panel(tech_str, title="Detected Technologies", border_style="green"))

    sec_table = Table(title="Security Header Audit", border_style="bright_black", show_lines=False)
    sec_table.add_column("Header", style="cyan", min_width=25)
    sec_table.add_column("Status", width=10)
    sec_table.add_column("Value", style="dim")
    for name, status in security_status.items():
        if status["present"]:
            sec_table.add_row(name, "Present", (status["value"] or "")[:60])
        else:
            sec_table.add_row(name, "Missing", "-")
    console.print(sec_table)

    if has_tool("whatweb"):
        info("Running whatweb for additional fingerprinting...")
        rc, out, _ = run_cmd(["whatweb", url, "--color=never"], timeout=30)
        if rc == 0 and out.strip():
            console.print(Panel(out.strip(), title="whatweb Output", border_style="dim"))
            results["whatweb"] = out.strip()

    if results["cookies"]:
        ck_table = Table(title="Cookies", border_style="bright_black")
        ck_table.add_column("Name", style="cyan")
        ck_table.add_column("Secure", style="green")
        ck_table.add_column("HttpOnly", style="green")
        ck_table.add_column("Value (truncated)", style="dim")
        for ck in results["cookies"]:
            if resp.url.startswith("https://") and not ck["secure"]:
                results["findings"].append(make_finding(
                    module="webfinger",
                    category="cookie_secure",
                    title=f"Cookie missing Secure flag: {ck['name']}",
                    severity="Medium",
                    evidence=f"Cookie {ck['name']} was set without Secure on HTTPS response.",
                    url=resp.url,
                    recommendation="Set the Secure attribute on cookies sent over HTTPS.",
                ))
            if not ck["httponly"]:
                results["findings"].append(make_finding(
                    module="webfinger",
                    category="cookie_httponly",
                    title=f"Cookie missing HttpOnly flag: {ck['name']}",
                    severity="Medium",
                    evidence=f"Cookie {ck['name']} was set without HttpOnly.",
                    url=resp.url,
                    recommendation="Set HttpOnly on session and sensitive cookies.",
                ))
            ck_table.add_row(
                ck["name"],
                "Yes" if ck["secure"] else "No",
                "Yes" if ck["httponly"] else "No",
                str(ck["value"])[:40],
            )
        console.print(ck_table)

    if results["findings"]:
        warn(f"{len(results['findings'])} web hardening finding(s) recorded for report")
    else:
        ok("No web hardening findings recorded.")

    return results
