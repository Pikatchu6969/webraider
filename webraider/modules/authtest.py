"""Authentication testing: default credentials and optional Hydra checks."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

from webraider.config import DEFAULT_CREDS, get_wordlist, has_tool
from webraider.utils import normalize_target, ok, run_cmd_stream, section_header, warn
from webraider.vulnmeta import make_finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/wp-login.php", "/administrator",
    "/user/login", "/signin", "/auth/login",
]

HEADERS = {"User-Agent": "Mozilla/5.0 WebRaider/1.0"}
REQUEST_TIMEOUT = 10


def _find_login_page(base_url: str):
    for path in LOGIN_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False, headers=HEADERS)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        form = soup.find("form")
        if not form:
            continue

        uname = None
        passwd = None
        extras = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            inp_type = (inp.get("type") or "").lower()
            if inp_type in {"text", "email"} and not uname:
                uname = name
            elif inp_type == "password" and not passwd:
                passwd = name
            elif inp_type in {"hidden", "submit"}:
                extras[name] = inp.get("value", "")

        if uname and passwd:
            action = urljoin(url, form.get("action") or url)
            return url, action, uname, passwd, extras

    return None, None, None, None, {}


def default_cred_check(target: str) -> dict:
    section_header("Default Credential Testing", "bold magenta")
    url = normalize_target(target)
    results = {"found": [], "tested": 0, "findings": []}

    login_url, action, user_f, pass_f, extras = _find_login_page(url)
    if not login_url:
        warn("No login page found.")
        return results

    ok(f"Login page: {login_url}")

    try:
        baseline_payload = dict(extras)
        baseline_payload.update({user_f: "webraider_baseline", pass_f: "webraider_baseline"})
        base = requests.post(action, data=baseline_payload, timeout=REQUEST_TIMEOUT, verify=False, headers=HEADERS, allow_redirects=False)
        base_len = len(base.text)
    except requests.RequestException as e:
        warn(f"Baseline login request failed: {e}")
        return results

    table = Table(title="Default Credential Results", border_style="bright_black")
    table.add_column("User", style="cyan")
    table.add_column("Pass", style="yellow")
    table.add_column("Status", style="white")

    for username, password in DEFAULT_CREDS:
        results["tested"] += 1
        try:
            payload = dict(extras)
            payload.update({user_f: username, pass_f: password})
            resp = requests.post(action, data=payload, timeout=REQUEST_TIMEOUT, verify=False, headers=HEADERS, allow_redirects=False)
            length_diff = abs(len(resp.text) - base_len)
            body_lower = resp.text.lower()
            success = (
                resp.status_code != base.status_code
                or length_diff > 80
                or "dashboard" in body_lower
                or "logout" in body_lower
            )
            if success:
                item = {"username": username, "password": password, "url": login_url, "cves": [], "cwe": "CWE-798"}
                results["found"].append(item)
                results["findings"].append(make_finding(
                    module="authtest",
                    category="default_creds",
                    title="Default credentials accepted",
                    severity="Critical",
                    evidence=f"Credential pair {username}:{password} appeared to change the login response.",
                    url=login_url,
                    recommendation="Disable default accounts, force password rotation, and enforce strong unique credentials.",
                ))
                table.add_row(username, password, "SUCCESS")
            else:
                table.add_row(username, password, "fail")
        except requests.RequestException:
            table.add_row(username, password, "error")

    console.print(table)
    return results


def hydra_bruteforce(target: str, userlist: str = "", passlist: str = "") -> dict:
    section_header("Hydra Brute Force", "bold magenta")
    results = {"found": [], "findings": []}

    if not has_tool("hydra"):
        warn("Hydra not installed")
        return results

    url = normalize_target(target)
    parsed = urlparse(url)
    host = parsed.hostname or target
    module = "https-post-form" if parsed.scheme == "https" else "http-post-form"
    users = userlist or get_wordlist("users")
    passwords = passlist or get_wordlist("rockyou")

    cmd = [
        "hydra", "-L", users, "-P", passwords, host, module,
        "/login:username=^USER^&password=^PASS^:invalid",
        "-t", "4", "-f",
    ]
    _, lines = run_cmd_stream(cmd, timeout=1800)

    for line in lines:
        if "login:" in line and "password:" in line:
            results["found"].append(line)
            results["findings"].append(make_finding(
                module="authtest",
                category="hydra",
                title="Weak credentials discovered by Hydra",
                severity="High",
                evidence=line,
                url=url,
                recommendation="Enforce account lockout, MFA, rate limiting, and stronger passwords.",
            ))

    return results


def run_authtest(target: str, run_hydra: bool = False, userlist: str = "", passlist: str = "") -> dict:
    results = {"default_creds": default_cred_check(target), "findings": []}
    if run_hydra:
        results["hydra"] = hydra_bruteforce(target, userlist=userlist, passlist=passlist)

    for section in results.values():
        if isinstance(section, dict):
            results["findings"].extend(section.get("findings", []))
    return results
