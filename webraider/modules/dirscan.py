"""Directory and file discovery using ffuf, gobuster, or dirb."""
from __future__ import annotations

import json
import os
import random
import re
import string
import tempfile
from urllib.parse import urljoin

import requests
import urllib3
from rich.console import Console
from rich.table import Table

from webraider.config import get_wordlist, has_tool
from webraider.utils import info, normalize_target, ok, run_cmd, run_cmd_stream, section_header, warn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()


def _random_path(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _selected_wordlist(wordlist: str = "") -> str:
    if wordlist:
        return wordlist
    return get_wordlist("common")


def _baseline_size(url: str) -> int:
    try:
        response = requests.get(f"{url}/{_random_path()}", timeout=10, verify=False)
        return len(response.text)
    except requests.RequestException:
        return 0


def _ffuf_scan(url: str, wordlist: str, threads: int, extensions: str, baseline_size: int) -> list[dict]:
    suffix = ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tf:
        out_path = tf.name
    cmd = [
        "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
        "-t", str(threads), "-mc", "200,204,301,302,307,401,403",
        "-of", "json", "-o", out_path,
    ]
    if baseline_size > 0:
        cmd.extend(["-fs", str(baseline_size)])
    ext = ",".join(e.strip().lstrip(".") for e in extensions.split(",") if e.strip())
    if ext:
        cmd.extend(["-e", ext])

    run_cmd(cmd, timeout=600)
    found: list[dict] = []
    try:
        with open(out_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("results", []):
            path = item.get("input", {}).get("FUZZ") or item.get("input", {}).get("FUZZ1") or item.get("url", "")
            found.append({
                "path": str(path).lstrip("/"),
                "url": item.get("url", urljoin(url + "/", str(path).lstrip("/"))),
                "status": item.get("status"),
                "size": item.get("length"),
                "source": "ffuf",
            })
    except Exception as e:
        warn(f"Could not parse ffuf JSON output: {e}")
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
    return found


def _gobuster_scan(url: str, wordlist: str, threads: int, extensions: str) -> list[dict]:
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", str(threads), "-q", "--no-error"]
    ext = ",".join(e.strip().lstrip(".") for e in extensions.split(",") if e.strip())
    if ext:
        cmd.extend(["-x", ext])
    _, lines = run_cmd_stream(cmd, timeout=600)
    found: list[dict] = []
    pattern = re.compile(r"^(\/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]")
    for line in lines:
        match = pattern.search(line)
        if match:
            path, status, size = match.groups()
            found.append({
                "path": path.lstrip("/"),
                "url": urljoin(url + "/", path.lstrip("/")),
                "status": int(status),
                "size": int(size),
                "source": "gobuster",
            })
        elif line.startswith("/"):
            path = line.split()[0]
            found.append({
                "path": path.lstrip("/"),
                "url": urljoin(url + "/", path.lstrip("/")),
                "status": None,
                "size": None,
                "source": "gobuster",
            })
    return found


def _dirb_scan(url: str, wordlist: str) -> list[dict]:
    _, lines = run_cmd_stream(["dirb", url, wordlist, "-S"], timeout=600)
    found: list[dict] = []
    pattern = re.compile(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
    for line in lines:
        match = pattern.search(line)
        if match:
            item_url, status, size = match.groups()
            found.append({
                "path": item_url.replace(url.rstrip("/") + "/", ""),
                "url": item_url,
                "status": int(status),
                "size": int(size),
                "source": "dirb",
            })
    return found


def dir_scan(target: str, wordlist: str = "", extensions: str = "php,html,txt,js,bak", threads: int = 40) -> dict:
    section_header("Directory Scan", "bold blue")
    url = normalize_target(target).rstrip("/")
    wordlist_path = _selected_wordlist(wordlist)

    if not os.path.exists(wordlist_path):
        warn(f"Wordlist missing: {wordlist_path}")
        return {"url": url, "wordlist": wordlist_path, "found": [], "error": "wordlist_missing"}

    baseline_size = _baseline_size(url)
    info(f"Baseline size: {baseline_size}")

    if has_tool("ffuf"):
        found = _ffuf_scan(url, wordlist_path, threads, extensions, baseline_size)
    elif has_tool("gobuster"):
        found = _gobuster_scan(url, wordlist_path, threads, extensions)
    elif has_tool("dirb"):
        found = _dirb_scan(url, wordlist_path)
    else:
        warn("No directory scanner installed. Install ffuf, gobuster, or dirb.")
        return {"url": url, "wordlist": wordlist_path, "found": [], "error": "tool_missing"}

    # De-duplicate by URL.
    deduped = {}
    for item in found:
        deduped[item.get("url") or item.get("path")] = item
    found = list(deduped.values())

    table = Table(title="Discovered Paths", border_style="bright_black")
    table.add_column("Path", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Size", style="dim")
    table.add_column("Source", style="green")
    for item in found[:200]:
        table.add_row(
            str(item.get("path", "")),
            str(item.get("status", "-")),
            str(item.get("size", "-")),
            str(item.get("source", "-")),
        )
    console.print(table)
    ok(f"{len(found)} path(s) found")

    return {"url": url, "wordlist": wordlist_path, "found": found, "count": len(found)}
