"""WebRaider main CLI entry point."""
from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from webraider.banner import print_banner
from webraider.config import DEFAULT_OUTPUT_DIR
from webraider.utils import err, info, section_header, warn

console = Console()
TARGET_OPT = click.argument("target", required=True)


def _out(output: str) -> str:
    return output or str(DEFAULT_OUTPUT_DIR)


def _add_nmap_cve_scripts(flags: str, enabled: bool) -> str:
    if not enabled:
        return flags
    if "--script" in flags:
        return flags
    return (flags + " --script vulners,vulscan").strip()


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
@click.version_option(prog_name="WebRaider")
def cli(ctx):
    """WebRaider - Web Pentesting CLI Toolkit for Kali Linux."""
    print_banner()
    if ctx.invoked_subcommand is None:
        _interactive_menu()


def _interactive_menu():
    choices = {
        "1": ("Full Scan (all modules)", "full"),
        "2": ("Recon (WHOIS, DNS, subdomains)", "recon"),
        "3": ("Port Scan (Nmap)", "scan"),
        "4": ("Web Fingerprinting", "webfinger"),
        "5": ("Directory Fuzzing", "dirscan"),
        "6": ("Vulnerability Scan", "vulnscan"),
        "7": ("SSL/TLS Check", "sslcheck"),
        "8": ("Auth Testing", "authtest"),
        "q": ("Quit", None),
    }
    console.print(Panel(
        "\n".join(f"  [bold cyan]{key}[/bold cyan]  {label}" for key, (label, _) in choices.items()),
        title="[bold red]Select Module[/bold red]",
        border_style="red",
        expand=False,
    ))
    choice = Prompt.ask("[bold]Enter choice[/bold]", choices=list(choices.keys()), default="1")
    if choice == "q":
        console.print("[dim]Goodbye.[/dim]")
        sys.exit(0)

    target = Prompt.ask("[bold cyan]Target URL or IP[/bold cyan]").strip()
    if not target:
        err("No target provided.")
        sys.exit(1)
    output = Prompt.ask("[bold]Output directory[/bold]", default=str(DEFAULT_OUTPUT_DIR))
    cmd_name = choices[choice][1]
    ctx = cli.make_context("webraider", [cmd_name, target, "--output", output])
    with ctx:
        cli.invoke(ctx)


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--wordlist", "-w", default="", help="Custom wordlist for subdomain enum")
def recon(target, output, wordlist):
    """Perform WHOIS, DNS enumeration, and subdomain discovery."""
    from webraider.modules.recon import run_recon
    from webraider.modules.reporter import generate_report

    results = run_recon(target, wordlist)
    if output:
        generate_report(target, {"recon": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--ports", "-p", default="1-1000", help="Port range (default: 1-1000)")
@click.option("--flags", "-f", default="-sV -sC", help="Extra Nmap flags")
@click.option("--full", "full_ports", is_flag=True, help="Scan all 65535 ports")
@click.option("--quick", is_flag=True, help="Quick top-100 scan")
@click.option("--nmap-cves", is_flag=True, help="Add Nmap CVE lookup scripts (vulners/vulscan) if installed")
def scan(target, output, ports, flags, full_ports, quick, nmap_cves):
    """Run a port and service scan using Nmap."""
    from webraider.modules import portscan

    flags = _add_nmap_cve_scripts(flags, nmap_cves)
    if full_ports:
        results = portscan.nmap_scan(target, ports="1-65535", flags=flags + " --open")
    elif quick:
        results = portscan.nmap_scan(target, ports="--top-ports 100", flags=flags + " --open")
    else:
        results = portscan.nmap_scan(target, ports=ports, flags=flags)
    if output:
        from webraider.modules.reporter import generate_report
        generate_report(target, {"scan": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
def webfinger(target, output):
    """Fingerprint the web server: HTTP headers, tech stack, security headers."""
    from webraider.modules.webfinger import fingerprint_web

    results = fingerprint_web(target)
    if output:
        from webraider.modules.reporter import generate_report
        generate_report(target, {"webfinger": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--wordlist", "-w", default="", help="Path to wordlist (default: dirb/common.txt)")
@click.option("--extensions", "-x", default="php,html,txt,js,bak", help="File extensions to fuzz")
@click.option("--threads", "-t", default=40, type=int, help="Number of threads")
def dirscan(target, output, wordlist, extensions, threads):
    """Fuzz directories and files using ffuf, gobuster, or dirb."""
    from webraider.modules.dirscan import dir_scan

    results = dir_scan(target, wordlist=wordlist, extensions=extensions, threads=threads)
    if output:
        from webraider.modules.reporter import generate_report
        generate_report(target, {"dirscan": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--skip-nikto", is_flag=True, help="Skip the Nikto scan")
def vulnscan(target, output, skip_nikto):
    """Run SQLi, XSS, LFI, SSRF probes, and optional Nikto."""
    from webraider.modules.reporter import generate_report
    from webraider.modules.vulnscan import run_vulnscan

    results = run_vulnscan(target, skip_nikto=skip_nikto)
    if output:
        generate_report(target, {"vulnscan": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--port", "-p", default=443, type=int, help="SSL port")
def sslcheck(target, output, port):
    """Analyze SSL/TLS configuration: protocols, certificate, and known TLS CVEs."""
    from webraider.modules.sslcheck import ssl_check

    results = ssl_check(target, port=port)
    if output:
        from webraider.modules.reporter import generate_report
        generate_report(target, {"sslcheck": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--hydra", "run_hydra", is_flag=True, help="Also run Hydra brute-force")
@click.option("--userlist", "-u", default="", help="Custom username wordlist for Hydra")
@click.option("--passlist", "-p", default="", help="Custom password wordlist for Hydra")
def authtest(target, output, run_hydra, userlist, passlist):
    """Test for default credentials and optionally run Hydra."""
    from webraider.modules.authtest import run_authtest

    results = run_authtest(target, run_hydra=run_hydra, userlist=userlist, passlist=passlist)
    if output:
        from webraider.modules.reporter import generate_report
        generate_report(target, {"authtest": results}, _out(output))


@cli.command()
@TARGET_OPT
@click.option("--output", "-o", default="", help="Output directory for reports")
@click.option("--ports", "-p", default="1-1000", help="Port range for Nmap")
@click.option("--wordlist", "-w", default="", help="Wordlist for dir/subdomain fuzzing")
@click.option("--skip-nikto", is_flag=True, help="Skip Nikto to speed up scan")
@click.option("--hydra", "run_hydra", is_flag=True, help="Run Hydra brute-force in full mode")
@click.option("--ssl-port", default=443, type=int, help="SSL port")
@click.option("--nmap-cves", is_flag=True, help="Add Nmap CVE lookup scripts (vulners/vulscan) if installed")
def full(target, output, ports, wordlist, skip_nikto, run_hydra, ssl_port, nmap_cves):
    """Run all modules and generate a report."""
    out_dir = _out(output)
    all_results = {}

    section_header("FULL SCAN MODE", "bold red")
    info(f"Target : [bold cyan]{target}[/bold cyan]")
    info(f"Output : [dim]{out_dir}[/dim]")
    console.print()

    try:
        from webraider.modules.recon import run_recon
        all_results["recon"] = run_recon(target, wordlist)
    except Exception as e:
        warn(f"Recon failed: {e}")

    try:
        from webraider.modules.portscan import nmap_scan
        flags = _add_nmap_cve_scripts("-sV -sC -T3", nmap_cves)
        all_results["scan"] = nmap_scan(target, ports=ports, flags=flags)
    except Exception as e:
        warn(f"Port scan failed: {e}")

    try:
        from webraider.modules.webfinger import fingerprint_web
        all_results["webfinger"] = fingerprint_web(target)
    except Exception as e:
        warn(f"Web fingerprint failed: {e}")

    try:
        from webraider.modules.dirscan import dir_scan
        all_results["dirscan"] = dir_scan(target, wordlist=wordlist)
    except Exception as e:
        warn(f"Dir scan failed: {e}")

    try:
        from webraider.modules.vulnscan import run_vulnscan
        all_results["vulnscan"] = run_vulnscan(target, skip_nikto=skip_nikto)
    except Exception as e:
        warn(f"Vuln scan failed: {e}")

    try:
        from webraider.modules.sslcheck import ssl_check
        all_results["sslcheck"] = ssl_check(target, port=ssl_port)
    except Exception as e:
        warn(f"SSL check failed: {e}")

    try:
        from webraider.modules.authtest import run_authtest
        all_results["authtest"] = run_authtest(target, run_hydra=run_hydra)
    except Exception as e:
        warn(f"Auth test failed: {e}")

    try:
        from webraider.modules.reporter import generate_report
        generate_report(target, all_results, out_dir)
    except Exception as e:
        err(f"Report generation failed: {e}")


def main():
    cli()


if __name__ == "__main__":
    main()
