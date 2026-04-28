# WebRaider

**CLI Web Pentesting Toolkit for Kali Linux**

> For authorized security testing only. Illegal use is strictly prohibited.

## Features

| Module | Description |
|--------|-------------|
| `recon` | WHOIS, DNS records, subdomain enumeration using subfinder/amass/dnsenum |
| `scan` | Nmap wrapper with XML parsing, service data, CPEs, and CVE extraction from NSE output |
| `webfinger` | HTTP headers, tech fingerprinting, security header audit, cookie flags |
| `dirscan` | Directory/file fuzzing with ffuf, gobuster, or dirb fallback |
| `vulnscan` | SQLi, XSS, LFI, SSRF probes plus Nikto/sqlmap integration |
| `sslcheck` | SSL/TLS protocols, certificate expiry, Heartbleed, CCS injection, ROBOT, CRIME/POODLE/DROWN mapping |
| `authtest` | Default credential testing and optional Hydra brute-force support |
| `full` | Run all modules end-to-end and generate JSON/HTML reports |

## CVE and CWE reporting

The report now has a **Findings and CVE Summary** table.

- CVEs are extracted from tool output when available, such as Nikto, sqlmap, Nmap NSE scripts, and sslyze.
- Known TLS issues are mapped to their CVEs where a stable CVE exists, for example Heartbleed, OpenSSL CCS injection, ROBOT, SSLv3 POODLE, SSLv2 DROWN, and TLS compression CRIME.
- Generic web vulnerability classes such as SQL injection, XSS, LFI, SSRF, missing headers, and default credentials do not have one universal CVE. For those, WebRaider reports the appropriate CWE ID, for example CWE-89 for SQL injection and CWE-79 for XSS.

## Installation

```bash
git clone <repo-url> webraider
cd webraider
chmod +x install.sh
./install.sh
```

Or manually:

```bash
pip install -r requirements.txt
pip install -e .
```

## Usage

### Interactive menu

```bash
webraider
```

### Subcommands

```bash
# Full scan with report
webraider full http://target.com --output ~/reports

# Full scan with Nmap CVE lookup scripts if vulners/vulscan are installed
webraider full http://target.com --nmap-cves --output ~/reports

# Recon only
webraider recon http://target.com

# Port scan
webraider scan http://target.com --ports 1-65535 --full
webraider scan http://target.com --nmap-cves --output ~/reports

# Web fingerprint
webraider webfinger http://target.com --output ~/reports

# Directory fuzzing
webraider dirscan http://target.com --wordlist /usr/share/wordlists/dirb/big.txt

# Vulnerability scan
webraider vulnscan http://target.com --skip-nikto

# SSL/TLS check
webraider sslcheck https://target.com --port 443 --output ~/reports

# Auth testing
webraider authtest http://target.com
webraider authtest http://target.com --hydra --passlist /usr/share/wordlists/rockyou.txt
```

## Kali tools used

```bash
sudo apt install nmap nikto ffuf gobuster dirb sqlmap hydra whatweb sslyze subfinder amass dnsenum
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

For Nmap CVE lookups, install and configure an NSE CVE script such as `vulners` or `vulscan`, then run with `--nmap-cves`.

## Output

Reports are saved to `~/webraider_reports/` by default or to the directory passed with `--output`:

- `webraider_<target>.json` contains the raw results plus a normalized `findings` list.
- `webraider_<target>.html` contains a dark themed report with a CVE/CWE summary.

## Disclaimer

This tool is intended solely for use by security professionals on systems they are explicitly authorized to test. Misuse may be illegal. The authors accept no liability.
