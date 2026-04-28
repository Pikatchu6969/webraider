#!/usr/bin/env bash
# WebRaider installer for Kali Linux
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[ERR]${NC} $1"; }

cat << 'EOF'
WebRaider - Kali Linux Web Pentesting CLI
For authorized security testing only.
EOF

info "Checking Python version..."
PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
  err "Python 3 is required but not found."
  exit 1
fi
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")
if [[ $PY_MINOR -lt 10 ]]; then
  err "Python 3.10+ required."
  exit 1
fi
ok "$($PYTHON --version)"

info "Installing Python dependencies..."
pip install -r requirements.txt --quiet
ok "Python packages installed."

info "Installing WebRaider..."
pip install -e . --quiet
ok "webraider installed. Run: webraider --help"

info "Checking Kali tool availability..."
TOOLS=(nmap nikto ffuf gobuster dirb sqlmap hydra whatweb sslyze subfinder amass dnsenum dig openssl)
MISSING=()
for tool in "${TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool"
  else
    warn "$tool not found"
    MISSING+=("$tool")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  warn "Some tools are missing. Install them for full functionality:"
  echo -e "  ${CYAN}sudo apt install ${MISSING[*]}${NC}"
fi

info "Checking wordlists..."
if [[ -f /usr/share/wordlists/dirb/common.txt ]]; then
  ok "dirb common wordlist found."
else
  warn "Kali wordlists not found."
  echo -e "  ${CYAN}sudo apt install dirb wordlists seclists${NC}"
fi
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
  warn "rockyou.txt is compressed. Run: sudo gzip -d /usr/share/wordlists/rockyou.txt.gz"
fi

echo ""
ok "Installation complete."
echo -e "${YELLOW}Use only on systems you are authorized to test.${NC}"
