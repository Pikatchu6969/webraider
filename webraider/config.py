"""Global configuration and tool path resolution for WebRaider."""
import shutil
from pathlib import Path

# Default Kali wordlists
WORDLISTS = {
    "common": "/usr/share/wordlists/dirb/common.txt",
    "big": "/usr/share/wordlists/dirb/big.txt",
    "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "subdomains": "/usr/share/wordlists/amass/subdomains.lst",
    "users": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "passwords": "/usr/share/wordlists/rockyou.txt",
}

# Default output directory
DEFAULT_OUTPUT_DIR = Path.home() / "webraider_reports"

# Tool presence cache
_tool_cache: dict[str, bool] = {}


def has_tool(name: str) -> bool:
    """Check if a system tool is available on PATH."""
    if name not in _tool_cache:
        _tool_cache[name] = shutil.which(name) is not None
    return _tool_cache[name]


def require_tool(name: str, console) -> bool:
    """Warn if a required tool is missing. Returns True if present."""
    if not has_tool(name):
        console.print(
            f"[bold yellow]⚠  Tool not found:[/bold yellow] [cyan]{name}[/cyan] "
            f"— install it with: [dim]sudo apt install {name}[/dim]"
        )
        return False
    return True


def get_wordlist(key: str = "common") -> str:
    """Return a wordlist path, falling back gracefully."""
    path = WORDLISTS.get(key, WORDLISTS["common"])
    if Path(path).exists():
        return path
    # Fallback: any dirb list
    fallback = "/usr/share/wordlists/dirb/common.txt"
    if Path(fallback).exists():
        return fallback
    return path  # caller must handle missing


# Common default credentials for auth testing
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
]
