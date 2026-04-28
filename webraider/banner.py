"""ASCII banner and branding for WebRaider."""
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from webraider import __version__

console = Console()

BANNER = r"""
 ██╗    ██╗███████╗██████╗ ██████╗  █████╗ ██╗██████╗ ███████╗██████╗ 
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝███████║██║██║  ██║█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══██║██║██║  ██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║██║██████╔╝███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""


def print_banner():
    """Print the WebRaider banner."""
    banner_text = Text(BANNER, style="bold red")
    subtitle = Text(
        f"  Web Pentesting CLI Toolkit  v{__version__}  |  By Pikatchu6969 imano Edition",
        style="bold cyan",
        justify="center",
    )
    disclaimer = Text(
        "  ⚠  For authorized security testing only. Illegal use is strictly prohibited.",
        style="bold yellow",
        justify="center",
    )
    console.print(Align.center(banner_text))
    console.print(Align.center(subtitle))
    console.print(Align.center(disclaimer))
    console.print()
    console.print(
        Panel(
            "[dim]Modules:[/dim] recon · scan · webfinger · dirscan · vulnscan · sslcheck · authtest · full",
            border_style="bright_black",
            expand=True,
        )
    )
    console.print()
