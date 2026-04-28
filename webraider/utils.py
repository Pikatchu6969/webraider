"""Shared utility functions for WebRaider."""
from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence
from urllib.parse import urlparse

from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

console = Console()

Command = str | Sequence[str]


def _to_args(cmd: Command) -> list[str]:
    if isinstance(cmd, str):
        return shlex.split(cmd)
    return [str(part) for part in cmd]


def command_to_string(cmd: Command) -> str:
    return " ".join(shlex.quote(str(part)) for part in _to_args(cmd))


def run_cmd(
    cmd: Command,
    timeout: int = 120,
    capture: bool = True,
    shell: bool = False,
    input_text: str | None = None,
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr).

    Prefer passing a list of arguments. String commands are split with shlex
    unless shell=True is explicitly requested.
    """
    try:
        if shell:
            proc = subprocess.run(
                cmd if isinstance(cmd, str) else command_to_string(cmd),
                shell=True,
                capture_output=capture,
                text=True,
                timeout=timeout,
                input=input_text,
            )
        else:
            proc = subprocess.run(
                _to_args(cmd),
                capture_output=capture,
                text=True,
                timeout=timeout,
                input=input_text,
            )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout}s: {command_to_string(cmd)}"
    except FileNotFoundError as e:
        return 1, "", str(e)
    except Exception as e:
        return 1, "", str(e)


def run_cmd_stream(cmd: Command, timeout: int = 300) -> tuple[int, list[str]]:
    """Run a command and stream combined stdout/stderr lines in real time."""
    lines: list[str] = []
    try:
        with subprocess.Popen(
            _to_args(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        ) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.rstrip()
                lines.append(stripped)
                console.print(f"  [dim]{stripped}[/dim]")
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                lines.append(f"Command timed out after {timeout}s")
                return 1, lines
            return proc.returncode or 0, lines
    except FileNotFoundError:
        first = _to_args(cmd)[0] if _to_args(cmd) else "command"
        return 1, [f"Tool not found: {first}"]
    except Exception as e:
        return 1, [str(e)]


def spinner_task(label: str):
    """Context manager: show a spinner while work is in progress."""

    class _Spinner:
        def __init__(self, label: str):
            self.label = label
            self._live = None

        def __enter__(self):
            self._live = Live(
                Text.assemble(
                    Spinner("dots", style="cyan"),
                    ("  " + self.label, "bold white"),
                ),
                refresh_per_second=10,
                console=console,
                transient=True,
            )
            self._live.__enter__()
            return self

        def __exit__(self, *args):
            if self._live is not None:
                self._live.__exit__(*args)

    return _Spinner(label)


def section_header(title: str, style: str = "bold cyan"):
    console.print()
    console.print(f"[{style}]{'-' * 60}[/{style}]")
    console.print(f"[{style}]  {title}[/{style}]")
    console.print(f"[{style}]{'-' * 60}[/{style}]")
    console.print()


def ok(msg: str):
    console.print(f"[bold green]  OK[/bold green]  {msg}")


def warn(msg: str):
    console.print(f"[bold yellow]  WARN[/bold yellow]  {msg}")


def err(msg: str):
    console.print(f"[bold red]  ERR[/bold red]  {msg}")


def info(msg: str):
    console.print(f"[bold blue]  INFO[/bold blue]  {msg}")


def normalize_target(target: str) -> str:
    """Ensure target URL has a scheme."""
    target = str(target).strip()
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target


def extract_host(url: str) -> str:
    """Extract hostname from URL or return the input if it is already a host."""
    parsed = urlparse(normalize_target(url))
    return parsed.hostname or str(url).strip().split("/")[0]


def safe_filename(value: str) -> str:
    """Return a filesystem-safe filename fragment."""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
    return "".join(ch if ch in allowed else "_" for ch in value)[:180] or "target"
