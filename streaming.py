"""Run an external command and stream its REAL output line by line (stdout + stderr merged)."""
import os
import re
import shlex
import shutil
import subprocess
import threading

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ENV_ALLOW = ("PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE")


def clean(text: str) -> str:
    return _ANSI.sub("", text)


def safe_env() -> dict:
    """Minimal environment so API keys, tokens and other secrets are never passed to child processes."""
    env = {k: os.environ[k] for k in _ENV_ALLOW if k in os.environ}
    env["PYTHONUNBUFFERED"] = "1"
    return env


def line_buffered(cmd: list[str]) -> list[str]:
    """Reduce C-stdio buffering of piped tools (nmap etc.). Uses stdbuf when available (Linux/macOS-coreutils)."""
    sb = shutil.which("stdbuf")
    return [sb, "-oL", "-eL", *cmd] if sb else cmd


def stream_command(cmd: list[str], emit, timeout: float | None = None) -> int:
    """Execute cmd (no shell) and call emit('out', line) for every line as it arrives. Returns the exit code."""
    emit("cmd", shlex.join(cmd))
    try:
        proc = subprocess.Popen(
            line_buffered(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True, bufsize=1, encoding="utf-8", errors="replace", env=safe_env(), shell=False)
    except FileNotFoundError:
        emit("error", f"Command not found: {cmd[0]}")
        return 127
    timer = threading.Timer(timeout, proc.kill) if timeout else None
    if timer:
        timer.start()
    try:
        for line in proc.stdout:
            emit("out", clean(line.rstrip("\n")))
    finally:
        if timer:
            timer.cancel()
    code = proc.wait()
    emit("ok" if code == 0 else "warn", f"Process exited with code {code}")
    return code
