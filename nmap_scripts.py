"""Nmap NSE backend: PLACEHOLDER, not implemented yet.

Contract: run(target, options, emit) -> {"scripts": [...], "findings": [{"script": ..., "detail": ...}]}
`options` holds the selected NSE category ids. Intrusive ones are only passed when the user ticked the authorization box.
"""
import shutil

STATUS = "placeholder"


def run(target, options, emit):
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap is not installed or not in PATH.")
    # When ready, stream the real process output into the Live Terminal:
    #   from streaming import stream_command
    #   stream_command(["nmap", "-v", "--stats-every", "5s", "--script", ",".join(options), target.host], emit)
    raise NotImplementedError("Nmap NSE integration is not implemented yet. Nothing was executed.")
