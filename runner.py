"""Scan orchestration: runs backends in a background thread so the Streamlit UI never blocks.
The thread only writes to a ScanSession (thread-safe); the UI polls it. No Streamlit calls in here."""
import threading
import time
from collections import deque
from dataclasses import dataclass

import catalog
import dns_recon, host_discovery, nmap_scripts, service_scan, web_recon
from streaming import clean

BACKENDS = {"dns": dns_recon, "web": web_recon, "hosts": host_discovery,
            "services": service_scan, "nmap": nmap_scripts}
MAX_LINES = 5000
TITLES = {m.id: m.title for m in catalog.MODULES}


@dataclass
class LogLine:
    ts: str
    level: str
    text: str


class ScanSession:
    """idle -> running -> completed | completed_errors. Lives in st.session_state only (no persistence)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.lines = deque(maxlen=MAX_LINES)
        self.total_lines = 0
        self.status = "idle"
        self.target = None
        self.module_ids: list[str] = []
        self.options: dict = {}
        self.outcomes: dict = {}   # module id -> {"status": ok|not_implemented|error, "data": dict, "error": str}
        self.done = 0
        self.current = ""
        self.started = self.finished = None

    @property
    def running(self) -> bool:
        return self.status == "running"

    @property
    def duration(self) -> float:
        return ((self.finished or time.time()) - self.started) if self.started else 0.0

    def emit(self, level: str, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        with self._lock:
            for part in clean(str(text)).splitlines() or [""]:
                self.lines.append(LogLine(stamp, level, part))
                self.total_lines += 1

    def snapshot(self, n: int = 400):
        with self._lock:
            return list(self.lines)[-n:], self.total_lines


def start_scan(target, module_ids, options) -> ScanSession:
    scan = ScanSession()
    scan.target, scan.module_ids, scan.options = target, list(module_ids), options
    scan.started, scan.status = time.time(), "running"
    threading.Thread(target=_worker, args=(scan,), daemon=True).start()
    return scan


def _worker(scan: ScanSession) -> None:
    scan.emit("info", f"Target: {scan.target.host}  |  modules: {', '.join(TITLES[m] for m in scan.module_ids)}")
    for mid in scan.module_ids:
        scan.current = TITLES[mid]
        scan.emit("info", f"Starting {TITLES[mid]}")
        try:
            data = BACKENDS[mid].run(scan.target, scan.options[mid], scan.emit)
            scan.outcomes[mid] = {"status": "ok", "data": data or {}}
            scan.emit("ok", f"{TITLES[mid]} finished")
        except NotImplementedError as exc:
            scan.outcomes[mid] = {"status": "not_implemented", "data": {}}
            scan.emit("warn", str(exc))
        except Exception as exc:  # a failing module must not stop the others
            scan.outcomes[mid] = {"status": "error", "data": {}, "error": f"{type(exc).__name__}: {exc}"}
            scan.emit("error", f"{TITLES[mid]} failed: {exc}")
        scan.done += 1
    scan.finished = time.time()
    failed = any(o["status"] == "error" for o in scan.outcomes.values())
    scan.emit("info", f"Scan finished in {scan.duration:.1f}s")
    scan.status = "completed_errors" if failed else "completed"
