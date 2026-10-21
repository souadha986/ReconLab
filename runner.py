"""Background scan orchestration for ReconLab."""

import threading
import time
from collections import deque
from dataclasses import dataclass

import catalog
import dns_recon  
import host_discovery
import nmap_scripts
import service_scan
import web_recon
from streaming import clean


BACKENDS = {
    "dns": dns_recon,
    "web": web_recon,
    "hosts": host_discovery,
    "services": service_scan,
    "nmap": nmap_scripts,
}

MAX_LINES = 5000
TITLES = {m.id: m.title for m in catalog.MODULES}


@dataclass
class LogLine:
    ts: str
    level: str
    text: str


class ScanSession:
    """Thread-safe state for one scan."""

    def __init__(self):
        self._lock = threading.Lock()
        self.lines = deque(maxlen=MAX_LINES)
        self.total_lines = 0

        self.status = "idle"
        self.target = None
        self.module_ids = []
        self.options = {}
        self.outcomes = {}

        self.done = 0
        self.current = ""
        self.started = None
        self.finished = None

    @property
    def running(self):
        return self.status == "running"

    @property
    def duration(self):
        if self.started is None:
            return 0.0

        end = self.finished or time.time()
        return end - self.started

    def emit(self, level, message):
        stamp = time.strftime("%H:%M:%S")
        cleaned = clean(str(message))

        with self._lock:
            for part in cleaned.splitlines() or [""]:
                self.lines.append(
                    LogLine(stamp, level, part)
                )
                self.total_lines += 1

    def snapshot(self, n=400):
        with self._lock:
            return list(self.lines)[-n:], self.total_lines


def start_scan(target, module_ids, options):
    """Create a session and launch the background worker."""

    scan = ScanSession()
    scan.target = target
    scan.module_ids = list(module_ids)
    scan.options = options
    scan.started = time.time()
    scan.status = "running"

    thread = threading.Thread(
        target=_worker,
        args=(scan,),
        daemon=True,
    )
    thread.start()

    return scan


def _worker(scan):
    """Execute selected modules without blocking Streamlit."""

    try:
        scan.emit(
            "info",
            f"Target: {scan.target.host} | "
            f"Modules: {', '.join(TITLES[m] for m in scan.module_ids)}",
        )

        for module_id in scan.module_ids:
            scan.current = TITLES[module_id]

            scan.emit(
                "info",
                f"Starting {TITLES[module_id]}",
            )

            try:
                data = BACKENDS[module_id].run(
                    scan.target,
                    scan.options.get(module_id, []),
                    scan.emit,
                )

                scan.outcomes[module_id] = {
                    "status": "ok",
                    "data": data or {},
                }

                scan.emit(
                    "ok",
                    f"{TITLES[module_id]} finished",
                )

            except NotImplementedError as exc:
                scan.outcomes[module_id] = {
                    "status": "not_implemented",
                    "data": {},
                }
                scan.emit("warn", str(exc))

            except Exception as exc:
                scan.outcomes[module_id] = {
                    "status": "error",
                    "data": {},
                    "error": f"{type(exc).__name__}: {exc}",
                }

                scan.emit(
                    "error",
                    f"{TITLES[module_id]} failed: {exc}",
                )

            finally:
                scan.done += 1

    except Exception as exc:
        scan.emit(
            "error",
            f"Controller error: {type(exc).__name__}: {exc}",
        )

    finally:
        scan.finished = time.time()

        failed = any(
            result.get("status") == "error"
            for result in scan.outcomes.values()
        )

        scan.emit(
            "info",
            f"Scan finished in {scan.duration:.1f}s",
        )

        scan.status = (
            "completed_errors" if failed else "completed"
        )