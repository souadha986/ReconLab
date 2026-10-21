"""Web Enumeration backend using httpx for ReconLab framework."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import httpx

STATUS = "ready"

COMMON_PATHS = [
    "admin", "login", "dashboard", "api", "v1", "v2",
    "config", "backup", "uploads", "static", "public",
    "assets", "dev", "test", "portal", "server-status",
    "robots.txt", "sitemap.xml", ".git", ".env"
]


def _build_url(target_host: str) -> str:
    if not target_host.startswith(("http://", "https://")):
        return f"http://{target_host}"
    return target_host


def _check_path(client: httpx.Client, base_url: str, path: str) -> tuple[str, int] | None:
    target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = client.get(target_url, follow_redirects=False)
        if response.status_code in (200, 301, 302, 307, 308, 403):
            return path, response.status_code
    except httpx.RequestError:
        pass
    return None


def run(target, options, emit) -> dict:
    base_url = _build_url(target.host)
    emit("cmd", f"Starting Web Enumeration on: {base_url}")

    page_data = {
        "url": base_url,
        "status": "N/A",
        "server": "Unknown",
        "title": "N/A",
        "paths": "None Discovered",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconLab/1.0"
    }

    # Header Inspection
    if "headers" in options or not options:
        emit("info", f"[*] Inspecting HTTP headers for: {base_url}")
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0, verify=False) as client:
                response = client.get(base_url, headers=headers)
                page_data["status"] = str(response.status_code)
                page_data["server"] = response.headers.get("server", "Unknown")

                emit("ok", f"  [+] Status Code: {response.status_code} ({response.reason_phrase})")
                for header, value in response.headers.items():
                    emit("out", f"      {header}: {value}")

        except httpx.RequestError as exc:
            emit("error", f"[!] Failed to connect to host: {exc}")
            return {"pages": [page_data]}

    # Directory Brute-Forcing
    if "dirs" in options or not options:
        max_threads = 10
        emit("info", f"[*] Starting Directory Discovery ({len(COMMON_PATHS)} paths)...")

        discovered_paths = []
        lock = threading.Lock()

        with httpx.Client(headers=headers, timeout=3.0, verify=False) as client:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_path = {
                    executor.submit(_check_path, client, base_url, path): path
                    for path in COMMON_PATHS
                }

                for future in as_completed(future_to_path):
                    result = future.result()
                    if result:
                        path, status_code = result
                        entry = f"/{path} ({status_code})"
                        with lock:
                            discovered_paths.append(entry)
                        emit("ok", f"  [+] Discovered: /{path:<20} (Status: {status_code})")

        if discovered_paths:
            page_data["paths"] = ", ".join(discovered_paths)
            emit("ok", f"[*] Directory discovery complete. Discovered {len(discovered_paths)} path(s).")
        else:
            page_data["paths"] = "None Discovered"
            emit("info", "[-] No common directories discovered.")

    emit("ok", "Web Enumeration task complete.")
    return {"pages": [page_data]}