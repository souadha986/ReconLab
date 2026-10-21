"""TCP/UDP service enumeration backend for ReconLab."""

import errno
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

STATUS = "ready"
LABELS = {"services": "TCP/UDP port states"}

FIRST_PORT = 1
LAST_PORT = 65535
WELL_KNOWN_LAST = 1024

MAX_THREADS = 300
TCP_TIMEOUT = 0.4
UDP_TIMEOUT = 0.8

MODE_ALL = "all_ports"
MODE_WELL_KNOWN = "well_known"
MODE_COMMON = "common"
MODE_CUSTOM = "custom"
CUSTOM_PREFIX = "custom:"

PROTO_TCP = "proto_tcp"
PROTO_UDP = "proto_udp"

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515,
    587, 631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2082, 2083, 2181, 2375, 3000, 3128, 3306, 3389, 4444, 5000, 5060,
    5432, 5601, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
]

COMMON_UDP_PORTS = [
    53, 67, 68, 69, 111, 123, 135, 137, 138, 161, 162, 500, 514,
    520, 623, 1434, 1900, 4500, 5353, 49152,
]


def parse_ports(spec: str) -> list:
    spec = (spec or "").strip()
    if not spec:
        raise ValueError("Enter at least one port or range.")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not all(b.strip().isdigit() for b in bounds):
                raise ValueError(f"Invalid range: '{part}'")
            start, end = int(bounds[0]), int(bounds[1])
            if start > end:
                raise ValueError(f"Range start is greater than end: '{part}'")
        else:
            if not part.isdigit():
                raise ValueError(f"Invalid port: '{part}'")
            start = end = int(part)
        if start < FIRST_PORT or end > LAST_PORT:
            raise ValueError(f"Ports must be between {FIRST_PORT} and {LAST_PORT}: '{part}'")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("Enter at least one port or range.")
    return sorted(ports)


def resolve_port_selection(options) -> list:
    for option in options or []:
        if option == MODE_ALL:
            return list(range(FIRST_PORT, LAST_PORT + 1))
        if option == MODE_WELL_KNOWN:
            return list(range(FIRST_PORT, WELL_KNOWN_LAST + 1))
        if option == MODE_COMMON:
            return sorted(set(COMMON_PORTS))
        if isinstance(option, str) and option.startswith(CUSTOM_PREFIX):
            return parse_ports(option[len(CUSTOM_PREFIX):])
    return list(range(FIRST_PORT, LAST_PORT + 1))


def resolve_protocols(options) -> list:
    protocols = []
    if PROTO_TCP in (options or []):
        protocols.append("tcp")
    if PROTO_UDP in (options or []):
        protocols.append("udp")
    return protocols or ["tcp"]


def describe_selection(options) -> str:
    port_desc = f"all ports ({FIRST_PORT}-{LAST_PORT})"
    for option in options or []:
        if option == MODE_ALL:
            port_desc = f"all ports ({FIRST_PORT}-{LAST_PORT})"
        elif option == MODE_WELL_KNOWN:
            port_desc = f"well-known ports ({FIRST_PORT}-{WELL_KNOWN_LAST})"
        elif option == MODE_COMMON:
            port_desc = "common service ports"
        elif isinstance(option, str) and option.startswith(CUSTOM_PREFIX):
            port_desc = f"custom ports ({option[len(CUSTOM_PREFIX):]})"
    protocols = resolve_protocols(options)
    return f"{'/'.join(p.upper() for p in protocols)}, {port_desc}"


def resolve_service_name(port: int, protocol: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, socket.error):
        return "unknown"


def scan_tcp_port(target_ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TCP_TIMEOUT)
    try:
        sock.connect((target_ip, port))
        return port, "OPEN", resolve_service_name(port, "tcp")
    except ConnectionRefusedError:
        return port, "CLOSED", "unknown"
    except socket.timeout:
        return port, "FILTERED", "unknown"
    except OSError as exc:
        if exc.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH):
            return port, "CLOSED", "unknown"
        return port, "FILTERED", "unknown"
    finally:
        sock.close()


def scan_udp_port(target_ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT)
    try:
        sock.sendto(b"", (target_ip, port))
        try:
            sock.recvfrom(1024)
            return port, "OPEN", resolve_service_name(port, "udp")
        except socket.timeout:
            return port, "OPEN|FILTERED", "unknown"
        except ConnectionRefusedError:
            return port, "CLOSED", "unknown"
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                return port, "CLOSED", "unknown"
            return port, "OPEN|FILTERED", "unknown"
    except OSError:
        return port, "OPEN|FILTERED", "unknown"
    finally:
        sock.close()


def _scan_protocol(target_ip, ports, protocol, emit):
    total = len(ports)
    progress_step = max(1, total // 10)
    scan_fn = scan_tcp_port if protocol == "tcp" else scan_udp_port
    open_states = {"OPEN"} if protocol == "tcp" else {"OPEN", "OPEN|FILTERED"}
    results = []
    completed = 0
    closed_count = 0
    with ThreadPoolExecutor(max_workers=min(MAX_THREADS, total)) as pool:
        futures = {pool.submit(scan_fn, target_ip, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            completed += 1
            try:
                scanned_port, state, service = future.result()
            except Exception as exc:
                scanned_port, state, service = port, "FILTERED", "unknown"
                emit("warn", f"{protocol.upper()} port {port}: {type(exc).__name__}")
            if state == "CLOSED":
                closed_count += 1
            else:
                results.append({
                    "ip": target_ip,
                    "port": scanned_port,
                    "protocol": protocol.upper(),
                    "service": service,
                    "state": state,
                })
            if state in open_states:
                emit("ok", f"{protocol.upper()} port {scanned_port} ({service.upper()}) {state}")
            if total > 20 and (completed % progress_step == 0 or completed == total):
                emit("info", f"{protocol.upper()} progress: {completed}/{total} ports scanned")
    return results, closed_count


def run(target, options, emit):
    hostname = target.host.strip()
    try:
        ports = resolve_port_selection(options)
    except ValueError as exc:
        raise ValueError(f"Invalid port selection: {exc}") from exc

    protocols = resolve_protocols(options)
    emit("info", f"Resolving target: {hostname}")

    try:
        target_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname: {hostname}") from exc

    emit("info", f"Target IP: {target_ip}")
    emit("info", f"Protocols: {', '.join(p.upper() for p in protocols)}")
    emit("info", f"Ports per protocol: {len(ports)}")

    if "udp" in protocols and len(ports) > 2000:
        emit("warn", "UDP scanning a large port range is slow and results are inherently less reliable than TCP (silence = OPEN|FILTERED).")

    all_results = []
    total_closed = 0
    for protocol in protocols:
        emit("info", f"Starting {protocol.upper()} scan...")
        results, closed_count = _scan_protocol(target_ip, ports, protocol, emit)
        all_results.extend(results)
        total_closed += closed_count
        emit("info", f"{protocol.upper()} scan complete.")

    all_results.sort(key=lambda row: (row["protocol"], row["port"]))
    open_count = sum(row["state"] == "OPEN" for row in all_results)
    ambiguous_count = sum(row["state"] == "OPEN|FILTERED" for row in all_results)
    filtered_count = sum(row["state"] == "FILTERED" for row in all_results)

    emit("info", f"Open ports: {open_count}")
    if ambiguous_count:
        emit("info", f"Open|Filtered (UDP, no reply): {ambiguous_count}")
    emit("info", f"Filtered/uncertain: {filtered_count}")
    emit("info", f"Closed ports (hidden): {total_closed}")
    emit("ok", "Port scan completed")

    return {"services": all_results}
