import ipaddress
import socket
import time
import os
import struct
import select
import threading
import errno
from concurrent.futures import ThreadPoolExecutor

STATUS = "partial"

# NEW: ports used by the TCP fallback probe
TCP_PROBE_PORTS = [80, 443, 22, 445, 135, 139, 3389, 8080, 53, 21, 23, 5900]


# ---------------------------------------------------------------
# checksum helper for the raw ICMP packet
# ---------------------------------------------------------------
def _checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16

    return ~total & 0xFFFF


# ---------------------------------------------------------------
# CHANGED: raw socket ICMP sweep, now with MULTIPLE PASSES
# Pass 1 triggers ARP resolution, later passes catch hosts whose
# first packet was dropped while the OS was resolving their MAC.
# ---------------------------------------------------------------
def icmp_sweep(targets, timeout=1.0, passes=3):
    """Fast ICMP sweep using a raw socket (needs root/admin)."""

    found = {}
    ident = os.getpid() & 0xFFFF
    sent_done = threading.Event()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_ICMP
    )

    def build_packet(seq):
        header = struct.pack("!BBHHH", 8, 0, 0, ident, seq & 0xFFFF)
        payload = b"reconlab"
        chk = _checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, chk, ident, seq & 0xFFFF)
        return header + payload

    def sender():
        try:
            for _ in range(passes):                      # NEW: several passes
                for n, ip in enumerate(targets):
                    try:
                        sock.sendto(build_packet(n), (str(ip), 0))
                    except OSError:
                        pass

                    if n % 128 == 127:                   # CHANGED: smaller bursts
                        time.sleep(0.005)

                time.sleep(0.3)                          # NEW: let ARP resolve
        finally:
            sent_done.set()

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()

    deadline = None

    try:
        while True:
            if sent_done.is_set() and deadline is None:
                deadline = time.time() + timeout

            if deadline is not None and time.time() >= deadline:
                break

            ready, _, _ = select.select([sock], [], [], 0.1)

            if not ready:
                continue

            data, addr = sock.recvfrom(65535)

            ihl = (data[0] & 0x0F) * 4
            icmp = data[ihl:ihl + 8]

            if len(icmp) < 8:
                continue

            icmp_type, _code, _chk, r_id, _seq = struct.unpack("!BBHHH", icmp)

            if icmp_type == 0 and r_id == ident:
                found[addr[0]] = {"ip": addr[0], "state": "up"}

    finally:
        sock.close()

    return list(found.values())


# ---------------------------------------------------------------
# ARP sweep, very reliable on the local network
# ---------------------------------------------------------------
def arp_sweep(cidr, timeout=2):
    """Discover hosts on the local subnet using ARP."""

    from scapy.all import ARP, Ether, srp

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
        timeout=timeout,
        retry=1,
        verbose=0
    )

    return [{"ip": r.psrc, "state": "up"} for _, r in answered]


# ---------------------------------------------------------------
# NEW: TCP probe, finds hosts that block ping
# A connection that succeeds OR is refused (RST) proves the host is up.
# Plain sockets are thread-safe, so threads are fine here.
# ---------------------------------------------------------------
def tcp_probe(ip, ports=TCP_PROBE_PORTS, timeout=0.5):
    """Return True if the host answers on any of the given TCP ports."""

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((str(ip), port))

            # 0 = open, ECONNREFUSED / 10061 = host alive but port closed
            if result in (0, errno.ECONNREFUSED, 10061):
                return True

        except OSError:
            pass

        finally:
            sock.close()

    return False


def tcp_sweep(targets, ports=TCP_PROBE_PORTS, timeout=0.5, workers=200):
    """Probe many hosts in parallel with TCP connects."""

    def check(ip):
        return str(ip) if tcp_probe(ip, ports, timeout) else None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(check, targets)

    return [{"ip": ip, "state": "up"} for ip in results if ip]


def run(target, options, emit):

    host = target.host
    target_kind = target.kind
    selected_options = options

    try:
        if "/" in host:
            network = ipaddress.ip_network(host, strict=False)

            if network.num_addresses <= 2:
                targets = list(network)
            else:
                targets = list(network.hosts())

        else:
            try:
                targets = [ipaddress.ip_address(host)]

            except ValueError:
                try:
                    ip = socket.gethostbyname(host)
                    targets = [ipaddress.ip_address(ip)]

                except socket.gaierror:
                    emit("error", "Could not resolve the domain.")
                    return {"hosts": []}

        # debug print removed (it was slow on big networks)
        # for target_ip in targets:
        #     print(target_ip)

    except ValueError:
        emit("error", "Invalid IP address or CIDR.")
        return {"hosts": []}

    # NEW: all methods write into one dict, so no host is listed twice
    found = {}

    def add(results):
        for h in results:
            found.setdefault(h["ip"], h)

    if "icmp" in selected_options:
        # Case 1: ICMP discovery

        if any(ip.version != 4 for ip in targets):
            emit(
                "error",
                "This ICMP implementation supports IPv4 targets only."
            )
            return {"hosts": []}

        # ---- Layer 1: raw socket ICMP, 3 passes ----
        try:
            add(icmp_sweep(targets))

        except PermissionError:
            emit(
                "error",
                "Raw sockets require root/administrator permissions. "
                "Check the ReconLab installation instructions."
            )

        except OSError as exc:
            emit("error", f"ICMP sweep failed: {exc}")

        # ---- Layer 2 (NEW): ARP on private ranges, finds hosts that block ping ----
        # Only works when the target is on your own subnet; harmless otherwise.
        # To disable it, comment out this block.
        if "/" in host and network.is_private:
            try:
                add(arp_sweep(host))

            except (PermissionError, OSError) as exc:
                emit("warn", f"ARP sweep failed: {exc}")

            except ImportError:
                emit("warn", "ARP sweep needs scapy installed.")

    # CHANGED: was "elif", now a separate "if" so it can run together with ICMP
    # ---- Layer 3 (NEW): TCP probe, only on hosts not found yet ----
    if "tcp" in selected_options:
        remaining = [ip for ip in targets if str(ip) not in found]

        try:
            add(tcp_sweep(remaining))

        except OSError as exc:
            emit("error", f"TCP sweep failed: {exc}")

    # =========================
    # 4. ERROR HANDLING
    # =========================
    # TODO: Handle errors and report them using emit()

    # =========================
    # 5. OUTPUT
    # =========================
    # Each host contains:
    # - ip
    # - state

    return {
        "hosts": list(found.values())
    }