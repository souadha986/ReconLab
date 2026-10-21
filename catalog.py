"""Module catalogue: what the UI shows."""

from typing import NamedTuple


class Opt(NamedTuple):
    id: str
    label: str
    default: bool = False


class Module(NamedTuple):
    id: str
    title: str
    desc: str
    options: tuple
    needs_nmap: bool = False




MODULES = (
    Module(
        "dns",
        "DNS Enumeration",
        "Automatically queries A, AAAA, MX, NS, TXT, CNAME, and subdomains.",
        (),
    ),
    Module(
        "web",
        "Web Enumeration",
        "Inspect HTTP response headers and brute-force common directories.",
        (
            Opt("headers", "HTTP Response Headers", True),
            Opt("dirs", "Directory Brute-Forcing", True),
        ),
    ),
    Module(
        "hosts",
        "Host Discovery",
        "Discover reachable hosts using ICMP or TCP.",
        (
            Opt("icmp", "ICMP Discovery (Ping)", True),
            Opt("tcp", "TCP Discovery", False),
        ),
    ),
    Module(
        "services",
        "Service Enumeration",
        "Scan TCP ports 1-65535 and report their states.",
        (),
    ),
)