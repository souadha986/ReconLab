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


# ---------------------------------------------------------
# Nmap options
# ---------------------------------------------------------

NMAP_SAFE = (
    Opt("default", "default: common, generally safe scripts", True),
    Opt("safe", "safe: should not affect the target", True),
    Opt("discovery", "discovery: gather extra information"),
    Opt("version", "version: extended service detection"),
)

NMAP_INTRUSIVE = (
    Opt("vuln", "vuln: check for known vulnerabilities"),
    Opt("auth", "auth: test authentication, e.g. default logins"),
    Opt("intrusive", "intrusive: may load or disturb the target"),
    Opt("brute", "brute: guess credentials"),
    Opt("fuzzer", "fuzzer: send unexpected input"),
    Opt("dos", "dos: may cause denial of service"),
    Opt("exploit", "exploit: actively exploit weaknesses"),
    Opt("malware", "malware: look for backdoors and malware"),
)

INTRUSIVE_IDS = {
    option.id for option in NMAP_INTRUSIVE
}


# ---------------------------------------------------------
# Module catalogue
# ---------------------------------------------------------

MODULES = (
    Module(
        "dns",
        "DNS Enumeration",
        "Look up DNS records and find subdomains.",
        (
            Opt("a", "A records", True),
            Opt("aaaa", "AAAA records", True),
            Opt("mx", "MX records", True),
            Opt("ns", "NS records", True),
            Opt("txt", "TXT records", True),
            Opt("cname", "CNAME records"),
            Opt("subdomains", "Subdomain enumeration"),
        ),
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

    # No options: scan all TCP ports automatically.
    Module(
        "services",
        "Service Enumeration",
        "Scan TCP ports 1-65535 and report their states.",
        (),
        needs_nmap=False,
    ),

    Module(
        "nmap",
        "Nmap NSE Scripts",
        "Run Nmap script categories. Requires Nmap.",
        NMAP_SAFE + NMAP_INTRUSIVE,
        needs_nmap=True,
    ),
)