"""Target validation module for ReconLab."""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_BAD = re.compile(r"""[\s;|&$`<>\\'"(){}]""")


@dataclass(frozen=True)
class Target:
    raw: str
    host: str            # Bare hostname, IP, or network range
    kind: str            # "domain" | "ip" | "network"


def parse_target(raw: str) -> tuple[Optional[Target], Optional[str]]:
    """Parse raw target input into a Target object."""
    raw = (raw or "").strip()

    if not raw:
        return None, "Please enter a target."

    if _BAD.search(raw) or raw.startswith("-"):
        return None, "Target contains invalid or dangerous characters."

    if "://" in raw:
        return None, "URLs are not supported. Enter a domain name, IP address, or network range."

    # Case 1: CIDR Network (e.g. 192.168.1.0/24)
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return Target(raw, str(network), "network"), None
        except ValueError:
            return None, "Invalid CIDR network format."

    host = raw.strip("[]")

    # Case 2: Individual IP Address
    try:
        ipaddress.ip_address(host)
        return Target(raw, host, "ip"), None
    except ValueError:
        pass

    # Case 3: Domain Name (FQDN)
    host_clean = host.rstrip(".")
    if 0 < len(host_clean) <= 253:
        labels = host_clean.split(".")
        if len(labels) >= 2 and all(_LABEL.match(p) for p in labels):
            return Target(raw, host_clean.lower(), "domain"), None

    return None, "Invalid target format. Enter a valid domain name, IP address, or CIDR range."


def validate_target_for_modules(target: Target, selected_module_ids: list[str]) -> list[str]:
    """Enforce strict target type constraints per selected module."""
    errors = []

    for mid in selected_module_ids:
        # DNS requires a Domain Name only
        if mid == "dns" and target.kind != "domain":
            errors.append(
                "DNS Enumeration requires a domain name (e.g. example.com). IP addresses and CIDR networks are not allowed."
            )

        # Web Enumeration requires a Domain Name only
        elif mid == "web" and target.kind != "domain":
            errors.append(
                "Web Enumeration requires a domain name (e.g. example.com). IP addresses and CIDR networks are not allowed."
            )

        # Service Enumeration allows single IPs or Domains (No CIDR networks)
        elif mid == "services" and target.kind not in ("ip", "domain"):
            errors.append(
                "Service Enumeration requires a single IP address or domain name. CIDR network blocks are not allowed."
            )

        # Host Discovery allows Domains, IPs, or CIDR Networks
        elif mid == "hosts" and target.kind not in ("ip", "domain", "network"):
            errors.append(
                "Host Discovery requires a valid domain name, IP address, or CIDR network block."
            )

    return errors