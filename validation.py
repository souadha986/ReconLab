
"""Target validation. Pure Python, no Streamlit.
Rejects anything that is not a plain host, IP, CIDR network or http(s) URL.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_BAD = re.compile(r"""[\s;|&$`<>\\'"(){}]""")


@dataclass(frozen=True)
class Target:
    raw: str
    host: str            # bare hostname or IP, safe to pass to backends
    kind: str            # "domain" | "ip" | "url" | "network"
    url: str | None = None
    scheme: str | None = None


def _host_ok(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass

    h = h.rstrip(".")

    return (
        0 < len(h) <= 253
        and all(_LABEL.match(p) for p in h.split("."))
    )


def parse_target(raw: str) -> tuple[Target | None, str | None]:
    """Return (Target, None) or (None, error_message)."""

    raw = (raw or "").strip()

    if not raw:
        return None, "Enter a target (domain, URL, IP or CIDR network)."

    if _BAD.search(raw) or raw.startswith("-"):
        return None, "Target contains whitespace or characters that are not allowed."

    # Case 1: HTTP or HTTPS URL
    if "://" in raw:
        try:
            p = urlparse(raw)
            _ = p.port
        except ValueError:
            return None, "That URL could not be parsed."

        if (
            p.scheme not in ("http", "https")
            or not p.hostname
            or p.username is not None
            or p.password is not None
        ):
            return None, "Use a plain http:// or https:// URL without credentials."

        if not _host_ok(p.hostname):
            return None, "The URL host is not a valid domain or IP address."

        return Target(raw, p.hostname, "url", raw, p.scheme), None

    # Case 2: CIDR network, such as 192.168.253.0/24
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return Target(raw, str(network), "network"), None
        except ValueError:
            return None, "Not a valid IP address or CIDR network."

    # Case 3: Individual IP address or domain
    host = raw.strip("[]")

    if not _host_ok(host):
        return None, "Not a valid domain, IP address or http(s) URL."

    kind = "ip" if _is_ip(host) else "domain"

    return Target(raw, host, kind), None


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False
