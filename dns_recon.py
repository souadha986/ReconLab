"""DNS Enumeration backend for ReconLab."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import dns.exception
import dns.query
import dns.resolver
import dns.zone

STATUS = "ready"

# Standard record types queried automatically
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "portal", "admin",
    "test", "cdn", "cloud", "dns", "app", "git", "gitlab", "shop", "m",
    "developers", "office", "email"
]


def create_resolver(timeout: float = 2.0) -> dns.resolver.Resolver:
    res = dns.resolver.Resolver()
    res.nameservers = ["1.1.1.1", "8.8.8.8"]
    res.timeout = timeout
    res.lifetime = timeout
    return res


def _resolve_single_subdomain(domain: str, sub: str, resolver: dns.resolver.Resolver) -> tuple[str, str] | None:
    """Worker function to resolve a single subdomain."""
    subdomain = f"{sub}.{domain}"
    try:
        answers = resolver.resolve(subdomain, "A")
        ips = [rdata.to_text() for rdata in answers]
        return subdomain, ", ".join(ips)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception:
        return None


def run(target, options, emit) -> dict:
    domain = target.host
    records_found = []
    seen = set()
    lock = threading.Lock()

    resolver = create_resolver()

    def add_record(rtype: str, val: str, status: str = "found"):
        entry = (rtype, val)
        with lock:
            if entry not in seen:
                seen.add(entry)
                records_found.append({"type": rtype, "value": val, "status": status})

    emit("cmd", f"Starting DNS Enumeration for: {domain}")

    # =========================================================
    # Step 1: Attempt Zone Transfer (AXFR)
    # =========================================================
    axfr_success = False
    emit("info", f"[*] Attempting Zone Transfer (AXFR) on {domain}...")
    try:
        ns_answers = resolver.resolve(domain, "NS")
        nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answers]

        for ns_host in nameservers:
            emit("info", f"  -> Resolving IP for Name Server: {ns_host}")
            try:
                ip_answers = resolver.resolve(ns_host, "A")
                ns_ip = str(ip_answers[0])
            except Exception as exc:
                emit("warn", f"  [-] Could not resolve IP for {ns_host}: {exc}")
                continue

            emit("cmd", f"  -> Testing AXFR over TCP (Port 53) directly to {ns_host} ({ns_ip})...")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(where=ns_ip, zone=domain, timeout=4.0))
                emit("ok", f"[+] AXFR SUCCESSFUL! Zone downloaded from {ns_host} ({ns_ip})")
                
                for name, node in zone.nodes.items():
                    subdomain_prefix = str(name)
                    full_name = f"{domain}" if subdomain_prefix == "@" else f"{subdomain_prefix}.{domain}"

                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            val = f"{full_name} -> {rdata.to_text()}"
                            add_record(rtype, val, status="axfr")
                            emit("out", f"    [AXFR] {rtype:<6} {val}")
                
                axfr_success = True
                break
            except dns.exception.FormError:
                emit("warn", f"  [-] AXFR Refused (FormError) by {ns_host}")
            except Exception as exc:
                emit("warn", f"  [-] AXFR Failed ({type(exc).__name__}) on {ns_host}")

    except Exception as exc:
        emit("warn", f"[-] Could not retrieve NS records for AXFR: {exc}")

    # If AXFR succeeded, we have the complete zone, so return early
    if axfr_success:
        emit("ok", f"DNS Enumeration complete via Zone Transfer ({len(records_found)} records retrieved).")
        return {"records": records_found}

    # =========================================================
    # Step 2: Query Standard DNS Records (Automatic)
    # =========================================================
    emit("info", f"[*] Querying base DNS records: {', '.join(DEFAULT_RECORD_TYPES)}...")
    
    for rtype in DEFAULT_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                val = rdata.to_text()
                add_record(rtype, val, status="found")
                emit("out", f"  [+] {rtype:<6} : {val}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as exc:
            emit("error", f"  [!] Error querying {rtype}: {exc}")

    # =========================================================
    # Step 3: Multi-Threaded Subdomain Brute-Forcing (Automatic)
    # =========================================================
    max_threads = 10
    emit("info", f"[*] Brute-forcing subdomains for {domain} ({max_threads} threads)...")
    found_subdomains = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_sub = {
            executor.submit(_resolve_single_subdomain, domain, sub, resolver): sub
            for sub in COMMON_SUBDOMAINS
        }

        for future in as_completed(future_to_sub):
            result = future.result()
            if result:
                subdomain, ip_str = result
                val = f"{subdomain} -> {ip_str}"
                add_record("A", val, status="found")
                emit("ok", f"  [+] Discovered: {subdomain:<35} -> {ip_str}")
                found_subdomains += 1

    emit("info", f"[*] Subdomain brute-force finished. Discovered: {found_subdomains}")

    emit("ok", f"DNS Enumeration complete. Total unique records found: {len(records_found)}")
    return {"records": records_found}