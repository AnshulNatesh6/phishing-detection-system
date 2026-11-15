"""
Behaviour Analysis Agent module.
Analyzes HTTP navigation behaviour, redirect chains, domain transitions,
and navigation patterns for phishing investigation and attack correlation.
Separates objective observations from risk interpretation.
Enforces timeouts, hop limits, and SSRF protections against internal/private network addresses.
Does not execute JavaScript or submit forms.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse
import requests
import tldextract


PRIVATE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0"
}

PRIVATE_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".priv"
)

# Initialize offline TLDExtract instance using bundled Public Suffix List snapshot
# without network fetching. Include standard reserved/testing suffixes (RFC 2606).
_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=None,
    extra_suffixes=["example", "test", "invalid", "localhost", "local"]
)


def get_registered_domain(hostname: str | None) -> str:
    """
    Extract the registered domain (effective TLD + 1 label) from a hostname
    using the Public Suffix List.

    Distinguishes hostnames (e.g., 'www.google.com') from registered domains
    ('google.com'), preventing false-positive cross-domain redirect flags.

    Examples:
        'www.google.com'       -> 'google.com'
        'google.com'           -> 'google.com'
        'mail.google.com'      -> 'google.com'
        'sub.domain.co.uk'     -> 'domain.co.uk'
        'short.example'        -> 'short.example'
        'target-portal.example'-> 'target-portal.example'
        '127.0.0.1'            -> '127.0.0.1'
        'localhost'            -> 'localhost'
    """
    if not hostname:
        return ""

    clean_host = hostname.strip().lower()
    if clean_host.endswith("."):
        clean_host = clean_host[:-1]

    # Handle IPv6 brackets
    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_ip = clean_host[1:-1]
    else:
        clean_ip = clean_host

    # If it is a raw IP address, the registered domain is the IP itself
    try:
        ipaddress.ip_address(clean_ip)
        return clean_host
    except ValueError:
        pass

    try:
        ext = _TLD_EXTRACTOR(clean_host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass

    # Fallback heuristic for unknown TLDs or edge-case multi-dot domains
    parts = clean_host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return clean_host


def is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to private, loopback, link-local, multicast, or reserved ranges."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or getattr(ip, "is_site_local", False)
    ):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_private_ip(ip.ipv4_mapped)
    return False


def is_private_or_local_host(hostname: str | None) -> bool:
    """
    Determine if a hostname or IP string refers to local, loopback, private,
    or internal network destinations to prevent SSRF attacks.
    Handles standard hostnames, private TLDs/suffixes, IPv4/IPv6 literals,
    dotted octal, abbreviated IPv4, integer DWORD, and hex formats.
    """
    if not hostname:
        return True

    clean = hostname.strip().lower()

    if clean.endswith("."):
        clean = clean[:-1]

    if clean in PRIVATE_HOSTNAMES:
        return True

    if any(clean.endswith(suffix) for suffix in PRIVATE_SUFFIXES):
        return True

    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    if "%" in clean:
        clean = clean.split("%")[0]

    # Standard IP address parsing (IPv4 and IPv6)
    try:
        ip = ipaddress.ip_address(clean)
        return is_private_ip(ip)
    except ValueError:
        pass

    # Support dotted-octal and abbreviated IPv4 (e.g. 0177.0.0.1, 127.1)
    try:
        raw_bytes = socket.inet_aton(clean)
        if clean.count(".") in (1, 2, 3) and not any(c.isalpha() for c in clean):
            return is_private_ip(ipaddress.IPv4Address(raw_bytes))
    except (OSError, ValueError):
        pass

    # Support integer DWORD IP representation (e.g. 2130706433 for 127.0.0.1)
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return is_private_ip(ipaddress.IPv4Address(val))
        except ValueError:
            pass

    # Support hexadecimal IP representation (e.g. 0x7f000001)
    if clean.startswith(("0x", "0X")):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return is_private_ip(ipaddress.IPv4Address(val))
        except ValueError:
            pass

    return False


def is_safe_destination_host(hostname: str | None, allow_private_ips: bool = False) -> bool:
    """
    Validate that destination hostname does not refer to localhost,
    private IPs, link-local, loopback, or internal networks.
    Performs static pattern matching, IP literal parsing, and DNS resolution.
    If ANY resolved IP is in private/loopback/reserved range, returns False.
    """
    if allow_private_ips:
        return True
    if not hostname:
        return False

    clean_host = hostname.strip().lower()
    if clean_host.endswith("."):
        clean_host = clean_host[:-1]

    if clean_host.startswith("[") and clean_host.endswith("]"):
        clean_host = clean_host[1:-1]

    if "%" in clean_host:
        clean_host = clean_host.split("%")[0]

    if is_private_or_local_host(clean_host):
        return False

    # Perform DNS resolution to check for hostnames that resolve to private/local IPs
    # (DNS rebinding / private resolution protection)
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str.startswith("[") and ip_str.endswith("]"):
                ip_str = ip_str[1:-1]
            if "%" in ip_str:
                ip_str = ip_str.split("%")[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if is_private_ip(ip):
                    return False
            except ValueError:
                return False
    except (socket.gaierror, socket.herror, OSError, ValueError):
        # In offline/sandbox testing or for dummy test domains (e.g. .example),
        # DNS resolution may fail. Non-resolvable hosts are permitted to continue
        # to the HTTP request layer where network/mock handling occurs.
        pass

    return True


def analyze_redirect_chain(
    original_url: str,
    redirect_chain: list[dict],
    status: str = "completed",
    error_detail: str | None = None
) -> dict:
    """
    Analyze a structured redirect chain and generate behavioral observations and findings.
    Distinguishes hostname transitions from genuine cross-registered-domain redirects.
    Does not execute requests.
    """
    findings = []
    final_url = redirect_chain[-1]["url"] if redirect_chain else original_url
    redirect_count = max(0, len(redirect_chain) - 1)

    # Decorate hops with registered domain if not already set
    for hop in redirect_chain:
        h = hop.get("hostname", "")
        if "registered_domain" not in hop and h:
            hop["registered_domain"] = get_registered_domain(h)

    hostnames = [hop.get("hostname", "") for hop in redirect_chain if hop.get("hostname")]
    registered_domains = [get_registered_domain(h) for h in hostnames if h]

    unique_hostnames = list(dict.fromkeys(hostnames))
    unique_domains = list(dict.fromkeys([d for d in registered_domains if d]))

    domain_changes = []
    hostname_changes = []

    for i in range(len(hostnames) - 1):
        src_host = hostnames[i]
        dst_host = hostnames[i + 1]
        src_reg = registered_domains[i] if i < len(registered_domains) else get_registered_domain(src_host)
        dst_reg = registered_domains[i + 1] if (i + 1) < len(registered_domains) else get_registered_domain(dst_host)

        # Record hostname change
        if src_host != dst_host:
            hostname_changes.append({
                "from": src_host,
                "to": dst_host,
                "at_hop": i + 1,
                "same_registered_domain": (src_reg == dst_reg)
            })

        # Record genuine cross-registered-domain change
        if src_reg and dst_reg and src_reg != dst_reg:
            domain_changes.append({
                "from": src_reg,
                "to": dst_reg,
                "from_hostname": src_host,
                "to_hostname": dst_host,
                "at_hop": i + 1
            })

    has_cross_domain = len(domain_changes) > 0
    has_hostname_change = len(hostname_changes) > 0
    has_protocol_downgrade = False

    # Protocol downgrade check (HTTPS -> HTTP)
    for i in range(len(redirect_chain) - 1):
        src_scheme = urlparse(redirect_chain[i].get("url", "")).scheme.lower()
        dst_scheme = urlparse(redirect_chain[i + 1].get("url", "")).scheme.lower()
        if src_scheme == "https" and dst_scheme == "http":
            has_protocol_downgrade = True
            findings.append({
                "type": "protocol_downgrade",
                "detail": f"Redirect downgraded from secure HTTPS to unencrypted HTTP at hop {i + 1}.",
                "from_url": redirect_chain[i].get("url"),
                "to_url": redirect_chain[i + 1].get("url"),
                "hop": i + 1
            })

    # Genuine cross-domain transitions finding
    if domain_changes:
        findings.append({
            "type": "cross_domain_redirects",
            "count": len(domain_changes),
            "detail": f"Navigation traversed {len(domain_changes)} registered domain transition(s).",
            "transitions": domain_changes,
            "unique_domains": unique_domains
        })

    # Subdomain/hostname change within the same registered domain finding
    same_domain_host_changes = [h for h in hostname_changes if h["same_registered_domain"]]
    if same_domain_host_changes and not domain_changes:
        findings.append({
            "type": "subdomain_redirect",
            "count": len(same_domain_host_changes),
            "detail": (
                f"Navigation redirected across subdomains within the same registered domain "
                f"({', '.join(h['from'] + ' -> ' + h['to'] for h in same_domain_host_changes)})."
            ),
            "transitions": same_domain_host_changes
        })

    # Long redirect chain finding
    if redirect_count >= 3:
        findings.append({
            "type": "unusually_long_chain",
            "count": redirect_count,
            "detail": (
                f"Redirect chain contains {redirect_count} hops. Long chains can be used "
                "to evade automated analysis or obscure final targets, though complex "
                "SSO or affiliate routing can also produce multiple hops."
            )
        })

    # Raw IP hostname at final destination
    final_host = (urlparse(final_url).hostname or "").lower()
    if final_host.startswith("[") and final_host.endswith("]"):
        clean_host = final_host[1:-1]
    else:
        clean_host = final_host

    try:
        ip = ipaddress.ip_address(clean_host)
        findings.append({
            "type": "ip_hostname_destination",
            "detail": f"Final destination uses raw IP address '{final_host}' instead of a domain name.",
            "ip": str(ip)
        })
    except ValueError:
        pass

    # Terminal HTTP error code check
    term_code = redirect_chain[-1].get("status_code") if redirect_chain else None
    if isinstance(term_code, (int, float)) and term_code >= 400:
        findings.append({
            "type": "http_error_response",
            "status_code": int(term_code),
            "detail": f"Final destination returned HTTP error status {int(term_code)}."
        })

    return {
        "agent": "Behaviour Analysis Agent",
        "original_url": original_url,
        "final_url": final_url,
        "final_hostname": final_host,
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "unique_domains": unique_domains,
        "unique_hostnames": unique_hostnames,
        "domain_changes_count": len(domain_changes),
        "domain_changes": domain_changes,
        "hostname_changes_count": len(hostname_changes),
        "hostname_changes": hostname_changes,
        "has_cross_domain_redirect": has_cross_domain,
        "has_hostname_change": has_hostname_change,
        "has_protocol_downgrade": has_protocol_downgrade,
        "status": status,
        "error_detail": error_detail,
        "findings": findings,
        "note": (
            "These are behavioral investigation observations, not proof of phishing. "
            "Redirects, domain transitions, and short links are frequently used in legitimate services "
            "(e.g., CDN routing, URL shorteners, SSO authentication flows)."
        )
    }


def analyze_behaviour(
    url: str,
    max_redirects: int = 5,
    timeout: float = 5.0,
    session: requests.Session | None = None,
    allow_private_ips: bool = False,
    pre_observed_chain: list[dict] | None = None
) -> dict:
    """
    Trace and analyze HTTP navigation behaviour for a given URL.

    Args:
        url: The starting URL to investigate.
        max_redirects: Maximum number of redirect hops to follow (default 5).
        timeout: Request timeout in seconds for each hop (default 5.0).
        session: Optional requests.Session (useful for testing or custom configuration).
        allow_private_ips: If False (default), blocks requests to local/private/loopback addresses.
        pre_observed_chain: Optional pre-recorded redirect chain for offline evaluation.

    Returns:
        dict: Structured JSON evidence containing redirect chain, domain transitions,
              hostname changes, final destination, counts, and explainable findings.
    """
    if pre_observed_chain is not None:
        return analyze_redirect_chain(url, pre_observed_chain)

    if not url or not isinstance(url, str):
        return {
            "agent": "Behaviour Analysis Agent",
            "original_url": str(url) if url is not None else "",
            "final_url": str(url) if url is not None else "",
            "final_hostname": "",
            "redirect_count": 0,
            "redirect_chain": [],
            "unique_domains": [],
            "unique_hostnames": [],
            "domain_changes_count": 0,
            "domain_changes": [],
            "hostname_changes_count": 0,
            "hostname_changes": [],
            "has_cross_domain_redirect": False,
            "has_hostname_change": False,
            "has_protocol_downgrade": False,
            "status": "invalid_url",
            "error_detail": "A valid non-empty URL string is required.",
            "findings": [{
                "type": "invalid_url",
                "detail": "Supplied URL is missing or invalid."
            }],
            "note": "These are behavioral investigation observations, not proof of phishing."
        }

    url = url.strip()
    parsed_initial = urlparse(url)
    if parsed_initial.scheme.lower() not in ("http", "https"):
        return {
            "agent": "Behaviour Analysis Agent",
            "original_url": url,
            "final_url": url,
            "final_hostname": "",
            "redirect_count": 0,
            "redirect_chain": [],
            "unique_domains": [],
            "unique_hostnames": [],
            "domain_changes_count": 0,
            "domain_changes": [],
            "hostname_changes_count": 0,
            "hostname_changes": [],
            "has_cross_domain_redirect": False,
            "has_hostname_change": False,
            "has_protocol_downgrade": False,
            "status": "invalid_scheme",
            "error_detail": f"Unsupported URL scheme '{parsed_initial.scheme}'. Only http and https are allowed.",
            "findings": [{
                "type": "invalid_scheme",
                "detail": f"Scheme '{parsed_initial.scheme}' is not allowed for HTTP behaviour analysis."
            }],
            "note": "These are behavioral investigation observations, not proof of phishing."
        }

    req_session = session or requests.Session()

    current_url = url
    visited_urls = []
    redirect_chain = []
    status = "completed"
    error_detail = None

    while True:
        parsed_current = urlparse(current_url)
        current_hostname = (parsed_current.hostname or "").lower()

        # Handle unbracketed IPv6 and raw IPs in netloc
        netloc = parsed_current.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if "/" in netloc:
            netloc = netloc.split("/")[0]
        if is_private_or_local_host(netloc):
            current_hostname = netloc.lower()
        elif ":" in netloc and is_private_or_local_host(netloc.rsplit(":", 1)[0]):
            current_hostname = netloc.rsplit(":", 1)[0].lower()

        # SSRF / Private address protection (static patterns, IP literals, and DNS resolution)
        if not allow_private_ips and not is_safe_destination_host(current_hostname, allow_private_ips=False):
            status = "blocked_private_address"
            error_detail = f"Access to private/local network address '{current_hostname}' was blocked."
            hop_info = {
                "hop": len(redirect_chain) + 1,
                "url": current_url,
                "status_code": None,
                "hostname": current_hostname,
                "registered_domain": get_registered_domain(current_hostname),
                "destination": None,
                "blocked": True
            }
            redirect_chain.append(hop_info)
            break

        # Redirect loop detection
        if current_url in visited_urls:
            status = "redirect_loop"
            error_detail = f"Redirect loop detected: '{current_url}' visited multiple times."
            break

        visited_urls.append(current_url)

        # Check maximum hops reached
        if len(redirect_chain) >= max_redirects:
            status = "max_redirects_exceeded"
            error_detail = f"Exceeded maximum allowed redirect limit of {max_redirects} hops."
            break

        try:
            response = req_session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout
            )
            status_code = response.status_code
            location_header = response.headers.get("Location")
        except requests.Timeout as e:
            status = "timeout"
            error_detail = f"Request timed out after {timeout} seconds: {str(e)}"
            redirect_chain.append({
                "hop": len(redirect_chain) + 1,
                "url": current_url,
                "status_code": None,
                "hostname": current_hostname,
                "registered_domain": get_registered_domain(current_hostname),
                "destination": None,
                "error": "timeout"
            })
            break
        except requests.RequestException as e:
            status = "connection_error"
            error_detail = f"Connection error: {str(e)}"
            redirect_chain.append({
                "hop": len(redirect_chain) + 1,
                "url": current_url,
                "status_code": None,
                "hostname": current_hostname,
                "registered_domain": get_registered_domain(current_hostname),
                "destination": None,
                "error": "connection_error"
            })
            break

        hop_info = {
            "hop": len(redirect_chain) + 1,
            "url": current_url,
            "status_code": status_code,
            "hostname": current_hostname,
            "registered_domain": get_registered_domain(current_hostname),
            "destination": None
        }

        # Check if response is a redirect
        if status_code in (301, 302, 303, 307, 308) and location_header:
            next_url = urljoin(current_url, location_header.strip())
            hop_info["destination"] = next_url
            redirect_chain.append(hop_info)

            # Validate next URL scheme
            parsed_next = urlparse(next_url)
            next_scheme = parsed_next.scheme.lower()
            if next_scheme not in ("http", "https"):
                status = "invalid_scheme"
                error_detail = f"Redirect to unsupported scheme '{next_scheme}' was blocked."
                redirect_chain.append({
                    "hop": len(redirect_chain) + 1,
                    "url": next_url,
                    "status_code": None,
                    "hostname": (parsed_next.hostname or "").lower(),
                    "registered_domain": get_registered_domain(parsed_next.hostname),
                    "destination": None,
                    "blocked": True,
                    "error": "invalid_scheme"
                })
                current_url = next_url
                break

            # Validate next URL destination host against private/local/SSRF targets before next request
            next_hostname = (parsed_next.hostname or "").lower()
            next_netloc = parsed_next.netloc
            if "@" in next_netloc:
                next_netloc = next_netloc.split("@")[-1]
            if "/" in next_netloc:
                next_netloc = next_netloc.split("/")[0]
            if is_private_or_local_host(next_netloc):
                next_hostname = next_netloc.lower()
            elif ":" in next_netloc and is_private_or_local_host(next_netloc.rsplit(":", 1)[0]):
                next_hostname = next_netloc.rsplit(":", 1)[0].lower()

            if not allow_private_ips and not is_safe_destination_host(next_hostname, allow_private_ips=False):
                status = "blocked_private_address"
                error_detail = f"Access to private/local network address '{next_hostname}' was blocked."
                redirect_chain.append({
                    "hop": len(redirect_chain) + 1,
                    "url": next_url,
                    "status_code": None,
                    "hostname": next_hostname,
                    "registered_domain": get_registered_domain(next_hostname),
                    "destination": None,
                    "blocked": True
                })
                current_url = next_url
                break

            current_url = next_url
        else:
            redirect_chain.append(hop_info)
            break

    result = analyze_redirect_chain(
        original_url=url,
        redirect_chain=redirect_chain,
        status=status,
        error_detail=error_detail
    )

    # Prepend specific findings for special termination conditions
    if status == "blocked_private_address":
        result["findings"].insert(0, {
            "type": "blocked_private_address",
            "detail": error_detail or "Navigation to private or internal address blocked.",
            "url": current_url
        })
    elif status == "redirect_loop":
        result["findings"].insert(0, {
            "type": "redirect_loop",
            "detail": error_detail or "Redirect loop detected.",
            "url": current_url
        })
    elif status == "max_redirects_exceeded":
        result["findings"].insert(0, {
            "type": "max_redirects_exceeded",
            "limit": max_redirects,
            "detail": error_detail or f"Maximum redirect limit of {max_redirects} exceeded."
        })
    elif status == "timeout":
        result["findings"].insert(0, {
            "type": "request_timeout",
            "detail": error_detail or f"Request timed out after {timeout}s.",
            "url": current_url
        })
    elif status == "connection_error":
        result["findings"].insert(0, {
            "type": "connection_error",
            "detail": error_detail or "HTTP connection error encountered.",
            "url": current_url
        })

    return result
