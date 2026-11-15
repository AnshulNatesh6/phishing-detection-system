"""
Comprehensive automated unit tests for SSRF (Server-Side Request Forgery) protection
in both the Behaviour Analysis Agent and Webpage Analysis Agent.

Tests:
1. Private IPv4 addresses (192.168.1.1, 10.0.0.1, 172.16.0.1, 169.254.169.254, 0.0.0.0).
2. IPv6 loopback (::1, [::1], ::ffff:127.0.0.1).
3. IPv6 private/local addresses (fe80::1 link-local, fc00::1 / fd00::1 ULA, :: unspecified).
4. Public URLs redirecting to private IP addresses.
5. Public URLs redirecting to localhost / loopback.
6. Hostnames that resolve to private IP addresses (DNS resolution & rebinding protection).
7. Redirect chains where an intermediate destination is private.
8. Webpage Analysis Agent pre-navigation and Playwright route-blocking tests.
"""

import socket
from unittest.mock import MagicMock, patch
import pytest
import requests

from src.behaviour_agent import (
    analyze_behaviour,
    is_safe_destination_host,
    is_private_or_local_host,
    is_private_ip
)
from src.webpage_agent import analyze_rendered_webpage
from test_both_agents import is_safe_destination_url, run_integrated_analysis


def create_mock_response(status_code: int, url: str, location: str | None = None) -> requests.Response:
    """Create a mock HTTP response for safe offline testing."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Location": location} if location else {}
    return resp


# ---------------------------------------------------------------------------
# 1. Private IPv4 Addresses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("private_ip", [
    "192.168.1.1",
    "192.168.0.254",
    "10.0.0.1",
    "10.254.0.1",
    "172.16.0.1",
    "172.31.255.254",
    "169.254.169.254",  # AWS/Cloud metadata service
    "0.0.0.0",
    "127.0.0.1",
    "127.0.0.2",
    "127.1",            # Abbreviated IPv4
    "0177.0.0.1",       # Octal IPv4
])
def test_private_ipv4_blocked_behaviour_agent(private_ip):
    """
    Verify Behaviour Analysis Agent blocks private IPv4 destinations
    before sending any HTTP request.
    """
    mock_session = MagicMock(spec=requests.Session)
    target_url = f"http://{private_ip}:8080/setup"

    result = analyze_behaviour(url=target_url, session=mock_session, allow_private_ips=False)

    assert result["status"] == "blocked_private_address"
    assert "private" in result["error_detail"].lower() or "blocked" in result["error_detail"].lower()
    # Verify no HTTP request was ever dispatched
    mock_session.get.assert_not_called()


@pytest.mark.parametrize("private_ip", [
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "169.254.169.254",
    "127.0.0.1"
])
def test_private_ipv4_blocked_webpage_agent(private_ip):
    """
    Verify Webpage Analysis Agent blocks private IPv4 destinations
    before launching the browser.
    """
    target_url = f"http://{private_ip}:8000/admin"
    result = analyze_rendered_webpage(url=target_url, allow_private_ips=False)

    assert result["status"] == "blocked_private_address"
    assert "private" in result["error_detail"].lower() or "blocked" in result["error_detail"].lower()
    assert result["forms_count"] == 0


# ---------------------------------------------------------------------------
# 2. IPv6 Loopback (::1 and mapped IPv4)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("loopback_host", [
    "::1",
    "[::1]",
    "::ffff:127.0.0.1",
    "[::ffff:127.0.0.1]",
])
def test_ipv6_loopback_blocked(loopback_host):
    """
    Verify IPv6 loopback addresses are blocked in both agents.
    """
    mock_session = MagicMock(spec=requests.Session)
    target_url = f"http://{loopback_host}:8080/debug"

    # Behaviour Agent
    res_beh = analyze_behaviour(url=target_url, session=mock_session, allow_private_ips=False)
    assert res_beh["status"] == "blocked_private_address"
    mock_session.get.assert_not_called()

    # Webpage Agent
    res_web = analyze_rendered_webpage(url=target_url, allow_private_ips=False)
    assert res_web["status"] == "blocked_private_address"


# ---------------------------------------------------------------------------
# 3. IPv6 Private and Local Addresses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ipv6_local", [
    "fe80::1",              # Link-local
    "[fe80::1]",
    "fe80::200:5aee:feaa:20a2",
    "fc00::1",              # Unique Local Address (ULA fc00::/7)
    "[fc00::1]",
    "fd00::1",              # Unique Local Address (ULA fd00::/8)
    "[fd00::1]",
    "fd12:3456:789a::1",
    "::",                   # Unspecified
    "[::]",
    "::ffff:192.168.1.1",   # IPv4-mapped private
    "::ffff:10.0.0.1",
])
def test_ipv6_private_local_blocked(ipv6_local):
    """
    Verify IPv6 link-local, ULA, unspecified, and mapped private IPs are blocked.
    """
    mock_session = MagicMock(spec=requests.Session)
    target_url = f"http://{ipv6_local}/status"

    # Behaviour Agent
    res_beh = analyze_behaviour(url=target_url, session=mock_session, allow_private_ips=False)
    assert res_beh["status"] == "blocked_private_address"
    mock_session.get.assert_not_called()

    # Webpage Agent
    res_web = analyze_rendered_webpage(url=target_url, allow_private_ips=False)
    assert res_web["status"] == "blocked_private_address"


# ---------------------------------------------------------------------------
# 4. Public URLs Redirecting to Private IP Addresses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("private_dest", [
    "http://192.168.1.1/setup",
    "http://10.0.0.1/admin",
    "http://172.16.0.1/portal",
    "http://169.254.169.254/latest/meta-data",
    "http://[fd00::1]/internal",
    "http://[fe80::1]/api",
])
def test_public_redirect_to_private_ip_blocked(private_dest):
    """
    When an external public URL issues an HTTP 302/301 redirecting
    to a private IP, Behaviour Agent must halt at the redirect hop
    and NEVER execute a request against the private target.
    """
    mock_session = MagicMock(spec=requests.Session)
    public_url = "https://public-service.example/redirect"

    mock_session.get.side_effect = [
        create_mock_response(302, public_url, private_dest)
    ]

    res = analyze_behaviour(url=public_url, session=mock_session, allow_private_ips=False)

    assert res["status"] == "blocked_private_address"
    assert len(res["redirect_chain"]) == 2
    assert res["redirect_chain"][0]["url"] == public_url
    assert res["redirect_chain"][1]["blocked"] is True

    # Critical: mock_session.get must ONLY be called ONCE for the public start
    assert mock_session.get.call_count == 1


# ---------------------------------------------------------------------------
# 5. Public URLs Redirecting to Localhost
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("localhost_dest", [
    "http://localhost:8000/callback",
    "http://127.0.0.1:3000/secret",
    "http://127.0.0.2:5000/console",
    "http://[::1]:9000/oauth",
    "http://localhost.localdomain/api",
])
def test_public_redirect_to_localhost_blocked(localhost_dest):
    """
    Verify redirects from public sites to localhost / loopback variants are blocked.
    """
    mock_session = MagicMock(spec=requests.Session)
    public_url = "https://auth-hub.example/login"

    mock_session.get.side_effect = [
        create_mock_response(302, public_url, localhost_dest)
    ]

    res = analyze_behaviour(url=public_url, session=mock_session, allow_private_ips=False)

    assert res["status"] == "blocked_private_address"
    assert len(res["redirect_chain"]) == 2
    assert res["redirect_chain"][1]["blocked"] is True
    assert mock_session.get.call_count == 1


# ---------------------------------------------------------------------------
# 6. Hostnames That Resolve to Private IP Addresses (DNS Resolution & Rebinding)
# ---------------------------------------------------------------------------

def test_dns_resolution_to_private_ip_initial_url():
    """
    A public-looking hostname (e.g. spoofed-intranet.example) whose DNS
    A record resolves to a private IP (192.168.1.50) must be blocked
    before making any HTTP request.
    """
    mock_session = MagicMock(spec=requests.Session)
    fake_host = "spoofed-intranet.example"
    fake_url = f"https://{fake_host}/login"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == fake_host:
            # Resolves to private IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        res = analyze_behaviour(url=fake_url, session=mock_session, allow_private_ips=False)

        assert res["status"] == "blocked_private_address"
        mock_session.get.assert_not_called()

        # Webpage Agent check
        res_web = analyze_rendered_webpage(url=fake_url, allow_private_ips=False)
        assert res_web["status"] == "blocked_private_address"


def test_dns_resolution_to_ipv6_loopback():
    """
    A domain resolving to IPv6 loopback (::1) must be blocked before request.
    """
    mock_session = MagicMock(spec=requests.Session)
    fake_host = "local-v6-tunnel.example"
    fake_url = f"https://{fake_host}/api"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == fake_host:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        res = analyze_behaviour(url=fake_url, session=mock_session, allow_private_ips=False)
        assert res["status"] == "blocked_private_address"
        mock_session.get.assert_not_called()


def test_dns_rebinding_mixed_records_blocked():
    """
    DNS Rebinding protection: If DNS returns multiple IP addresses and ANY of them
    is private/loopback, the destination must be treated as unsafe and blocked.
    """
    fake_host = "rebind-trick.example"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == fake_host:
            # Returns a public IP alongside a private loopback IP
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        assert is_safe_destination_host(fake_host, allow_private_ips=False) is False


def test_dns_resolution_on_redirect_destination():
    """
    Public URL redirects to a domain that resolves to a private IP (10.0.0.5).
    Behaviour Agent must validate the redirect destination DNS and halt.
    """
    mock_session = MagicMock(spec=requests.Session)
    public_url = "https://public-cdn.example/fetch"
    target_host = "internal-cache.example"
    target_url = f"http://{target_host}/data"

    mock_session.get.side_effect = [
        create_mock_response(302, public_url, target_url)
    ]

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == target_host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        if host == "public-cdn.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.26.10.1", 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        res = analyze_behaviour(url=public_url, session=mock_session, allow_private_ips=False)

        assert res["status"] == "blocked_private_address"
        assert len(res["redirect_chain"]) == 2
        assert res["redirect_chain"][1]["blocked"] is True
        # Session called only for public initial hop
        assert mock_session.get.call_count == 1


# ---------------------------------------------------------------------------
# 7. Intermediate Destination in Redirect Chain is Private
# ---------------------------------------------------------------------------

def test_intermediate_redirect_is_private():
    """
    Test a multi-hop redirect chain where an intermediate hop is private:
    Hop 1 (public 302) -> Hop 2 (private 192.168.1.1) -> Hop 3 (attacker target).
    The agent must halt immediately at Hop 2, blocking any connection to the private hop
    and never attempting Hop 3.
    """
    mock_session = MagicMock(spec=requests.Session)
    hop1_url = "https://public-start.example/go"
    hop2_url = "http://192.168.1.1/setup"

    mock_session.get.side_effect = [
        create_mock_response(302, hop1_url, hop2_url)
    ]

    res = analyze_behaviour(url=hop1_url, session=mock_session, allow_private_ips=False)

    assert res["status"] == "blocked_private_address"
    assert len(res["redirect_chain"]) == 2
    assert res["redirect_chain"][0]["url"] == hop1_url
    assert res["redirect_chain"][1]["url"] == hop2_url
    assert res["redirect_chain"][1]["blocked"] is True

    # Critical: mock_session.get must ONLY be called for Hop 1
    assert mock_session.get.call_count == 1


def test_three_hop_chain_with_intermediate_private_domain():
    """
    Hop 1 (public 302) -> Hop 2 (public 302) -> Hop 3 (internal DNS 10.0.0.2).
    Hops 1 and 2 succeed, but Hop 3 is detected as resolving to private IP and blocked.
    """
    mock_session = MagicMock(spec=requests.Session)
    hop1 = "https://short.example/1"
    hop2 = "https://intermediary.example/2"
    hop3_host = "secret-vault.example"
    hop3 = f"http://{hop3_host}/tokens"

    mock_session.get.side_effect = [
        create_mock_response(302, hop1, hop2),
        create_mock_response(302, hop2, hop3)
    ]

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == hop3_host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 0))]
        if host in ("short.example", "intermediary.example"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("151.101.1.69", 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        res = analyze_behaviour(url=hop1, session=mock_session, allow_private_ips=False)

        assert res["status"] == "blocked_private_address"
        assert len(res["redirect_chain"]) == 3
        assert res["redirect_chain"][0]["url"] == hop1
        assert res["redirect_chain"][1]["url"] == hop2
        assert res["redirect_chain"][2]["url"] == hop3
        assert res["redirect_chain"][2]["blocked"] is True

        # Exactly 2 calls made; 3rd hop was blocked before request
        assert mock_session.get.call_count == 2


# ---------------------------------------------------------------------------
# 8. Webpage Agent Route Interception & Integration Protection
# ---------------------------------------------------------------------------

def test_webpage_agent_blocks_subresource_to_private_ip():
    """
    Verify Playwright route interceptor in Webpage Analysis Agent blocks
    injected subresources (scripts, images) targeting private IPs.
    """
    html_with_private_subresource = """
    <html>
    <head>
        <script src="http://192.168.1.1:8080/exploit.js"></script>
    </head>
    <body>
        <h1>Benign Looking Page</h1>
        <img src="http://10.0.0.1/tracker.png" />
    </body>
    </html>
    """
    res = analyze_rendered_webpage(
        html=html_with_private_subresource,
        url="https://legit-portal.example/page",
        allow_private_ips=False
    )

    assert res["status"] == "completed"
    finding_types = [f["type"] for f in res["findings"]]
    assert "blocked_subresources" in finding_types

    subresource_finding = next(f for f in res["findings"] if f["type"] == "blocked_subresources")
    assert subresource_finding["count"] >= 1
    # Verify the private subresources were blocked
    blocked_items = subresource_finding["items"]
    assert any("192.168.1.1" in item or "10.0.0.1" in item for item in blocked_items)


def test_integrated_runner_blocks_resolved_private_destination():
    """
    Verify run_integrated_analysis from test_both_agents.py blocks browser
    navigation when destination resolves to private IP.
    """
    fake_host = "internal-victim.example"
    target_url = f"https://{fake_host}/login"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == fake_host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.50.1", 0))]
        raise socket.gaierror(11001, "getaddrinfo failed")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        res = run_integrated_analysis(target_url, allow_private_ips=False)

        assert res["webpage_analysis_original"]["status"] == "blocked_private_address"
        assert res["behaviour_analysis"]["status"] == "blocked_private_address"

