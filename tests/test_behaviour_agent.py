"""
Unit tests for Behaviour Analysis Agent (src/behaviour_agent.py).
Tests redirect chains, cross-domain navigation, loops, hop limits, timeouts,
protocol downgrades, and SSRF private address protections using mocked HTTP responses.
No real external network requests are made.
"""

from unittest.mock import MagicMock
import pytest
import requests
from src.behaviour_agent import (
    analyze_behaviour,
    analyze_redirect_chain,
    is_private_or_local_host,
    get_registered_domain
)


def create_mock_response(status_code: int, url: str, location: str | None = None):
    """Helper to generate a mock HTTP response object."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Location": location} if location else {}
    return resp


def test_single_page_no_redirect():
    """Test standard single URL that returns 200 OK directly without redirects."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.return_value = create_mock_response(200, "https://example.com/home")

    result = analyze_behaviour(
        url="https://example.com/home",
        session=mock_session
    )

    assert result["agent"] == "Behaviour Analysis Agent"
    assert result["original_url"] == "https://example.com/home"
    assert result["final_url"] == "https://example.com/home"
    assert result["redirect_count"] == 0
    assert len(result["redirect_chain"]) == 1
    assert result["redirect_chain"][0]["status_code"] == 200
    assert result["redirect_chain"][0]["hostname"] == "example.com"
    assert result["unique_domains"] == ["example.com"]
    assert result["domain_changes_count"] == 0
    assert result["has_cross_domain_redirect"] is False
    assert result["has_protocol_downgrade"] is False
    assert result["status"] == "completed"
    assert "not proof of phishing" in result["note"]


def test_legitimate_redirect_chain():
    """
    Test standard canonical redirect (HTTP -> HTTPS -> login) on the same domain.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(301, "http://example.com", "https://example.com"),
        create_mock_response(302, "https://example.com", "https://example.com/login"),
        create_mock_response(200, "https://example.com/login")
    ]

    result = analyze_behaviour(
        url="http://example.com",
        session=mock_session
    )

    assert result["redirect_count"] == 2
    assert len(result["redirect_chain"]) == 3
    assert result["final_url"] == "https://example.com/login"
    assert result["unique_domains"] == ["example.com"]
    assert result["domain_changes_count"] == 0
    assert result["has_cross_domain_redirect"] is False
    assert result["status"] == "completed"


def test_cross_domain_redirect():
    """
    Test redirect from a shortener/affiliate domain to another target domain.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://short.example/xyz", "https://target-portal.example/welcome"),
        create_mock_response(200, "https://target-portal.example/welcome")
    ]

    result = analyze_behaviour(
        url="https://short.example/xyz",
        session=mock_session
    )

    assert result["redirect_count"] == 1
    assert result["has_cross_domain_redirect"] is True
    assert result["domain_changes_count"] == 1
    assert result["unique_domains"] == ["short.example", "target-portal.example"]
    assert result["domain_changes"][0]["from"] == "short.example"
    assert result["domain_changes"][0]["to"] == "target-portal.example"

    finding_types = [f["type"] for f in result["findings"]]
    assert "cross_domain_redirects" in finding_types


def test_redirect_loop_detection():
    """
    Test circular redirect loop (URL A -> URL B -> URL A) terminates safely.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://loop.example/step1", "https://loop.example/step2"),
        create_mock_response(302, "https://loop.example/step2", "https://loop.example/step1"),
    ]

    result = analyze_behaviour(
        url="https://loop.example/step1",
        session=mock_session,
        max_redirects=10
    )

    assert result["status"] == "redirect_loop"
    finding_types = [f["type"] for f in result["findings"]]
    assert "redirect_loop" in finding_types


def test_max_redirects_exceeded():
    """
    Test exceeding the maximum allowed redirect hops threshold.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, f"https://chain.example/hop{i}", f"https://chain.example/hop{i+1}")
        for i in range(10)
    ]

    result = analyze_behaviour(
        url="https://chain.example/hop0",
        session=mock_session,
        max_redirects=3
    )

    assert result["status"] == "max_redirects_exceeded"
    assert len(result["redirect_chain"]) == 3
    finding_types = [f["type"] for f in result["findings"]]
    assert "max_redirects_exceeded" in finding_types


def test_unusually_long_chain():
    """
    Test that a chain with 3 or more redirects generates the unusually_long_chain finding.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://chain.example/hop1", "https://chain.example/hop2"),
        create_mock_response(302, "https://chain.example/hop2", "https://chain.example/hop3"),
        create_mock_response(302, "https://chain.example/hop3", "https://chain.example/hop4"),
        create_mock_response(200, "https://chain.example/hop4"),
    ]

    result = analyze_behaviour(
        url="https://chain.example/hop1",
        session=mock_session,
        max_redirects=5
    )

    assert result["status"] == "completed"
    assert result["redirect_count"] == 3
    finding_types = [f["type"] for f in result["findings"]]
    assert "unusually_long_chain" in finding_types


def test_protocol_downgrade():
    """
    Test detection of navigation downgrading from secure HTTPS to unencrypted HTTP.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://secure.example/auth", "http://insecure.example/auth"),
        create_mock_response(200, "http://insecure.example/auth")
    ]

    result = analyze_behaviour(
        url="https://secure.example/auth",
        session=mock_session
    )

    assert result["has_protocol_downgrade"] is True
    finding_types = [f["type"] for f in result["findings"]]
    assert "protocol_downgrade" in finding_types


def test_ssrf_blocked_private_initial_url():
    """
    Test that private, localhost, or internal network addresses are blocked
    before making any HTTP request.
    """
    mock_session = MagicMock(spec=requests.Session)

    private_urls = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:5000/api",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/router",
        "http://192.168.1.50/dashboard",
        "http://[::1]:8080/",
        "http://internal.service.local/status",
        "http://backend.internal/info"
    ]

    for p_url in private_urls:
        result = analyze_behaviour(url=p_url, session=mock_session)
        assert result["status"] == "blocked_private_address"
        finding_types = [f["type"] for f in result["findings"]]
        assert "blocked_private_address" in finding_types
        # Verify session.get was never called for private address
        mock_session.get.assert_not_called()


def test_ssrf_blocked_redirect_to_private_address():
    """
    Test that an external URL redirecting into a private IP address is stopped at the hop.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://public-gateway.example/go", "http://192.168.1.1/admin")
    ]

    result = analyze_behaviour(
        url="https://public-gateway.example/go",
        session=mock_session
    )

    assert result["status"] == "blocked_private_address"
    assert len(result["redirect_chain"]) == 2
    assert result["redirect_chain"][0]["url"] == "https://public-gateway.example/go"
    assert result["redirect_chain"][1]["blocked"] is True
    assert result["redirect_chain"][1]["hostname"] == "192.168.1.1"

    # mock_session.get should only have been called ONCE (for the public gateway)
    assert mock_session.get.call_count == 1


def test_request_timeout():
    """Test handling of request timeouts gracefully."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = requests.Timeout("Connection timed out after 5.0s")

    result = analyze_behaviour(
        url="https://slow-site.example/page",
        session=mock_session,
        timeout=5.0
    )

    assert result["status"] == "timeout"
    finding_types = [f["type"] for f in result["findings"]]
    assert "request_timeout" in finding_types


def test_connection_error():
    """Test handling of connection errors gracefully."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = requests.ConnectionError("Failed to resolve host")

    result = analyze_behaviour(
        url="https://down-host.example/page",
        session=mock_session
    )

    assert result["status"] == "connection_error"
    finding_types = [f["type"] for f in result["findings"]]
    assert "connection_error" in finding_types


def test_terminal_http_error():
    """Test terminal 4xx / 5xx HTTP error statuses."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.return_value = create_mock_response(404, "https://example.com/notfound")

    result = analyze_behaviour(
        url="https://example.com/notfound",
        session=mock_session
    )

    finding_types = [f["type"] for f in result["findings"]]
    assert "http_error_response" in finding_types


def test_raw_public_ip_final_destination():
    """Test identification of raw IP addresses as final destinations."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://link.example/target", "http://198.51.100.25/login"),
        create_mock_response(200, "http://198.51.100.25/login")
    ]

    result = analyze_behaviour(
        url="https://link.example/target",
        session=mock_session
    )

    finding_types = [f["type"] for f in result["findings"]]
    assert "ip_hostname_destination" in finding_types


def test_invalid_urls_and_schemes():
    """Test unsupported schemes (file://, ftp://) and invalid/empty inputs."""
    # Empty URL
    res_empty = analyze_behaviour("")
    assert res_empty["status"] == "invalid_url"

    # None URL
    res_none = analyze_behaviour(None)
    assert res_none["status"] == "invalid_url"

    # Unsupported scheme file://
    res_file = analyze_behaviour("file:///etc/passwd")
    assert res_file["status"] == "invalid_scheme"

    # Unsupported scheme javascript:
    res_js = analyze_behaviour("javascript:alert(1)")
    assert res_js["status"] == "invalid_scheme"


def test_analyze_redirect_chain_offline():
    """Test offline analysis of pre-recorded redirect chains."""
    pre_recorded = [
        {"hop": 1, "url": "https://a.example/1", "status_code": 302, "hostname": "a.example"},
        {"hop": 2, "url": "https://b.example/2", "status_code": 302, "hostname": "b.example"},
        {"hop": 3, "url": "http://c.example/3", "status_code": 200, "hostname": "c.example"}
    ]

    result = analyze_redirect_chain("https://a.example/1", pre_recorded)

    assert result["redirect_count"] == 2
    assert result["has_cross_domain_redirect"] is True
    assert result["has_protocol_downgrade"] is True
    assert len(result["unique_domains"]) == 3


def test_google_to_www_google_not_cross_domain():
    """
    Test redirect from google.com to www.google.com.
    Must be treated as a hostname/subdomain change within the same registered domain,
    NOT as a cross-domain redirect (has_cross_domain_redirect must be False).
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(301, "https://google.com", "https://www.google.com/"),
        create_mock_response(200, "https://www.google.com/")
    ]

    result = analyze_behaviour(
        url="https://google.com",
        session=mock_session
    )

    assert result["redirect_count"] == 1
    # Distinguish hostname from registered domain
    assert result["has_cross_domain_redirect"] is False
    assert result["domain_changes_count"] == 0
    assert result["domain_changes"] == []
    assert result["unique_domains"] == ["google.com"]

    # Hostname change is tracked
    assert result["has_hostname_change"] is True
    assert result["hostname_changes_count"] == 1
    assert result["unique_hostnames"] == ["google.com", "www.google.com"]
    assert result["hostname_changes"][0]["from"] == "google.com"
    assert result["hostname_changes"][0]["to"] == "www.google.com"
    assert result["hostname_changes"][0]["same_registered_domain"] is True

    # Findings should NOT contain cross_domain_redirects
    finding_types = [f["type"] for f in result["findings"]]
    assert "cross_domain_redirects" not in finding_types
    assert "subdomain_redirect" in finding_types


def test_example_to_another_site_cross_domain():
    """
    Test genuine registered-domain change: example.com -> another-site.com.
    Must set has_cross_domain_redirect to True.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://example.com", "https://another-site.com/landing"),
        create_mock_response(200, "https://another-site.com/landing")
    ]

    result = analyze_behaviour(
        url="https://example.com",
        session=mock_session
    )

    assert result["redirect_count"] == 1
    assert result["has_cross_domain_redirect"] is True
    assert result["domain_changes_count"] == 1
    assert result["domain_changes"][0]["from"] == "example.com"
    assert result["domain_changes"][0]["to"] == "another-site.com"
    assert result["unique_domains"] == ["example.com", "another-site.com"]
    assert result["has_hostname_change"] is True

    finding_types = [f["type"] for f in result["findings"]]
    assert "cross_domain_redirects" in finding_types


def test_example_to_same_domain_path():
    """
    Test internal path redirect on the same domain and hostname:
    example.com -> example.com/page.
    has_cross_domain_redirect and has_hostname_change must both be False.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(301, "https://example.com", "https://example.com/page"),
        create_mock_response(200, "https://example.com/page")
    ]

    result = analyze_behaviour(
        url="https://example.com",
        session=mock_session
    )

    assert result["redirect_count"] == 1
    assert result["has_cross_domain_redirect"] is False
    assert result["domain_changes_count"] == 0
    assert result["domain_changes"] == []
    assert result["has_hostname_change"] is False
    assert result["hostname_changes_count"] == 0
    assert result["hostname_changes"] == []
    assert result["unique_domains"] == ["example.com"]
    assert result["unique_hostnames"] == ["example.com"]

    finding_types = [f["type"] for f in result["findings"]]
    assert "cross_domain_redirects" not in finding_types
    assert "subdomain_redirect" not in finding_types


def test_https_to_http_protocol_downgrade_explicit():
    """
    Test HTTPS -> HTTP protocol downgrade detection.
    """
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = [
        create_mock_response(302, "https://example.com/secure", "http://example.com/insecure"),
        create_mock_response(200, "http://example.com/insecure")
    ]

    result = analyze_behaviour(
        url="https://example.com/secure",
        session=mock_session
    )

    assert result["has_protocol_downgrade"] is True
    assert result["redirect_count"] == 1
    assert result["has_cross_domain_redirect"] is False

    finding_types = [f["type"] for f in result["findings"]]
    assert "protocol_downgrade" in finding_types


def test_get_registered_domain_psl():
    """
    Verify get_registered_domain extracts correct eTLD+1 for hostnames,
    subdomains, multi-level TLDs, IP addresses, and reserved test domains.
    """
    assert get_registered_domain("google.com") == "google.com"
    assert get_registered_domain("www.google.com") == "google.com"
    assert get_registered_domain("mail.google.com") == "google.com"
    assert get_registered_domain("another-site.com") == "another-site.com"
    assert get_registered_domain("sub.example.co.uk") == "example.co.uk"
    assert get_registered_domain("short.example") == "short.example"
    assert get_registered_domain("127.0.0.1") == "127.0.0.1"
    assert get_registered_domain("localhost") == "localhost"
    assert get_registered_domain("") == ""

