"""
Unit and integration tests for the Behaviour Analysis Agent and Webpage Analysis Agent
integration workflow (test_both_agents.py).

Tests:
1. URL normalization and scheme validation.
2. SSRF validation blocking localhost and private IP addresses prior to navigation.
3. Execution order: Behaviour Agent runs first, followed by Webpage Agent.
4. Single webpage analysis when no redirects occur.
5. Dual webpage analysis (original & final destination) when redirects occur.
6. SSRF prevention when redirect destination targets private network address.
7. Resilience against connection errors, timeouts, and browser exceptions.
"""

from unittest.mock import MagicMock, patch
import pytest

from test_both_agents import (
    normalize_and_validate_url,
    is_safe_destination_url,
    run_integrated_analysis,
    test_url as run_test_url
)


def test_normalize_and_validate_url():
    """Verify URL normalization, scheme prepending, and validation."""
    # Prepending https://
    url, err = normalize_and_validate_url("example.com")
    assert err is None
    assert url == "https://example.com"

    url, err = normalize_and_validate_url("sub.example.com/path?q=1")
    assert err is None
    assert url == "https://sub.example.com/path?q=1"

    # Preserving existing http/https
    url, err = normalize_and_validate_url("http://insecure.example.com")
    assert err is None
    assert url == "http://insecure.example.com"

    # Rejecting empty or whitespace
    url, err = normalize_and_validate_url("")
    assert url is None
    assert "empty" in err.lower()

    url, err = normalize_and_validate_url("   ")
    assert url is None
    assert "empty" in err.lower()

    # Rejecting unsupported schemes
    url, err = normalize_and_validate_url("ftp://files.example.com")
    assert url is None
    assert "unsupported scheme" in err.lower()

    url, err = normalize_and_validate_url("javascript:alert(1)")
    assert url is None
    assert "unsupported scheme" in err.lower()


def test_ssrf_destination_validation():
    """Verify SSRF validation blocks localhost, loopback, and private IPs."""
    # Blocked private and loopback destinations
    assert is_safe_destination_url("http://127.0.0.1")[0] is False
    assert is_safe_destination_url("http://localhost")[0] is False
    assert is_safe_destination_url("http://localhost:8080/admin")[0] is False
    assert is_safe_destination_url("http://192.168.1.1/router")[0] is False
    assert is_safe_destination_url("http://10.0.0.5/secret")[0] is False
    assert is_safe_destination_url("http://172.16.0.1")[0] is False
    assert is_safe_destination_url("http://[::1]")[0] is False

    # Allowed public destinations
    assert is_safe_destination_url("https://example.com")[0] is True
    assert is_safe_destination_url("https://www.google.com")[0] is True
    assert is_safe_destination_url("https://bit.ly")[0] is True


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_integrated_no_redirect(mock_behaviour, mock_webpage):
    """
    When no redirect occurs, Webpage Agent runs only on the original URL.
    Final destination webpage analysis should be None.
    """
    mock_behaviour.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://example.com/portal",
        "final_url": "https://example.com/portal",
        "redirect_count": 0,
        "redirect_chain": [],
        "domain_changes_count": 0,
        "hostname_changes_count": 0,
        "has_cross_domain_redirect": False,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    mock_webpage.return_value = {
        "agent": "Webpage Analysis Agent",
        "rendering": "playwright",
        "page_url": "https://example.com/portal",
        "final_url": "https://example.com/portal",
        "status": "completed",
        "forms_count": 1,
        "findings": []
    }

    res = run_integrated_analysis("https://example.com/portal")

    # Verify Behaviour agent ran first
    mock_behaviour.assert_called_once_with(
        url="https://example.com/portal",
        max_redirects=5,
        timeout=5.0,
        allow_private_ips=False
    )

    # Verify Webpage agent was called exactly once on original URL
    mock_webpage.assert_called_once_with(
        url="https://example.com/portal",
        timeout=15.0,
        allow_private_ips=False,
        browser=None
    )

    assert res["has_redirect"] is False
    assert res["redirect_count"] == 0
    assert res["original_url"] == "https://example.com/portal"
    assert res["final_url"] == "https://example.com/portal"
    assert res["webpage_analysis_original"] is not None
    assert res["webpage_analysis_final"] is None


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_integrated_with_redirect(mock_behaviour, mock_webpage):
    """
    When a redirect occurs to a different destination, Webpage Agent
    must be run on BOTH original URL and final destination.
    """
    mock_behaviour.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://bit.ly/testlink",
        "final_url": "https://target-service.example/login",
        "redirect_count": 1,
        "redirect_chain": [{
            "hop": 1,
            "url": "https://bit.ly/testlink",
            "status_code": 302,
            "redirect_to": "https://target-service.example/login"
        }],
        "domain_changes_count": 1,
        "hostname_changes_count": 1,
        "has_cross_domain_redirect": True,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    mock_webpage.side_effect = [
        # Call 1: Original URL
        {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": "https://bit.ly/testlink",
            "final_url": "https://bit.ly/testlink",
            "status": "completed",
            "forms_count": 0,
            "findings": []
        },
        # Call 2: Final destination
        {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": "https://target-service.example/login",
            "final_url": "https://target-service.example/login",
            "status": "completed",
            "forms_count": 1,
            "password_fields_count": 1,
            "findings": [{"type": "password_fields", "count": 1}]
        }
    ]

    res = run_integrated_analysis("https://bit.ly/testlink")

    assert res["has_redirect"] is True
    assert res["redirect_count"] == 1
    assert res["original_url"] == "https://bit.ly/testlink"
    assert res["final_url"] == "https://target-service.example/login"

    # Verify both calls to Webpage agent
    assert mock_webpage.call_count == 2
    mock_webpage.assert_any_call(
        url="https://bit.ly/testlink",
        timeout=15.0,
        allow_private_ips=False,
        browser=None
    )
    mock_webpage.assert_any_call(
        url="https://target-service.example/login",
        timeout=15.0,
        allow_private_ips=False,
        browser=None
    )

    assert res["webpage_analysis_original"]["page_url"] == "https://bit.ly/testlink"
    assert res["webpage_analysis_final"]["page_url"] == "https://target-service.example/login"
    assert res["webpage_analysis_final"]["password_fields_count"] == 1


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_integrated_ssrf_blocked_on_original(mock_behaviour, mock_webpage):
    """
    If the original target URL is a private address (e.g. localhost / 127.0.0.1),
    Webpage Agent must NOT navigate in browser; it returns blocked status.
    """
    mock_behaviour.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "http://127.0.0.1:8080/admin",
        "final_url": "http://127.0.0.1:8080/admin",
        "redirect_count": 0,
        "status": "blocked_private_address",
        "findings": [{"type": "blocked_private_address"}]
    }

    res = run_integrated_analysis("http://127.0.0.1:8080/admin", allow_private_ips=False)

    # Browser must NEVER be opened on private IP
    mock_webpage.assert_not_called()

    assert res["webpage_analysis_original"]["status"] == "blocked_private_address"
    assert res["webpage_analysis_final"] is None


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_integrated_ssrf_blocked_on_redirect(mock_behaviour, mock_webpage):
    """
    If an external URL redirects to an internal/private address,
    the Webpage Agent must NOT navigate to the internal address.
    """
    mock_behaviour.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://public-proxy.example/redir",
        "final_url": "http://192.168.1.1/secret",
        "redirect_count": 1,
        "redirect_chain": [{
            "hop": 1,
            "url": "https://public-proxy.example/redir",
            "status_code": 302,
            "redirect_to": "http://192.168.1.1/secret"
        }],
        "status": "blocked_private_address",
        "findings": [{"type": "blocked_private_address"}]
    }

    # Original URL is public, so it can be analyzed
    mock_webpage.return_value = {
        "agent": "Webpage Analysis Agent",
        "rendering": "playwright",
        "page_url": "https://public-proxy.example/redir",
        "final_url": "https://public-proxy.example/redir",
        "status": "completed",
        "findings": []
    }

    res = run_integrated_analysis("https://public-proxy.example/redir", allow_private_ips=False)

    assert res["has_redirect"] is True
    # Called on original public URL
    mock_webpage.assert_called_once_with(
        url="https://public-proxy.example/redir",
        timeout=15.0,
        allow_private_ips=False,
        browser=None
    )

    # Final destination was blocked before browser navigation
    assert res["webpage_analysis_final"]["status"] == "blocked_private_address"
    assert "private" in res["webpage_analysis_final"]["error_detail"].lower()


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_integrated_error_resilience(mock_behaviour, mock_webpage):
    """
    Verify that unexpected exceptions in agents are caught cleanly
    without crashing the integration runner.
    """
    mock_behaviour.side_effect = Exception("Fatal socket failure")
    mock_webpage.side_effect = Exception("Playwright crashed")

    res = run_integrated_analysis("https://problematic-site.example")

    assert res["behaviour_analysis"]["status"] == "error"
    assert "Fatal socket failure" in res["behaviour_analysis"]["error_detail"]

    assert res["webpage_analysis_original"]["status"] == "connection_error"
    assert "Playwright crashed" in res["webpage_analysis_original"]["error_detail"]


@patch("test_both_agents.analyze_rendered_webpage")
@patch("test_both_agents.analyze_behaviour")
def test_test_url_cli_helper(mock_behaviour, mock_webpage, capsys):
    """
    Verify test_url function prints formatted output including redirect summary
    and returns complete dictionary.
    """
    mock_behaviour.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://short.example/go",
        "final_url": "https://landing.example/page",
        "redirect_count": 1,
        "redirect_chain": [{
            "hop": 1,
            "url": "https://short.example/go",
            "status_code": 301,
            "redirect_to": "https://landing.example/page"
        }],
        "has_cross_domain_redirect": True,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    mock_webpage.return_value = {
        "agent": "Webpage Analysis Agent",
        "rendering": "playwright",
        "page_url": "https://landing.example/page",
        "final_url": "https://landing.example/page",
        "status": "completed",
        "forms_count": 0,
        "findings": []
    }

    results = run_test_url("https://short.example/go")
    captured = capsys.readouterr().out

    assert "Running Behaviour Analysis Agent first..." in captured
    assert "REDIRECT CHAIN & NAVIGATION SUMMARY" in captured
    assert "Original URL:      https://short.example/go" in captured
    assert "Final Destination: https://landing.example/page" in captured
    assert "BEHAVIOUR ANALYSIS RESULTS" in captured
    assert "WEBPAGE ANALYSIS RESULTS (ORIGINAL DESTINATION:" in captured
    assert "WEBPAGE ANALYSIS RESULTS (FINAL DESTINATION:" in captured
    assert "TEST COMPLETED" in captured
    assert results["redirect_count"] == 1
