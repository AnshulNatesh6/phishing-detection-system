"""
Tests for api.py.
Tests /scan, /analyze-webpage, and / endpoints, including valid and invalid requests.
"""

from unittest.mock import patch
import pytest
from src.api import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test health check route."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}


def test_analyze_webpage_valid(client):
    """Test POST /analyze-webpage with valid HTML and URL."""
    payload = {
        "html": """
        <html>
            <body>
                <form action="https://phish.example/login" method="post">
                    <input type="password" name="pwd">
                </form>
            </body>
        </html>
        """,
        "url": "https://bank.example/home"
    }
    response = client.post("/analyze-webpage", json=payload)
    assert response.status_code == 200
    data = response.get_json()

    assert data["agent"] == "Webpage Analysis Agent"
    assert data["page_url"] == "https://bank.example/home"
    assert data["forms_count"] == 1
    assert data["password_fields_count"] == 1
    assert len(data["suspicious_form_actions"]) == 1
    assert data["suspicious_form_actions"][0]["destination"] == "https://phish.example/login"
    assert "findings" in data
    assert "note" in data


def test_analyze_webpage_page_url_alias(client):
    """Test POST /analyze-webpage accepting 'page_url' instead of 'url'."""
    payload = {
        "html": "<p>Content</p>",
        "page_url": "https://example.com"
    }
    response = client.post("/analyze-webpage", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["page_url"] == "https://example.com"


def test_analyze_webpage_without_url(client):
    """Test POST /analyze-webpage when URL is not provided."""
    payload = {
        "html": "<p>Content without URL</p>"
    }
    response = client.post("/analyze-webpage", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["page_url"] == ""


@patch("requests.get")
def test_analyze_webpage_does_not_fetch_network(mock_get, client):
    """
    Verify that /analyze-webpage processes supplied HTML directly
    and NEVER attempts to make a network request to the URL.
    """
    payload = {
        "html": "<html><body><a href='https://other.example'>Link</a></body></html>",
        "url": "https://do-not-fetch.example/page"
    }
    response = client.post("/analyze-webpage", json=payload)
    assert response.status_code == 200
    mock_get.assert_not_called()


def test_analyze_webpage_invalid_non_json(client):
    """Test POST /analyze-webpage with non-JSON payload returns 400."""
    response = client.post(
        "/analyze-webpage",
        data="plain text not json",
        content_type="text/plain"
    )
    assert response.status_code == 400
    assert "JSON required" in response.get_json().get("error", "")


def test_analyze_webpage_missing_html(client):
    """Test POST /analyze-webpage missing 'html' field returns 400."""
    response = client.post("/analyze-webpage", json={"url": "https://example.com"})
    assert response.status_code == 400
    assert "'html' field is required" in response.get_json().get("error", "")


def test_analyze_webpage_invalid_html_type(client):
    """Test POST /analyze-webpage with non-string 'html' returns 400."""
    response = client.post("/analyze-webpage", json={"html": 12345})
    assert response.status_code == 400
    assert "'html' must be a string" in response.get_json().get("error", "")


def test_analyze_webpage_invalid_url_type(client):
    """Test POST /analyze-webpage with non-string 'url' returns 400."""
    response = client.post("/analyze-webpage", json={"html": "<p>hi</p>", "url": 999})
    assert response.status_code == 400
    assert "'url' must be a string" in response.get_json().get("error", "")


@patch("src.api.predict")
def test_scan_valid(mock_predict, client):
    """Test existing POST /scan endpoint with a valid URL."""
    mock_predict.return_value = (0.12, "legit", "Contains HTTPS, no suspicious patterns")

    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["url"] == "https://example.com"
    assert data["score"] == 0.12
    assert data["label"] == "legit"
    assert "Contains HTTPS" in data["explanation"]


def test_scan_invalid_non_json(client):
    """Test POST /scan with non-JSON payload returns 400."""
    response = client.post("/scan", data="not json", content_type="text/plain")
    assert response.status_code == 400
    assert "JSON required" in response.get_json().get("error", "")


def test_scan_missing_url(client):
    """Test POST /scan without 'url' returns 400."""
    response = client.post("/scan", json={})
    assert response.status_code == 400
    assert "Valid 'url' required" in response.get_json().get("error", "")


def test_scan_invalid_url_format(client):
    """Test POST /scan with malformed URL returns 400."""
    response = client.post("/scan", json={"url": "not-a-valid-url"})
    assert response.status_code == 400
    assert "Valid 'url' required" in response.get_json().get("error", "")


@patch("src.api.analyze_behaviour")
def test_analyze_behaviour_valid(mock_analyze, client):
    """Test POST /analyze-behaviour with valid URL."""
    mock_analyze.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://example.com",
        "final_url": "https://example.com",
        "redirect_count": 0,
        "redirect_chain": [],
        "findings": [],
        "status": "completed"
    }

    response = client.post("/analyze-behaviour", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["agent"] == "Behaviour Analysis Agent"
    assert data["status"] == "completed"


@patch("src.api.analyze_behaviour")
def test_analyze_behavior_alias(mock_analyze, client):
    """Test American spelling route POST /analyze-behavior."""
    mock_analyze.return_value = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://example.com",
        "status": "completed"
    }

    response = client.post("/analyze-behavior", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json()["status"] == "completed"


def test_analyze_behaviour_invalid_non_json(client):
    """Test POST /analyze-behaviour with non-JSON returns 400."""
    response = client.post("/analyze-behaviour", data="not json", content_type="text/plain")
    assert response.status_code == 400
    assert "JSON required" in response.get_json().get("error", "")


def test_analyze_behaviour_missing_url(client):
    """Test POST /analyze-behaviour missing url returns 400."""
    response = client.post("/analyze-behaviour", json={})
    assert response.status_code == 400
    assert "Valid 'url' string required" in response.get_json().get("error", "")


def test_analyze_behaviour_invalid_url_type(client):
    """Test POST /analyze-behaviour non-string url returns 400."""
    response = client.post("/analyze-behaviour", json={"url": 12345})
    assert response.status_code == 400
    assert "Valid 'url' string required" in response.get_json().get("error", "")


def test_analyze_behaviour_ssrf_blocked(client):
    """Test that private addresses sent to /analyze-behaviour are blocked securely."""
    response = client.post("/analyze-behaviour", json={"url": "http://127.0.0.1:8080/admin"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "blocked_private_address"
    assert any(f["type"] == "blocked_private_address" for f in data["findings"])


def test_correlate_valid(client):
    """Test POST /correlate with valid structured agent inputs."""
    payload = {
        "url": "https://example.com/login",
        "url_analysis": {"label": "legit", "score": 0.10},
        "webpage_analysis": {"forms_count": 0, "password_fields_count": 0},
        "behaviour_analysis": {"redirect_count": 0, "status": "completed"}
    }
    response = client.post("/correlate", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["agent"] == "Evidence Correlation Agent"
    assert data["overall_risk"] == "low"
    assert "reasons" in data
    assert "supporting_indicators" in data
    assert "conflicting_indicators" in data


def test_correlate_invalid_non_json(client):
    """Test POST /correlate with non-JSON payload returns 400."""
    response = client.post("/correlate", data="not-json", content_type="text/plain")
    assert response.status_code == 400
    assert "JSON required" in response.get_json().get("error", "")


@patch("src.api.investigate_url")
def test_investigate_valid(mock_investigate, client):
    """Test POST /investigate pipeline endpoint."""
    mock_investigate.return_value = {
        "agent": "Evidence Correlation Agent",
        "target_url": "https://example.com",
        "overall_risk": "low",
        "risk_score": 0.05
    }
    response = client.post("/investigate", json={"url": "https://example.com", "html": "<p>hi</p>"})
    assert response.status_code == 200
    assert response.get_json()["overall_risk"] == "low"


def test_investigate_missing_url(client):
    """Test POST /investigate with missing url returns 400."""
    response = client.post("/investigate", json={"html": "<p>hi</p>"})
    assert response.status_code == 400
    assert "Valid 'url' string required" in response.get_json().get("error", "")


@patch("src.api.analyze_rendered_webpage")
def test_analyze_rendered_webpage_valid(mock_analyze_rendered, client):
    """Test POST /analyze-rendered-webpage with valid payload."""
    mock_analyze_rendered.return_value = {
        "agent": "Webpage Analysis Agent",
        "rendering": "playwright",
        "status": "completed",
        "forms_count": 1,
        "password_fields_count": 1,
        "findings": []
    }
    payload = {
        "url": "https://example.com/login",
        "html": "<form><input type='password'></form>",
        "timeout": 10.0
    }
    response = client.post("/analyze-rendered-webpage", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["rendering"] == "playwright"
    assert data["status"] == "completed"
    assert data["forms_count"] == 1


@patch("src.api.analyze_rendered_webpage")
def test_analyze_webpage_playwright_alias(mock_analyze_rendered, client):
    """Test alias route POST /analyze-webpage-playwright."""
    mock_analyze_rendered.return_value = {
        "agent": "Webpage Analysis Agent",
        "rendering": "playwright",
        "status": "completed"
    }
    response = client.post("/analyze-webpage-playwright", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.get_json()["rendering"] == "playwright"


def test_analyze_rendered_webpage_invalid_non_json(client):
    """Test POST /analyze-rendered-webpage with non-JSON returns 400."""
    response = client.post("/analyze-rendered-webpage", data="raw string", content_type="text/plain")
    assert response.status_code == 400
    assert "JSON required" in response.get_json().get("error", "")


def test_analyze_rendered_webpage_missing_url_and_html(client):
    """Test POST /analyze-rendered-webpage missing both url and html returns 400."""
    response = client.post("/analyze-rendered-webpage", json={"timeout": 5.0})
    assert response.status_code == 400
    assert "Either 'url' or 'html' is required" in response.get_json().get("error", "")


def test_analyze_rendered_webpage_invalid_url_type(client):
    """Test POST /analyze-rendered-webpage with invalid url type returns 400."""
    response = client.post("/analyze-rendered-webpage", json={"url": 12345})
    assert response.status_code == 400
    assert "'url' must be a string" in response.get_json().get("error", "")


def test_analyze_rendered_webpage_ssrf_blocked(client):
    """Test POST /analyze-rendered-webpage blocks localhost."""
    response = client.post("/analyze-rendered-webpage", json={"url": "http://127.0.0.1:8080/admin"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "blocked_private_address"
    assert any(f["type"] == "blocked_private_address" for f in data["findings"])


@patch("src.api.investigate_url")
def test_investigate_with_use_playwright(mock_investigate, client):
    """Test POST /investigate with use_playwright flag."""
    mock_investigate.return_value = {
        "agent": "Evidence Correlation Agent",
        "target_url": "https://example.com",
        "overall_risk": "low"
    }
    response = client.post("/investigate", json={
        "url": "https://example.com",
        "use_playwright": True
    })
    assert response.status_code == 200
    mock_investigate.assert_called_once()
    assert mock_investigate.call_args[1]["use_playwright"] is True