"""
Unit tests for Evidence Correlation Agent (src/correlation_agent.py).
Tests low-risk, medium-risk, high-risk, conflicting-evidence, incomplete-input,
deduplication, and custom scoring rules using synthetic fixtures.
"""

from unittest.mock import MagicMock, patch
import pytest
import requests

from src.correlation_agent import (
    correlate_evidence,
    investigate_url,
    DEFAULT_WEIGHTS,
    DEFAULT_THRESHOLDS
)


def test_low_risk_benign_case():
    """
    Test benign case where all three agents report clean, normal operations.
    Should result in overall_risk='low' with high confidence.
    """
    url_res = {
        "url": "https://example.com/portal",
        "score": 0.05,
        "label": "legit",
        "explanation": "Valid HTTPS and clean domain structure."
    }
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://example.com/portal",
        "forms_count": 1,
        "password_fields_count": 0,
        "hidden_fields_count": 0,
        "iframes_count": 0,
        "external_scripts_count": 0,
        "external_links_count": 0,
        "suspicious_form_actions": [],
        "missing_form_actions": [],
        "credential_forms": [],
        "findings": []
    }
    beh_res = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://example.com/portal",
        "final_url": "https://example.com/portal",
        "redirect_count": 0,
        "redirect_chain": [{"hop": 1, "url": "https://example.com/portal", "status_code": 200}],
        "unique_domains": ["example.com"],
        "domain_changes_count": 0,
        "has_cross_domain_redirect": False,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    report = correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=beh_res
    )

    assert report["agent"] == "Evidence Correlation Agent"
    assert report["overall_risk"] == "low"
    assert report["risk_score"] < 0.30
    assert report["confidence"] == "high"
    assert len(report["supporting_indicators"]) == 0
    assert len(report["conflicting_indicators"]) == 0
    assert len(report["missing_data"]) == 0
    assert "not certified proof of phishing" in report["note"]


def test_medium_risk_case():
    """
    Test scenario with mild indicators (e.g. cross-domain redirect and external scripts).
    Should evaluate to overall_risk='medium'.
    """
    url_res = {
        "url": "https://track.example/link",
        "score": 0.35,
        "label": "legit",
        "explanation": "Moderate URL length."
    }
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://track.example/link",
        "forms_count": 1,
        "password_fields_count": 0,
        "hidden_fields_count": 0,
        "iframes_count": 1,
        "external_scripts_count": 2,
        "external_links_count": 1,
        "suspicious_form_actions": [
            {"destination": "https://partner.example/submit", "method": "post"}
        ],
        "missing_form_actions": [],
        "credential_forms": [],
        "findings": []
    }
    beh_res = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://track.example/link",
        "final_url": "https://partner.example/landing",
        "redirect_count": 1,
        "redirect_chain": [
            {"hop": 1, "url": "https://track.example/link", "status_code": 302},
            {"hop": 2, "url": "https://partner.example/landing", "status_code": 200}
        ],
        "unique_domains": ["track.example", "partner.example"],
        "domain_changes_count": 1,
        "has_cross_domain_redirect": True,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    report = correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=beh_res
    )

    assert report["overall_risk"] == "medium"
    assert 0.30 <= report["risk_score"] < 0.60
    assert report["confidence"] == "high"


def test_high_risk_case():
    """
    Test attack scenario with multiple severe corroborating indicators:
    - ML model predicts phishing with high confidence
    - Password form submits to external destination
    - Navigation downgraded to HTTP
    """
    url_res = {
        "url": "https://secure-login.suspicious.example/auth",
        "score": 0.88,
        "label": "phishing",
        "explanation": "Contains suspicious symbols and high dot count."
    }
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://secure-login.suspicious.example/auth",
        "forms_count": 1,
        "password_fields_count": 1,
        "hidden_fields_count": 1,
        "iframes_count": 0,
        "external_scripts_count": 1,
        "external_links_count": 0,
        "suspicious_form_actions": [
            {"destination": "https://data-collector.attacker.example/post", "method": "post"}
        ],
        "missing_form_actions": [],
        "credential_forms": [
            {
                "action": "https://data-collector.attacker.example/post",
                "destination": "https://data-collector.attacker.example/post",
                "method": "post",
                "password_fields_count": 1,
                "is_external": True,
                "is_missing_action": False
            }
        ],
        "findings": []
    }
    beh_res = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://secure-login.suspicious.example/auth",
        "final_url": "http://data-collector.attacker.example/post",
        "redirect_count": 1,
        "redirect_chain": [
            {"hop": 1, "url": "https://secure-login.suspicious.example/auth", "status_code": 302},
            {"hop": 2, "url": "http://data-collector.attacker.example/post", "status_code": 200}
        ],
        "unique_domains": ["secure-login.suspicious.example", "data-collector.attacker.example"],
        "domain_changes_count": 1,
        "has_cross_domain_redirect": True,
        "has_protocol_downgrade": True,
        "status": "completed",
        "findings": [
            {"type": "protocol_downgrade", "detail": "Downgraded to http"}
        ]
    }

    report = correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=beh_res
    )

    assert report["overall_risk"] == "high"
    assert report["risk_score"] >= 0.60
    assert report["confidence"] == "high"
    # Verify supporting indicators detected
    assert len(report["supporting_indicators"]) >= 2
    # Reasons should list the critical findings
    assert any("credential" in r.lower() for r in report["reasons"])


def test_conflicting_evidence_ml_vs_benign_page():
    """
    Test conflicting evidence: ML model flags phishing based on URL,
    but the webpage is completely static with 0 forms and 0 passwords.
    """
    url_res = {
        "url": "https://oddly-named-page.example/login-info",
        "score": 0.82,
        "label": "phishing",
        "explanation": "High score based on URL length and keywords."
    }
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://oddly-named-page.example/login-info",
        "forms_count": 0,
        "password_fields_count": 0,
        "hidden_fields_count": 0,
        "iframes_count": 0,
        "external_scripts_count": 0,
        "external_links_count": 0,
        "suspicious_form_actions": [],
        "missing_form_actions": [],
        "credential_forms": [],
        "findings": []
    }
    beh_res = {
        "agent": "Behaviour Analysis Agent",
        "original_url": "https://oddly-named-page.example/login-info",
        "final_url": "https://oddly-named-page.example/login-info",
        "redirect_count": 0,
        "redirect_chain": [{"hop": 1, "url": "https://oddly-named-page.example/login-info", "status_code": 200}],
        "unique_domains": ["oddly-named-page.example"],
        "domain_changes_count": 0,
        "has_cross_domain_redirect": False,
        "has_protocol_downgrade": False,
        "status": "completed",
        "findings": []
    }

    report = correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=beh_res
    )

    # Conflicting indicators should catch this mismatch
    assert len(report["conflicting_indicators"]) >= 1
    assert any("zero forms" in c for c in report["conflicting_indicators"])


def test_conflicting_evidence_legit_url_vs_credential_phish():
    """
    Test conflicting evidence: URL model says 'legit' (0.05), but webpage contains
    an external credential collection form.
    """
    url_res = {
        "url": "https://clean-domain.example/account",
        "score": 0.05,
        "label": "legit",
        "explanation": "Short URL with HTTPS."
    }
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://clean-domain.example/account",
        "forms_count": 1,
        "password_fields_count": 1,
        "hidden_fields_count": 0,
        "iframes_count": 0,
        "external_scripts_count": 0,
        "external_links_count": 0,
        "suspicious_form_actions": [
            {"destination": "https://evil-harvest.example/steal", "method": "post"}
        ],
        "missing_form_actions": [],
        "credential_forms": [
            {
                "action": "https://evil-harvest.example/steal",
                "destination": "https://evil-harvest.example/steal",
                "method": "post",
                "password_fields_count": 1,
                "is_external": True,
                "is_missing_action": False
            }
        ],
        "findings": []
    }

    report = correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=None
    )

    # Must flag the contradiction between legit URL score and external credential form
    assert len(report["conflicting_indicators"]) >= 1
    assert any("external hostname" in c for c in report["conflicting_indicators"])


def test_incomplete_input_only_url():
    """
    Test graceful degradation when only URL Analysis is available.
    """
    url_res = {
        "url": "https://example.com",
        "score": 0.10,
        "label": "legit",
        "explanation": "Clean URL."
    }

    report = correlate_evidence(url_result=url_res)

    assert report["overall_risk"] == "low"
    assert report["confidence"] == "low"
    assert len(report["missing_data"]) == 2
    assert any("Webpage Analysis" in m for m in report["missing_data"])
    assert any("Behaviour Analysis" in m for m in report["missing_data"])


def test_incomplete_input_all_none():
    """
    Test completely missing input data returns unknown risk without crashing.
    """
    report = correlate_evidence(None, None, None)

    assert report["overall_risk"] == "unknown"
    assert report["risk_score"] == 0.0
    assert report["confidence"] == "none"
    assert len(report["missing_data"]) == 3
    assert len(report["deduplicated_evidence"]) == 0


def test_deduplication_of_overlapping_indicators():
    """
    Verify that multiple representations of the same underlying event
    (e.g., external credential form + generic suspicious form action)
    are deduplicated and not counted twice.
    """
    web_res = {
        "agent": "Webpage Analysis Agent",
        "page_url": "https://demo.example/login",
        "forms_count": 1,
        "password_fields_count": 1,
        "hidden_fields_count": 0,
        "iframes_count": 0,
        "external_scripts_count": 0,
        "external_links_count": 0,
        "suspicious_form_actions": [
            {"destination": "https://other.example/post", "method": "post"}
        ],
        "missing_form_actions": [],
        "credential_forms": [
            {
                "action": "https://other.example/post",
                "destination": "https://other.example/post",
                "method": "post",
                "password_fields_count": 1,
                "is_external": True,
                "is_missing_action": False
            }
        ],
        "findings": []
    }

    report = correlate_evidence(webpage_result=web_res)

    indicators = [e["indicator"] for e in report["deduplicated_evidence"]]
    # Should contain credential_external_destination
    assert "credential_external_destination" in indicators
    # Should NOT also add duplicate suspicious_form_action for the same form
    assert "suspicious_form_action" not in indicators


def test_distinguish_observation_from_inference():
    """
    Verify that every evidence item clearly separates observed facts
    from analytical inferences.
    """
    url_res = {
        "url": "https://phish.example",
        "score": 0.85,
        "label": "phishing",
        "explanation": "Model flagged"
    }
    web_res = {
        "credential_forms": [{"is_external": True}],
        "iframes_count": 1
    }

    report = correlate_evidence(url_result=url_res, webpage_result=web_res)

    for item in report["deduplicated_evidence"]:
        assert "observation" in item and len(item["observation"]) > 0
        assert "inference" in item and len(item["inference"]) > 0
        assert "source_agent" in item


def test_custom_scoring_weights_and_thresholds():
    """
    Verify that scoring weights and risk thresholds can be configured.
    """
    custom_weights = {
        "credential_external_destination": 0.85
    }
    custom_thresholds = {
        "high": 0.80,
        "medium": 0.40,
        "low": 0.0
    }

    web_res = {
        "credential_forms": [{"is_external": True}]
    }

    report = correlate_evidence(
        webpage_result=web_res,
        weights=custom_weights,
        thresholds=custom_thresholds
    )

    assert report["risk_score"] == 0.85
    assert report["overall_risk"] == "high"


@patch("src.correlation_agent.predict")
def test_investigate_url_pipeline_mocked(mock_predict):
    """
    Test convenience end-to-end investigate_url coordinator with mock sessions.
    """
    mock_predict.return_value = (0.15, "legit", "Safe URL")

    html = "<html><body><form action='/login'><input type='password'></form></body></html>"

    mock_session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.url = "https://safe.example/home"
    mock_resp.headers = {}
    mock_session.get.return_value = mock_resp

    report = investigate_url(
        url="https://safe.example/home",
        html=html,
        include_behaviour=True,
        behaviour_session=mock_session
    )

    assert report["agent"] == "Evidence Correlation Agent"
    assert report["target_url"] == "https://safe.example/home"
    assert report["overall_risk"] == "low"
    assert report["confidence"] == "high"
    assert report["agent_results"]["url_analysis"]["label"] == "legit"
    assert report["agent_results"]["webpage_analysis"]["forms_count"] == 1
    assert report["agent_results"]["behaviour_analysis"]["redirect_count"] == 0
