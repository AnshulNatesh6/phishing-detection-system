"""
Evidence Correlation Agent module.
Combines findings from URL Analysis, Webpage Analysis, and Behaviour Analysis
into an explainable overall risk assessment.
Identifies supporting indicators, conflicting signals, and missing data streams.
Deduplicates overlapping indicators and distinguishes observed evidence from inferences.
Uses configurable, documented scoring heuristics for investigation triage.
"""

from typing import Any
import requests

from src.model import predict
from src.webpage_agent import analyze_webpage, analyze_rendered_webpage
from src.behaviour_agent import analyze_behaviour


# Documented, configurable heuristic scoring weights for investigation triage.
# Note: These weights are heuristic triage prioritization weights and are not claimed
# to be statistically or scientifically validated constants for all production environments.
DEFAULT_WEIGHTS = {
    # High-severity indicators
    "credential_external_destination": 0.45,  # Password form submitting to external domain
    "blocked_private_address": 0.40,          # Attempted SSRF or redirect to private IP
    "protocol_downgrade": 0.35,               # Navigation downgraded from HTTPS to HTTP

    # Medium-severity indicators
    "ml_phishing_label": 0.30,                # Random Forest URL model predicted phishing
    "credential_missing_action": 0.25,        # Password form with missing, empty, or javascript action
    "ip_hostname_destination": 0.25,          # Final navigation destination is a raw public IP
    "redirect_loop": 0.25,                    # Navigation trapped in circular redirect loop
    "unusually_long_chain": 0.20,             # Redirect chain has 3 or more hops
    "suspicious_form_action": 0.20,           # Non-password form submitting to external hostname

    # Corroborating / Low-severity indicators
    "ml_high_confidence": 0.15,               # ML model score exceeds 0.75
    "cross_domain_redirects": 0.15,           # Redirect chain traversed across multiple domains
    "external_iframes": 0.10,                 # Page embeds external iframes
    "external_scripts": 0.05,                 # Page loads external scripts
    "hidden_fields": 0.05                     # Hidden input fields present
}

# Configurable risk thresholds
DEFAULT_THRESHOLDS = {
    "high": 0.60,
    "medium": 0.30,
    "low": 0.0
}


def _extract_url_evidence(url_result: dict[str, Any] | None) -> tuple[list[dict], list[str]]:
    """Extract deduplicated evidence and missing data flags from URL Analysis."""
    evidence = []
    missing = []

    if not url_result or not isinstance(url_result, dict):
        missing.append("URL Analysis: No valid result provided")
        return evidence, missing

    if "error" in url_result:
        missing.append(f"URL Analysis error: {url_result['error']}")
        return evidence, missing

    label = url_result.get("label")
    score = url_result.get("score")

    if label == "phishing":
        evidence.append({
            "category": "url_reputation",
            "indicator": "ml_phishing_label",
            "source_agent": "URL Analysis Agent",
            "observation": f"Random Forest URL model classified target as phishing with score {score:.2f}.",
            "inference": "Lexical and structural URL features match known phishing patterns.",
            "weight_key": "ml_phishing_label",
            "severity": "medium"
        })
        if score is not None and score >= 0.75:
            evidence.append({
                "category": "url_reputation",
                "indicator": "ml_high_confidence",
                "source_agent": "URL Analysis Agent",
                "observation": f"Model probability score {score:.2f} exceeds high confidence threshold (0.75).",
                "inference": "Strong statistical resemblance to malicious training samples.",
                "weight_key": "ml_high_confidence",
                "severity": "low"
            })
    elif label == "legit":
        # Neutral / positive observation
        pass
    else:
        missing.append("URL Analysis: Score or label was omitted")

    return evidence, missing


def _extract_webpage_evidence(webpage_result: dict[str, Any] | None) -> tuple[list[dict], list[str]]:
    """Extract deduplicated evidence and missing data flags from Webpage Analysis."""
    evidence = []
    missing = []

    if not webpage_result or not isinstance(webpage_result, dict):
        missing.append("Webpage Analysis: No HTML analysis provided")
        return evidence, missing

    if "error" in webpage_result:
        missing.append(f"Webpage Analysis error: {webpage_result['error']}")
        return evidence, missing

    credential_forms = webpage_result.get("credential_forms", [])
    suspicious_actions = webpage_result.get("suspicious_form_actions", [])
    missing_actions = webpage_result.get("missing_form_actions", [])
    iframes_count = webpage_result.get("iframes_count", 0)
    scripts_count = webpage_result.get("external_scripts_count", 0)
    hidden_count = webpage_result.get("hidden_fields_count", 0)

    # 1. Deduplicated Credential Forms handling
    has_ext_credential_form = any(cf.get("is_external") for cf in credential_forms)
    has_missing_action_credential_form = any(cf.get("is_missing_action") for cf in credential_forms)

    if has_ext_credential_form:
        # Highest risk credential form signal
        evidence.append({
            "category": "credential_risk",
            "indicator": "credential_external_destination",
            "source_agent": "Webpage Analysis Agent",
            "observation": "Form containing password field submits credentials to a different external hostname.",
            "inference": "High risk of credential theft; credentials transmitted to third-party infrastructure.",
            "weight_key": "credential_external_destination",
            "severity": "high"
        })
    elif has_missing_action_credential_form:
        evidence.append({
            "category": "credential_risk",
            "indicator": "credential_missing_action",
            "source_agent": "Webpage Analysis Agent",
            "observation": "Form containing password field has missing, empty, or placeholder action destination.",
            "inference": "Form may rely on client-side script interception or incomplete phishing template.",
            "weight_key": "credential_missing_action",
            "severity": "medium"
        })

    # 2. Suspicious non-credential form actions (only if not already captured by external credential form)
    if suspicious_actions and not has_ext_credential_form:
        evidence.append({
            "category": "form_destination",
            "indicator": "suspicious_form_action",
            "source_agent": "Webpage Analysis Agent",
            "observation": f"{len(suspicious_actions)} form(s) submit to external hostname(s).",
            "inference": "Data submission targets external host, which may indicate data exfiltration.",
            "weight_key": "suspicious_form_action",
            "severity": "medium"
        })

    # 3. External iframes
    if iframes_count > 0:
        evidence.append({
            "category": "embedded_content",
            "indicator": "external_iframes",
            "source_agent": "Webpage Analysis Agent",
            "observation": f"Page contains {iframes_count} iframe element(s) loading external content.",
            "inference": "Iframes can be used to overlay deceptive content or mask true destinations.",
            "weight_key": "external_iframes",
            "severity": "low"
        })

    # 4. External scripts
    if scripts_count > 0:
        evidence.append({
            "category": "embedded_content",
            "indicator": "external_scripts",
            "source_agent": "Webpage Analysis Agent",
            "observation": f"Page loads {scripts_count} script(s) from external hostnames.",
            "inference": "External scripts execute third-party code; normal on modern sites but relevant for audit.",
            "weight_key": "external_scripts",
            "severity": "low"
        })

    # 5. Hidden fields
    if hidden_count > 0 and not has_ext_credential_form:
        evidence.append({
            "category": "form_structure",
            "indicator": "hidden_fields",
            "source_agent": "Webpage Analysis Agent",
            "observation": f"Page contains {hidden_count} hidden input field(s).",
            "inference": "Hidden fields frequently store CSRF tokens (benign) or tracking identifiers.",
            "weight_key": "hidden_fields",
            "severity": "low"
        })

    return evidence, missing


def _extract_behaviour_evidence(behaviour_result: dict[str, Any] | None) -> tuple[list[dict], list[str]]:
    """Extract deduplicated evidence and missing data flags from Behaviour Analysis."""
    evidence = []
    missing = []

    if not behaviour_result or not isinstance(behaviour_result, dict):
        missing.append("Behaviour Analysis: No redirect/navigation data provided")
        return evidence, missing

    status = behaviour_result.get("status")
    if status in ("invalid_url", "invalid_scheme"):
        missing.append(f"Behaviour Analysis: {behaviour_result.get('error_detail', 'Invalid input')}")
        return evidence, missing

    if status == "blocked_private_address":
        evidence.append({
            "category": "ssrf_risk",
            "indicator": "blocked_private_address",
            "source_agent": "Behaviour Analysis Agent",
            "observation": "Navigation targeted a private, loopback, or internal network address and was blocked.",
            "inference": "Attempted Server-Side Request Forgery (SSRF) or internal network probing.",
            "weight_key": "blocked_private_address",
            "severity": "high"
        })

    if status == "redirect_loop":
        evidence.append({
            "category": "navigation_anomaly",
            "indicator": "redirect_loop",
            "source_agent": "Behaviour Analysis Agent",
            "observation": "Navigation entered a circular redirect loop.",
            "inference": "May indicate redirection evasion, misconfigured crawler traps, or defensive loops.",
            "weight_key": "redirect_loop",
            "severity": "medium"
        })

    if behaviour_result.get("has_protocol_downgrade"):
        evidence.append({
            "category": "transport_security",
            "indicator": "protocol_downgrade",
            "source_agent": "Behaviour Analysis Agent",
            "observation": "Redirect chain downgraded communication from HTTPS to unencrypted HTTP.",
            "inference": "Exposes submitted data and session tokens to cleartext network eavesdropping.",
            "weight_key": "protocol_downgrade",
            "severity": "high"
        })

    redirect_count = behaviour_result.get("redirect_count", 0)
    if redirect_count >= 3:
        evidence.append({
            "category": "navigation_anomaly",
            "indicator": "unusually_long_chain",
            "source_agent": "Behaviour Analysis Agent",
            "observation": f"Observed {redirect_count} redirect hops before arriving at final destination.",
            "inference": "Multi-hop chains are commonly used in phishing campaigns to evade automated scanners.",
            "weight_key": "unusually_long_chain",
            "severity": "medium"
        })

    if behaviour_result.get("has_cross_domain_redirect"):
        changes = behaviour_result.get("domain_changes_count", 1)
        evidence.append({
            "category": "domain_transition",
            "indicator": "cross_domain_redirects",
            "source_agent": "Behaviour Analysis Agent",
            "observation": f"Navigation crossed {changes} domain boundary(ies).",
            "inference": "Cross-domain redirects occur in URL shorteners, SSO flows, and deceptive redirects.",
            "weight_key": "cross_domain_redirects",
            "severity": "low"
        })

    # Check for raw IP final destination in findings
    findings = behaviour_result.get("findings", [])
    if any(f.get("type") == "ip_hostname_destination" for f in findings):
        evidence.append({
            "category": "origin_risk",
            "indicator": "ip_hostname_destination",
            "source_agent": "Behaviour Analysis Agent",
            "observation": "Final destination host uses a raw IP address instead of a domain name.",
            "inference": "Direct IP destinations bypass domain reputation controls and avoid registration records.",
            "weight_key": "ip_hostname_destination",
            "severity": "medium"
        })

    return evidence, missing


def correlate_evidence(
    url_result: dict[str, Any] | None = None,
    webpage_result: dict[str, Any] | None = None,
    behaviour_result: dict[str, Any] | None = None,
    weights: dict[str, float] | None = None,
    thresholds: dict[str, float] | None = None,
    target_url: str = ""
) -> dict[str, Any]:
    """
    Correlate structured findings from URL Analysis, Webpage Analysis,
    and Behaviour Analysis into an explainable overall risk assessment.

    Args:
        url_result: Findings from URL model/analysis.
        webpage_result: Findings from Webpage Analysis Agent.
        behaviour_result: Findings from Behaviour Analysis Agent.
        weights: Optional custom scoring weights mapping indicator keys to float values.
        thresholds: Optional custom risk level thresholds (high, medium, low).
        target_url: Optional URL string being investigated.

    Returns:
        dict: Explainable correlation report including overall_risk, risk_score,
              evidence_summary, supporting_indicators, conflicting_indicators,
              missing_data, reasons, and deduplicated evidence items.
    """
    scoring_weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    risk_thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}

    # Resolve target URL if not explicitly provided
    if not target_url:
        if url_result and isinstance(url_result, dict):
            target_url = url_result.get("url", "")
        elif webpage_result and isinstance(webpage_result, dict):
            target_url = webpage_result.get("page_url", "")
        elif behaviour_result and isinstance(behaviour_result, dict):
            target_url = behaviour_result.get("original_url", "")

    # Extract evidence and missing data per stage
    url_ev, url_missing = _extract_url_evidence(url_result)
    web_ev, web_missing = _extract_webpage_evidence(webpage_result)
    beh_ev, beh_missing = _extract_behaviour_evidence(behaviour_result)

    all_evidence = url_ev + web_ev + beh_ev
    missing_data = url_missing + web_missing + beh_missing

    # Determine data completeness & confidence
    available_streams = 0
    if url_result and isinstance(url_result, dict) and "error" not in url_result:
        available_streams += 1
    if webpage_result and isinstance(webpage_result, dict) and "error" not in webpage_result:
        available_streams += 1
    if behaviour_result and isinstance(behaviour_result, dict) and behaviour_result.get("status") not in ("invalid_url", "invalid_scheme", None):
        available_streams += 1

    if available_streams == 3:
        confidence = "high"
    elif available_streams == 2:
        confidence = "medium"
    elif available_streams == 1:
        confidence = "low"
    else:
        confidence = "none"

    # If completely empty inputs
    if available_streams == 0 and not all_evidence:
        return {
            "agent": "Evidence Correlation Agent",
            "target_url": target_url,
            "overall_risk": "unknown",
            "risk_score": 0.0,
            "confidence": "none",
            "summary": "Insufficient data available to assess risk. All investigation agents were unavailable or omitted.",
            "reasons": ["No agent data was supplied for evaluation."],
            "supporting_indicators": [],
            "conflicting_indicators": [],
            "missing_data": missing_data,
            "deduplicated_evidence": [],
            "agent_results": {
                "url_analysis": url_result,
                "webpage_analysis": webpage_result,
                "behaviour_analysis": behaviour_result
            },
            "note": (
                "This assessment is a rule-based correlation heuristic combining multi-stage signals. "
                "It is designed for investigation triage and attack correlation, not certified proof of phishing. "
                "No claim of production-ready real-world phishing detection accuracy is made without representative evaluation data."
            )
        }

    # Deduplication: ensure each indicator key is only scored once
    seen_indicators = set()
    deduplicated_evidence = []
    raw_score = 0.0

    for item in all_evidence:
        ind = item["indicator"]
        if ind not in seen_indicators:
            seen_indicators.add(ind)
            weight = scoring_weights.get(item["weight_key"], 0.10)
            item["applied_weight"] = weight
            deduplicated_evidence.append(item)
            raw_score += weight

    # Cap score at 1.0
    risk_score = min(1.0, round(raw_score, 2))

    # Evaluate Supporting Indicators
    supporting_indicators = []
    has_ml_phish = any(e["indicator"] == "ml_phishing_label" for e in deduplicated_evidence)
    has_cred_ext = any(e["indicator"] == "credential_external_destination" for e in deduplicated_evidence)
    has_proto_down = any(e["indicator"] == "protocol_downgrade" for e in deduplicated_evidence)
    has_cross_domain = any(e["indicator"] == "cross_domain_redirects" for e in deduplicated_evidence)
    has_long_chain = any(e["indicator"] == "unusually_long_chain" for e in deduplicated_evidence)
    has_blocked_ip = any(e["indicator"] == "blocked_private_address" for e in deduplicated_evidence)

    if has_ml_phish and has_cred_ext:
        supporting_indicators.append(
            "URL model predicted phishing and Webpage analysis confirmed an external credential submission destination."
        )
    if has_cred_ext and has_cross_domain:
        supporting_indicators.append(
            "Webpage credential form submits externally and Behaviour analysis observed cross-domain redirect activity."
        )
    if has_proto_down and has_cred_ext:
        supporting_indicators.append(
            "Protocol downgrade to unencrypted HTTP correlates with presence of credential collection forms."
        )
    if has_ml_phish and (has_long_chain or has_cross_domain):
        supporting_indicators.append(
            "Suspicious URL model classification is corroborated by complex redirect navigation behaviour."
        )
    if has_blocked_ip:
        supporting_indicators.append(
            "Target attempted to navigate to a private/internal network address, indicating SSRF probing."
        )

    # Evaluate Conflicting Evidence
    conflicting_indicators = []

    # Case A: URL ML predicts phishing, but webpage is completely benign (no forms, no password fields, no external actions)
    if has_ml_phish and webpage_result and isinstance(webpage_result, dict):
        forms_cnt = webpage_result.get("forms_count", 0)
        pass_cnt = webpage_result.get("password_fields_count", 0)
        susp_cnt = len(webpage_result.get("suspicious_form_actions", []))
        if forms_cnt == 0 and pass_cnt == 0 and susp_cnt == 0:
            conflicting_indicators.append(
                "Conflict: URL model flagged phishing, but Webpage analysis observed zero forms, zero password fields, and no external submission destinations."
            )

    # Case B: URL ML predicts legit (very low score), but webpage has external credential form
    url_label = url_result.get("label") if isinstance(url_result, dict) else None
    url_score = url_result.get("score") if isinstance(url_result, dict) else None
    if url_label == "legit" and url_score is not None and url_score < 0.20 and has_cred_ext:
        conflicting_indicators.append(
            f"Conflict: URL model scored low risk ({url_score:.2f}, 'legit'), but Webpage analysis discovered a credential form submitting to an external hostname."
        )

    # Case C: Cross-domain redirect observed, but no credential fields or suspicious actions present on landing page
    if has_cross_domain and webpage_result and isinstance(webpage_result, dict):
        pass_cnt = webpage_result.get("password_fields_count", 0)
        susp_cnt = len(webpage_result.get("suspicious_form_actions", []))
        if pass_cnt == 0 and susp_cnt == 0 and not has_ml_phish:
            conflicting_indicators.append(
                "Conflict: Redirect crossed domain boundaries, but the destination page contains no credential fields or suspicious actions (consistent with benign shorteners or CDNs)."
            )

    # Adjust score if strong conflicting evidence offsets isolated weak heuristics
    if conflicting_indicators and not has_cred_ext and not has_blocked_ip and not has_proto_down:
        # Moderate risk inflation if only ML flagged it but page is static/benign
        if has_ml_phish and any("zero forms" in c for c in conflicting_indicators):
            risk_score = max(0.20, round(risk_score * 0.70, 2))

    # Determine Overall Risk Level
    if risk_score >= risk_thresholds["high"]:
        overall_risk = "high"
    elif risk_score >= risk_thresholds["medium"]:
        overall_risk = "medium"
    else:
        overall_risk = "low"

    # Assemble primary reasons
    reasons = []
    for item in sorted(deduplicated_evidence, key=lambda x: x.get("applied_weight", 0), reverse=True):
        reasons.append(f"[{item['source_agent']}] {item['observation']}")

    if not reasons:
        reasons.append("No suspicious indicators detected across available analysis modules.")

    if conflicting_indicators:
        reasons.append(f"Noted {len(conflicting_indicators)} conflicting indicator(s); see conflict details.")

    if missing_data:
        reasons.append(f"Evaluation performed with partial data ({len(missing_data)} missing stream(s)).")

    # Generate Summary
    if overall_risk == "high":
        summary = (
            f"High risk detected (score: {risk_score:.2f}, confidence: {confidence}). "
            f"Observed critical indicators such as external credential collection or transport security violations."
        )
    elif overall_risk == "medium":
        summary = (
            f"Medium risk identified (score: {risk_score:.2f}, confidence: {confidence}). "
            f"Multiple corroborating or suspicious navigation/page attributes observed; manual investigation recommended."
        )
    else:
        summary = (
            f"Low risk assessment (score: {risk_score:.2f}, confidence: {confidence}). "
            f"Observed indicators are minimal or consistent with standard web operations."
        )

    return {
        "agent": "Evidence Correlation Agent",
        "target_url": target_url,
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "confidence": confidence,
        "summary": summary,
        "reasons": reasons,
        "supporting_indicators": supporting_indicators,
        "conflicting_indicators": conflicting_indicators,
        "missing_data": missing_data,
        "deduplicated_evidence": deduplicated_evidence,
        "agent_results": {
            "url_analysis": url_result,
            "webpage_analysis": webpage_result,
            "behaviour_analysis": behaviour_result
        },
        "note": (
            "This assessment is a rule-based correlation heuristic combining multi-stage signals. "
            "It is designed for investigation triage and attack correlation, not certified proof of phishing. "
            "No claim of production-ready real-world phishing detection accuracy is made without representative evaluation data."
        )
    }


def investigate_url(
    url: str,
    html: str | None = None,
    include_behaviour: bool = False,
    behaviour_session: requests.Session | None = None,
    weights: dict[str, float] | None = None,
    use_playwright: bool = False,
    playwright_timeout: float = 15.0
) -> dict[str, Any]:
    """
    Convenience end-to-end coordinator: runs URL, Webpage, and Behaviour agents
    and correlates their outputs into a unified report.

    Args:
        url: The URL to investigate.
        html: Optional raw HTML string if already fetched or supplied offline.
        include_behaviour: If True, performs safe HTTP redirect behaviour analysis.
        behaviour_session: Optional mock requests.Session for safe unit testing.
        weights: Optional custom correlation weights.
        use_playwright: If True, uses Playwright headless browser to analyze rendered DOM.
        playwright_timeout: Navigation timeout for Playwright rendering (seconds).

    Returns:
        dict: Correlated multi-stage investigation report.
    """
    # 1. URL Analysis
    url_res = None
    try:
        score, label, explanation = predict(url)
        url_res = {
            "url": url,
            "score": float(score),
            "label": label,
            "explanation": explanation
        }
    except Exception as e:
        url_res = {"error": f"URL analysis failed: {str(e)}"}

    # 2. Webpage Analysis
    web_res = None
    if use_playwright:
        try:
            web_res = analyze_rendered_webpage(url=url, html=html, timeout=playwright_timeout)
        except Exception as e:
            web_res = {"error": f"Playwright rendered webpage analysis failed: {str(e)}"}
    elif html is not None:
        try:
            web_res = analyze_webpage(html=html, page_url=url)
        except Exception as e:
            web_res = {"error": f"Webpage analysis failed: {str(e)}"}

    # 3. Behaviour Analysis
    beh_res = None
    if include_behaviour:
        try:
            beh_res = analyze_behaviour(url=url, session=behaviour_session)
        except Exception as e:
            beh_res = {"error": f"Behaviour analysis failed: {str(e)}"}

    return correlate_evidence(
        url_result=url_res,
        webpage_result=web_res,
        behaviour_result=beh_res,
        weights=weights,
        target_url=url
    )
