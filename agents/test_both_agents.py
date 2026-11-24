"""
Testing Interface for Webpage Analysis Agent and Behaviour Analysis Agent.
Part of the AI-Based Multi-Stage Phishing Detection and Investigation System.

Integrates Behaviour Analysis Agent and Webpage Analysis Agent:
1. Runs Behaviour Analysis first to trace HTTP redirects, domain transitions, and final destination.
2. Runs Webpage Analysis on the original URL.
3. If the final URL differs from the original URL, runs Webpage Analysis on the final destination.
4. Displays separate webpage analysis findings for original and final destinations.
5. Clearly displays the redirect chain and navigation transitions.
6. Enforces SSRF destination validation before all browser navigations (blocking localhost,
   private/internal IPs, and unsafe redirect targets).
7. Never submits forms, enters credentials, or clicks suspicious links.
8. Handles connection errors, timeouts, and invalid URLs without crashing.
"""

import json
import logging
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

# Ensure project root and agents directory are on sys.path for direct script execution
AGENTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENTS_DIR.parent
for p in (str(PROJECT_ROOT), str(AGENTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from agents.behaviour_agent import (
        analyze_behaviour,
        is_private_or_local_host,
        is_private_ip
    )
    from agents.webpage_agent import (
        analyze_rendered_webpage,
        is_safe_destination_host
    )
except ImportError:
    from behaviour_agent import (
        analyze_behaviour,
        is_private_or_local_host,
        is_private_ip
    )
    from webpage_agent import (
        analyze_rendered_webpage,
        is_safe_destination_host
    )

logger = logging.getLogger(__name__)


def normalize_and_validate_url(raw_input: str) -> tuple[str | None, str | None]:
    """
    Validates and normalizes user input into a valid HTTP/HTTPS URL.

    - Strips whitespace.
    - If scheme is omitted, automatically prepends 'https://'.
    - Validates that the scheme is http or https.
    - Ensures a valid network location (hostname) is present.

    Returns:
        tuple[normalized_url, error_message]:
            (url, None) on success, or (None, error_message) on failure.
    """
    if not raw_input:
        return None, "URL cannot be empty. Please enter a valid URL."

    cleaned = raw_input.strip()
    if not cleaned:
        return None, "URL cannot be empty. Please enter a valid URL."

    # Check if a scheme is present (e.g. scheme: or scheme://)
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):", cleaned)
    if match:
        scheme = match.group(1).lower()
        if scheme not in ("http", "https"):
            return None, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS URLs are allowed."
        if not cleaned.lower().startswith(("http://", "https://")):
            return None, f"Invalid URL formatting for scheme '{scheme}'."
    else:
        # User entered a domain/path without a scheme; default to https://
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        return None, f"Failed to parse URL '{cleaned}': {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS URLs are allowed."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return None, f"Invalid URL '{raw_input}': Hostname/domain could not be identified."

    return cleaned, None


def is_safe_destination_url(url: str, allow_private_ips: bool = False) -> tuple[bool, str | None]:
    """
    Validate that destination URL does not target localhost, private IPs,
    link-local, loopback, or internal networks to prevent SSRF before navigation.

    Returns:
        tuple[is_safe, error_reason]:
            (True, None) if safe, or (False, reason) if blocked.
    """
    if allow_private_ips:
        return True, None
    if not url:
        return False, "Destination URL is empty."

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Failed to parse URL '{url}': {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS URLs are allowed."

    host = parsed.hostname
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    if "/" in netloc:
        netloc = netloc.split("/")[0]
    if is_private_or_local_host(netloc):
        host = netloc.lower()
    elif ":" in netloc and is_private_or_local_host(netloc.rsplit(":", 1)[0]):
        host = netloc.rsplit(":", 1)[0].lower()

    if not host:
        return False, f"URL '{url}' does not contain a valid hostname."

    if not is_safe_destination_host(host, allow_private_ips=False):
        return False, f"Destination host '{host}' is a private, loopback, or internal network address (SSRF blocked)."

    return True, None


def run_integrated_analysis(
    url: str,
    allow_private_ips: bool = False,
    webpage_timeout: float = 15.0,
    behaviour_timeout: float = 5.0,
    max_redirects: int = 5,
    browser=None
) -> dict:
    """
    Integrates Behaviour Analysis Agent and Webpage Analysis Agent:
    1. Runs Behaviour Analysis first to trace HTTP redirects and obtain final destination.
    2. Runs Webpage Analysis on original URL.
    3. If final URL differs from original URL, runs Webpage Analysis on final URL.
    4. Enforces SSRF destination validation before all browser navigations.
    5. Returns structured results for all stages without crashing.

    Args:
        url: The URL to investigate.
        allow_private_ips: If False (default), blocks requests to local/private addresses.
        webpage_timeout: Navigation timeout for Playwright rendering (seconds).
        behaviour_timeout: HTTP request timeout for behaviour hops (seconds).
        max_redirects: Maximum redirect hops followed by behaviour agent.
        browser: Optional pre-launched Playwright browser instance for testing/pooling.

    Returns:
        dict: Complete structured findings for behaviour analysis, original webpage,
              and final webpage (if different destination).
    """
    # -------------------------------------------------------------------------
    # Stage 1: Behaviour Analysis Agent (Runs First)
    # -------------------------------------------------------------------------
    behaviour_result = None
    try:
        behaviour_result = analyze_behaviour(
            url=url,
            max_redirects=max_redirects,
            timeout=behaviour_timeout,
            allow_private_ips=allow_private_ips
        )
    except Exception as exc:
        behaviour_result = {
            "agent": "Behaviour Analysis Agent",
            "original_url": url,
            "final_url": url,
            "final_hostname": (urlparse(url).hostname or "").lower(),
            "redirect_count": 0,
            "redirect_chain": [],
            "unique_domains": [],
            "unique_hostnames": [],
            "domain_changes_count": 0,
            "domain_changes": [],
            "hostname_changes_count": 0,
            "hostname_changes": [],
            "has_cross_domain_redirect": False,
            "has_hostname_change": False,
            "has_protocol_downgrade": False,
            "status": "error",
            "error_detail": f"Behaviour analysis failed unexpectedly: {exc}",
            "findings": [{
                "type": "execution_error",
                "detail": str(exc)
            }],
            "note": "These are behavioral investigation observations, not proof of phishing."
        }

    original_url = behaviour_result.get("original_url") or url
    final_url = behaviour_result.get("final_url") or url
    redirect_chain = behaviour_result.get("redirect_chain", [])
    redirect_count = behaviour_result.get("redirect_count", 0)

    # -------------------------------------------------------------------------
    # Stage 2: Webpage Analysis Agent on Original URL
    # -------------------------------------------------------------------------
    original_webpage_result = None
    is_safe_orig, orig_ssrf_err = is_safe_destination_url(original_url, allow_private_ips=allow_private_ips)
    if not is_safe_orig:
        original_webpage_result = {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": original_url,
            "final_url": original_url,
            "title": "",
            "status": "blocked_private_address",
            "error_detail": orig_ssrf_err,
            "forms_count": 0,
            "password_fields_count": 0,
            "hidden_fields_count": 0,
            "iframes_count": 0,
            "scripts_count": 0,
            "external_scripts_count": 0,
            "external_links_count": 0,
            "suspicious_form_actions": [],
            "missing_form_actions": [],
            "credential_forms": [],
            "findings": [{
                "type": "blocked_private_address",
                "detail": orig_ssrf_err,
                "url": original_url
            }],
            "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
        }
    else:
        try:
            original_webpage_result = analyze_rendered_webpage(
                url=original_url,
                timeout=webpage_timeout,
                allow_private_ips=allow_private_ips,
                browser=browser
            )
        except Exception as exc:
            original_webpage_result = {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": original_url,
                "final_url": original_url,
                "title": "",
                "status": "connection_error",
                "error_detail": f"Webpage analysis failed on original URL: {exc}",
                "forms_count": 0,
                "password_fields_count": 0,
                "hidden_fields_count": 0,
                "iframes_count": 0,
                "scripts_count": 0,
                "external_scripts_count": 0,
                "external_links_count": 0,
                "suspicious_form_actions": [],
                "missing_form_actions": [],
                "credential_forms": [],
                "findings": [{
                    "type": "connection_error",
                    "detail": str(exc),
                    "url": original_url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }

    # -------------------------------------------------------------------------
    # Stage 3: Webpage Analysis Agent on Final Destination (If Different)
    # -------------------------------------------------------------------------
    final_webpage_result = None
    has_redirect = bool(
        final_url
        and final_url.strip()
        and final_url.strip() != original_url.strip()
    )

    if has_redirect:
        is_safe_final, final_ssrf_err = is_safe_destination_url(final_url, allow_private_ips=allow_private_ips)
        if not is_safe_final:
            final_webpage_result = {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": final_url,
                "final_url": final_url,
                "title": "",
                "status": "blocked_private_address",
                "error_detail": final_ssrf_err,
                "forms_count": 0,
                "password_fields_count": 0,
                "hidden_fields_count": 0,
                "iframes_count": 0,
                "scripts_count": 0,
                "external_scripts_count": 0,
                "external_links_count": 0,
                "suspicious_form_actions": [],
                "missing_form_actions": [],
                "credential_forms": [],
                "findings": [{
                    "type": "blocked_private_address",
                    "detail": final_ssrf_err,
                    "url": final_url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }
        else:
            try:
                final_webpage_result = analyze_rendered_webpage(
                    url=final_url,
                    timeout=webpage_timeout,
                    allow_private_ips=allow_private_ips,
                    browser=browser
                )
            except Exception as exc:
                final_webpage_result = {
                    "agent": "Webpage Analysis Agent",
                    "rendering": "playwright",
                    "page_url": final_url,
                    "final_url": final_url,
                    "title": "",
                    "status": "connection_error",
                    "error_detail": f"Webpage analysis failed on final destination: {exc}",
                    "forms_count": 0,
                    "password_fields_count": 0,
                    "hidden_fields_count": 0,
                    "iframes_count": 0,
                    "scripts_count": 0,
                    "external_scripts_count": 0,
                    "external_links_count": 0,
                    "suspicious_form_actions": [],
                    "missing_form_actions": [],
                    "credential_forms": [],
                    "findings": [{
                        "type": "connection_error",
                        "detail": str(exc),
                        "url": final_url
                    }],
                    "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
                }

    return {
        "target_url": url,
        "original_url": original_url,
        "final_url": final_url,
        "redirect_count": redirect_count,
        "has_redirect": has_redirect,
        "redirect_chain": redirect_chain,
        "behaviour_analysis": behaviour_result,
        "webpage_analysis_original": original_webpage_result,
        "webpage_analysis_final": final_webpage_result,
        "domain_changes": behaviour_result.get("domain_changes", []),
        "hostname_changes": behaviour_result.get("hostname_changes", []),
        "has_cross_domain_redirect": behaviour_result.get("has_cross_domain_redirect", False),
        "has_protocol_downgrade": behaviour_result.get("has_protocol_downgrade", False)
    }


def display_redirect_chain_summary(integrated_data: dict) -> None:
    """
    Displays a clear, human-readable summary of the redirect chain and destinations.
    """
    print("\n========== REDIRECT CHAIN & NAVIGATION SUMMARY ==========")
    orig = integrated_data.get("original_url", "")
    fin = integrated_data.get("final_url", "")
    count = integrated_data.get("redirect_count", 0)
    has_redir = integrated_data.get("has_redirect", False)
    chain = integrated_data.get("redirect_chain", [])

    print(f"Original URL:      {orig}")
    print(f"Final Destination: {fin}")
    print(f"Redirect Count:    {count}")

    if has_redir and chain:
        print("\nRedirect Chain Details:")
        for hop_info in chain:
            hop_num = hop_info.get("hop", "?")
            code = hop_info.get("status_code", "---")
            hop_url = hop_info.get("url", "")
            loc = hop_info.get("redirect_to")
            if loc:
                print(f"  [Hop {hop_num}] HTTP {code}: {hop_url} -> {loc}")
            else:
                print(f"  [Hop {hop_num}] HTTP {code}: {hop_url}")

        if integrated_data.get("has_cross_domain_redirect"):
            print("\n  [!] Warning: Cross-registered-domain redirect detected!")
        if integrated_data.get("has_protocol_downgrade"):
            print("  [!] Warning: Protocol downgrade detected (HTTPS -> HTTP)!")
    elif not has_redir:
        print("\n  [i] No redirects detected. Target stayed on original destination.")


def display_agent_results(agent_header: str, result: dict | None, exception: Exception | None = None) -> None:
    """
    Displays the complete findings returned by an agent.
    Identifies and highlights errors if any occurred.
    """
    print(f"\n========== {agent_header.upper()} ==========")

    if exception is not None:
        print("[!] Execution Error: An unexpected exception occurred while running the agent:")
        print(f"    Exception Type: {type(exception).__name__}")
        print(f"    Details: {exception}")
        return

    if not isinstance(result, dict):
        print(f"[!] Warning: Agent returned unexpected type ({type(result).__name__}):")
        print(result)
        return

    # Check if agent indicated an error or abnormal status
    status = result.get("status", "unknown")
    if status != "completed":
        print(f"[!] Agent Status: {status.upper()}")
        error_detail = result.get("error_detail")
        if error_detail:
            print(f"[!] Error Detail: {error_detail}")

    # Output the complete returned dictionary as formatted JSON
    print(json.dumps(result, indent=2, default=str))


def test_url(target_url: str) -> dict:
    """
    Executes the integrated analysis workflow on the target URL:
    1. Runs Behaviour Analysis first.
    2. Runs Webpage Analysis on original URL.
    3. If final URL is different, runs Webpage Analysis on final destination.
    4. Displays redirect chain and findings for each stage.
    """
    print(f"\nTarget URL: {target_url}")
    print("Running Behaviour Analysis Agent first...")

    # Run integrated analysis
    results = run_integrated_analysis(url=target_url, allow_private_ips=False)

    orig_url = results["original_url"]
    fin_url = results["final_url"]
    has_redir = results["has_redirect"]

    # Display clear redirect summary
    display_redirect_chain_summary(results)

    # Indicate webpage analysis execution
    print(f"\nRunning Webpage Analysis Agent on Original URL: {orig_url}...")
    if has_redir:
        print(f"Redirect detected: Running Webpage Analysis Agent on Final Destination: {fin_url}...")

    # 1. Display Behaviour Analysis Findings
    display_agent_results("BEHAVIOUR ANALYSIS RESULTS", results["behaviour_analysis"])

    # 2. Display Original Destination Webpage Findings
    display_agent_results(
        f"WEBPAGE ANALYSIS RESULTS (ORIGINAL DESTINATION: {orig_url})",
        results["webpage_analysis_original"]
    )

    # 3. Display Final Destination Webpage Findings (if different)
    if has_redir:
        display_agent_results(
            f"WEBPAGE ANALYSIS RESULTS (FINAL DESTINATION: {fin_url})",
            results["webpage_analysis_final"]
        )
    else:
        print("\n[i] Final destination is identical to original URL; separate render not required.")

    print("\n========== TEST COMPLETED ==========\n")
    return results


test_url.__test__ = False


def main() -> None:
    """
    Main terminal runner / interactive loop for testing both phishing analysis agents.
    """
    # If a URL is provided directly as a command-line argument:
    if len(sys.argv) > 1 and sys.argv[1].strip() not in ("-h", "--help"):
        raw_url = sys.argv[1].strip()
        target_url, err = normalize_and_validate_url(raw_url)
        if err:
            print(f"[!] {err}\n")
            sys.exit(1)
        test_url(target_url)
        return

    print("========== PHISHING AGENT TESTER ==========\n")

    while True:
        try:
            raw_url = input("Enter URL: ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Phishing Agent Tester. Goodbye!")
            break

        target_url, err = normalize_and_validate_url(raw_url)
        if err:
            print(f"[!] {err}\n")
            continue

        test_url(target_url)

        try:
            again = input("Enter another URL? (y/n): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Phishing Agent Tester. Goodbye!")
            break

        if again == "n" or again.startswith("n"):
            print("Exiting Phishing Agent Tester. Goodbye!")
            break

        print()  # Spacer line before next URL prompt


if __name__ == "__main__":
    main()
