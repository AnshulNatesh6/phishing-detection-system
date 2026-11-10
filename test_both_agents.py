"""
Testing Interface for Webpage Analysis Agent and Behaviour Analysis Agent.
Part of the AI-Based Multi-Stage Phishing Detection and Investigation System.

Runs both agents sequentially against user-provided URLs and displays
the authentic returned investigation findings.
"""

import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

# Ensure project root is on sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.webpage_agent import analyze_rendered_webpage
from src.behaviour_agent import analyze_behaviour


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

    # Check if a scheme is present (e.g. scheme://)
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned))

    if not has_scheme:
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


def test_url(target_url: str) -> None:
    """
    Executes Webpage Analysis Agent and Behaviour Analysis Agent on the target URL
    and prints their respective results.
    """
    print("\nRunning Webpage Analysis Agent...")
    webpage_result = None
    webpage_exception = None
    try:
        # Pass entered URL via its 'url' parameter with strict private IP safety checks
        webpage_result = analyze_rendered_webpage(url=target_url, allow_private_ips=False)
    except Exception as exc:
        webpage_exception = exc

    print("Running Behaviour Analysis Agent...")
    behaviour_result = None
    behaviour_exception = None
    try:
        # Pass entered URL directly with strict private IP safety checks
        behaviour_result = analyze_behaviour(target_url, allow_private_ips=False)
    except Exception as exc:
        behaviour_exception = exc

    display_agent_results("WEBPAGE ANALYSIS RESULTS", webpage_result, webpage_exception)
    display_agent_results("BEHAVIOUR ANALYSIS RESULTS", behaviour_result, behaviour_exception)

    print("\n========== TEST COMPLETED ==========\n")


def main() -> None:
    """
    Main terminal interactive loop for testing both phishing analysis agents.
    """
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

