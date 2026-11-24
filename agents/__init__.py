"""
Agents package for AI-Based Phishing Detection System.
Exports Webpage Analysis Agent and Behaviour Analysis Agent.
"""

from .behaviour_agent import (
    analyze_behaviour,
    analyze_redirect_chain,
    is_safe_destination_host,
    is_private_or_local_host,
    is_private_ip,
)
from .webpage_agent import (
    analyze_rendered_webpage,
    analyze_webpage,
    analyze_webpage_playwright,
)

__all__ = [
    "analyze_behaviour",
    "analyze_redirect_chain",
    "is_safe_destination_host",
    "is_private_or_local_host",
    "is_private_ip",
    "analyze_rendered_webpage",
    "analyze_webpage",
    "analyze_webpage_playwright",
]
