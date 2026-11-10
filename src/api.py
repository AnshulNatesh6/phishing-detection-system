"""
Flask API.
Exposes /scan (POST JSON {"url": "str"}).
Run: python -m src.api
"""

from flask import Flask, request, jsonify
import logging
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.config import FLASK_ENV, FLASK_DEBUG
from src.model import predict
from src.logging_config import setup_logging
from src.utils import validate_url
from src.webpage_agent import analyze_webpage, analyze_rendered_webpage
from src.behaviour_agent import analyze_behaviour
from src.correlation_agent import correlate_evidence, investigate_url

setup_logging()
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['ENV'] = FLASK_ENV
app.config['DEBUG'] = FLASK_DEBUG
# Maximum request size limit (2 MB) to prevent denial of service via large payloads
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle payloads exceeding MAX_CONTENT_LENGTH."""
    return jsonify({"error": "Payload exceeds maximum allowed size of 2MB"}), 413

@app.route('/scan', methods=['POST'])
def scan_url():
    """
    Scan endpoint.
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    
    data = request.get_json()
    url = data.get('url')
    if not url or not validate_url(url):
        return jsonify({"error": "Valid 'url' required"}), 400
    
    try:
        score, label, explanation = predict(url)
        return jsonify({
            "url": url,
            "score": float(score),
            "label": label,
            "explanation": explanation
        })
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-webpage', methods=['POST'])
def analyze_webpage_endpoint():
    """
    Analyze supplied HTML using Webpage Analysis Agent.
    Accepts JSON: {"html": "...", "url": "..."} (or "page_url").
    Does not fetch the page URL over the network.
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    html = data.get('html')
    if html is None:
        return jsonify({"error": "'html' field is required"}), 400

    if not isinstance(html, str):
        return jsonify({"error": "'html' must be a string"}), 400

    page_url = data.get('page_url') if 'page_url' in data else data.get('url', '')
    if page_url is None:
        page_url = ""
    elif not isinstance(page_url, str):
        return jsonify({"error": "'url' must be a string"}), 400

    try:
        result = analyze_webpage(html=html, page_url=page_url)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Webpage analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-rendered-webpage', methods=['POST'])
@app.route('/analyze-webpage-playwright', methods=['POST'])
def analyze_rendered_webpage_endpoint():
    """
    Analyze JavaScript-rendered webpage using Playwright in headless Chromium.
    Inspects rendered DOM for forms, password inputs, hidden fields, iframes,
    scripts, external links, and form destinations.
    Enforces navigation timeouts, resource limits, and SSRF/private IP protections.
    Accepts JSON body:
    {
        "url": "https://example.com",
        "html": "...",  # optional pre-supplied HTML
        "timeout": 15.0, # optional timeout in seconds (default 15.0)
        "allow_private_ips": false
    }
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    url = data.get('page_url') if 'page_url' in data else data.get('url', '')
    if url is not None and not isinstance(url, str):
        return jsonify({"error": "'url' must be a string"}), 400

    html = data.get('html')
    if html is not None and not isinstance(html, str):
        return jsonify({"error": "'html' must be a string"}), 400

    if not url and html is None:
        return jsonify({"error": "Either 'url' or 'html' is required"}), 400

    timeout = data.get('timeout', 15.0)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        timeout = 15.0

    allow_private_ips = bool(data.get('allow_private_ips', False))

    try:
        result = analyze_rendered_webpage(
            url=url or "",
            html=html,
            timeout=timeout,
            allow_private_ips=allow_private_ips
        )
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Rendered webpage analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/analyze-behaviour', methods=['POST'])
@app.route('/analyze-behavior', methods=['POST'])
def analyze_behaviour_endpoint():
    """
    Analyze HTTP redirect and navigation behaviour using Behaviour Analysis Agent.
    Accepts JSON body: {"url": "https://example.com", "max_redirects": 5, "timeout": 5.0}
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    url = data.get('url')
    if not url or not isinstance(url, str):
        return jsonify({"error": "Valid 'url' string required"}), 400

    max_redirects = data.get('max_redirects', 5)
    if not isinstance(max_redirects, int) or max_redirects < 1:
        max_redirects = 5

    timeout = data.get('timeout', 5.0)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        timeout = 5.0

    try:
        result = analyze_behaviour(url=url, max_redirects=max_redirects, timeout=timeout)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Behaviour analysis failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/correlate', methods=['POST'])
def correlate_endpoint():
    """
    Correlate pre-computed findings from URL, Webpage, and Behaviour agents.
    Accepts JSON body:
    {
      "url": "https://example.com",
      "url_analysis": { ... },
      "webpage_analysis": { ... },
      "behaviour_analysis": { ... },
      "weights": { ... },
      "thresholds": { ... }
    }
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    url = data.get('url', '')
    url_result = data.get('url_analysis')
    webpage_result = data.get('webpage_analysis')
    behaviour_result = data.get('behaviour_analysis')
    weights = data.get('weights')
    thresholds = data.get('thresholds')

    try:
        report = correlate_evidence(
            url_result=url_result,
            webpage_result=webpage_result,
            behaviour_result=behaviour_result,
            weights=weights,
            thresholds=thresholds,
            target_url=url
        )
        return jsonify(report), 200
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/investigate', methods=['POST'])
def investigate_endpoint():
    """
    Convenience end-to-end investigation pipeline:
    Runs URL model, Webpage agent (if html provided), and Behaviour agent (if requested),
    and correlates results into a single report.
    Accepts JSON body: {"url": "https://...", "html": "...", "include_behaviour": false}
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    url = data.get('url')
    if not url or not isinstance(url, str):
        return jsonify({"error": "Valid 'url' string required"}), 400

    url = url.strip()
    if not validate_url(url):
        return jsonify({"error": "Valid 'url' required"}), 400

    html = data.get('html')
    if html is not None and not isinstance(html, str):
        return jsonify({"error": "'html' must be a string if provided"}), 400

    include_behaviour = bool(data.get('include_behaviour', False))
    use_playwright = bool(data.get('use_playwright', False) or data.get('render_js', False))
    playwright_timeout = data.get('playwright_timeout', 15.0)
    if not isinstance(playwright_timeout, (int, float)) or playwright_timeout <= 0:
        playwright_timeout = 15.0

    weights = data.get('weights')
    if weights is not None and not isinstance(weights, dict):
        return jsonify({"error": "'weights' must be a dictionary"}), 400

    try:
        report = investigate_url(
            url=url,
            html=html,
            include_behaviour=include_behaviour,
            weights=weights,
            use_playwright=use_playwright,
            playwright_timeout=playwright_timeout
        )
        return jsonify(report), 200
    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def health():
    """Health check."""
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    app.run(debug=FLASK_DEBUG, host='0.0.0.0', port=5000)