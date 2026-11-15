import ipaddress
import logging
import socket
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.behaviour_agent import (
    is_private_or_local_host,
    is_private_ip,
    is_safe_destination_host
)

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None
    PlaywrightTimeoutError = Exception


def analyze_webpage(html: str, page_url: str = "") -> dict:
    """
    Analyze webpage HTML and return explainable findings.
    Does not submit forms or execute webpage scripts.
    Does not fetch page_url from the network.

    Args:
        html: The HTML string of the webpage to analyze.
        page_url: The URL where the HTML originated from (used for base domain comparisons).

    Returns:
        dict: Findings, element counts, and investigation indicators.
    """
    if html is None:
        html = ""
    elif not isinstance(html, str):
        html = str(html)

    if page_url is None:
        page_url = ""
    elif not isinstance(page_url, str):
        page_url = str(page_url)
    page_url = page_url.strip()

    soup = BeautifulSoup(html, "html.parser")

    # Extract base href if <base> tag is present
    base_tag = soup.find("base", href=True)
    base_href = ""
    if base_tag and base_tag.get("href"):
        raw_base = base_tag.get("href")
        if isinstance(raw_base, str):
            base_href = raw_base.strip()

    effective_base = urljoin(page_url, base_href) if base_href else page_url

    # Resolve page domain for hostname comparisons
    parsed_page = urlparse(page_url)
    if not parsed_page.scheme and not parsed_page.netloc and page_url:
        first_segment = page_url.split("/")[0]
        if "." in first_segment or ":" in first_segment:
            parsed_page = urlparse("https://" + page_url)

    page_domain = (parsed_page.hostname or "").lower() if parsed_page.hostname else ""

    # Find forms and credential fields (case-insensitive type matching)
    forms = soup.find_all("form")
    password_fields = soup.find_all(
        lambda tag: tag.name == "input" and (tag.get("type") or "").strip().lower() == "password"
    )
    hidden_fields = soup.find_all(
        lambda tag: tag.name == "input" and (tag.get("type") or "").strip().lower() == "hidden"
    )
    iframes = soup.find_all("iframe")
    scripts = soup.find_all("script", src=True)
    links = soup.find_all("a", href=True)

    findings = []

    if password_fields:
        findings.append({
            "type": "password_fields",
            "count": len(password_fields),
            "detail": "Password input fields are present."
        })

    if hidden_fields:
        findings.append({
            "type": "hidden_fields",
            "count": len(hidden_fields),
            "detail": "Hidden input fields are present; review their purpose."
        })

    # Check form actions, destinations, and credential forms
    suspicious_form_actions = []
    missing_form_actions = []
    credential_forms = []

    for form in forms:
        raw_action = form.get("action")
        action = raw_action.strip() if isinstance(raw_action, str) else ""
        method = form.get("method", "get")
        method = method.strip().lower() if isinstance(method, str) else "get"

        form_passwords = form.find_all(
            lambda tag: tag.name == "input" and (tag.get("type") or "").strip().lower() == "password"
        )
        has_password = len(form_passwords) > 0

        # Check for missing, empty, or placeholder action destinations
        is_missing_action = (
            raw_action is None
            or action == ""
            or action == "#"
            or action.lower().startswith("javascript:")
        )

        if is_missing_action:
            missing_entry = {
                "action": action if raw_action is not None else "",
                "method": method,
                "has_password": has_password
            }
            missing_form_actions.append(missing_entry)
            destination = page_url
            destination_domain = page_domain
        else:
            destination = urljoin(effective_base, action)
            dest_parsed = urlparse(destination)
            destination_domain = (dest_parsed.hostname or "").lower()

            if page_domain and destination_domain and destination_domain != page_domain:
                suspicious_form_actions.append({
                    "destination": destination,
                    "method": method
                })

        if has_password:
            credential_forms.append({
                "action": action if raw_action is not None else "",
                "destination": destination,
                "method": method,
                "password_fields_count": len(form_passwords),
                "is_external": bool(page_domain and destination_domain and destination_domain != page_domain),
                "is_missing_action": is_missing_action
            })

    if credential_forms:
        findings.append({
            "type": "credential_forms",
            "count": len(credential_forms),
            "detail": "Credential-related form(s) detected; review destination and context.",
            "items": credential_forms
        })

    if missing_form_actions:
        findings.append({
            "type": "missing_form_actions",
            "count": len(missing_form_actions),
            "detail": "One or more forms have missing, empty, or placeholder action destinations.",
            "items": missing_form_actions
        })

    if suspicious_form_actions:
        findings.append({
            "type": "external_form_destinations",
            "count": len(suspicious_form_actions),
            "detail": "One or more forms submit to a different hostname.",
            "items": suspicious_form_actions
        })

    # Check external iframes
    external_iframes = []
    for iframe in iframes:
        src = iframe.get("src")
        if not src or not isinstance(src, str):
            continue
        src = src.strip()
        if not src or src.lower().startswith(("javascript:", "about:", "data:")):
            continue

        destination = urljoin(effective_base, src)
        domain = (urlparse(destination).hostname or "").lower()

        if page_domain and domain and domain != page_domain:
            external_iframes.append(destination)

    if external_iframes:
        findings.append({
            "type": "external_iframes",
            "count": len(external_iframes),
            "detail": "Iframes load content from other hostnames.",
            "items": external_iframes
        })

    # Check externally hosted scripts
    external_scripts = []
    for script in scripts:
        src = script.get("src")
        if not src or not isinstance(src, str):
            continue
        src = src.strip()
        if not src or src.lower().startswith(("javascript:", "data:")):
            continue

        destination = urljoin(effective_base, src)
        domain = (urlparse(destination).hostname or "").lower()

        if page_domain and domain and domain != page_domain:
            external_scripts.append(destination)

    if external_scripts:
        findings.append({
            "type": "external_scripts",
            "count": len(external_scripts),
            "detail": "Scripts are loaded from other hostnames.",
            "items": external_scripts
        })

    # Count links to other hostnames
    external_links = []
    for link in links:
        href = link.get("href")
        if not href or not isinstance(href, str):
            continue
        href = href.strip()
        if not href or href.startswith("#") or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue

        destination = urljoin(effective_base, href)
        parsed = urlparse(destination)
        domain = (parsed.hostname or "").lower()

        if (
            parsed.scheme in ("http", "https")
            and page_domain
            and domain
            and domain != page_domain
        ):
            external_links.append(destination)

    return {
        "agent": "Webpage Analysis Agent",
        "page_url": page_url,
        "forms_count": len(forms),
        "password_fields_count": len(password_fields),
        "hidden_fields_count": len(hidden_fields),
        "iframes_count": len(iframes),
        "external_scripts_count": len(external_scripts),
        "external_links_count": len(external_links),
        "suspicious_form_actions": suspicious_form_actions,
        "missing_form_actions": missing_form_actions,
        "credential_forms": credential_forms,
        "findings": findings,
        "note": (
            "These are investigation indicators, not proof of phishing. "
            "External resources and hidden fields can be legitimate."
        )
    }


def _extract_dom_data_from_soup(soup: BeautifulSoup, page_url: str = "") -> dict:
    """
    Fallback extractor that parses live HTML using BeautifulSoup if browser evaluation fails
    (e.g., if execution context is destroyed during in-flight navigation/redirect).
    """
    base_tag = soup.find("base", href=True)
    base_href = base_tag.get("href", "") if base_tag else ""
    effective_base = urljoin(page_url, base_href) if base_href else page_url

    title_tag = soup.find("title")
    title = title_tag.get_text().strip() if title_tag else ""

    forms_list = []
    for idx, form in enumerate(soup.find_all("form")):
        raw_action = form.get("action")
        action = raw_action.strip() if isinstance(raw_action, str) else ""
        resolved_action = urljoin(effective_base, action) if action else ""
        method = (form.get("method") or "get").lower()
        inputs = form.find_all("input")
        passwords = [i for i in inputs if (i.get("type") or "text").lower() == "password"]
        hiddens = [i for i in inputs if (i.get("type") or "").lower() == "hidden"]
        forms_list.append({
            "index": idx,
            "raw_action": raw_action,
            "resolved_action": resolved_action,
            "method": method,
            "passwords_count": len(passwords),
            "hiddens_count": len(hiddens),
        })

    all_inputs = soup.find_all("input")
    password_inputs = []
    for i in all_inputs:
        if (i.get("type") or "text").lower() == "password":
            parent_form = i.find_parent("form")
            form_action = parent_form.get("action") if parent_form else None
            password_inputs.append({
                "name": i.get("name") or "",
                "id": i.get("id") or "",
                "form_action": form_action,
            })

    hidden_inputs = []
    for i in all_inputs:
        if (i.get("type") or "").lower() == "hidden":
            hidden_inputs.append({
                "name": i.get("name") or "",
                "id": i.get("id") or "",
                "value": (i.get("value") or "")[:50],
            })

    iframes = []
    for f in soup.find_all("iframe"):
        raw_src = f.get("src")
        resolved_src = urljoin(effective_base, raw_src.strip()) if raw_src else ""
        iframes.append({
            "raw_src": raw_src,
            "resolved_src": resolved_src,
        })

    scripts = []
    for s in soup.find_all("script"):
        raw_src = s.get("src")
        resolved_src = urljoin(effective_base, raw_src.strip()) if raw_src else ""
        scripts.append({
            "raw_src": raw_src,
            "resolved_src": resolved_src,
            "is_inline": not bool(raw_src),
        })

    links = []
    for a in soup.find_all("a", href=True):
        raw_href = a.get("href")
        resolved_href = urljoin(effective_base, raw_href.strip()) if raw_href else ""
        links.append({
            "raw_href": raw_href,
            "resolved_href": resolved_href,
            "text": a.get_text().strip()[:100],
        })

    return {
        "title": title,
        "base_href": base_href,
        "forms": forms_list,
        "password_inputs": password_inputs,
        "hidden_inputs": hidden_inputs,
        "iframes": iframes,
        "scripts": scripts,
        "links": links,
    }


def analyze_rendered_webpage(
    url: str = "",
    html: str | None = None,
    page_url: str = "",
    timeout: float = 15.0,
    allow_private_ips: bool = False,
    wait_until: str = "domcontentloaded",
    settle_delay_ms: int = 400,
    browser = None
) -> dict:
    """
    Analyze JavaScript-rendered webpage using Playwright in headless Chromium.
    Extracts rendered DOM elements (forms, password fields, hidden inputs,
    iframes, scripts, external links, form destinations) after script execution.

    Enforces navigation timeouts, resource limits (blocking heavy media/fonts),
    and SSRF protections (blocking localhost, private IPs, internal services, and unsafe redirects).
    Does not submit forms, enter credentials, or click suspicious links.

    Args:
        url: The URL to navigate to and render (or page_url).
        html: Optional raw HTML string to render in Playwright without external fetching.
        page_url: Optional alias for url (used for origin/base domain).
        timeout: Navigation timeout in seconds (default 15.0).
        allow_private_ips: If False (default), blocks requests to localhost/private IPs.
        wait_until: Navigation wait condition ('domcontentloaded', 'load', 'networkidle').
        settle_delay_ms: Milliseconds to wait for dynamic scripts to settle (default 400).
        browser: Optional pre-launched Playwright browser instance for testing/pooling.

    Returns:
        dict: Findings, element counts, rendered page properties, and investigation indicators.
    """
    if not url and page_url:
        url = page_url
    url = (url or "").strip()

    if not url and html is None:
        return {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": "",
            "final_url": "",
            "title": "",
            "status": "invalid_input",
            "error_detail": "Either 'url' or 'html' must be provided.",
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
                "type": "invalid_input",
                "detail": "Either 'url' or 'html' must be provided for rendered webpage analysis."
            }],
            "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
        }

    if url:
        parsed_url = urlparse(url)
        if parsed_url.scheme.lower() not in ("http", "https"):
            return {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": url,
                "final_url": url,
                "title": "",
                "status": "invalid_scheme",
                "error_detail": f"Unsupported URL scheme '{parsed_url.scheme}'. Only http and https are allowed.",
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
                    "type": "invalid_scheme",
                    "detail": f"Scheme '{parsed_url.scheme}' is not allowed for rendered webpage analysis."
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }

        url_host = parsed_url.hostname
        netloc = parsed_url.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if "/" in netloc:
            netloc = netloc.split("/")[0]
        if is_private_or_local_host(netloc):
            url_host = netloc.lower()
        elif ":" in netloc and is_private_or_local_host(netloc.rsplit(":", 1)[0]):
            url_host = netloc.rsplit(":", 1)[0].lower()

        if not allow_private_ips and not is_safe_destination_host(url_host, allow_private_ips=False):
            return {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": url,
                "final_url": url,
                "title": "",
                "status": "blocked_private_address",
                "error_detail": f"Access to private/local network address '{url_host}' was blocked.",
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
                    "detail": f"Access to private or local destination '{url_host}' blocked.",
                    "url": url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }

    if not PLAYWRIGHT_AVAILABLE:
        return {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": url,
            "final_url": url,
            "title": "",
            "status": "error",
            "error_detail": "Playwright is not installed. Install using 'pip install playwright' and 'playwright install chromium'.",
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
                "type": "playwright_unavailable",
                "detail": "Playwright library is not available in the current environment."
            }],
            "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
        }

    timeout_ms = max(500, int(timeout * 1000))
    close_browser_when_done = False
    playwright_ctx = None

    try:
        if browser is None:
            playwright_ctx = sync_playwright().start()
            browser = playwright_ctx.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--no-first-run"
                ]
            )
            close_browser_when_done = True

        context = browser.new_context(
            java_script_enabled=True,
            accept_downloads=False,
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800}
        )
        context.set_default_navigation_timeout(timeout_ms)
        context.set_default_timeout(timeout_ms)

        page = context.new_page()

        blocked_subresources = []
        unsafe_redirect_state = {"blocked": False, "url": None}

        def handle_route(route):
            req = route.request
            req_url = req.url
            parsed_req = urlparse(req_url)
            scheme = parsed_req.scheme.lower()
            host = parsed_req.hostname

            if scheme not in ("http", "https"):
                if scheme == "data" and req.resource_type in ("image", "media"):
                    route.continue_()
                    return
                route.abort("accessdenied")
                return

            if not allow_private_ips and not is_safe_destination_host(host, allow_private_ips=False):
                if req.frame == page.main_frame and req.is_navigation_request():
                    unsafe_redirect_state["blocked"] = True
                    unsafe_redirect_state["url"] = req_url
                blocked_subresources.append(req_url)
                route.abort("accessdenied")
                return

            # Resource limits: prevent excessive bandwidth / heavy assets
            if req.resource_type in ("media", "font"):
                route.abort("blockedbyclient")
                return

            route.continue_()

        page.route("**/*", handle_route)

        try:
            if html is not None:
                page.set_content(html, timeout=timeout_ms, wait_until=wait_until)
                if settle_delay_ms > 0:
                    page.wait_for_timeout(settle_delay_ms)
            elif url:
                page.goto(url, timeout=timeout_ms, wait_until=wait_until)
                # Allow page navigation/redirects to reach a stable state
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=min(timeout_ms, 3000))
                except Exception:
                    pass
                if settle_delay_ms > 0:
                    page.wait_for_timeout(settle_delay_ms)
        except PlaywrightTimeoutError:
            return {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": url,
                "final_url": page.url or url,
                "title": "",
                "status": "timeout",
                "error_detail": f"Page navigation timed out after {timeout} seconds.",
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
                    "type": "request_timeout",
                    "detail": f"Page navigation timed out after {timeout}s.",
                    "url": url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }
        except Exception as e:
            err_str = str(e)
            if unsafe_redirect_state["blocked"] or "ERR_NETWORK_ACCESS_DENIED" in err_str:
                blocked_dest = unsafe_redirect_state["url"] or url
                return {
                    "agent": "Webpage Analysis Agent",
                    "rendering": "playwright",
                    "page_url": url,
                    "final_url": blocked_dest,
                    "title": "",
                    "status": "blocked_private_address",
                    "error_detail": f"Navigation redirected to blocked private address '{blocked_dest}'.",
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
                        "detail": f"Navigation redirected to private/local address '{blocked_dest}' and was blocked.",
                        "url": blocked_dest
                    }],
                    "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
                }
            return {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": url,
                "final_url": page.url or url,
                "title": "",
                "status": "connection_error",
                "error_detail": f"Browser navigation failed: {err_str}",
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
                    "detail": f"Failed to load URL in browser: {err_str}",
                    "url": url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }

        # Retry loop for HTML and DOM extraction to handle in-flight navigations/redirects
        rendered_html = None
        dom_data = None
        page_title = ""
        max_extract_retries = 3
        last_extract_err = None

        for attempt in range(max_extract_retries):
            # Check if an unsafe redirect occurred during in-flight navigation
            if unsafe_redirect_state["blocked"]:
                blocked_dest = unsafe_redirect_state["url"] or url
                return {
                    "agent": "Webpage Analysis Agent",
                    "rendering": "playwright",
                    "page_url": url,
                    "final_url": blocked_dest,
                    "title": "",
                    "status": "blocked_private_address",
                    "error_detail": f"Navigation redirected to blocked private address '{blocked_dest}'.",
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
                        "detail": f"Navigation redirected to private/local address '{blocked_dest}' and was blocked.",
                        "url": blocked_dest
                    }],
                    "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
                }

            final_url = page.url or url
            if final_url == "about:blank":
                final_url = url

            try:
                try:
                    page_title = page.title()
                except Exception:
                    page_title = ""

                rendered_html = page.content()

                # Attempt live DOM evaluation
                try:
                    dom_data = page.evaluate("""() => {
                        const forms = Array.from(document.querySelectorAll('form')).map((form, idx) => {
                            const rawAction = form.getAttribute('action');
                            const actionProp = form.action || '';
                            const method = (form.getAttribute('method') || form.method || 'get').toLowerCase();
                            const inputs = Array.from(form.querySelectorAll('input'));
                            const passwords = inputs.filter(i => (i.type || '').toLowerCase() === 'password');
                            const hiddens = inputs.filter(i => (i.type || '').toLowerCase() === 'hidden');
                            return {
                                index: idx,
                                raw_action: rawAction,
                                resolved_action: actionProp,
                                method: method,
                                passwords_count: passwords.length,
                                hiddens_count: hiddens.length
                            };
                        });

                        const passwordInputs = Array.from(document.querySelectorAll('input')).filter(
                            i => (i.type || '').toLowerCase() === 'password'
                        ).map(i => ({
                            name: i.name || '',
                            id: i.id || '',
                            form_action: i.form ? (i.form.getAttribute('action') || '') : null
                        }));

                        const hiddenInputs = Array.from(document.querySelectorAll('input')).filter(
                            i => (i.type || '').toLowerCase() === 'hidden'
                        ).map(i => ({
                            name: i.name || '',
                            id: i.id || '',
                            value: (i.value || '').substring(0, 50)
                        }));

                        const iframes = Array.from(document.querySelectorAll('iframe')).map(f => ({
                            raw_src: f.getAttribute('src'),
                            resolved_src: f.src || ''
                        }));

                        const scripts = Array.from(document.querySelectorAll('script')).map(s => ({
                            raw_src: s.getAttribute('src'),
                            resolved_src: s.src || '',
                            is_inline: !s.src
                        }));

                        const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({
                            raw_href: a.getAttribute('href'),
                            resolved_href: a.href || '',
                            text: (a.textContent || '').trim().substring(0, 100)
                        }));

                        const baseTag = document.querySelector('base[href]');
                        const baseHref = baseTag ? baseTag.getAttribute('href') : '';

                        return {
                            title: document.title,
                            base_href: baseHref,
                            forms,
                            password_inputs: passwordInputs,
                            hidden_inputs: hiddenInputs,
                            iframes,
                            scripts,
                            links
                        };
                    }""")
                except Exception:
                    # Live evaluation failed (e.g. execution context destroyed); parse rendered HTML with BeautifulSoup
                    soup = BeautifulSoup(rendered_html, "html.parser")
                    dom_data = _extract_dom_data_from_soup(soup, final_url)
                    if not page_title:
                        page_title = dom_data.get("title", "")

                # Successfully retrieved HTML and DOM data
                break

            except Exception as e:
                last_extract_err = e
                err_msg = str(e).lower()
                is_nav_err = (
                    "navigating" in err_msg
                    or "context was destroyed" in err_msg
                    or "execution context" in err_msg
                    or "target closed" in err_msg
                )
                if is_nav_err and attempt < max_extract_retries - 1:
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=2000)
                    except Exception:
                        pass
                    try:
                        page.wait_for_timeout(500 * (attempt + 1))
                    except Exception:
                        pass
                    continue
                else:
                    break

        if rendered_html is None or dom_data is None:
            final_url = page.url or url
            if final_url == "about:blank":
                final_url = url
            try:
                context.close()
            except Exception:
                pass
            return {
                "agent": "Webpage Analysis Agent",
                "rendering": "playwright",
                "page_url": url,
                "final_url": final_url,
                "title": page_title or "",
                "status": "extraction_error",
                "error_detail": f"Failed to retrieve page content after retries: {last_extract_err}",
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
                    "type": "extraction_error",
                    "detail": f"Page content could not be extracted: {last_extract_err}",
                    "url": final_url
                }],
                "note": "These are investigation indicators, not proof of phishing. External resources and hidden fields can be legitimate."
            }

        try:
            context.close()
        except Exception:
            pass

        # Process domain and base resolution
        base_href = dom_data.get("base_href", "")
        effective_base = urljoin(final_url, base_href) if base_href else final_url

        parsed_page = urlparse(final_url)
        page_domain = (parsed_page.hostname or "").lower() if parsed_page.hostname else ""

        forms = dom_data.get("forms", [])
        password_fields = dom_data.get("password_inputs", [])
        hidden_fields = dom_data.get("hidden_inputs", [])
        iframes = dom_data.get("iframes", [])
        scripts = dom_data.get("scripts", [])
        links = dom_data.get("links", [])

        findings = []

        if password_fields:
            findings.append({
                "type": "password_fields",
                "count": len(password_fields),
                "detail": "Password input fields are present in rendered DOM."
            })

        if hidden_fields:
            findings.append({
                "type": "hidden_fields",
                "count": len(hidden_fields),
                "detail": "Hidden input fields are present; review their purpose."
            })

        suspicious_form_actions = []
        missing_form_actions = []
        credential_forms = []

        for form in forms:
            raw_action = form.get("raw_action")
            action = raw_action.strip() if isinstance(raw_action, str) else ""
            method = form.get("method", "get")
            has_password = form.get("passwords_count", 0) > 0
            pwd_count = form.get("passwords_count", 0)

            is_missing_action = (
                raw_action is None
                or action == ""
                or action == "#"
                or action.lower().startswith("javascript:")
            )

            if is_missing_action:
                missing_entry = {
                    "action": action if raw_action is not None else "",
                    "method": method,
                    "has_password": has_password
                }
                missing_form_actions.append(missing_entry)
                destination = final_url
                destination_domain = page_domain
            else:
                destination = form.get("resolved_action") or urljoin(effective_base, action)
                dest_parsed = urlparse(destination)
                destination_domain = (dest_parsed.hostname or "").lower()

                if page_domain and destination_domain and destination_domain != page_domain:
                    suspicious_form_actions.append({
                        "destination": destination,
                        "method": method
                    })

            if has_password:
                credential_forms.append({
                    "action": action if raw_action is not None else "",
                    "destination": destination,
                    "method": method,
                    "password_fields_count": pwd_count,
                    "is_external": bool(page_domain and destination_domain and destination_domain != page_domain),
                    "is_missing_action": is_missing_action
                })

        if credential_forms:
            findings.append({
                "type": "credential_forms",
                "count": len(credential_forms),
                "detail": "Credential-related form(s) detected; review destination and context.",
                "items": credential_forms
            })

        if missing_form_actions:
            findings.append({
                "type": "missing_form_actions",
                "count": len(missing_form_actions),
                "detail": "One or more forms have missing, empty, or placeholder action destinations.",
                "items": missing_form_actions
            })

        if suspicious_form_actions:
            findings.append({
                "type": "external_form_destinations",
                "count": len(suspicious_form_actions),
                "detail": "One or more forms submit to a different hostname.",
                "items": suspicious_form_actions
            })

        # Process external iframes
        external_iframes = []
        for iframe in iframes:
            src = iframe.get("resolved_src") or iframe.get("raw_src")
            if not src or not isinstance(src, str):
                continue
            src = src.strip()
            if not src or src.lower().startswith(("javascript:", "about:", "data:")):
                continue

            destination = urljoin(effective_base, src)
            domain = (urlparse(destination).hostname or "").lower()

            if page_domain and domain and domain != page_domain:
                external_iframes.append(destination)

        if external_iframes:
            findings.append({
                "type": "external_iframes",
                "count": len(external_iframes),
                "detail": "Iframes load content from other hostnames.",
                "items": external_iframes
            })

        # Process external scripts
        external_scripts = []
        for script in scripts:
            src = script.get("resolved_src") or script.get("raw_src")
            if not src or not isinstance(src, str):
                continue
            src = src.strip()
            if not src or src.lower().startswith(("javascript:", "data:")):
                continue

            destination = urljoin(effective_base, src)
            domain = (urlparse(destination).hostname or "").lower()

            if page_domain and domain and domain != page_domain:
                external_scripts.append(destination)

        if external_scripts:
            findings.append({
                "type": "external_scripts",
                "count": len(external_scripts),
                "detail": "Scripts are loaded from other hostnames.",
                "items": external_scripts
            })

        # Process external links
        external_links = []
        for link in links:
            href = link.get("resolved_href") or link.get("raw_href")
            if not href or not isinstance(href, str):
                continue
            href = href.strip()
            if not href or href.startswith("#") or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue

            destination = urljoin(effective_base, href)
            parsed = urlparse(destination)
            domain = (parsed.hostname or "").lower()

            if (
                parsed.scheme in ("http", "https")
                and page_domain
                and domain
                and domain != page_domain
            ):
                external_links.append(destination)

        if blocked_subresources:
            findings.append({
                "type": "blocked_subresources",
                "count": len(blocked_subresources),
                "detail": "One or more subresource requests to private or internal addresses were blocked.",
                "items": blocked_subresources
            })

        return {
            "agent": "Webpage Analysis Agent",
            "rendering": "playwright",
            "page_url": url or final_url,
            "final_url": final_url,
            "title": page_title or dom_data.get("title", ""),
            "status": "completed",
            "forms_count": len(forms),
            "password_fields_count": len(password_fields),
            "hidden_fields_count": len(hidden_fields),
            "iframes_count": len(iframes),
            "scripts_count": len(scripts),
            "external_scripts_count": len(external_scripts),
            "external_links_count": len(external_links),
            "suspicious_form_actions": suspicious_form_actions,
            "missing_form_actions": missing_form_actions,
            "credential_forms": credential_forms,
            "findings": findings,
            "note": (
                "These are investigation indicators, not proof of phishing. "
                "External resources and hidden fields can be legitimate."
            ),
            "rendered_html_length": len(rendered_html)
        }
    finally:
        if close_browser_when_done and browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if playwright_ctx is not None:
            try:
                playwright_ctx.stop()
            except Exception:
                pass


# Alias for flexible importing
analyze_webpage_playwright = analyze_rendered_webpage
