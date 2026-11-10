# AI-Based Multi-Stage Phishing Investigation & Attack Correlation System

An explainable, multi-stage cybersecurity investigation system designed to detect, analyze, and correlate phishing threats across multiple stages of an attack lifecycle. Built with Python, Flask, Playwright, scikit-learn, and BeautifulSoup.

---

## 1. Project Title and Description

**AI-Based Multi-Stage Phishing Investigation and Attack Correlation System** is a modular defense-in-depth security framework. Rather than relying on a single opaque machine-learning prediction on a URL, this system decouples phishing investigation into distinct, specialized, and independently testable analysis agents coordinated by an Evidence Correlation engine.

The system evaluates:
1. **URL Structural & Lexical Characteristics** (Random Forest Classifier).
2. **Webpage Content & DOM Structure** (Static parsing via BeautifulSoup and dynamic JavaScript rendering via Playwright headless Chromium).
3. **HTTP Navigation & Redirect Behaviour** (Hop-by-hop tracking, cross-domain redirection, protocol downgrades, and SSRF protection).
4. **Evidence Correlation & Heuristic Triage** (Synthesizes findings, resolves conflicts, deduplicates indicators, and computes an explainable risk assessment).

---

## 2. Project Objectives

- **Multi-Stage Detection:** Corroborate indicators across URL features, webpage structure, and redirect behaviour to catch advanced phishing attacks.
- **Explainable Triage Scoring:** Generate clear, human-understandable reasoning for risk scores rather than unexplainable black-box verdicts.
- **Dynamic JavaScript Analysis:** Uncover evasive client-side cloaking, late-loaded credential forms, and hidden iframes using headless Chromium automation.
- **Defense-in-Depth Safety:** Implement strict Server-Side Request Forgery (SSRF) protections, preventing scanning agents from probing private/intranet subnets.
- **Independent & Modular Components:** Allow every agent to run standalone, via a unified interactive tester, or through REST API endpoints.

---

## 3. Features of the Webpage Analysis Agent

Implemented in `src/webpage_agent.py`, the Webpage Analysis Agent operates in two modes:

### Static Structural Analysis (`analyze_webpage`)
- Fast, safe, zero-network DOM inspection using **BeautifulSoup**.
- Discovers `<form>` elements and classifies password (`type="password"`) and hidden inputs (`type="hidden"`).
- Analyzes form destination actions against the base page hostname to identify off-domain credential submission.
- Flags missing, empty, or placeholder actions (`action=""`, `action="#"`, `javascript:`).
- Detects external `<iframe>` embeddings and third-party `<script>` tags.

### Dynamic JavaScript-Rendered Analysis (`analyze_rendered_webpage`)
- Executes modern JavaScript frameworks (React, Vue, Angular, vanilla DOM manipulation) in an isolated **Playwright headless Chromium** environment.
- Captures post-render DOM state, discovering dynamically injected forms and credential harvesting inputs.
- Inspects resolved form actions and destinations.
- **Safety & SSRF Protections:**
  - Enforces `allow_private_ips=False` by default (blocks requests to `localhost`, `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`).
  - Aborts unsafe requests to media, fonts, and unauthorized external schemes.
  - Strict navigation timeouts and settled-state verification.
  - Read-only analysis: never auto-submits forms, clicks links, or inputs credentials.

---

## 4. Features of the Behaviour Analysis Agent

Implemented in `src/behaviour_agent.py`, the Behaviour Analysis Agent audits HTTP navigation dynamics:

- **Hop-by-Hop Redirect Tracking:** Inspects redirect chains hop-by-hop (`allow_redirects=False`) to record HTTP status codes (`301`, `302`, `303`, `307`, `308`).
- **Domain Transition Auditing:** Flags cross-domain redirects (e.g., from legitimate URL shorteners to attacker landing sites).
- **Circular Loop Detection:** Detects infinite redirect loops and breaks safely.
- **Hop Limit Enforcement:** Enforces a configurable hop ceiling (default: 5 hops).
- **Transport Security Downgrade Detection:** Alerts if navigation downgrades from secure `https://` to unencrypted `http://`.
- **SSRF & Intranet Protection:** Proactively resolves hostnames at every hop and blocks attempts to navigate to local, private, or loopback addresses.

---

## 5. Project Directory Structure

```text
phishing-detector/
│
├── data/
│   ├── sample_urls.csv          # Sample seed URLs for testing fixtures
│   └── processed.parquet        # Processed feature parquet dataset
│
├── models/
│   └── baseline.joblib          # Trained Random Forest URL classification model
│
├── src/
│   ├── __init__.py              # Python package marker
│   ├── api.py                   # Flask REST API implementation
│   ├── behaviour_agent.py       # Behaviour Analysis Agent (redirects, SSRF, hops)
│   ├── webpage_agent.py         # Webpage Analysis Agent (BeautifulSoup + Playwright)
│   ├── correlation_agent.py     # Evidence Correlation Agent (multi-stage triage)
│   ├── features.py              # URL & DOM lexical feature extraction
│   ├── model.py                 # ML model loading & inference wrapper
│   ├── config.py                # Environment configuration loader
│   ├── data_processing.py       # Data transformation pipeline
│   ├── train.py                 # Model training script
│   ├── evaluate.py              # Model evaluation metrics & confusion matrix
│   ├── predict.py               # Quick CLI prediction utility
│   ├── run_agents.py            # Benchmark multi-scenario agent runner
│   ├── demo.py                  # College mini-project offline demonstration
│   ├── ml_helpers.py            # Verification and evaluation helpers
│   ├── logging_config.py        # Centralized logging configuration
│   ├── screenshot.py            # Optional visual capture helper
│   └── utils.py                 # URL validation and string helpers
│
├── tests/
│   ├── test_api.py              # Flask endpoint integration tests
│   ├── test_behaviour_agent.py  # Behaviour agent unit tests
│   ├── test_correlation_agent.py# Correlation agent unit tests
│   ├── test_data_processing.py  # Data preprocessing unit tests
│   ├── test_evaluation.py       # Model evaluation unit tests
│   ├── test_features.py         # Feature extraction unit tests
│   ├── test_integration.py     # End-to-end multi-agent pipeline tests
│   ├── test_playwright_agent.py # Dynamic browser rendering unit tests
│   └── test_webpage_agent.py    # Static HTML analysis unit tests
│
├── .env.example                 # Environment variables template
├── .gitignore                   # Git exclusion rules
├── requirements.txt             # Pinned project dependencies
├── pyproject.toml               # Pytest and tooling configuration
├── README.md                    # Project documentation
├── SECURITY.md                  # Security and disclosure policy
├── LICENSE                      # MIT License
└── test_both_agents.py          # Interactive CLI tester for Webpage & Behaviour agents
```

---

## 6. Technology Stack

- **Language:** Python 3.10+ (Tested on Python 3.11)
- **Web Framework:** Flask 2.3+
- **Machine Learning:** scikit-learn, joblib, NumPy, pandas
- **Web & DOM Parsing:** BeautifulSoup4, requests, urllib3
- **Browser Automation:** Playwright (Headless Chromium)
- **Data Serialization:** pyarrow
- **Testing Framework:** pytest

---

## 7. Prerequisites

Before installing the project, verify that your machine has:
1. **Python 3.10 or higher** installed (`python --version`).
2. **Git** installed (`git --version`).
3. An active internet connection (for downloading dependencies and Playwright Chromium).

---

## 8. Installation Instructions

Clone the repository to your local machine:

```powershell
git clone https://github.com/mantrapatil03/phishing-detector.git
cd phishing-detector
```

---

## 9. Virtual Environment Setup for Windows PowerShell

Open Windows PowerShell in the project root directory and run:

```powershell
# Create virtual environment named 'venv'
python -m venv venv

# If PowerShell script execution is restricted, temporarily enable it for your user:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

*(For Linux or macOS users: `source venv/bin/activate`)*

---

## 10. Dependency Installation

With your virtual environment activated, install the required packages:

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 11. Playwright Chromium Installation

Install the required headless Chromium browser binary used by the Webpage Analysis Agent:

```powershell
playwright install chromium
```

---

## 12. How to Run the Flask API

Start the local REST API server:

```powershell
python -m src.api
```

The server initializes on `http://127.0.0.1:5000` (or `http://localhost:5000`).

---

## 13. How to Test Each Agent Independently

### A. Test Both Agents Together (Interactive CLI)
Run the dedicated testing interface in your terminal:

```powershell
python test_both_agents.py
```

```text
========== PHISHING AGENT TESTER ==========

Enter URL: https://example.com

Running Webpage Analysis Agent...
Running Behaviour Analysis Agent...

========== WEBPAGE ANALYSIS RESULTS ==========
...
========== BEHAVIOUR ANALYSIS RESULTS ==========
...
========== TEST COMPLETED ==========

Enter another URL? (y/n): n
```

### B. Test the Webpage Analysis Agent in Python
```powershell
python -c "from src.webpage_agent import analyze_rendered_webpage; import json; print(json.dumps(analyze_rendered_webpage(url='https://example.com'), indent=2))"
```

For static HTML analysis without network access:
```powershell
python -c "from src.webpage_agent import analyze_webpage; import json; html = '<form action=\"https://bad.example/steal\"><input type=\"password\"></form>'; print(json.dumps(analyze_webpage(html, 'https://legit.example'), indent=2))"
```

### C. Test the Behaviour Analysis Agent in Python
```powershell
python -c "from src.behaviour_agent import analyze_behaviour; import json; print(json.dumps(analyze_behaviour('https://example.com'), indent=2))"
```

### D. Run Benchmark Cyber-Attack Profiles
To run a batch of real-world scenarios (legitimate portal, credential stealer, protocol downgrade, SSRF block, URL shortener):

```powershell
python -m src.run_agents
```

### E. Run Mini-Project Academic Demonstration
To run the offline college mini-project presentation walkthrough:

```powershell
python -m src.demo
```

---

## 14. How to Run the Automated Tests

The project includes 95 comprehensive unit and integration tests. Run them using `pytest`:

```powershell
# Run the entire test suite
pytest tests/ -v

# Run only Webpage and Playwright agent tests
pytest tests/test_webpage_agent.py tests/test_playwright_agent.py -v

# Run only Behaviour agent tests
pytest tests/test_behaviour_agent.py -v

# Run only Evidence Correlation tests
pytest tests/test_correlation_agent.py -v

# Run API integration tests
pytest tests/test_api.py tests/test_integration.py -v
```

All unit tests use mock network sessions and synthetic HTML fixtures, ensuring they run completely offline with zero external network traffic.

---

## 15. Example API Requests and Responses

Ensure the API is running (`python -m src.api`), then send requests using `curl` or PowerShell `Invoke-RestMethod`:

### 1. Multi-Stage Investigation (`POST /investigate`)
Runs URL classification, Webpage DOM inspection, and Behaviour tracing, correlating evidence into a unified assessment.

```powershell
curl -X POST http://127.0.0.1:5000/investigate `
  -H "Content-Type: application/json" `
  -d '{
    "url": "https://apex-university.example/login",
    "html": "<html><body><form action=\"/auth/login\" method=\"post\"><input type=\"password\" name=\"pwd\"></form></body></html>",
    "include_behaviour": false,
    "use_playwright": false
  }'
```

**Response:**
```json
{
  "agent": "Evidence Correlation Agent",
  "target_url": "https://apex-university.example/login",
  "overall_risk": "low",
  "risk_score": 0.05,
  "confidence": "medium",
  "summary": "Low risk assessment (score: 0.05, confidence: medium). Observed indicators are minimal or consistent with standard web operations.",
  "reasons": [
    "No suspicious indicators detected across available analysis modules.",
    "Evaluation performed with partial data (1 missing stream(s))."
  ],
  "supporting_indicators": [],
  "conflicting_indicators": [],
  "missing_data": [
    "Behaviour Analysis: No redirect/navigation data provided"
  ],
  "deduplicated_evidence": [],
  "agent_results": { ... }
}
```

### 2. Static Webpage Analysis (`POST /analyze-webpage`)
```powershell
curl -X POST http://127.0.0.1:5000/analyze-webpage `
  -H "Content-Type: application/json" `
  -d '{
    "html": "<form action=\"https://attacker.example/collect\" method=\"post\"><input type=\"password\"></form>",
    "url": "https://legit-site.example/login"
  }'
```

### 3. Dynamic Playwright Webpage Rendering (`POST /analyze-rendered-webpage`)
```powershell
curl -X POST http://127.0.0.1:5000/analyze-rendered-webpage `
  -H "Content-Type: application/json" `
  -d '{
    "url": "https://example.com",
    "timeout": 15.0,
    "allow_private_ips": false
  }'
```

### 4. Behaviour Analysis (`POST /analyze-behaviour`)
```powershell
curl -X POST http://127.0.0.1:5000/analyze-behaviour `
  -H "Content-Type: application/json" `
  -d '{
    "url": "https://example.com",
    "max_redirects": 5,
    "timeout": 5.0
  }'
```

### 5. URL ML Model Scan (`POST /scan`)
```powershell
curl -X POST http://127.0.0.1:5000/scan `
  -H "Content-Type: application/json" `
  -d '{"url": "https://example.com"}'
```

---

## 16. Known Limitations

- **Heuristic Scoring Model:** The Evidence Correlation Agent applies explainable heuristic rule weights designed to prioritize investigation queues; it is not a probabilistic Bayesian inference engine.
- **Dynamic Evasion (Cloaking):** Sophisticated phishing sites using browser fingerprinting, bot detection (e.g. Cloudflare Turnstile, CAPTCHAs), or delayed timers beyond the timeout window may evade automated headless rendering.
- **Offline ML Fixture:** The baseline Random Forest model (`models/baseline.joblib`) was trained on a synthetic Gaussian fixture pipeline demonstrating pipeline wiring. Real-world deployment requires continuous retraining on live threat intelligence feeds.
- **Read-Only Scope:** For defensive safety, agents do not interact with CAPTCHAs, enter credentials, or follow active exploit chains.
