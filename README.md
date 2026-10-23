# SecureScope — Automated Web Security Scanner

**Project submission:** IBM SkillsBuild Cyber Security 2026 — BharatCares  
**Author:** Laksh Garg

## Project description
SecureScope is a Python and Streamlit application that audits HTTP response headers and selected transport/CORS indicators for a URL that the user is authorized to assess. It presents findings, a transparent heuristic hardening score, prioritized remediation suggestions, and downloadable JSON, CSV, and PDF reports. It stores scan history locally in SQLite and can chart score trends for repeated scans of the same URL.

## Features
- HTTPS certificate-validation observation and HTTP-only warning
- Checks for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy
- Preliminary CORS response-header observations
- Severity summary and explainable hardening score
- Remediation guidance
- Local SQLite scan history and score-trend chart
- JSON, CSV, and PDF exports

## Dataset
**No external dataset is required.** SecureScope analyzes HTTP response headers returned at scan time from the user-supplied authorized URL. The response data is collected live, not trained on a static dataset. For demonstrations, use a website you own or a deliberately configured local test server. Do not scan systems without authorization.

## Technologies
- Python 3
- Requests
- Streamlit
- Pandas
- SQLite (`sqlite3`, part of Python)
- ReportLab

## Setup (Windows PowerShell)
```powershell
cd D:\Projects\SecureScope
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run
```powershell
python -m streamlit run LakshGarg_SecureScope.py
```
Open the local address printed by Streamlit, normally `http://localhost:8501`.

## Output files
- `securescope.db` — generated local scan-history database
- JSON report — complete scan metadata and findings
- CSV report — findings in tabular format
- PDF report — summary, severity counts, findings, evidence, recommendations, and limitations

## How scoring works
The hardening score begins at 100. The current heuristic subtracts 20 points for an HTTP-only URL, 10 points for each missing medium-severity header, and 5 points for each missing low-severity header. The score is bounded between 0 and 100. Informational observations do not deduct points. This is an educational heuristic, not a standardized rating or a probability of compromise. A present header is not necessarily configured correctly.

## Security and limitations
- Only scan websites you own or have explicit permission to assess.
- This tool performs a limited response-header audit; it is not a penetration test or full vulnerability scanner.
- CORS observations require application context and browser-side validation.
- The scanner does not follow redirects automatically.
- URL/DNS validation reduces accidental access to private targets but cannot eliminate every DNS-rebinding or server-side request forgery edge case. Do not deploy this app as an unrestricted public URL-fetching service.
- The local SQLite database may contain target names and scan details; do not commit it to a public repository.

## Project code
The submitted `LakshGarg_SecureScope.py` is a self-contained Streamlit application including scanner logic, scoring, SQLite persistence, and report generation. The notebook companion `LakshGarg_SecureScope.ipynb` documents the workflow and provides testable examples.

## Future enhancements
- Add mocked unit tests for HTTP responses and more URL validation edge cases
- Validate response security policies more deeply
- Add authenticated users and rate limiting before any hosted deployment
- Compare historical results after normalizing URLs and redirect behavior
