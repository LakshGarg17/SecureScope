# SecureScope — Automated Web Security Scanner

**Author:** Laksh Garg  
**Program:** IBM SkillsBuild Cyber Security 2026 — BharatCares  
**Project type:** Defensive web security configuration auditing tool

> **Responsible use:** SecureScope is intended for education and authorized defensive assessment. Scan only systems you own or have explicit permission to assess.

## 1. Project Overview

SecureScope is a web application that helps users review selected HTTP response security settings. It uses a **React + Vite frontend** and a **Python FastAPI backend**. The backend inspects selected security headers, observes HTTPS/TLS certificate-validation outcomes, records preliminary CORS-related information, calculates a transparent heuristic hardening score, provides remediation guidance, stores scan history in SQLite, and supports report exports.

SecureScope is a limited response-header auditing tool. It is **not** a full vulnerability scanner, penetration-testing platform, or guarantee that a website is secure.

## 2. Features

- React dashboard for submitting URLs and reviewing scan results.
- FastAPI REST API for scanning and retrieving stored results.
- HTTPS/TLS certificate-validation observation; HTTP URLs are flagged.
- Checks for selected response headers:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Preliminary observations of CORS-related response headers.
- Explainable hardening score, severity summary, and remediation suggestions.
- SQLite-backed scan history.
- JSON, CSV, and PDF exports, plus CSV export of scan history.

## 3. Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Dashboard visualization | Recharts |
| Interface icons | Lucide React |
| Backend/API | Python, FastAPI, Uvicorn, Pydantic |
| HTTP requests | Requests |
| Database | SQLite |
| PDF generation | ReportLab |
| Other output formats | JSON and CSV |

## 4. Dataset

No external static dataset is required. SecureScope uses live HTTP response metadata returned by the authorized target at scan time. It does not train a machine-learning model.

## 5. Scoring Methodology

The score starts at **100** and applies the following deductions:

| Condition | Deduction |
|---|---:|
| HTTP instead of HTTPS | 20 points |
| Each missing Medium-severity header | 10 points |
| Each missing Low-severity header | 5 points |
| Informational finding | 0 points |

The score is clamped to the range 0–100. In the current implementation, `Content-Security-Policy` and `Strict-Transport-Security` are Medium severity; `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are Low severity; and `Permissions-Policy` is Informational.

This score is a learning-oriented hardening heuristic. It is not a standardized security rating or a probability of compromise. Header presence alone does not prove that a site is secure.

## 6. Requirements

- Python 3.10 or newer.
- Node.js 18 or newer and npm.
- Internet access for scans of authorized public targets.

## 7. Installation and Setup

Clone the repository, or download the project source. The commands below assume the repository contains `backend/` and `frontend/` directories.

### Start the backend — Windows PowerShell

Open a terminal in the project root and run:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

If PowerShell blocks virtual-environment activation, these commands still work because they call the virtual environment's Python executable directly.

### Start the frontend

Open a **second terminal** in the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open the local frontend URL printed by Vite, normally `http://localhost:5173`.

### macOS/Linux

Backend:

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Frontend, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

## 8. API Endpoints

With the backend running, interactive API documentation is available at `http://127.0.0.1:8000/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Backend health check |
| `POST` | `/api/scans` | Run a scan and save the result |
| `GET` | `/api/scans?limit=100` | List recent scans |
| `GET` | `/api/scans/{id}` | Retrieve a saved scan |
| `GET` | `/api/scans/{id}/export?format=json` | Export a scan as JSON |
| `GET` | `/api/scans/{id}/export?format=csv` | Export findings as CSV |
| `GET` | `/api/scans/{id}/export?format=pdf` | Export a scan as PDF |
| `GET` | `/api/scans/export/history.csv` | Export scan history as CSV |

Health-check URL: `http://127.0.0.1:8000/api/health`

## 9. Storage

The backend creates a local SQLite database at `backend/securescope.db` when it is first run. Scan history and findings are saved there. Do not commit the database to a public repository if it contains real target URLs or sensitive scan information.

## 10. Security Notes and Limitations

- The scanner performs a limited set of response-header checks; it does not perform a full penetration test.
- TLS certificate verification being enabled is not the same as a complete TLS configuration audit.
- CORS header observations need application-specific and browser-side validation.
- Redirects are not automatically followed by the scanner.
- URL and DNS validation can reduce risk but cannot, by themselves, eliminate DNS-rebinding or time-of-check/time-of-use server-side request forgery (SSRF) risks.
- Do not expose the scanner as an unrestricted public URL-fetching service. Before public deployment, add connection-time destination enforcement, outbound network restrictions, safe redirect handling, rate limiting, and abuse prevention.
- The local CORS allowlist is configured for development/preview origins. Update it deliberately when deploying to another frontend origin.
- Scan only systems you own or have explicit authorization to assess.

## 11. Testing Status

The frontend and backend have been started successfully in the developer's local environment. This confirms startup, but does not by itself establish that every scanning, history, export, error-handling, or security-protection feature has passed end-to-end testing. Test those workflows and document the actual results before claiming they all pass.

## 12. Repository

After uploading this project to GitHub, add the public repository URL here:

**GitHub:** `REPLACE_WITH_YOUR_PUBLIC_GITHUB_REPOSITORY_URL`

## 13. Project Structure

```text
SecureScope_React_FastAPI/
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       └── styles.css
├── README.md
├── LakshGarg_ProjectReport.docx
├── .gitignore
└── LICENSE
```

## 14. License

Refer to the repository's `LICENSE` file for the applicable license terms.
