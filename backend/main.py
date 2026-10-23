"""
SecureScope API — FastAPI backend for the React web security dashboard.

Use only on systems you own or have explicit permission to assess.
This is a limited HTTP response-header audit, not a penetration test.
"""
import csv
import ipaddress
import io
import json
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "securescope.db"
USER_AGENT = "SecureScope/1.0 (authorized security header audit)"
REQUEST_TIMEOUT = 10

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "recommendation": "Define a Content Security Policy suited to the application; test it in report-only mode before enforcement."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "recommendation": "After confirming HTTPS works throughout the site, configure HSTS with a suitable max-age."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "severity": "Low",
        "recommendation": "Set an appropriate framing policy, such as X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Set an appropriate Referrer-Policy, for example strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "severity": "Informational",
        "recommendation": "Restrict browser features that the application does not need."
    },
}

SEVERITY_WEIGHTS = {"High": 20, "Medium": 10, "Low": 5, "Informational": 0}
REMEDIATION_PRIORITY = {
    "HTTPS": 1,
    "Content-Security-Policy": 2,
    "Strict-Transport-Security": 3,
    "X-Frame-Options": 4,
    "X-Content-Type-Options": 5,
    "Referrer-Policy": 6,
    "Permissions-Policy": 7,
    "CORS configuration": 8,
}

app = FastAPI(
    title="SecureScope API",
    version="2.0.0",
    description="Authorized website security-header audit API."
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)


def validate_target(url: str):
    """Accept public HTTP(S) URLs and reject local/non-public address targets."""
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are supported."
        if not parsed.hostname:
            return False, "A hostname is required."
        if parsed.username or parsed.password:
            return False, "URLs containing embedded credentials are not allowed."
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False, "Invalid port."
        host = parsed.hostname.rstrip(".")
        if host.lower() == "localhost" or host.lower().endswith(".localhost"):
            return False, "Localhost targets are not allowed by the normal scanner."
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False, "Hostname could not be resolved."
        if not records:
            return False, "Hostname did not resolve to an address."
        for record in records:
            ip = ipaddress.ip_address(record[4][0])
            if not ip.is_global:
                return False, "Local, private, reserved, or non-public IP addresses are not allowed."
        return True, "Target accepted."
    except (ValueError, UnicodeError):
        return False, "Invalid URL or hostname."


def scan_website(url: str):
    """Perform a single non-following HTTP(S) response-header audit."""
    valid, message = validate_target(url)
    if not valid:
        return {"target": url, "status": "Rejected", "findings": [], "error": message}

    response = None
    findings = []
    try:
        response = requests.get(
            url.strip(),
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=True,
            stream=True,
        )
        headers = response.headers
        status_code = response.status_code
        findings.append({
            "check": "HTTP response", "severity": "Informational", "status": "Passed",
            "evidence": f"HTTP status: {status_code}",
            "recommendation": "Review the remaining findings and confirm the response is expected."
        })

        if 300 <= status_code < 400:
            findings.append({
                "check": "Redirect", "severity": "Informational", "status": "Review",
                "evidence": f"Redirect location: {headers.get('Location', 'Not provided')}",
                "recommendation": "Review the destination manually. Redirects are not followed automatically."
            })

        is_https = urlparse(url.strip()).scheme == "https"
        if is_https:
            findings.append({
                "check": "HTTPS", "severity": "Informational", "status": "Passed",
                "evidence": "TLS certificate validation succeeded for this request.",
                "recommendation": "Keep certificates valid and monitor renewal dates."
            })
        else:
            findings.append({
                "check": "HTTPS", "severity": "High", "status": "Failed",
                "evidence": "The supplied URL uses HTTP.",
                "recommendation": "Serve the site over HTTPS and redirect HTTP requests to HTTPS."
            })

        for header, info in SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                findings.append({
                    "check": header, "severity": info["severity"], "status": "Present",
                    "evidence": value,
                    "recommendation": "Review the policy value for suitability; presence alone does not prove correctness."
                })
            else:
                findings.append({
                    "check": header, "severity": info["severity"], "status": "Missing",
                    "evidence": f"{header} was not present in the response.",
                    "recommendation": info["recommendation"]
                })

        allow_origin = headers.get("Access-Control-Allow-Origin")
        allow_credentials = headers.get("Access-Control-Allow-Credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            cors_status = "Review"
            cors_severity = "Medium"
            cors_evidence = "Wildcard origin and credentials permission were both returned."
            cors_recommendation = (
                "Review the policy and actual browser behavior. Browsers reject credentialed CORS "
                "responses that use wildcard origin; this observation alone does not prove exploitability."
            )
        elif allow_origin == "*":
            cors_status = "Review"
            cors_severity = "Informational"
            cors_evidence = "Access-Control-Allow-Origin: *"
            cors_recommendation = (
                "Confirm that the resource is intentionally public and does not expose sensitive data "
                "to arbitrary origins."
            )
        elif allow_origin:
            cors_status = "Review"
            cors_severity = "Informational"
            cors_evidence = f"Access-Control-Allow-Origin: {allow_origin}"
            cors_recommendation = "Verify that allowed origins are trusted and credential permissions are appropriate."
        else:
            cors_status = "Not indicated"
            cors_severity = "Informational"
            cors_evidence = "No Access-Control-Allow-Origin header was returned."
            cors_recommendation = "CORS may be unnecessary. Test actual cross-origin behavior before drawing conclusions."

        findings.append({
            "check": "CORS configuration", "severity": cors_severity, "status": cors_status,
            "evidence": cors_evidence, "recommendation": cors_recommendation
        })
        return {
            "target": url.strip(), "status": "Completed", "http_status": status_code,
            "findings": findings, "error": None
        }
    except requests.exceptions.SSLError:
        return {"target": url, "status": "Failed", "findings": findings,
                "error": "TLS certificate validation failed. The scanner does not disable certificate verification."}
    except requests.exceptions.Timeout:
        return {"target": url, "status": "Failed", "findings": findings, "error": "The request timed out."}
    except requests.exceptions.RequestException:
        # Avoid returning low-level exception details that might contain internal host/network information.
        return {"target": url, "status": "Failed", "findings": findings, "error": "The request failed. Check reachability and try again."}
    finally:
        if response is not None:
            response.close()


def calculate_security_score(findings):
    """Transparent heuristic score; not a probability of compromise."""
    deductions = 0
    for finding in findings:
        check = finding.get("check", "")
        status = finding.get("status", "")
        severity = finding.get("severity", "Informational")
        if check == "HTTPS" and status == "Failed":
            deductions += SEVERITY_WEIGHTS["High"]
        elif status == "Missing":
            deductions += SEVERITY_WEIGHTS.get(severity, 0)
    return max(0, min(100, 100 - deductions))


def classify_risk(findings):
    summary = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        if severity in summary:
            summary[severity] += 1
    return summary


def get_score_label(score):
    if score >= 90:
        return "Strong header configuration"
    if score >= 75:
        return "Good configuration; improvements recommended"
    if score >= 50:
        return "Needs security hardening"
    return "Significant hardening gaps detected"


def generate_remediation_plan(findings):
    actionable = [
        item for item in findings
        if item.get("status") == "Missing"
        or (item.get("check") == "HTTPS" and item.get("status") == "Failed")
    ]
    return sorted(actionable, key=lambda item: REMEDIATION_PRIORITY.get(item.get("check", ""), 99))


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                status TEXT NOT NULL,
                http_status INTEGER,
                score INTEGER,
                score_label TEXT,
                risk_json TEXT NOT NULL,
                error TEXT,
                findings_json TEXT NOT NULL
            )
        """)


def save_scan(result, score=None, score_label=None, risk=None):
    risk = risk or classify_risk(result.get("findings", []))
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("""
            INSERT INTO scans
            (target, scanned_at, status, http_status, score, score_label, risk_json, error, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("target", ""),
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            result.get("status", "Unknown"),
            result.get("http_status"),
            score,
            score_label,
            json.dumps(risk),
            result.get("error"),
            json.dumps(result.get("findings", [])),
        ))
        return cur.lastrowid


def list_scans(limit=500):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT id, target, scanned_at, status, http_status, score, score_label, risk_json, error
            FROM scans ORDER BY id DESC LIMIT ?
        """, (max(1, min(int(limit), 5000)),)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["risk"] = json.loads(item.pop("risk_json"))
        output.append(item)
    return output


def get_scan(scan_id):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["risk"] = json.loads(result.pop("risk_json"))
    result["findings"] = json.loads(result.pop("findings_json"))
    return result


def build_pdf_report(scan, score=None, score_label=None, risk_summary=None):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=14*mm, leftMargin=14*mm,
                            topMargin=14*mm, bottomMargin=14*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7, leading=9))
    story = [
        Paragraph("SecureScope", styles["Title"]),
        Paragraph("Automated Web Security Scan Report", styles["Heading2"]),
        Paragraph(f"<b>Target:</b> {escape(str(scan.get('target', '—')))}", styles["BodyText"]),
        Paragraph(f"<b>Status:</b> {escape(str(scan.get('status', '—')))}", styles["BodyText"]),
        Paragraph(f"<b>Hardening score:</b> {score if score is not None else 'Not available'}/100", styles["BodyText"]),
        Paragraph(f"<b>Assessment:</b> {escape(str(score_label or 'Not scored'))}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Severity Summary", styles["Heading2"]),
    ]
    risk_summary = risk_summary or {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    risk_table = Table([
        ["High", "Medium", "Low", "Informational"],
        [str(risk_summary.get("High", 0)), str(risk_summary.get("Medium", 0)),
         str(risk_summary.get("Low", 0)), str(risk_summary.get("Informational", 0))]
    ], colWidths=[40*mm]*4)
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17253C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([risk_table, Spacer(1, 8), Paragraph("Findings and Recommendations", styles["Heading2"])])
    rows = [[Paragraph("<b>Check</b>", styles["Small"]),
             Paragraph("<b>Severity / Status</b>", styles["Small"]),
             Paragraph("<b>Evidence</b>", styles["Small"]),
             Paragraph("<b>Recommendation</b>", styles["Small"])]]
    for f in scan.get("findings", []):
        rows.append([
            Paragraph(escape(str(f.get("check", "—"))), styles["Small"]),
            Paragraph(escape(f"{f.get('severity', '—')} / {f.get('status', '—')}"), styles["Small"]),
            Paragraph(escape(str(f.get("evidence", "—"))), styles["Small"]),
            Paragraph(escape(str(f.get("recommendation", "—"))), styles["Small"]),
        ])
    table = Table(rows, colWidths=[31*mm, 30*mm, 54*mm, 54*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17253C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6F9")]),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    story.extend([
        Spacer(1, 8),
        Paragraph("Limitations", styles["Heading2"]),
        Paragraph(
            "This is a limited HTTP response-header audit, not a penetration test or a comprehensive security assessment. "
            "The hardening score is a heuristic and is not a probability of compromise. Missing headers do not by themselves "
            "prove exploitability. CORS observations require contextual and browser-side validation. Only scan systems you "
            "own or have explicit permission to assess.", styles["BodyText"]
        )
    ])
    doc.build(story)
    return buffer.getvalue()


def export_record(record):
    return {
        "id": record["id"],
        "target": record["target"],
        "scanned_at": record["scanned_at"],
        "status": record["status"],
        "http_status": record["http_status"],
        "security_score": record["score"],
        "score_label": record["score_label"],
        "risk_summary": record["risk"],
        "error": record["error"],
        "findings": record["findings"],
        "remediation_plan": generate_remediation_plan(record["findings"]),
        "scoring_note": "Heuristic hardening score; not a probability of compromise."
    }


def make_csv(findings):
    buffer = io.StringIO()
    fields = ["check", "severity", "status", "evidence", "recommendation"]
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in findings:
        writer.writerow(item)
    return buffer.getvalue().encode("utf-8-sig")


init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SecureScope API", "version": "2.0.0"}


@app.post("/api/scans")
def create_scan(payload: ScanRequest):
    target = payload.target_url.strip()
    result = scan_website(target)
    findings = result.get("findings", [])
    score = calculate_security_score(findings) if result["status"] == "Completed" else None
    label = get_score_label(score) if score is not None else None
    risk = classify_risk(findings)
    scan_id = save_scan(result, score, label, risk)
    record = get_scan(scan_id)
    return export_record(record)


@app.get("/api/scans")
def history(limit: int = Query(default=100, ge=1, le=500)):
    scans = list_scans(limit)
    return [
        {
            "id": s["id"], "target": s["target"], "scanned_at": s["scanned_at"],
            "status": s["status"], "http_status": s["http_status"], "score": s["score"],
            "score_label": s["score_label"], "risk": s["risk"], "error": s["error"]
        } for s in scans
    ]


@app.get("/api/scans/export/history.csv")
def export_history_csv(limit: int = Query(default=500, ge=1, le=500)):
    rows = list_scans(limit)
    buffer = io.StringIO()
    fields = ["id", "target", "scanned_at", "status", "http_status", "score", "score_label", "error"]
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return Response(content=buffer.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="securescope_scan_history.csv"'})


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: int):
    record = get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return export_record(record)


@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: int, format: str = Query(default="json", pattern="^(json|csv|pdf)$")):
    record = get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    data = export_record(record)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if format == "json":
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f'attachment; filename="securescope_{scan_id}_{stamp}.json"'}
        )
    if format == "csv":
        content = make_csv(record["findings"])
        return Response(content=content, media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="securescope_{scan_id}_{stamp}.csv"'})
    pdf = build_pdf_report(record, record["score"], record["score_label"], record["risk"])
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="securescope_{scan_id}_{stamp}.pdf"'})
