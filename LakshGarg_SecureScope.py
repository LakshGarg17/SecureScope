"""
SecureScope — Automated Web Security Scanner
Educational security-header auditing tool.
Only scan websites you own or have explicit permission to assess.
"""

import ipaddress
import json
import socket
import sqlite3
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

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


def validate_target(url):
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


def scan_website(url):
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
    except requests.exceptions.RequestException as exc:
        return {"target": url, "status": "Failed", "findings": findings, "error": f"Request failed: {exc}"}
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
    return [dict(row) for row in rows]


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
    """Generate a PDF report in memory and return bytes."""
    buffer = BytesIO()
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
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24364B")),
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
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#24364B")),
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


init_db()
st.set_page_config(page_title="SecureScope", page_icon="🔐", layout="wide")
st.title("SecureScope")
st.caption("Automated Web Security Scanner")
page = st.sidebar.radio("Navigation", ["New Scan", "Scan History"])

if page == "New Scan":
    st.info("Use only on systems you own or are explicitly authorized to assess. This is a limited header audit.")
    target = st.text_input("Target URL", placeholder="https://your-authorized-domain.example")
    if st.button("Run Security Scan", type="primary"):
        if not target.strip():
            st.warning("Enter a URL first.")
        else:
            with st.spinner("Checking HTTP response headers..."):
                result = scan_website(target.strip())
            findings = result.get("findings", [])
            score = calculate_security_score(findings) if result["status"] == "Completed" else None
            label = get_score_label(score) if score is not None else None
            risk = classify_risk(findings)
            scan_id = save_scan(result, score, label, risk)
            st.session_state["current_result"] = result
            st.session_state["current_scan_id"] = scan_id
    result = st.session_state.get("current_result")
    if result:
        st.divider()
        st.write("Target:", result.get("target"))
        st.write("Status:", result.get("status"))
        if result.get("error"):
            st.error(result["error"])
        findings = result.get("findings", [])
        if result["status"] == "Completed":
            score = calculate_security_score(findings)
            label = get_score_label(score)
            risk = classify_risk(findings)
            cols = st.columns(5)
            cols[0].metric("Hardening score", f"{score}/100")
            cols[1].metric("High", risk["High"])
            cols[2].metric("Medium", risk["Medium"])
            cols[3].metric("Low", risk["Low"])
            cols[4].metric("Informational", risk["Informational"])
            st.caption(label + ". This heuristic score is not a probability of compromise.")
            st.subheader("Findings")
            st.dataframe(pd.DataFrame(findings), use_container_width=True, hide_index=True)
            plan = generate_remediation_plan(findings)
            st.subheader("Prioritized remediation")
            if plan:
                for i, item in enumerate(plan, 1):
                    with st.expander(f"{i}. {item['check']} — {item['severity']}"):
                        st.write("Evidence:", item.get("evidence", ""))
                        st.write("Recommendation:", item.get("recommendation", ""))
            else:
                st.success("No missing headers or HTTP-only finding detected by these checks.")
            report = {
                **result, "security_score": score, "score_label": label,
                "risk_summary": risk, "remediation_plan": plan,
                "scoring_note": "Heuristic hardening score; not a probability of compromise."
            }
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            a, b, c = st.columns(3)
            a.download_button("Download JSON", json.dumps(report, indent=2),
                              file_name=f"securescope_{stamp}.json", mime="application/json")
            b.download_button("Download CSV", pd.DataFrame(findings).to_csv(index=False).encode("utf-8"),
                              file_name=f"securescope_{stamp}.csv", mime="text/csv")
            pdf = build_pdf_report(result, score, label, risk)
            c.download_button("Download PDF", pdf, file_name=f"securescope_{stamp}.pdf",
                              mime="application/pdf")

else:
    st.subheader("Scan History")
    scans = list_scans()
    if not scans:
        st.info("No scans saved yet. Run a scan from New Scan.")
    else:
        history = pd.DataFrame(scans).rename(columns={
            "id": "Scan ID", "target": "Target", "scanned_at": "Timestamp (UTC)",
            "status": "Status", "http_status": "HTTP Status", "score": "Score",
            "score_label": "Score Label"
        })
        cols = ["Scan ID", "Target", "Timestamp (UTC)", "Status", "HTTP Status", "Score", "Score Label"]
        st.dataframe(history[cols], use_container_width=True, hide_index=True)
        st.download_button("Export history CSV", history[cols].to_csv(index=False).encode("utf-8"),
                           file_name="securescope_scan_history.csv", mime="text/csv")
        options = {f"#{s['id']} | {s['target']} | {s['scanned_at']}": s["id"] for s in scans}
        label = st.selectbox("View a saved scan", list(options.keys()))
        saved = get_scan(options[label])
        if saved:
            st.write("Score:", saved["score"])
            st.write("Status:", saved["status"])
            if saved["findings"]:
                st.dataframe(pd.DataFrame(saved["findings"]), use_container_width=True, hide_index=True)
            reconstructed = {"target": saved["target"], "status": saved["status"],
                             "http_status": saved["http_status"], "findings": saved["findings"]}
            pdf = build_pdf_report(reconstructed, saved["score"], saved["score_label"], saved["risk"])
            st.download_button("Download saved scan PDF", pdf,
                               file_name=f"securescope_scan_{saved['id']}.pdf",
                               mime="application/pdf", key=f"saved_pdf_{saved['id']}")
        scored = [s for s in scans if s["score"] is not None]
        if scored:
            st.subheader("Score trend")
            target_choice = st.selectbox("Target for trend", sorted({s["target"] for s in scored}))
            trend = [s for s in scored if s["target"] == target_choice]
            trend_df = pd.DataFrame(trend)
            trend_df["scanned_at"] = pd.to_datetime(trend_df["scanned_at"], utc=True)
            trend_df = trend_df.sort_values("scanned_at").set_index("scanned_at")
            st.line_chart(trend_df["score"])
