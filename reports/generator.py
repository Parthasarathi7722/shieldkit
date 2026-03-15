"""
ShieldKit Report Generator
Produces CSV, PDF, and HTML reports from DuckDB scan data.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime
from typing import Any


# Severity colour palette (used in PDF + HTML)
_SEV_COLORS = {
    "critical": "#dc2626",
    "high":     "#f97316",
    "medium":   "#f59e0b",
    "low":      "#3b82f6",
    "unknown":  "#6b7280",
}

_REPORT_TITLES = {
    "vulnerability": "Vulnerability Report",
    "sbom":          "SBOM Component Inventory",
    "cloud":         "Cloud Security Findings",
    "executive":     "Executive Summary",
    "full":          "Full Security Report",
}


class ReportGenerator:
    def __init__(self, conn) -> None:
        self.conn = conn

    # ── Public API ──────────────────────────────────────────────────

    def generate(self, report_type: str, fmt: str, filters: dict, title: str = "") -> tuple[str, bytes]:
        """Return (filename, content_bytes) for the requested report."""
        sections = self._collect_sections(report_type, filters)
        display_title = title or _REPORT_TITLES.get(report_type, "Security Report")

        if fmt == "csv":
            content = self._to_csv(report_type, sections)
            ext = "csv"
        elif fmt == "pdf":
            content = self._to_pdf(report_type, sections, filters, display_title)
            ext = "pdf"
        else:  # html
            content = self._to_html(report_type, sections, filters, display_title)
            ext = "html"

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"shieldkit_{report_type}_{ts}.{ext}"
        return filename, content

    # ── Data collection ──────────────────────────────────────────────

    def _collect_sections(self, report_type: str, filters: dict) -> dict[str, list[dict]]:
        sections: dict[str, list[dict]] = {}
        if report_type in ("vulnerability", "full"):
            sections["vulnerabilities"] = self._query_vulns(filters)
        if report_type in ("sbom", "full"):
            sections["sbom"] = self._query_sbom(filters)
        if report_type in ("cloud", "full"):
            sections["cloud"] = self._query_cloud(filters)
        if report_type in ("executive", "full"):
            sections["executive"] = self._query_executive(filters)
        return sections

    def _apply_date_filter(self, conditions: list, params: list, filters: dict,
                           ts_col: str = "sr.started_at") -> None:
        if filters.get("date_from"):
            conditions.append(f"{ts_col} >= ?")
            params.append(filters["date_from"])
        if filters.get("date_to"):
            conditions.append(f"{ts_col} <= ?")
            params.append(filters["date_to"])

    def _query_vulns(self, filters: dict) -> list[dict]:
        conditions: list[str] = []
        params: list[Any] = []

        self._apply_date_filter(conditions, params, filters, "sr.started_at")

        if filters.get("target"):
            conditions.append("sr.target ILIKE ?")
            params.append(f"%{filters['target']}%")

        if filters.get("severity"):
            placeholders = ",".join("?" * len(filters["severity"]))
            conditions.append(f"v.severity IN ({placeholders})")
            params.extend(filters["severity"])

        if filters.get("scan_type"):
            conditions.append("sr.scan_type = ?")
            params.append(filters["scan_type"])

        if filters.get("scan_ids"):
            placeholders = ",".join("?" * len(filters["scan_ids"]))
            conditions.append(f"v.scan_id IN ({placeholders})")
            params.extend(filters["scan_ids"])

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"""
            SELECT
                v.vuln_id, v.severity, v.cvss_score, v.package,
                v.installed_version, v.fixed_version, v.description,
                sr.target, sr.scan_type, sr.started_at
            FROM vulnerabilities v
            LEFT JOIN scan_results sr ON v.scan_id = sr.id
            {where}
            ORDER BY v.cvss_score DESC NULLS LAST, v.severity
            LIMIT 2000
        """
        return self._fetch(sql, params)

    def _query_sbom(self, filters: dict) -> list[dict]:
        conditions: list[str] = []
        params: list[Any] = []

        self._apply_date_filter(conditions, params, filters, "s.discovered_at")

        if filters.get("target"):
            conditions.append("s.target ILIKE ?")
            params.append(f"%{filters['target']}%")

        if filters.get("scan_ids"):
            placeholders = ",".join("?" * len(filters["scan_ids"]))
            conditions.append(f"s.scan_id IN ({placeholders})")
            params.extend(filters["scan_ids"])

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"""
            SELECT
                s.name, s.version, s.type, s.purl,
                s.licenses, s.target, s.discovered_at
            FROM sbom_components s
            {where}
            ORDER BY s.name
            LIMIT 5000
        """
        return self._fetch(sql, params)

    def _query_cloud(self, filters: dict) -> list[dict]:
        conditions: list[str] = []
        params: list[Any] = []

        self._apply_date_filter(conditions, params, filters, "cf.discovered_at")

        if filters.get("severity"):
            placeholders = ",".join("?" * len(filters["severity"]))
            conditions.append(f"cf.severity IN ({placeholders})")
            params.extend(filters["severity"])

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"""
            SELECT
                cf.provider, cf.service, cf.check_id, cf.check_title,
                cf.severity, cf.resource_arn, cf.status, cf.description,
                cf.remediation, cf.discovered_at
            FROM cloud_findings cf
            {where}
            ORDER BY cf.severity, cf.provider
            LIMIT 2000
        """
        return self._fetch(sql, params)

    def _query_executive(self, filters: dict) -> list[dict]:
        """Returns a list with a single dict containing aggregated stats."""
        conditions_v: list[str] = []
        params_v: list[Any] = []
        conditions_s: list[str] = []
        params_s: list[Any] = []

        if filters.get("date_from"):
            conditions_v.append("sr.started_at >= ?")
            params_v.append(filters["date_from"])
            conditions_s.append("started_at >= ?")
            params_s.append(filters["date_from"])
        if filters.get("date_to"):
            conditions_v.append("sr.started_at <= ?")
            params_v.append(filters["date_to"])
            conditions_s.append("started_at <= ?")
            params_s.append(filters["date_to"])

        where_v = "WHERE " + " AND ".join(conditions_v) if conditions_v else ""
        where_s = "WHERE " + " AND ".join(conditions_s) if conditions_s else ""

        # Severity breakdown
        sev_sql = f"""
            SELECT v.severity, COUNT(*) as cnt
            FROM vulnerabilities v
            LEFT JOIN scan_results sr ON v.scan_id = sr.id
            {where_v}
            GROUP BY v.severity ORDER BY cnt DESC
        """
        sev_rows = self._fetch(sev_sql, params_v)
        severity_counts = {r["severity"]: r["cnt"] for r in sev_rows}

        # Top-10 CVEs by CVSS
        top_sql = f"""
            SELECT v.vuln_id, v.cvss_score, v.severity, v.package, sr.target
            FROM vulnerabilities v
            LEFT JOIN scan_results sr ON v.scan_id = sr.id
            {where_v}
            ORDER BY v.cvss_score DESC NULLS LAST
            LIMIT 10
        """
        top_cves = self._fetch(top_sql, params_v)

        # Scan activity
        scan_sql = f"""
            SELECT scan_type, COUNT(*) as total,
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
                   MAX(started_at) as last_scan
            FROM scan_results
            {where_s}
            GROUP BY scan_type ORDER BY total DESC
        """
        scan_activity = self._fetch(scan_sql, params_s)

        total_vulns = sum(severity_counts.values())
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        risk_score = min(100, int((critical * 10 + high * 3) / max(total_vulns, 1) * 100))

        return [{
            "severity_counts": severity_counts,
            "top_cves": top_cves,
            "scan_activity": scan_activity,
            "total_vulns": total_vulns,
            "risk_score": risk_score,
        }]

    def _fetch(self, sql: str, params: list) -> list[dict]:
        try:
            result = self.conn.execute(sql, params)
            columns = [desc[0] for desc in result.description]
            rows = result.fetchall()
            out = []
            for row in rows:
                d = {}
                for col, val in zip(columns, row):
                    if hasattr(val, "isoformat"):
                        d[col] = val.isoformat()
                    elif isinstance(val, (list, tuple)) and not isinstance(val, str):
                        d[col] = ", ".join(str(v) for v in val)
                    else:
                        d[col] = val
                out.append(d)
            return out
        except Exception as exc:
            return [{"error": str(exc)}]

    # ── CSV ─────────────────────────────────────────────────────────

    def _to_csv(self, report_type: str, sections: dict) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)

        for section_name, rows in sections.items():
            if not rows:
                continue
            if section_name == "executive":
                exec_data = rows[0] if rows else {}
                writer.writerow([f"=== {section_name.upper()} SUMMARY ==="])
                writer.writerow(["Metric", "Value"])
                writer.writerow(["Total Vulnerabilities", exec_data.get("total_vulns", 0)])
                writer.writerow(["Risk Score", exec_data.get("risk_score", 0)])
                for sev, cnt in exec_data.get("severity_counts", {}).items():
                    writer.writerow([f"Severity: {sev}", cnt])
                writer.writerow([])
                writer.writerow(["=== TOP CVEs ==="])
                top_cves = exec_data.get("top_cves", [])
                if top_cves:
                    writer.writerow(list(top_cves[0].keys()))
                    for r in top_cves:
                        writer.writerow(list(r.values()))
                writer.writerow([])
                writer.writerow(["=== SCAN ACTIVITY ==="])
                scan_act = exec_data.get("scan_activity", [])
                if scan_act:
                    writer.writerow(list(scan_act[0].keys()))
                    for r in scan_act:
                        writer.writerow(list(r.values()))
            else:
                writer.writerow([f"=== {section_name.upper()} ==="])
                if rows and "error" not in rows[0]:
                    writer.writerow(list(rows[0].keys()))
                    for row in rows:
                        writer.writerow(list(row.values()))
            writer.writerow([])

        return buf.getvalue().encode("utf-8")

    # ── HTML ─────────────────────────────────────────────────────────

    def _to_html(self, report_type: str, sections: dict, filters: dict,
                 title: str) -> bytes:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        date_range = ""
        if filters.get("date_from") or filters.get("date_to"):
            date_range = f" | {filters.get('date_from', '')} — {filters.get('date_to', '')}"

        body_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#f8fafc;color:#1e293b;padding:32px}}
  h1{{font-size:24px;font-weight:700;margin-bottom:4px}}
  .meta{{color:#64748b;font-size:13px;margin-bottom:32px}}
  h2{{font-size:16px;font-weight:600;color:#0f172a;margin:28px 0 12px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:8px}}
  th{{background:#1e293b;color:#f8fafc;text-align:left;padding:7px 10px;font-weight:600}}
  td{{padding:6px 10px;border-bottom:1px solid #e2e8f0}}
  tr:nth-child(even){{background:#f1f5f9}}
  .sev-critical{{background:#fef2f2;color:#dc2626;font-weight:700;padding:2px 6px;border-radius:4px}}
  .sev-high{{background:#fff7ed;color:#f97316;font-weight:700;padding:2px 6px;border-radius:4px}}
  .sev-medium{{background:#fffbeb;color:#d97706;font-weight:700;padding:2px 6px;border-radius:4px}}
  .sev-low{{background:#eff6ff;color:#3b82f6;font-weight:700;padding:2px 6px;border-radius:4px}}
  .sev-unknown{{background:#f8fafc;color:#6b7280;padding:2px 6px;border-radius:4px}}
  .kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin:16px 0}}
  .kpi{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center}}
  .kpi-val{{font-size:28px;font-weight:700;color:#0f172a}}
  .kpi-lbl{{font-size:12px;color:#64748b;margin-top:4px}}
  .empty{{color:#94a3b8;font-style:italic;padding:12px 0}}
  @media print{{body{{padding:16px}}h2{{page-break-before:auto}}.kpi-grid{{grid-template-columns:repeat(4,1fr)}}}}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="meta">Generated {now}{date_range}</div>
"""]

        for section_name, rows in sections.items():
            if section_name == "executive":
                exec_data = rows[0] if rows else {}
                sev_counts = exec_data.get("severity_counts", {})
                body_parts.append("<h2>Executive Summary</h2>")
                body_parts.append('<div class="kpi-grid">')
                body_parts.append(f'<div class="kpi"><div class="kpi-val">{exec_data.get("total_vulns",0)}</div><div class="kpi-lbl">Total Vulnerabilities</div></div>')
                body_parts.append(f'<div class="kpi"><div class="kpi-val" style="color:#dc2626">{sev_counts.get("critical",0)}</div><div class="kpi-lbl">Critical</div></div>')
                body_parts.append(f'<div class="kpi"><div class="kpi-val" style="color:#f97316">{sev_counts.get("high",0)}</div><div class="kpi-lbl">High</div></div>')
                body_parts.append(f'<div class="kpi"><div class="kpi-val" style="color:#d97706">{sev_counts.get("medium",0)}</div><div class="kpi-lbl">Medium</div></div>')
                body_parts.append(f'<div class="kpi"><div class="kpi-val" style="color:#3b82f6">{sev_counts.get("low",0)}</div><div class="kpi-lbl">Low</div></div>')
                body_parts.append(f'<div class="kpi"><div class="kpi-val">{exec_data.get("risk_score",0)}</div><div class="kpi-lbl">Risk Score</div></div>')
                body_parts.append("</div>")

                top_cves = exec_data.get("top_cves", [])
                if top_cves:
                    body_parts.append("<h2>Top 10 Vulnerabilities by CVSS</h2>")
                    body_parts.append(self._html_table(top_cves, sev_col="severity"))

                scan_act = exec_data.get("scan_activity", [])
                if scan_act:
                    body_parts.append("<h2>Scan Activity</h2>")
                    body_parts.append(self._html_table(scan_act))

            elif section_name == "vulnerabilities":
                body_parts.append(f"<h2>Vulnerabilities ({len(rows)} found)</h2>")
                if rows:
                    body_parts.append(self._html_table(rows, sev_col="severity"))
                else:
                    body_parts.append('<div class="empty">No vulnerabilities found for the selected filters.</div>')

            elif section_name == "sbom":
                body_parts.append(f"<h2>SBOM Components ({len(rows)} found)</h2>")
                if rows:
                    body_parts.append(self._html_table(rows))
                else:
                    body_parts.append('<div class="empty">No SBOM components found.</div>')

            elif section_name == "cloud":
                body_parts.append(f"<h2>Cloud Findings ({len(rows)} found)</h2>")
                if rows:
                    body_parts.append(self._html_table(rows, sev_col="severity"))
                else:
                    body_parts.append('<div class="empty">No cloud findings found.</div>')

        body_parts.append("</body></html>")
        return "".join(body_parts).encode("utf-8")

    def _html_table(self, rows: list[dict], sev_col: str = "") -> str:
        if not rows or "error" in rows[0]:
            return '<div class="empty">No data.</div>'
        cols = list(rows[0].keys())
        out = ["<table><thead><tr>"]
        for col in cols:
            out.append(f"<th>{col}</th>")
        out.append("</tr></thead><tbody>")
        for row in rows:
            out.append("<tr>")
            for col in cols:
                val = row.get(col, "")
                if col == sev_col and isinstance(val, str):
                    css = f"sev-{val.lower()}"
                    out.append(f'<td><span class="{css}">{val}</span></td>')
                else:
                    safe = str(val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    out.append(f"<td>{safe}</td>")
            out.append("</tr>")
        out.append("</tbody></table>")
        return "".join(out)

    # ── PDF ──────────────────────────────────────────────────────────

    def _to_pdf(self, report_type: str, sections: dict, filters: dict,
                title: str) -> bytes:
        try:
            from fpdf import FPDF
        except ImportError:
            # Graceful fallback: return HTML as PDF is unavailable
            return self._to_html(report_type, sections, filters, title)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Cover page header
        pdf.set_fill_color(15, 23, 42)   # #0f172a
        pdf.rect(0, 0, 210, 40, "F")
        pdf.set_text_color(248, 250, 252)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_xy(10, 12)
        pdf.cell(190, 10, title, align="C")

        pdf.set_font("Helvetica", "", 10)
        pdf.set_xy(10, 26)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        date_range = ""
        if filters.get("date_from") or filters.get("date_to"):
            date_range = f"  |  {filters.get('date_from','')} — {filters.get('date_to','')}"
        pdf.cell(190, 8, f"Generated: {now}{date_range}", align="C")

        pdf.set_text_color(30, 41, 59)
        pdf.set_xy(10, 48)

        for section_name, rows in sections.items():
            if section_name == "executive":
                exec_data = rows[0] if rows else {}
                sev_counts = exec_data.get("severity_counts", {})
                self._pdf_section_header(pdf, "Executive Summary")

                # KPI row
                kpis = [
                    ("Total Vulns", exec_data.get("total_vulns", 0), (30, 41, 59)),
                    ("Critical", sev_counts.get("critical", 0), (220, 38, 38)),
                    ("High", sev_counts.get("high", 0), (249, 115, 22)),
                    ("Medium", sev_counts.get("medium", 0), (245, 158, 11)),
                    ("Low", sev_counts.get("low", 0), (59, 130, 246)),
                    ("Risk Score", exec_data.get("risk_score", 0), (30, 41, 59)),
                ]
                col_w = 30
                x_start = 10
                y = pdf.get_y()
                for i, (lbl, val, color) in enumerate(kpis):
                    x = x_start + i * col_w
                    pdf.set_fill_color(248, 250, 252)
                    pdf.rect(x, y, col_w - 2, 16, "FD")
                    pdf.set_text_color(*color)
                    pdf.set_font("Helvetica", "B", 14)
                    pdf.set_xy(x, y + 2)
                    pdf.cell(col_w - 2, 7, str(val), align="C")
                    pdf.set_text_color(100, 116, 139)
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_xy(x, y + 9)
                    pdf.cell(col_w - 2, 5, lbl, align="C")
                pdf.set_xy(10, y + 20)

                top_cves = exec_data.get("top_cves", [])
                if top_cves:
                    self._pdf_section_header(pdf, "Top 10 Vulnerabilities by CVSS")
                    cols = [
                        ("vuln_id", 40), ("package", 35), ("severity", 22),
                        ("cvss_score", 20), ("target", 55),
                    ]
                    self._pdf_table(pdf, top_cves, cols, sev_col="severity")

                scan_act = exec_data.get("scan_activity", [])
                if scan_act:
                    self._pdf_section_header(pdf, "Scan Activity")
                    cols = [("scan_type", 40), ("total", 25), ("completed", 30), ("last_scan", 80)]
                    self._pdf_table(pdf, scan_act, cols)

            elif section_name == "vulnerabilities":
                self._pdf_section_header(pdf, f"Vulnerabilities ({len(rows)} found)")
                if rows:
                    cols = [
                        ("vuln_id", 38), ("package", 30), ("severity", 20),
                        ("cvss_score", 18), ("installed_version", 22),
                        ("fixed_version", 22), ("target", 30),
                    ]
                    self._pdf_table(pdf, rows, cols, sev_col="severity")

            elif section_name == "sbom":
                self._pdf_section_header(pdf, f"SBOM Components ({len(rows)} found)")
                if rows:
                    cols = [
                        ("name", 45), ("version", 25), ("type", 20),
                        ("licenses", 40), ("target", 40), ("purl", 0),
                    ]
                    self._pdf_table(pdf, rows, cols)

            elif section_name == "cloud":
                self._pdf_section_header(pdf, f"Cloud Findings ({len(rows)} found)")
                if rows:
                    cols = [
                        ("provider", 20), ("service", 25), ("severity", 20),
                        ("check_title", 60), ("resource_arn", 45), ("status", 20),
                    ]
                    self._pdf_table(pdf, rows, cols, sev_col="severity")

        return pdf.output()

    def _pdf_section_header(self, pdf, text: str) -> None:
        pdf.ln(4)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(248, 250, 252)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(190, 8, text, fill=True, ln=True)
        pdf.set_text_color(30, 41, 59)
        pdf.ln(2)

    def _pdf_table(self, pdf, rows: list[dict], cols: list[tuple],
                   sev_col: str = "") -> None:
        if not rows:
            return
        # Header row
        pdf.set_fill_color(51, 65, 85)
        pdf.set_text_color(248, 250, 252)
        pdf.set_font("Helvetica", "B", 7)
        available_w = 190
        fixed_w = sum(w for _, w in cols if w > 0)
        flex_cols = sum(1 for _, w in cols if w == 0)
        flex_w = (available_w - fixed_w) // max(flex_cols, 1) if flex_cols else 0

        col_widths = [w if w > 0 else flex_w for _, w in cols]
        col_keys = [k for k, _ in cols]

        for key, width in zip(col_keys, col_widths):
            pdf.cell(width, 6, key.replace("_", " ").title(), fill=True, border=0)
        pdf.ln()

        # Data rows
        pdf.set_font("Helvetica", "", 7)
        for i, row in enumerate(rows):
            if pdf.get_y() > 270:
                pdf.add_page()
                pdf.set_xy(10, 15)

            fill = i % 2 == 0
            if fill:
                pdf.set_fill_color(241, 245, 249)
            else:
                pdf.set_fill_color(255, 255, 255)

            row_y = pdf.get_y()
            for key, width in zip(col_keys, col_widths):
                raw_val = str(row.get(key, "") or "")
                # Sanitize: fpdf2 core fonts are latin-1 only
                val = raw_val.encode("latin-1", errors="replace").decode("latin-1")
                if key == sev_col:
                    sev = val.lower()
                    color_hex = _SEV_COLORS.get(sev, _SEV_COLORS["unknown"])
                    r, g, b = int(color_hex[1:3], 16), int(color_hex[3:5], 16), int(color_hex[5:7], 16)
                    pdf.set_text_color(r, g, b)
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.cell(width, 5, val[:20], fill=fill, border=0)
                    pdf.set_text_color(30, 41, 59)
                    pdf.set_font("Helvetica", "", 7)
                else:
                    # Truncate long values; strip non-latin-1 chars (fpdf2 core fonts)
                    max_chars = max(int(width / 1.8), 8)
                    truncated = val[:max_chars] + "..." if len(val) > max_chars else val
                    safe = truncated.encode("latin-1", errors="replace").decode("latin-1")
                    pdf.cell(width, 5, safe, fill=fill, border=0)
            pdf.ln()

        pdf.ln(3)
