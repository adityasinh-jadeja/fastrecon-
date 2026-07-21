"""
FastRecon Reporter — JSON, HTML, and CSV report generation with severity grading.
Supports timestamped export for structured reporting and integration.
"""

import csv
import io
import json
import os
from datetime import datetime, timezone


def generate_report(
    target,
    scan_duration,
    subdomains,
    live_hosts,
    alerts,
    cloud_buckets,
    dns_info=None,
    open_ports=None,
    ssl_info=None,
    technologies=None,
    tech_insights=None,
    endpoints=None,
    js_files=None,
    api_endpoints=None,
    html_links=None,
    vulnerabilities=None,
    header_report=None,
    robots_paths=None,
    sitemap_urls=None,
    well_known=None,
    scan_mode="normal",
):
    """
    Build the comprehensive JSON report from all scan results.

    Returns:
        Report dict ready for JSON serialization
    """
    takeover_count = sum(1 for a in alerts if a.get("type") == "Subdomain Takeover")
    open_bucket_count = sum(1 for b in (cloud_buckets or []) if b.get("status") == "PUBLIC")
    vuln_count = len(vulnerabilities) if vulnerabilities else 0
    port_count = len(open_ports) if open_ports else 0

    # Calculate overall risk score
    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low = sum(1 for a in alerts if a.get("severity") == "LOW")

    risk_score = (critical * 40) + (high * 20) + (medium * 10) + (low * 3)
    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    report = {
        "target": target,
        "scanDate": datetime.now(timezone.utc).isoformat() + "Z",
        "scanDuration": scan_duration,
        "scanMode": scan_mode,
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "stats": {
            "subdomainsDiscovered": len(subdomains) if subdomains else 0,
            "liveHosts": len(live_hosts) if live_hosts else 0,
            "takeoversFound": takeover_count,
            "openBuckets": open_bucket_count,
            "openPorts": port_count,
            "vulnerabilities": vuln_count,
            "totalAlerts": len(alerts),
            "criticalAlerts": critical,
            "highAlerts": high,
            "mediumAlerts": medium,
            "lowAlerts": low,
        },
        "alerts": alerts,
        "liveHosts": live_hosts or [],
        "cloudBuckets": cloud_buckets or [],
        "dnsInfo": dns_info or {},
        "openPorts": open_ports or [],
        "sslInfo": ssl_info or {},
        "technologies": technologies or [],
        "techInsights": tech_insights or [],
        "endpoints": endpoints or [],
        "jsFiles": js_files or [],
        "apiEndpoints": api_endpoints or [],
        "htmlLinks": html_links or [],
        "vulnerabilities": vulnerabilities or [],
        "headerReport": header_report or {},
        "robotsPaths": robots_paths or [],
        "sitemapUrls": sitemap_urls or [],
        "wellKnown": well_known or {},
    }

    return report


def save_report(report, output_file):
    """Write the report dict to a JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True) if os.path.dirname(output_file) else None
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    print(f"\n  📄 JSON report saved to {output_file}")


def generate_csv_report(report, output_dir=None):
    """
    Generate CSV files from scan results.
    Creates three CSV files: alerts, subdomains (live hosts), and endpoints.

    Args:
        report: Full scan report dict
        output_dir: Directory to save CSV files (optional — returns strings if None)

    Returns:
        Dict of {filename: csv_string} if output_dir is None,
        or dict of {filename: filepath} if output_dir is given.
    """
    target = report.get("target", "unknown")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_")
    results = {}

    # --- Alerts CSV ---
    alerts_buf = io.StringIO()
    writer = csv.writer(alerts_buf)
    writer.writerow(["Severity", "Type", "Asset", "Service", "Details", "Evidence", "Remediation", "Time"])
    for alert in report.get("alerts", []):
        writer.writerow([
            alert.get("severity", ""),
            alert.get("type", ""),
            alert.get("asset", ""),
            alert.get("service", ""),
            alert.get("details", ""),
            alert.get("evidence", ""),
            alert.get("remediation", ""),
            alert.get("time", ""),
        ])
    alerts_name = f"{safe_target}_{timestamp}_alerts.csv"
    results[alerts_name] = alerts_buf.getvalue()

    # --- Subdomains / Live Hosts CSV ---
    hosts_buf = io.StringIO()
    writer = csv.writer(hosts_buf)
    writer.writerow(["Subdomain", "URL", "Status Code", "Title", "Server", "Powered By", "Content Length"])
    for host in report.get("liveHosts", []):
        writer.writerow([
            host.get("subdomain", ""),
            host.get("url", ""),
            host.get("status", ""),
            host.get("title", ""),
            host.get("server", ""),
            host.get("poweredBy", ""),
            host.get("contentLength", ""),
        ])
    hosts_name = f"{safe_target}_{timestamp}_subdomains.csv"
    results[hosts_name] = hosts_buf.getvalue()

    # --- Endpoints CSV ---
    endpoints_buf = io.StringIO()
    writer = csv.writer(endpoints_buf)
    writer.writerow(["Path", "URL", "Status Code", "Severity", "Type", "Content Length", "Redirect"])
    for ep in report.get("endpoints", []):
        writer.writerow([
            ep.get("path", ""),
            ep.get("url", ""),
            ep.get("status", ""),
            ep.get("severity", ""),
            ep.get("type", ""),
            ep.get("contentLength", ""),
            ep.get("redirect", ""),
        ])
    endpoints_name = f"{safe_target}_{timestamp}_endpoints.csv"
    results[endpoints_name] = endpoints_buf.getvalue()

    # Save to files if output_dir provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        file_results = {}
        for filename, content in results.items():
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            file_results[filename] = filepath
        print(f"  📄 CSV reports saved to {output_dir}/")
        return file_results

    return results


def save_timestamped_report(report, base_dir="reports"):
    """
    Save report with timestamped filenames for structured export.
    Creates: {target}_{YYYYMMDD_HHMMSS}.json and matching CSVs.

    Args:
        report: Full scan report dict
        base_dir: Base directory for reports

    Returns:
        Dict of saved file paths
    """
    os.makedirs(base_dir, exist_ok=True)
    target = report.get("target", "unknown")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_")

    saved = {}

    # Timestamped JSON
    json_file = os.path.join(base_dir, f"{safe_target}_{timestamp}.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    saved["json"] = json_file

    # CSV files
    csv_files = generate_csv_report(report, output_dir=base_dir)
    saved["csv"] = csv_files

    print(f"  📄 Timestamped reports saved to {base_dir}/")
    return saved


def generate_html_report(report, output_file=None):
    """
    Generate a self-contained HTML report from the scan results.
    Returns HTML string, and optionally saves to file.
    """
    target = report.get("target", "Unknown")
    scan_date = report.get("scanDate", "")
    duration = report.get("scanDuration", "N/A")
    risk_score = report.get("riskScore", 0)
    risk_level = report.get("riskLevel", "CLEAN")
    stats = report.get("stats", {})
    mode = report.get("scanMode", "normal")

    risk_colors = {
        "CRITICAL": "#ef476f", "HIGH": "#f77f00",
        "MEDIUM": "#ffd166", "LOW": "#06d6a0", "CLEAN": "#06d6a0",
    }
    risk_color = risk_colors.get(risk_level, "#06d6a0")

    # Build alerts HTML
    alerts_html = ""
    for alert in report.get("alerts", []):
        sev = alert.get("severity", "INFO")
        sev_color = {"CRITICAL": "#ef476f", "HIGH": "#f77f00", "MEDIUM": "#ffd166", "LOW": "#06d6a0"}.get(sev, "#6c757d")
        remediation = alert.get("remediation", "")
        remediation_html = f'<div class="remediation"><strong>Fix:</strong> {_esc(remediation)}</div>' if remediation else ""
        alerts_html += f"""
        <div class="alert-card" style="border-left: 4px solid {sev_color};">
            <div class="alert-header">
                <span class="severity-badge" style="background: {sev_color};">{_esc(sev)}</span>
                <span class="alert-type">{_esc(alert.get('type', ''))}</span>
            </div>
            <div class="alert-asset"><strong>Asset:</strong> {_esc(alert.get('asset', ''))}</div>
            <div class="alert-details">{_esc(alert.get('details', ''))}</div>
            <div class="alert-evidence"><strong>Evidence:</strong> <code>{_esc(alert.get('evidence', '')[:200])}</code></div>
            {remediation_html}
        </div>
        """

    # Build open ports HTML
    ports_html = ""
    for port in report.get("openPorts", []):
        port_num = port.get("port", 0)
        is_dangerous = port_num in [6379, 27017, 9200, 11211, 5900, 3389, 23, 445]
        row_class = "dangerous-port" if is_dangerous else ""
        ports_html += f"""
        <tr class="{row_class}">
            <td>{port_num}</td>
            <td>{_esc(port.get('service', 'Unknown'))}</td>
            <td><span class="status-open">OPEN</span></td>
            <td>{_esc(port.get('banner', '')[:80])}</td>
        </tr>
        """

    # Build endpoints HTML
    endpoints_html = ""
    for ep in report.get("endpoints", [])[:50]:
        sev = ep.get("severity", "INFO")
        sev_color = {"CRITICAL": "#ef476f", "HIGH": "#f77f00", "MEDIUM": "#ffd166", "LOW": "#06d6a0"}.get(sev, "#6c757d")
        endpoints_html += f"""
        <tr>
            <td><span class="severity-badge-sm" style="background: {sev_color};">{_esc(sev)}</span></td>
            <td><code>{_esc(ep.get('path', ''))}</code></td>
            <td>{ep.get('status', '')}</td>
            <td>{_esc(ep.get('type', ''))}</td>
        </tr>
        """

    # Build technologies HTML
    tech_html = ""
    for tech in report.get("technologies", []):
        conf = tech.get("confidence", 0)
        bar_color = "#06d6a0" if conf >= 70 else "#ffd166" if conf >= 40 else "#ef476f"
        tech_html += f"""
        <div class="tech-item">
            <div class="tech-name">{_esc(tech.get('name', ''))}</div>
            <div class="tech-category">{_esc(tech.get('category', ''))}</div>
            <div class="confidence-bar"><div class="confidence-fill" style="width: {conf}%; background: {bar_color};"></div></div>
            <div class="confidence-text">{conf}%</div>
        </div>
        """

    # Build header analysis HTML
    header_report_data = report.get("headerReport", {})
    header_grade = header_report_data.get("grade", "N/A")
    header_score = header_report_data.get("score", 0)
    header_color = header_report_data.get("gradeColor", "#6c757d")
    headers_detail_html = ""
    for h_name, h_data in header_report_data.get("headers", {}).items():
        present = h_data.get("present", False)
        status_class = "header-present" if present else "header-missing"
        status_text = h_data.get("value", "MISSING")[:80] if present else "MISSING"
        icon = "✓" if present else "✗"
        headers_detail_html += f"""
        <tr class="{status_class}">
            <td>{icon} {_esc(h_name)}</td>
            <td><code>{_esc(status_text)}</code></td>
            <td>{_esc(h_data.get('description', ''))}</td>
        </tr>
        """

    # Build cloud buckets HTML
    buckets_html = ""
    for bucket in report.get("cloudBuckets", []):
        b_status = bucket.get("status", "")
        status_class = "bucket-public" if b_status == "PUBLIC" else "bucket-private"
        buckets_html += f"""
        <tr class="{status_class}">
            <td>{_esc(bucket.get('name', ''))}</td>
            <td>{_esc(bucket.get('provider', ''))}</td>
            <td><span class="status-{b_status.lower()}">{_esc(b_status)}</span></td>
            <td><a href="{_esc(bucket.get('url', ''))}" target="_blank">View</a></td>
        </tr>
        """

    # Build vulnerabilities HTML
    vulns_html = ""
    for vuln in report.get("vulnerabilities", []):
        sev = vuln.get("severity", "INFO")
        sev_color = {"CRITICAL": "#ef476f", "HIGH": "#f77f00", "MEDIUM": "#ffd166", "LOW": "#06d6a0"}.get(sev, "#6c757d")
        remediation = vuln.get("remediation", "")
        remediation_html = f'<div class="remediation"><strong>How to Fix:</strong> {_esc(remediation)}</div>' if remediation else ""
        vulns_html += f"""
        <div class="vuln-card" style="border-left: 4px solid {sev_color};">
            <div class="vuln-header">
                <span class="severity-badge" style="background: {sev_color};">{_esc(sev)}</span>
                <span class="vuln-type">{_esc(vuln.get('type', ''))}</span>
            </div>
            <div class="vuln-details">{_esc(vuln.get('details', ''))}</div>
            <div class="vuln-evidence"><strong>Evidence:</strong> <code>{_esc(vuln.get('evidence', '')[:200])}</code></div>
            {remediation_html}
        </div>
        """

    # Full HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FastRecon Report — {_esc(target)}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0a0e17; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ font-size: 2rem; font-weight: 800; background: linear-gradient(135deg, #06d6a0, #118ab2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 5px; }}
        h2 {{ font-size: 1.3rem; font-weight: 700; color: #06d6a0; margin: 30px 0 15px; padding-bottom: 8px; border-bottom: 1px solid rgba(6,214,160,0.2); }}
        h3 {{ font-size: 1.1rem; color: #94a3b8; margin-bottom: 10px; }}
        .header {{ text-align: center; padding: 30px 0; border-bottom: 1px solid rgba(255,255,255,0.06); margin-bottom: 30px; }}
        .meta {{ color: #64748b; font-size: 0.85rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 30px; }}
        .stat-card {{ background: rgba(17,24,39,0.7); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; padding: 16px; text-align: center; }}
        .stat-value {{ font-size: 1.8rem; font-weight: 800; }}
        .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
        .risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 20px; font-weight: 700; font-size: 1rem; color: white; margin: 10px 0; }}
        .section {{ background: rgba(17,24,39,0.5); border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .alert-card, .vuln-card {{ background: rgba(17,24,39,0.7); border-radius: 8px; padding: 14px; margin-bottom: 10px; }}
        .alert-header, .vuln-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
        .severity-badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; color: white; }}
        .severity-badge-sm {{ padding: 2px 6px; border-radius: 3px; font-size: 0.65rem; font-weight: 600; color: white; }}
        .alert-type, .vuln-type {{ font-weight: 600; font-size: 0.95rem; }}
        .alert-asset, .alert-details, .alert-evidence, .vuln-details, .vuln-evidence {{ font-size: 0.85rem; color: #94a3b8; margin: 4px 0; }}
        .remediation {{ background: rgba(6,214,160,0.1); border-radius: 6px; padding: 8px 12px; margin-top: 8px; font-size: 0.8rem; color: #06d6a0; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        th {{ background: rgba(6,214,160,0.1); color: #06d6a0; padding: 10px; text-align: left; font-weight: 600; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .dangerous-port {{ background: rgba(239,71,111,0.1); }}
        .status-open {{ color: #06d6a0; font-weight: 600; }}
        .status-public {{ color: #ef476f; font-weight: 600; }}
        .status-private {{ color: #ffd166; }}
        .header-present {{ color: #06d6a0; }}
        .header-missing {{ color: #ef476f; }}
        .header-missing td {{ opacity: 0.7; }}
        .tech-item {{ display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }}
        .tech-name {{ font-weight: 600; min-width: 150px; }}
        .tech-category {{ color: #64748b; font-size: 0.8rem; min-width: 120px; }}
        .confidence-bar {{ flex: 1; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; overflow: hidden; }}
        .confidence-fill {{ height: 100%; border-radius: 3px; transition: width 0.3s; }}
        .confidence-text {{ font-size: 0.8rem; color: #64748b; min-width: 40px; text-align: right; }}
        .grade-circle {{ width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.8rem; font-weight: 800; color: white; margin: 10px auto; }}
        code {{ background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; word-break: break-all; }}
        a {{ color: #118ab2; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ text-align: center; padding: 20px; color: #475569; font-size: 0.8rem; margin-top: 40px; border-top: 1px solid rgba(255,255,255,0.06); }}
        @media print {{
            body {{ background: white; color: #1a1a1a; }}
            .section {{ border: 1px solid #ddd; }}
            .stat-card {{ border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ FastRecon Security Report</h1>
            <h3>{_esc(target)}</h3>
            <div class="meta">
                Scanned: {_esc(scan_date)} | Duration: {_esc(duration)} | Mode: {_esc(mode)}
            </div>
            <div class="risk-badge" style="background: {risk_color};">
                Risk: {_esc(risk_level)} ({risk_score}/100)
            </div>
        </div>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: #118ab2;">{stats.get('subdomainsDiscovered', 0)}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #06d6a0;">{stats.get('liveHosts', 0)}</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #9b5de5;">{stats.get('openPorts', 0)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ef476f;">{stats.get('vulnerabilities', 0)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ef476f;">{stats.get('criticalAlerts', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #f77f00;">{stats.get('highAlerts', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ffd166;">{stats.get('mediumAlerts', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #06d6a0;">{stats.get('lowAlerts', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <!-- Security Headers Grade -->
        {'<div class="section"><h2>🛡️ Security Headers</h2><div class="grade-circle" style="background: ' + header_color + ';">' + _esc(header_grade) + '</div><p style="text-align:center; color: #64748b;">Score: ' + str(header_score) + '/100</p><table><tr><th>Header</th><th>Value</th><th>Description</th></tr>' + headers_detail_html + '</table></div>' if header_report_data.get("headers") else ''}

        <!-- Vulnerabilities -->
        {'<div class="section"><h2>🐛 Vulnerabilities Found</h2>' + vulns_html + '</div>' if vulns_html else '<div class="section"><h2>🐛 Vulnerabilities</h2><p style="color: #06d6a0;">✓ No vulnerabilities detected</p></div>'}

        <!-- All Alerts -->
        {'<div class="section"><h2>🚨 Security Alerts (' + str(len(report.get("alerts", []))) + ')</h2>' + alerts_html + '</div>' if alerts_html else ''}

        <!-- Open Ports -->
        {'<div class="section"><h2>🔌 Open Ports</h2><table><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr>' + ports_html + '</table></div>' if ports_html else ''}

        <!-- Endpoints -->
        {'<div class="section"><h2>📂 Discovered Endpoints</h2><table><tr><th>Severity</th><th>Path</th><th>Status</th><th>Type</th></tr>' + endpoints_html + '</table></div>' if endpoints_html else ''}

        <!-- Technologies -->
        {'<div class="section"><h2>🔬 Technologies Detected</h2>' + tech_html + '</div>' if tech_html else ''}

        <!-- Cloud Buckets -->
        {'<div class="section"><h2>☁️ Cloud Buckets</h2><table><tr><th>Name</th><th>Provider</th><th>Status</th><th>URL</th></tr>' + buckets_html + '</table></div>' if buckets_html else ''}

        <div class="footer">
            Generated by FastRecon ⚡ — Automated Security Reconnaissance Framework<br>
            <strong>Disclaimer:</strong> Use only on authorized targets. The authors assume no liability for misuse.
        </div>
    </div>
</body>
</html>"""

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  📄 HTML report saved to {output_file}")

    return html


def _esc(text):
    """HTML escape a string."""
    if not isinstance(text, str):
        text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
