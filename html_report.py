"""
html_report.py - Generate HTML reports from email analysis.
Creates professional, shareable reports for non-technical stakeholders.
"""

import html
from datetime import datetime
from typing import Dict, List, Optional


def generate_html_report(headers: dict, iocs: dict, auth: dict, hops: dict,
                         risk: dict, enrichment: dict = None) -> str:
    """Generate a complete HTML report."""
    subject = html.escape(headers.get("subject", "(empty)"))
    from_addr = html.escape(headers.get("from", "(empty)"))
    to_addr = html.escape(headers.get("to", "(empty)"))
    date = html.escape(headers.get("date", "(empty)"))
    message_id = html.escape(headers.get("message_id", "(empty)"))
    return_path = html.escape(headers.get("return_path", "(empty)"))

    risk_level = risk.get("risk_level", "UNKNOWN")
    risk_score = risk.get("total_score", 0)
    confidence = risk.get("confidence", 0)

    # Risk level color
    risk_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#dc3545",
        "MEDIUM": "#ffc107",
        "LOW": "#17a2b8",
        "BENIGN": "#28a745",
    }
    risk_color = risk_colors.get(risk_level, "#6c757d")

    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Analysis Report - {subject}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 24px; margin-bottom: 10px; }}
        .header .subtitle {{ opacity: 0.8; font-size: 14px; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
        .card h2 {{ font-size: 18px; color: #1a1a2e; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 5px; font-weight: bold; font-size: 18px; color: white; background: {risk_color}; }}
        .risk-bar {{ height: 20px; background: #eee; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
        .risk-fill {{ height: 100%; background: {risk_color}; width: {min(risk_score, 100)}%; transition: width 0.5s; }}
        .risk-stats {{ display: flex; gap: 20px; margin-top: 15px; }}
        .risk-stat {{ text-align: center; }}
        .risk-stat .value {{ font-size: 24px; font-weight: bold; color: #1a1a2e; }}
        .risk-stat .label {{ font-size: 12px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #1a1a2e; }}
        .status-pass {{ color: #28a745; font-weight: bold; }}
        .status-fail {{ color: #dc3545; font-weight: bold; }}
        .status-softfail {{ color: #ffc107; font-weight: bold; }}
        .status-notfound {{ color: #6c757d; }}
        .ioc-list {{ list-style: none; }}
        .ioc-list li {{ padding: 5px 0; }}
        .ioc-list li:before {{ content: "•"; color: #dc3545; font-weight: bold; margin-right: 10px; }}
        .hop {{ display: flex; align-items: center; padding: 10px; background: #f8f9fa; border-radius: 5px; margin: 5px 0; }}
        .hop-number {{ background: #1a1a2e; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; margin-right: 15px; }}
        .hop-arrow {{ color: #666; margin: 0 10px; }}
        .signal {{ padding: 10px; margin: 5px 0; border-radius: 5px; }}
        .signal-strong {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .signal-moderate {{ background: #fff3cd; border-left: 4px solid #ffc107; }}
        .signal-weak {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
        .enrichment {{ margin-top: 15px; }}
        .enrichment-item {{ padding: 10px; background: #f8f9fa; border-radius: 5px; margin: 5px 0; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-malicious {{ background: #dc3545; color: white; }}
        .badge-suspicious {{ background: #ffc107; color: #333; }}
        .badge-clean {{ background: #28a745; color: white; }}
        .badge-unknown {{ background: #6c757d; color: white; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
        .warning {{ background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 10px 0; color: #721c24; }}
        .info {{ background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin: 10px 0; color: #0c5460; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 Email Header Analysis Report</h1>
            <div class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
        </div>

        <!-- Risk Assessment -->
        <div class="card">
            <h2>⚠️ Risk Assessment</h2>
            <div style="text-align: center; margin: 20px 0;">
                <span class="risk-badge">{risk_level}</span>
            </div>
            <div class="risk-bar">
                <div class="risk-fill"></div>
            </div>
            <div style="text-align: center; color: #666;">{risk_score}/100</div>
            <div class="risk-stats">
                <div class="risk-stat">
                    <div class="value">{len(risk.get('strong_signals', []))}</div>
                    <div class="label">Strong Signals</div>
                </div>
                <div class="risk-stat">
                    <div class="value">{len(risk.get('moderate_signals', []))}</div>
                    <div class="label">Moderate Signals</div>
                </div>
                <div class="risk-stat">
                    <div class="value">{len(risk.get('weak_signals', []))}</div>
                    <div class="label">Weak Signals</div>
                </div>
                <div class="risk-stat">
                    <div class="value">{confidence:.0f}%</div>
                    <div class="label">Confidence</div>
                </div>
            </div>
        </div>

        <!-- Email Summary -->
        <div class="card">
            <h2>📧 Email Summary</h2>
            <table>
                <tr><th>Subject</th><td>{subject}</td></tr>
                <tr><th>From</th><td>{from_addr}</td></tr>
                <tr><th>To</th><td>{to_addr}</td></tr>
                <tr><th>Date</th><td>{date}</td></tr>
                <tr><th>Message-ID</th><td><code>{message_id}</code></td></tr>
                <tr><th>Return-Path</th><td><code>{return_path}</code></td></tr>
            </table>
        </div>

        <!-- Authentication -->
        <div class="card">
            <h2>🔐 Authentication (SPF / DKIM / DMARC)</h2>
            <table>
                <tr>
                    <th>Mechanism</th>
                    <th>Result</th>
                    <th>Domain</th>
                    <th>Details</th>
                </tr>"""

    # Add authentication rows
    for mechanism in ["spf", "dkim", "dmarc"]:
        data = auth.get(mechanism, {})
        result = data.get("result", "NOT FOUND")
        domain = html.escape(data.get("domain", ""))
        detail = html.escape(data.get("detail", ""))

        status_class = "status-pass" if result == "PASS" else "status-fail" if result in ("FAIL", "HARDFAIL") else "status-softfail" if result in ("SOFTFAIL", "NEUTRAL") else "status-notfound"

        html_content += f"""
                <tr>
                    <td><strong>{mechanism.upper()}</strong></td>
                    <td class="{status_class}">{result}</td>
                    <td>{domain}</td>
                    <td>{detail}</td>
                </tr>"""

    html_content += """
            </table>
        </div>

        <!-- Delivery Path -->
        <div class="card">
            <h2>🛤️ Delivery Path</h2>"""

    hop_list = hops.get("hops", [])
    if hop_list:
        html_content += f"""
            <p style="color: #666; margin-bottom: 15px;">{hops.get('hop_count', 0)} hop(s) | Total transit: {_format_duration(hops.get('total_time_seconds'))}</p>"""

        for hop in hop_list:
            num = hop.get("hop_number", "?")
            from_host = html.escape(hop.get("from_host", "?"))
            from_ip = html.escape(hop.get("from_ip", ""))
            by_host = html.escape(hop.get("by_host", "?"))
            proto = html.escape(hop.get("with", ""))
            ts = html.escape(hop.get("timestamp", ""))

            ip_str = f" [{from_ip}]" if from_ip else ""
            proto_str = f" ({proto})" if proto else ""

            html_content += f"""
            <div class="hop">
                <div class="hop-number">{num}</div>
                <div>
                    <strong>{from_host}{ip_str}</strong>
                    <span class="hop-arrow">→</span>
                    <strong>{by_host}</strong>{proto_str}
                    <br><small style="color: #666;">{ts}</small>
                </div>
            </div>"""

    # Anomalies
    anomalies = hops.get("anomalies", [])
    if anomalies:
        html_content += """
            <h3 style="margin-top: 20px; margin-bottom: 10px;">Anomalies</h3>"""
        for a in anomalies:
            sev = a.get("severity", "INFO")
            finding = html.escape(a.get("finding", ""))
            detail = html.escape(a.get("detail", ""))
            html_content += f"""
            <div class="warning">
                <strong>[{sev}]</strong> {finding}: {detail}
            </div>"""

    html_content += """
        </div>

        <!-- IOCs -->
        <div class="card">
            <h2>🔍 Indicators of Compromise</h2>"""

    # Public IPs
    pub_ips = iocs.get("public_ips", [])
    if pub_ips:
        html_content += """
            <h3>Public IPs</h3>
            <ul class="ioc-list">"""
        for ip in pub_ips:
            html_content += f"""
                <li><code>{html.escape(ip)}</code></li>"""
        html_content += """
            </ul>"""

    # Domains
    domains = iocs.get("domains", [])
    if domains:
        html_content += """
            <h3>Domains</h3>
            <ul class="ioc-list">"""
        for d in domains:
            marker = " (sender)" if d == iocs.get("sender_domain") else ""
            html_content += f"""
                <li><code>{html.escape(d)}</code>{marker}</li>"""
        html_content += """
            </ul>"""

    # URLs
    urls = iocs.get("urls", [])
    if urls:
        html_content += """
            <h3>URLs</h3>
            <ul class="ioc-list">"""
        for u in urls:
            html_content += f"""
                <li><code>{html.escape(u)}</code></li>"""
        html_content += """
            </ul>"""

    # Attachments
    attachments = headers.get("attachments", [])
    if attachments:
        html_content += """
            <h3>Attachments</h3>
            <table>
                <tr><th>Filename</th><th>Type</th><th>Size</th><th>SHA256</th></tr>"""
        for att in attachments:
            size_kb = att.get("size_bytes", 0) / 1024
            sha256 = html.escape(att.get("sha256", "N/A"))
            html_content += f"""
                <tr>
                    <td>{html.escape(att.get('filename', 'unnamed'))}</td>
                    <td>{html.escape(att.get('content_type', ''))}</td>
                    <td>{size_kb:.1f} KB</td>
                    <td><code>{sha256[:16]}...</code></td>
                </tr>"""
        html_content += """
            </table>"""

    html_content += """
        </div>

        <!-- Risk Signals -->
        <div class="card">
            <h2>📊 Risk Signals</h2>"""

    signals = risk.get("signals", [])
    if signals:
        for s in signals:
            tier = s.get("tier", "")
            finding = html.escape(s.get("finding", ""))
            detail = html.escape(s.get("detail", ""))

            signal_class = "signal-strong" if tier == "STRONG" else "signal-moderate" if tier == "MODERATE" else "signal-weak"

            html_content += f"""
            <div class="signal {signal_class}">
                <strong>[{tier}]</strong> {finding}
                <br><small style="color: #666;">{detail}</small>
            </div>"""

    html_content += """
        </div>"""

    # Enrichment
    if enrichment:
        html_content += """
        <div class="card">
            <h2>🌐 Threat Intel Enrichment</h2>"""

        summary = enrichment.get("summary", {})
        html_content += f"""
            <div class="info">
                <strong>Summary:</strong>
                Malicious: {summary.get('malicious', 0)} |
                Suspicious: {summary.get('suspicious', 0)} |
                Clean: {summary.get('clean', 0)} |
                Unknown: {summary.get('unknown', 0)}
            </div>"""

        # IP results
        for ip, sources in enrichment.get("ip_results", {}).items():
            html_content += f"""
            <h3>IP: {html.escape(ip)}</h3>"""
            for source_name, data in sources.items():
                if not isinstance(data, dict):
                    continue
                status = data.get("status", "UNKNOWN")
                badge_class = "badge-malicious" if "MALICIOUS" in status else "badge-suspicious" if "SUSPICIOUS" in status else "badge-clean" if status == "CLEAN" else "badge-unknown"
                html_content += f"""
                <div class="enrichment-item">
                    <span class="badge {badge_class}">{status}</span>
                    <strong>{html.escape(source_name)}</strong>
                </div>"""

        html_content += """
        </div>"""

    # Footer
    html_content += f"""
        <div class="footer">
            <p>Generated by Email Header Analysis Tool | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>This report is for informational purposes only. Verify findings before taking action.</p>
        </div>
    </div>
</body>
</html>"""

    return html_content


def _format_duration(seconds) -> str:
    """Format seconds into human-readable duration."""
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


def export_html_report(html_content: str, output_path: str) -> str:
    """Export HTML report to file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
