import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from models.network import Network

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """
    Generates standalone, styled executive HTML Wi-Fi Security Reports.
    """

    @staticmethod
    def generate_html_report(
        networks: List[Network],
        events: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        stats: Dict[str, Any],
        output_filepath: str,
        title: str = "Wi-Fi Security Intelligence & Monitoring Report"
    ) -> bool:
        """
        Builds and saves styled HTML security report to disk.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        total_nets = len(networks)
        open_cnt = sum(1 for n in networks if n.security.upper() == "OPEN")
        wpa3_cnt = sum(1 for n in networks if "WPA3" in n.security.upper())
        wpa2_cnt = sum(1 for n in networks if "WPA2" in n.security.upper() and "WPA3" not in n.security.upper())
        other_cnt = total_nets - (open_cnt + wpa3_cnt + wpa2_cnt)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-amber: #fbbf24;
            --accent-red: #f87171;
            --border-color: #334155;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            color: var(--accent-blue);
            font-size: 28px;
        }}
        .meta {{
            font-size: 14px;
            color: #94a3b8;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        .card-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #94a3b8;
            margin-bottom: 8px;
        }}
        .card-val {{
            font-size: 28px;
            font-weight: bold;
        }}
        .section-title {{
            font-size: 20px;
            color: var(--accent-blue);
            margin-top: 40px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent-blue);
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }}
        th {{
            background-color: #0f172a;
            color: var(--accent-blue);
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #334155;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-low {{ background-color: #065f46; color: #34d399; }}
        .badge-medium {{ background-color: #854d0e; color: #fde047; }}
        .badge-high {{ background-color: #991b1b; color: #fca5a5; }}
        .badge-critical {{ background-color: #881337; color: #fda4af; }}
        .notice {{
            background-color: #1e293b;
            border: 1px solid #3b82f6;
            padding: 15px;
            border-radius: 6px;
            font-size: 13px;
            color: #cbd5e1;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="meta">Generated: {timestamp} | Scope: Passive Defensive Observation</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">Total Networks</div>
                <div class="card-val">{total_nets}</div>
            </div>
            <div class="card">
                <div class="card-title">Open Networks</div>
                <div class="card-val" style="color: var(--accent-red);">{open_cnt}</div>
            </div>
            <div class="card">
                <div class="card-title">WPA3 Networks</div>
                <div class="card-val" style="color: var(--accent-green);">{wpa3_cnt}</div>
            </div>
            <div class="card">
                <div class="card-title">WPA2 Networks</div>
                <div class="card-val">{wpa2_cnt}</div>
            </div>
        </div>

        <div class="section-title">Discovered Wireless Networks</div>
        <table>
            <thead>
                <tr>
                    <th>SSID</th>
                    <th>BSSID</th>
                    <th>Signal</th>
                    <th>Channel</th>
                    <th>Band</th>
                    <th>Security</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
"""
        for n in networks:
            risk = n.risk_level()
            badge_class = f"badge-{risk.lower()}"
            rssi_str = f"{n.signal_percent}% ({n.signal_dbm} dBm)"
            html_content += f"""
                <tr>
                    <td><strong>{n.ssid}</strong></td>
                    <td><code>{n.bssid}</code></td>
                    <td>{rssi_str}</td>
                    <td>{n.channel or 'N/A'}</td>
                    <td>{n.band}</td>
                    <td>{n.security} ({n.encryption})</td>
                    <td><span class="badge {badge_class}">{risk}</span></td>
                </tr>
"""

        html_content += """
            </tbody>
        </table>

        <div class="section-title">Recent Security Events</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>SSID</th>
                    <th>BSSID</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""
        if events:
            for ev in events[:50]:
                sev = ev.get("severity", "INFO")
                badge_class = f"badge-{sev.lower()}" if sev.lower() in ("low", "medium", "high", "critical") else "badge-low"
                html_content += f"""
                <tr>
                    <td>{ev.get('timestamp', '')}</td>
                    <td><code>{ev.get('event_type', '')}</code></td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td>{ev.get('ssid', '')}</td>
                    <td><code>{ev.get('bssid', '')}</code></td>
                    <td>{ev.get('description', '')}</td>
                </tr>
"""
        else:
            html_content += "<tr><td colspan='6'>No security events recorded.</td></tr>"

        html_content += """
            </tbody>
        </table>

        <div class="section-title">Passive Environment Anomalies</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>SSID / BSSID</th>
                    <th>What Observed</th>
                    <th>Explanation</th>
                </tr>
            </thead>
            <tbody>
"""
        if anomalies:
            for an in anomalies[:50]:
                sev = an.get("severity", "INFO")
                badge_class = f"badge-{sev.lower()}" if sev.lower() in ("low", "medium", "high", "critical") else "badge-low"
                html_content += f"""
                <tr>
                    <td>{an.get('timestamp', '')}</td>
                    <td><code>{an.get('anomaly_type', '')}</code></td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td>{an.get('ssid', '')}<br><code>{an.get('bssid', '')}</code></td>
                    <td>{an.get('what', '')}</td>
                    <td>{an.get('why_flagged', '')}</td>
                </tr>
"""
        else:
            html_content += "<tr><td colspan='6'>No anomalies detected.</td></tr>"

        html_content += """
            </tbody>
        </table>

        <div class="notice">
            <strong>Security Scope & Limitations Statement:</strong><br>
            This security report is generated entirely from passive wireless environment observations. Risk classifications, scores, and anomaly indicators represent passive configuration metrics and heuristic observations. Passive monitoring cannot conclusively determine malicious intent or active compromise.
        </div>
    </div>
</body>
</html>
"""
        try:
            out_dir = os.path.dirname(output_filepath)
            if out_dir and not os.path.exists(out_dir):
                os.makedirs(out_dir, exist_ok=True)

            with open(output_filepath, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info("Generated HTML report successfully at %s", output_filepath)
            return True
        except Exception as err:
            logger.error("Failed to generate HTML report: %s", err)
            return False
