from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def _sanitize_filename(text: str) -> str:
    for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|', ' '):
        text = text.replace(ch, "_")
    return text


def generate_text_report(
    target: str,
    data: List[Dict[str, Any]],
    output_dir: str = "reports",
) -> str:
    """
    Generate a plain-text vulnerability report.

    :param target: Scan target (for info + filename)
    :param data: Parsed scan data from parse_scan_result()
    :param output_dir: Directory to save the report in
    :return: Path to generated report file as string
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    safe_target = _sanitize_filename(target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = Path(output_dir) / f"report_{safe_target}_{timestamp}.txt"

    with filename.open("w", encoding="utf-8") as f:
        f.write("VULNERABILITY ASSESSMENT REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target       : {target}\n")
        f.write(f"Generated at : {datetime.now()}\n")
        f.write("=" * 60 + "\n\n")

        if not data:
            f.write("No hosts found or no data to report.\n")
            return str(filename)

        for host in data:
            f.write(f"Host    : {host['host']} ({host['hostname']})\n")
            f.write(f"State   : {host['state']}\n")
            f.write("-" * 60 + "\n")

            for proto in host["protocols"]:
                f.write(f"Protocol: {proto['protocol']}\n")
                for p in proto["ports"]:
                    f.write(
                        f"  Port {p['port']}/"
                        f"{proto['protocol']}  -  State: {p['state']}  -  Service: {p['name']}\n"
                    )
                    if p["product"] or p["version"]:
                        f.write(f"    Product: {p['product']} {p['version']}\n")
                    if p["extrainfo"]:
                        f.write(f"    Extra  : {p['extrainfo']}\n")

                    if p["scripts"]:
                        f.write("    Potential Vulnerabilities / Script Results:\n")
                        for script_name, output in p["scripts"].items():
                            # Indent multi-line script output
                            formatted_output = "\n          ".join(str(output).splitlines())
                            f.write(f"      - {script_name}: {formatted_output}\n")
                f.write("\n")

            f.write("=" * 60 + "\n\n")

    return str(filename)


def generate_html_report(
    target: str,
    data: List[Dict[str, Any]],
    output_dir: str = "reports",
) -> str:
    """
    Generate a simple HTML vulnerability report.

    :param target: Scan target (for info + filename)
    :param data: Parsed scan data
    :param output_dir: Directory to save the report in
    :return: Path to generated HTML file as string
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    safe_target = _sanitize_filename(target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = Path(output_dir) / f"report_{safe_target}_{timestamp}.html"

    html_parts: List[str] = []
    html_parts.append("<!DOCTYPE html>")
    html_parts.append("<html lang='en'>")
    html_parts.append("<head>")
    html_parts.append("<meta charset='UTF-8'>")
    html_parts.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html_parts.append(f"<title>Vulnerability Report - {target}</title>")
    html_parts.append("""<style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        .host { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .meta { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; font-size: 0.9em; }
        th { background: #f5f5f5; text-align: left; }
        .vuln { background: #fff3cd; }
        .scripts { font-size: 0.9em; white-space: pre-wrap; }
    </style>""")

    html_parts.append("</head>")
    html_parts.append("<body>")
    html_parts.append("<h1>Vulnerability Assessment Report</h1>")
    html_parts.append("<div class='meta'>")
    html_parts.append(f"<strong>Target:</strong> {target}<br>")
    html_parts.append(f"<strong>Generated at:</strong> {datetime.now()}")
    html_parts.append("</div>")

    if not data:
        html_parts.append("<p>No hosts found or no data to report.</p>")
    else:
        for host in data:
            html_parts.append("<div class='host'>")
            html_parts.append(f"<h2>Host: {host['host']} ({host['hostname']})</h2>")
            html_parts.append(f"<div class='meta'><strong>State:</strong> {host['state']}</div>")

            for proto in host["protocols"]:
                html_parts.append(f"<h3>Protocol: {proto['protocol']}</h3>")
                html_parts.append("<table>")
                html_parts.append(
                    "<tr><th>Port</th><th>State</th><th>Service</th>"
                    "<th>Product</th><th>Version</th><th>Extra</th>"
                    "<th>Vulnerabilities / Scripts</th></tr>"
                )

                for p in proto["ports"]:
                    scripts_html = ""
                    if p["scripts"]:
                        lines = []
                        for script_name, output in p["scripts"].items():
                            lines.append(f"{script_name}: {output}")
                        scripts_html = "<div class='scripts'>" + "<br>".join(lines) + "</div>"

                    row_class = " class='vuln'" if scripts_html else ""
                    html_parts.append(
                        f"<tr{row_class}>"
                        f"<td>{p['port']}/{proto['protocol']}</td>"
                        f"<td>{p['state']}</td>"
                        f"<td>{p['name']}</td>"
                        f"<td>{p['product']}</td>"
                        f"<td>{p['version']}</td>"
                        f"<td>{p['extrainfo']}</td>"
                        f"<td>{scripts_html}</td>"
                        f"</tr>"
                    )
                html_parts.append("</table>")

            html_parts.append("</div>")  # .host

    html_parts.append("</body></html>")

    filename.write_text("\n".join(html_parts), encoding="utf-8")
    return str(filename)
