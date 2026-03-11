from flask import Flask, render_template, request
from scanner import run_vuln_scan
from parser import parse_scan_result
from report import generate_text_report, generate_html_report

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    scan_result = None
    error = None
    report_paths = []

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        ports = request.form.get("ports", "").strip() or None
        report_type = request.form.get("report_type", "none")

        if not target:
            error = "Please enter a valid target (IP / domain / range)."
        else:
            try:
                # Run the scan
                nm = run_vuln_scan(target, ports=ports)
                parsed_data = parse_scan_result(nm)

                if not parsed_data:
                    error = "No hosts found or no data to report."
                else:
                    scan_result = {
                        "target": target,
                        "data": parsed_data,
                    }

                    # Generate downloadable reports if requested
                    if report_type in ("text", "both"):
                        txt_path = generate_text_report(target, parsed_data)
                        report_paths.append(("Text Report", txt_path))

                    if report_type in ("html", "both"):
                        html_path = generate_html_report(target, parsed_data)
                        report_paths.append(("HTML Report", html_path))

            except Exception as e:
                error = f"Error running scan: {e}"

    return render_template(
        "index.html",
        scan_result=scan_result,
        error=error,
        report_paths=report_paths,
    )


if __name__ == "__main__":
    # Debug mode for development; turn off in production
    app.run(host="0.0.0.0", port=5000, debug=True)
