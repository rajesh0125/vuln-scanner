from scanner import run_vuln_scan
from parser import parse_scan_result
from report import generate_text_report, generate_html_report


def main():
    print("=" * 60)
    print("       Simple Vulnerability Assessment Tool (Python + Nmap)")
    print("=" * 60)
    print("WARNING: Only scan systems you own or have permission to test.")
    print("=" * 60)

    target = input(
        "Enter target IP / hostname / range "
        "(e.g. 192.168.1.1 or scanme.nmap.org): "
    ).strip()
    if not target:
        print("No target provided. Exiting.")
        return

    choice = input(
        "Generate (1) Text report, (2) HTML report, (3) Both [default: 1]: "
    ).strip()
    if choice not in {"1", "2", "3"}:
        choice = "1"

    ports = input(
        "Optional: enter ports to scan (e.g. 1-1024 or 80,443) "
        "or leave blank for default: "
    ).strip()
    ports = ports or None

    print("\n[*] Running Nmap vulnerability scan... This may take a while.")
    try:
        nm = run_vuln_scan(target, ports=ports)
    except Exception as e:
        print(f"[!] Error running Nmap scan: {e}")
        return

    print("[*] Parsing scan results...")
    parsed_data = parse_scan_result(nm)

    if not parsed_data:
        print("[!] No hosts found or no data to report.")
        return

    report_paths = []

    if choice in {"1", "3"}:
        print("[*] Generating text report...")
        txt_path = generate_text_report(target, parsed_data)
        report_paths.append(txt_path)

    if choice in {"2", "3"}:
        print("[*] Generating HTML report...")
        html_path = generate_html_report(target, parsed_data)
        report_paths.append(html_path)

    print("\n[+] Scan complete!")
    for path in report_paths:
        print(f"    Report saved: {path}")


if __name__ == "__main__":
    main()
