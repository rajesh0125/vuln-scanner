import nmap


def run_vuln_scan(target: str, ports: str | None = None):
    """
    Run an Nmap vulnerability scan against a target.

    :param target: IP address, hostname, or CIDR range (e.g., "192.168.1.1" or "192.168.1.0/24")
    :param ports: Optional ports string, e.g. "1-1024" or "80,443"
    :return: nmap.PortScanner() object with scan results
    """
    nm = nmap.PortScanner()

    # Build arguments
    # -sV          : version detection
    # --script vuln: run common vulnerability scripts
    # -T4          : faster timing template
    args = "-sV --script vuln -T4"
    if ports:
        nm.scan(target, ports=ports, arguments=args)
    else:
        nm.scan(target, arguments=args)

    return nm
