from typing import Any, Dict, List


def parse_scan_result(nm) -> List[Dict[str, Any]]:
    """
    Convert the Nmap PortScanner object into a Python data structure
    that is easy to use for reporting.

    :param nm: nmap.PortScanner instance
    :return: List of host information dictionaries
    """
    report_data: List[Dict[str, Any]] = []

    for host in nm.all_hosts():
        host_info: Dict[str, Any] = {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": []
        }

        for proto in nm[host].all_protocols():
            ports = []
            proto_data = nm[host][proto]

            # Sort ports for nicer output
            for port in sorted(proto_data.keys()):
                port_data = proto_data[port]
                ports.append({
                    "port": port,
                    "state": port_data.get("state"),
                    "name": port_data.get("name"),
                    "product": port_data.get("product"),
                    "version": port_data.get("version"),
                    "extrainfo": port_data.get("extrainfo"),
                    "scripts": port_data.get("script", {}) or {},
                })

            host_info["protocols"].append({
                "protocol": proto,
                "ports": ports,
            })

        report_data.append(host_info)

    return report_data
