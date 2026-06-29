"""Port scanner — python-nmap with socket fallback."""

import socket
import subprocess

COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    8080: "http-proxy",
}

PORT_LIST = sorted(COMMON_PORTS.keys())


def _nmap_available():
    """Check if nmap is installed on the system."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _scan_with_nmap(host):
    """Scan common ports using python-nmap."""
    import nmap

    scanner = nmap.PortScanner()
    port_str = ",".join(str(p) for p in PORT_LIST)

    scanner.scan(host, port_str, arguments="-T3 --open")

    results = []
    if host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                if port not in COMMON_PORTS:
                    continue
                state = scanner[host][proto][port]["state"]
                service = scanner[host][proto][port].get(
                    "name", COMMON_PORTS.get(port, "unknown")
                )
                results.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service,
                    }
                )

    results.sort(key=lambda x: x["port"])
    return {
        "success": True,
        "method": "nmap",
        "ports": results,
        "error": None,
    }


def _scan_with_socket(host, timeout=1.0):
    """Fallback port scan using raw socket connections."""
    results = []

    for port in PORT_LIST:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            state = "open" if result == 0 else "closed"
        except socket.gaierror:
            return {
                "success": False,
                "method": "socket",
                "ports": [],
                "error": "Could not resolve host for port scan.",
            }
        except socket.timeout:
            state = "filtered"
        except OSError:
            state = "closed"
        finally:
            sock.close()

        results.append(
            {
                "port": port,
                "state": state,
                "service": COMMON_PORTS.get(port, "unknown"),
            }
        )

    return {
        "success": True,
        "method": "socket",
        "ports": results,
        "error": None,
    }


def scan_ports(host):
    """
    Scan common ports on a target host.

    Uses nmap if available, otherwise falls back to socket scanning.
    """
    if _nmap_available():
        try:
            return _scan_with_nmap(host)
        except Exception as exc:
            fallback = _scan_with_socket(host)
            fallback["error"] = f"Nmap failed ({exc}); used socket fallback."
            return fallback

    result = _scan_with_socket(host)
    result["error"] = "Nmap not installed; used socket-based scanning."
    return result
