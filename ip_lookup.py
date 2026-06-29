"""IP information module — version, public/private, reverse DNS."""

import ipaddress
import socket

from dns_lookup import reverse_dns
from utils.validators import is_private_ip


def get_public_ip():
    """
    Retrieve the machine's public IP using a free service.

    Returns:
        dict with public_ip or error.
    """
    try:
        import requests

        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        data = response.json()
        return {"success": True, "public_ip": data.get("ip"), "error": None}
    except Exception as exc:
        return {
            "success": False,
            "public_ip": None,
            "error": f"Could not determine public IP: {str(exc)}",
        }


def get_ip_info(target, target_type):
    """
    Gather IP-related information for a target.

    Args:
        target: domain or IP string
        target_type: 'domain', 'ipv4', or 'ipv6'

    Returns:
        dict with ip details.
    """
    result = {
        "success": True,
        "resolved_ip": None,
        "reverse_dns": None,
        "classification": None,
        "ip_version": None,
        "error": None,
    }

    ip_address = None

    if target_type in ("ipv4", "ipv6"):
        ip_address = target
    else:
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            result["success"] = False
            result["error"] = "Could not resolve domain to an IP address."
            return result

    result["resolved_ip"] = ip_address

    try:
        addr = ipaddress.ip_address(ip_address)
        if isinstance(addr, ipaddress.IPv4Address):
            result["ip_version"] = "IPv4"
        else:
            result["ip_version"] = "IPv6"
    except ValueError:
        result["ip_version"] = "Unknown"

    if is_private_ip(ip_address):
        result["classification"] = "Private"
    else:
        result["classification"] = "Public"

    rdns = reverse_dns(ip_address)
    if rdns["success"]:
        result["reverse_dns"] = rdns["hostname"]
    else:
        result["reverse_dns"] = rdns.get("error", "Not available")

    return result
