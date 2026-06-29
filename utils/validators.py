"""Host validation — detect domain, IPv4, or IPv6."""

import ipaddress
import re


DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_target(target):
    """
    Validate user input and classify the target.

    Returns:
        dict with keys: valid (bool), type (str|None), target (str), error (str|None)
        type is one of: 'domain', 'ipv4', 'ipv6'
    """
    if not target or not isinstance(target, str):
        return {
            "valid": False,
            "type": None,
            "target": "",
            "error": "Target is required.",
        }

    cleaned = target.strip().lower()
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        return {
            "valid": False,
            "type": None,
            "target": "",
            "error": "Target cannot be empty.",
        }

    # IPv4
    try:
        addr = ipaddress.ip_address(cleaned)
        if isinstance(addr, ipaddress.IPv4Address):
            return {
                "valid": True,
                "type": "ipv4",
                "target": cleaned,
                "error": None,
            }
        if isinstance(addr, ipaddress.IPv6Address):
            return {
                "valid": True,
                "type": "ipv6",
                "target": cleaned,
                "error": None,
            }
    except ValueError:
        pass

    # Domain
    if DOMAIN_PATTERN.match(cleaned):
        return {
            "valid": True,
            "type": "domain",
            "target": cleaned,
            "error": None,
        }

    return {
        "valid": False,
        "type": None,
        "target": cleaned,
        "error": "Invalid domain or IP address.",
    }


def is_private_ip(ip_str):
    """Return True if the IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
