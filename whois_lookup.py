"""WHOIS lookup module."""

from datetime import datetime

import whois


def _format_date(value):
    """Convert WHOIS date values to a readable string."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def lookup_whois(domain):
    """
    Perform WHOIS lookup for a domain.

    Returns:
        dict with registrar info or unavailable message.
    """
    result = {
        "success": False,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "organization": None,
        "country": None,
        "error": None,
    }

    try:
        data = whois.whois(domain)

        if data is None or (not data.domain_name and not data.registrar):
            result["error"] = "WHOIS information is unavailable for this target."
            return result

        result["success"] = True
        result["registrar"] = data.registrar if data.registrar else "Unknown"
        result["creation_date"] = _format_date(data.creation_date)
        result["expiration_date"] = _format_date(data.expiration_date)
        result["updated_date"] = _format_date(data.updated_date)
        result["organization"] = data.org if data.org else "Unknown"
        result["country"] = data.country if data.country else "Unknown"

    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {str(exc)}"

    return result
