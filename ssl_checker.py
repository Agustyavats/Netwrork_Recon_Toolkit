"""SSL/TLS certificate checker."""

import socket
import ssl
from datetime import datetime, timezone


def check_ssl(hostname, port=443, timeout=5):
    """
    Retrieve SSL certificate details for a host.

    Returns:
        dict with certificate info or error message.
    """
    result = {
        "success": False,
        "available": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "expired": False,
        "warning": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure:
                cert = secure.getpeercert()

        if not cert:
            result["error"] = "No certificate data returned."
            return result

        result["success"] = True
        result["available"] = True

        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        subject_parts = dict(x[0] for x in cert.get("subject", []))

        result["issuer"] = issuer_parts.get("organizationName", "Unknown")
        result["subject"] = subject_parts.get("commonName", hostname)

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        if not_before:
            valid_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            result["valid_from"] = valid_from.strftime("%Y-%m-%d %H:%M:%S UTC")

        if not_after:
            valid_until = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result["valid_until"] = valid_until.strftime("%Y-%m-%d %H:%M:%S UTC")

            now = datetime.now(timezone.utc).replace(tzinfo=None)
            days_left = (valid_until - now).days
            result["days_remaining"] = days_left

            if days_left < 0:
                result["expired"] = True
                result["warning"] = "Certificate has EXPIRED."
            elif days_left <= 30:
                result["warning"] = f"Certificate expires in {days_left} days."

    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {str(exc)}"
    except socket.timeout:
        result["error"] = "Connection timed out while checking SSL."
    except socket.gaierror:
        result["error"] = "Could not resolve hostname for SSL check."
    except ConnectionRefusedError:
        result["error"] = "HTTPS port (443) is not open."
    except OSError as exc:
        result["error"] = f"SSL unavailable: {str(exc)}"
    except Exception as exc:
        result["error"] = f"SSL check failed: {str(exc)}"

    return result
