"""DNS lookup module — A, AAAA, MX, NS, TXT, CNAME records."""

import dns.resolver


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def lookup_dns(domain):
    """
    Perform DNS lookups for common record types.

    Returns:
        dict with keys: success, records (dict), errors (list)
    """
    result = {
        "success": True,
        "records": {},
        "errors": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            entries = []

            for rr in answers:
                if rtype == "MX":
                    entries.append(f"{rr.preference} {rr.exchange}")
                elif rtype == "TXT":
                    txt = b"".join(rr.strings).decode("utf-8", errors="replace")
                    entries.append(txt)
                elif rtype == "CNAME":
                    entries.append(str(rr.target).rstrip("."))
                else:
                    entries.append(str(rr))

            result["records"][rtype] = entries

        except dns.resolver.NoAnswer:
            result["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            result["errors"].append(f"Domain does not exist: {domain}")
            result["success"] = False
            break
        except dns.resolver.NoNameservers:
            result["errors"].append("No nameservers available.")
            result["success"] = False
            break
        except dns.resolver.Timeout:
            result["errors"].append(f"DNS timeout for {rtype} records.")
        except Exception as exc:
            result["errors"].append(f"{rtype}: {str(exc)}")

    if not result["records"] and not result["errors"]:
        result["success"] = False
        result["errors"].append("No DNS records found.")

    return result


def reverse_dns(ip_address):
    """
    Perform reverse DNS lookup for an IP address.

    Returns:
        dict with keys: success, hostname, error
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        answers = resolver.resolve_address(ip_address)
        hostname = str(answers[0]).rstrip(".")
        return {"success": True, "hostname": hostname, "error": None}
    except dns.resolver.NXDOMAIN:
        return {
            "success": False,
            "hostname": None,
            "error": "No reverse DNS record found.",
        }
    except dns.resolver.Timeout:
        return {
            "success": False,
            "hostname": None,
            "error": "Reverse DNS lookup timed out.",
        }
    except Exception as exc:
        return {
            "success": False,
            "hostname": None,
            "error": str(exc),
        }
