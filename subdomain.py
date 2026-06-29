"""Basic subdomain enumeration using a small built-in wordlist."""

import dns.resolver

SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "test",
    "blog",
    "shop",
    "portal",
    "admin",
]


def enumerate_subdomains(domain):
    """
    Check a small wordlist of common subdomains against a domain.

    Returns:
        dict with discovered subdomains and their resolved IPs.
    """
    result = {
        "success": True,
        "subdomains": [],
        "error": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    for prefix in SUBDOMAIN_WORDLIST:
        fqdn = f"{prefix}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            result["subdomains"].append(
                {
                    "subdomain": fqdn,
                    "ips": ips,
                }
            )
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            continue
        except dns.resolver.Timeout:
            continue
        except Exception:
            continue

    if not result["subdomains"]:
        result["error"] = "No subdomains found from the built-in wordlist."

    return result
