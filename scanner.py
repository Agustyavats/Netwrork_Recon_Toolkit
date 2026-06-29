"""Main scanner orchestrator — runs all recon modules."""

import socket

from dns_lookup import lookup_dns, reverse_dns
from http_headers import get_http_headers
from ip_lookup import get_ip_info
from port_scanner import scan_ports
from security_summary import generate_summary
from ssl_checker import check_ssl
from subdomain import enumerate_subdomains
from utils.validators import validate_target
from whois_lookup import lookup_whois


def _resolve_scan_host(target, target_type):
    """Determine the host to use for port/SSL scans."""
    if target_type in ("ipv4", "ipv6"):
        return target

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def run_scan(target):
    """
    Run a full reconnaissance scan against a target.

    Args:
        target: domain name or IP address string

    Returns:
        dict containing all module results and validation info.
    """
    validation = validate_target(target)

    if not validation["valid"]:
        return {
            "success": False,
            "validation": validation,
            "error": validation["error"],
        }

    cleaned = validation["target"]
    target_type = validation["type"]
    scan_host = _resolve_scan_host(cleaned, target_type)

    results = {
        "success": True,
        "validation": validation,
        "target": cleaned,
        "target_type": target_type,
        "scan_host": scan_host,
        "error": None,
    }

    # Module 2 — DNS Lookup
    if target_type == "domain":
        results["dns"] = lookup_dns(cleaned)
    else:
        results["dns"] = {
            "success": True,
            "records": {},
            "errors": ["DNS lookup skipped for IP target."],
        }

    # Module 3 — WHOIS
    if target_type == "domain":
        results["whois"] = lookup_whois(cleaned)
    else:
        results["whois"] = {
            "success": False,
            "error": "WHOIS lookup is only available for domains.",
        }

    # Module 4 — SSL Certificate
    ssl_host = cleaned if target_type == "domain" else scan_host
    results["ssl"] = check_ssl(ssl_host)

    # Module 5 — Port Scanner
    results["port_scan"] = scan_ports(scan_host)

    # Module 6 — Reverse DNS
    rdns_ip = scan_host if target_type == "domain" else cleaned
    results["reverse_dns"] = reverse_dns(rdns_ip)

    # Module 7 — IP Information
    results["ip_info"] = get_ip_info(cleaned, target_type)

    # Module 8 — Subdomain Enumeration
    if target_type == "domain":
        results["subdomains"] = enumerate_subdomains(cleaned)
    else:
        results["subdomains"] = {
            "success": False,
            "subdomains": [],
            "error": "Subdomain enumeration is only available for domains.",
        }

    # Module 9 — HTTP Headers
    header_target = cleaned if target_type == "domain" else cleaned
    results["http_headers"] = get_http_headers(header_target)

    # Module 10 — Security Summary
    results["summary"] = generate_summary(results)

    return results
