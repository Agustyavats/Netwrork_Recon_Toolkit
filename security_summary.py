"""Security summary — observational summary of scan results."""


def generate_summary(scan_results):
    """
    Generate a simple observational security summary.

    This is NOT a vulnerability assessment — only summarizes observations.
    """
    summary = {
        "open_ports": [],
        "ssl_status": "Unknown",
        "dns_status": "Unknown",
        "security_headers": [],
        "missing_headers": [],
        "overall": "",
    }

    # Open ports
    port_data = scan_results.get("port_scan", {})
    if port_data.get("success"):
        for entry in port_data.get("ports", []):
            if entry.get("state") == "open":
                summary["open_ports"].append(entry["port"])
    else:
        summary["open_ports"] = []

    # SSL
    ssl_data = scan_results.get("ssl", {})
    if ssl_data.get("success") and ssl_data.get("available"):
        if ssl_data.get("expired"):
            summary["ssl_status"] = "Expired"
        elif ssl_data.get("warning"):
            summary["ssl_status"] = ssl_data["warning"]
        else:
            summary["ssl_status"] = "Valid"
    elif ssl_data.get("error"):
        summary["ssl_status"] = "Unavailable"
    else:
        summary["ssl_status"] = "Not available"

    # DNS
    dns_data = scan_results.get("dns", {})
    target_type = scan_results.get("target_type", "")
    if target_type in ("ipv4", "ipv6"):
        summary["dns_status"] = "N/A (IP target)"
    elif dns_data.get("success") and dns_data.get("records"):
        has_records = any(dns_data["records"].values())
        summary["dns_status"] = "Healthy" if has_records else "No records found"
    elif dns_data.get("errors"):
        summary["dns_status"] = "Issues detected"
    else:
        summary["dns_status"] = "Unknown"

    # Security headers
    headers_data = scan_results.get("http_headers", {})
    if headers_data.get("success"):
        header_map = headers_data.get("headers", {})
        for name in [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]:
            value = header_map.get(name, "Not set")
            if value and value != "Not set":
                summary["security_headers"].append(name)
            else:
                summary["missing_headers"].append(name)

    # Overall observation
    observations = []

    if summary["open_ports"]:
        port_str = ", ".join(str(p) for p in summary["open_ports"])
        observations.append(f"Open ports detected: {port_str}.")
    else:
        observations.append("No common open ports detected.")

    observations.append(f"SSL: {summary['ssl_status']}.")
    observations.append(f"DNS: {summary['dns_status']}.")

    if summary["missing_headers"]:
        missing = ", ".join(summary["missing_headers"])
        observations.append(f"Missing security headers: {missing}.")
    elif summary["security_headers"]:
        observations.append("Key security headers are present.")

    if summary["ssl_status"] == "Valid" and summary["dns_status"] == "Healthy":
        summary["overall"] = "Basic configuration appears secure."
    elif summary["ssl_status"] == "Expired":
        summary["overall"] = "SSL certificate requires attention."
    elif summary["missing_headers"]:
        summary["overall"] = (
            "Some security headers are missing; review configuration."
        )
    else:
        summary["overall"] = "Review individual scan results for details."

    summary["observations"] = observations
    return summary
