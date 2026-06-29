"""HTTP header retrieval module."""

import requests

SECURITY_HEADERS = [
    "Server",
    "Content-Type",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Cache-Control",
]


def get_http_headers(target, timeout=5):
    """
    Retrieve HTTP response headers from a target.

    Tries HTTPS first, then HTTP.

    Returns:
        dict with header values or error.
    """
    result = {
        "success": False,
        "url": None,
        "headers": {},
        "error": None,
    }

    urls = [f"https://{target}", f"http://{target}"]

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "NetworkReconToolkit/1.0"},
            )
            result["success"] = True
            result["url"] = response.url

            for header in SECURITY_HEADERS:
                value = response.headers.get(header)
                result["headers"][header] = value if value else "Not set"

            return result

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            result["error"] = "Connection timed out while fetching headers."
            return result
        except Exception as exc:
            result["error"] = str(exc)
            continue

    if not result["error"]:
        result["error"] = "Could not connect via HTTP or HTTPS."

    return result
