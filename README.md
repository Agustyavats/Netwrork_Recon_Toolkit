# Network Recon Toolkit

A Python-based web application that automates basic network reconnaissance against a host or domain. Built for educational purposes and authorized security testing only.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## Overview

Network Recon Toolkit is a lightweight reconnaissance tool designed to help cybersecurity students and beginners understand how information gathering works during authorized security assessments. Enter a domain name or IP address, and the toolkit runs a series of passive and active checks — DNS lookups, WHOIS queries, SSL certificate inspection, port scanning, subdomain enumeration, and HTTP header analysis — then presents the results in a clean web interface.

This project is **not** a vulnerability scanner or penetration testing framework. It summarizes observable network information to support learning.

---

## Features

| Module | Description |
|--------|-------------|
| **Host Validation** | Detects whether input is a domain, IPv4, or IPv6 address |
| **DNS Lookup** | A, AAAA, MX, NS, TXT, and CNAME records |
| **WHOIS Lookup** | Registrar, dates, organization, and country |
| **SSL Certificate** | Issuer, validity dates, days remaining, expiry warnings |
| **Port Scanner** | Scans 16 common ports via Nmap (if installed) or socket fallback |
| **Reverse DNS** | PTR record lookup for IP addresses |
| **IP Information** | Resolved IP, public/private classification, IP version |
| **Subdomain Enumeration** | Checks 10 common subdomains from a built-in wordlist |
| **HTTP Headers** | Server, CSP, HSTS, X-Frame-Options, and more |
| **Security Summary** | Observational summary of scan results |
| **Scan History** | SQLite-backed history of past scans |
| **REST API** | `POST /api/scan` returns JSON results |

---


## Installation

### Prerequisites

- Python 3.10 or higher
- pip
- Nmap (optional — enables faster, more accurate port scanning)

### Steps

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/Network_Recon_Toolkit.git
cd Network_Recon_Toolkit
```

2. **Create a virtual environment**

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Install Nmap (optional)**

- **Windows:** Download from [https://nmap.org/download.html](https://nmap.org/download.html)
- **macOS:** `brew install nmap`
- **Linux:** `sudo apt install nmap`

5. **Run the application**

```bash
python app.py
```

6. **Open in browser**

Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Usage

### Web Interface

1. Open the home page.
2. Enter a domain (e.g. `example.com`) or IP address (e.g. `8.8.8.8`).
3. Click **Start Scan**.
4. Review results on the scan results page.
5. Access past scans from the **History** page.

### API

**Endpoint:** `POST /api/scan`

**Request:**

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Response (200 OK):**

```json
{
  "success": true,
  "target": "example.com",
  "target_type": "domain",
  "dns": { "success": true, "records": { "A": ["93.184.216.34"] } },
  "whois": { "success": true, "registrar": "..." },
  "ssl": { "success": true, "available": true, "issuer": "..." },
  "port_scan": { "success": true, "method": "socket", "ports": [] },
  "summary": { "overall": "Basic configuration appears secure." }
}
```

**Error (400 Bad Request):**

```json
{
  "success": false,
  "error": "Invalid domain or IP address."
}
```

---

## Folder Structure

```
Network_Recon_Toolkit/
├── app.py                 # Flask application and routes
├── scanner.py             # Scan orchestrator
├── dns_lookup.py          # DNS record lookups
├── whois_lookup.py        # WHOIS queries
├── ssl_checker.py         # SSL/TLS certificate checks
├── port_scanner.py        # Port scanning (Nmap + socket)
├── ip_lookup.py           # IP information
├── subdomain.py           # Subdomain enumeration
├── http_headers.py        # HTTP header retrieval
├── security_summary.py    # Observational summary
├── utils/
│   ├── __init__.py
│   └── validators.py      # Host validation
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── results.html
│   └── history.html
├── static/
│   ├── css/style.css
│   └── js/main.js
├── tests/
│   ├── test_dns_lookup.py
│   ├── test_ip_validation.py
│   ├── test_port_scanner.py
│   └── test_http_headers.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

---

## Project Architecture

```
User Input (Domain / IP)
        │
        ▼
  Host Validation (utils/validators.py)
        │
        ▼
  Scanner Orchestrator (scanner.py)
        │
        ├── DNS Lookup
        ├── WHOIS Lookup
        ├── SSL Checker
        ├── Port Scanner
        ├── Reverse DNS
        ├── IP Information
        ├── Subdomain Enumeration
        ├── HTTP Headers
        └── Security Summary
        │
        ▼
  Flask UI / JSON API (app.py)
        │
        └── SQLite History (optional)
```

Each module is a standalone Python file that returns a dictionary. The scanner orchestrator calls each module sequentially and aggregates the results. The Flask app renders results in HTML or returns JSON via the API.

---

## Running Tests

```bash
pytest tests/ -v
```

Tests cover:

- IP and domain validation
- DNS lookup (mocked)
- Port scanner (mocked)
- HTTP header retrieval (mocked)

---

## Limitations

- **Authorized use only** — Only scan targets you own or have explicit permission to test.
- **Small wordlist** — Subdomain enumeration checks only 10 common prefixes; not a substitute for dedicated tools.
- **Common ports only** — Port scanner covers 16 well-known ports, not full range scans.
- **No rate limiting** — Running many scans quickly may trigger blocks from remote services.
- **WHOIS variability** — WHOIS data format and availability varies by TLD and registrar.
- **Socket scan accuracy** — Without Nmap, socket-based scanning may report `filtered` instead of `closed`.
- **Not a vulnerability assessment** — The security summary is observational only.

---

## Future Improvements

- Export scan results to PDF or JSON file
- Configurable port list and subdomain wordlist
- Async scanning with threading for faster results
- IPv6 full support across all modules
- User authentication for multi-user deployments
- Comparison view between two scan results
- Integration with Shodan/Censys APIs (with API keys)

---

## Transparency

I built this project as part of my cybersecurity learning journey.

The core programming knowledge (Python, HTML, CSS, JavaScript, and SQL) comes from my school and college curriculum.

To complete this project, I learned Flask and supporting Python libraries through YouTube tutorials, official documentation, online walkthroughs, and publicly available GitHub repositories for educational purposes.

The goal of this project was to better understand network reconnaissance and information gathering techniques used during authorized security assessments.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Unauthorized scanning of systems you do not own or have permission to test may violate laws and terms of service. The author assumes no liability for misuse.
