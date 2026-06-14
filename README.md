# VulnScan — Web Vulnerability Scanner

A professional, dark-themed web vulnerability scanner built with Python (Flask) and Bootstrap 5.

## Features

| Category | Checks |
|---|---|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, XSS-Protection, Referrer-Policy, Permissions-Policy |
| **Transport Security** | HTTPS enforcement, HTTP→HTTPS redirect |
| **SQL Injection** | Safe payload testing on query parameters |
| **XSS Detection** | Reflected XSS indicator scanning |
| **Open Redirect** | Common redirect parameter probing |
| **Cookie Security** | HttpOnly, Secure, SameSite attribute checks |
| **Info Disclosure** | Stack traces, private keys, internal IPs |
| **Server Info** | Version banners in Server/X-Powered-By headers |
| **Directory Listing** | Common path enumeration |
| **Risk Scoring** | Aggregate 0–100 score with Safe/Low/Medium/High/Critical label |

## Project Structure

```
/
├── app.py              # Flask routes
├── scanner.py          # All scanning logic
├── requirements.txt
├── README.md
├── templates/
│   └── index.html      # Main UI
└── static/
    ├── css/style.css   # Dark cybersecurity theme
    └── js/script.js    # AJAX, rendering, export
```

## Quick Start

### 1. Clone / download

```bash
git clone <repo-url>
cd vuln-scanner
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the development server

```bash
python app.py
```

Open your browser at **http://localhost:5000**

---

## Usage

1. Enter a target URL (e.g. `https://example.com`) in the input field.
2. Click **Start Scan**. A progress bar shows live status.
3. Results appear below — each finding is expandable with description + fix.
4. Use **Export JSON** to download the raw results.
5. Use **Download PDF** to generate a print-ready report.
6. The **Scan History** table tracks your last 20 scans (session only).

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | `{"url": "https://example.com"}` → JSON results |
| `GET` | `/api/history` | List of recent scans |
| `POST` | `/api/export` | Echoes scan data as a downloadable JSON file |

## Production Notes

- Replace `app.secret_key` with `os.urandom(32)` and keep it secret.
- Use `gunicorn app:app` behind nginx in production.
- Implement rate limiting (e.g. `flask-limiter`) before exposing publicly.
- Add authentication to prevent unauthorised scanning.
- Logs are written to `app.log` and `scanner.log`.

## Legal Notice

**Only scan targets you own or have explicit written permission to test.**
Unauthorised scanning may violate computer crime laws in your jurisdiction.

---

*VulnScan — for educational and authorised security testing only.*
