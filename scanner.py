"""
scanner.py - Core vulnerability scanning logic
Web Vulnerability Scanner
"""

import requests
import re
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode
from requests.exceptions import RequestException, Timeout, ConnectionError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('scanner.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Request timeout in seconds
REQUEST_TIMEOUT = 10

# Common SQL injection test payloads (safe, detection only)
SQL_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1' ORDER BY 1--", "1 UNION SELECT NULL--"
]

# XSS test payloads (safe, detection only)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>"
]

# Open redirect payloads
REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com",
    "//evil.com/%2F..", "///evil.com"
]

# Common sensitive paths for directory listing & info disclosure
SENSITIVE_PATHS = [
    "/admin", "/.git", "/.env", "/backup",
    "/config", "/phpinfo.php", "/server-info",
    "/wp-admin", "/uploads", "/files"
]


def make_request(url, params=None, allow_redirects=True):
    """
    Make an HTTP GET request with a browser-like User-Agent.
    Returns the response or None on failure.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        response = requests.get(
            url, params=params, headers=headers,
            timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects,
            verify=False  # Allow self-signed certs for testing
        )
        return response
    except Timeout:
        logger.warning(f"Timeout reaching {url}")
    except ConnectionError:
        logger.warning(f"Connection error for {url}")
    except RequestException as e:
        logger.warning(f"Request failed for {url}: {e}")
    return None


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_security_headers(response):
    """Check for missing or weak security headers."""
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}

    checks = [
        {
            "header": "content-security-policy",
            "name": "Missing Content-Security-Policy",
            "risk": "High",
            "description": (
                "Content-Security-Policy (CSP) header is absent. "
                "CSP helps prevent XSS and data injection attacks by "
                "controlling which resources the browser may load."
            ),
            "fix": (
                "Add a Content-Security-Policy header. Example: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'"
            ),
        },
        {
            "header": "x-frame-options",
            "name": "Missing X-Frame-Options",
            "risk": "Medium",
            "description": (
                "X-Frame-Options header is absent. Without it, the page can be "
                "embedded in an iframe, enabling clickjacking attacks."
            ),
            "fix": "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
        },
        {
            "header": "strict-transport-security",
            "name": "Missing Strict-Transport-Security (HSTS)",
            "risk": "High",
            "description": (
                "HSTS header is absent. This allows attackers to downgrade "
                "HTTPS connections to HTTP via man-in-the-middle attacks."
            ),
            "fix": (
                "Add: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
        },
        {
            "header": "x-content-type-options",
            "name": "Missing X-Content-Type-Options",
            "risk": "Low",
            "description": (
                "X-Content-Type-Options: nosniff is absent. Browsers may "
                "MIME-sniff responses, enabling certain XSS attacks."
            ),
            "fix": "Add: X-Content-Type-Options: nosniff",
        },
        {
            "header": "x-xss-protection",
            "name": "Missing X-XSS-Protection",
            "risk": "Low",
            "description": (
                "X-XSS-Protection header is absent. While modern browsers "
                "rely on CSP, older browsers benefit from this header."
            ),
            "fix": "Add: X-XSS-Protection: 1; mode=block",
        },
        {
            "header": "referrer-policy",
            "name": "Missing Referrer-Policy",
            "risk": "Low",
            "description": (
                "Referrer-Policy is absent. Sensitive URL data may be leaked "
                "via the Referer header to third-party sites."
            ),
            "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        {
            "header": "permissions-policy",
            "name": "Missing Permissions-Policy",
            "risk": "Low",
            "description": (
                "Permissions-Policy is absent. Browser features such as "
                "camera, microphone, or geolocation may be accessible to "
                "embedded scripts without restriction."
            ),
            "fix": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
    ]

    for check in checks:
        if check["header"] not in headers:
            findings.append({
                "name": check["name"],
                "risk": check["risk"],
                "description": check["description"],
                "fix": check["fix"],
                "category": "Security Headers",
            })

    return findings


def check_https(url):
    """Check whether the site forces HTTPS."""
    findings = []
    parsed = urlparse(url)

    if parsed.scheme == "http":
        findings.append({
            "name": "HTTPS Not Enforced",
            "risk": "Critical",
            "description": (
                "The target URL uses HTTP instead of HTTPS. All data transmitted "
                "is unencrypted and susceptible to interception and tampering."
            ),
            "fix": (
                "Obtain an SSL/TLS certificate (e.g., via Let's Encrypt) and "
                "redirect all HTTP traffic to HTTPS."
            ),
            "category": "Transport Security",
        })
    else:
        # Check whether HTTP redirects to HTTPS
        http_url = url.replace("https://", "http://", 1)
        response = make_request(http_url, allow_redirects=False)
        if response and response.status_code not in (301, 302, 307, 308):
            findings.append({
                "name": "HTTP Not Redirected to HTTPS",
                "risk": "High",
                "description": (
                    "The HTTP version of the site does not redirect to HTTPS, "
                    "allowing users to access the site over an insecure channel."
                ),
                "fix": "Configure your web server to redirect HTTP (port 80) to HTTPS (port 443).",
                "category": "Transport Security",
            })

    return findings


def check_sql_injection(url):
    """Test for basic SQL injection indicators using safe payloads."""
    findings = []
    parsed = urlparse(url)

    # Only test if there are query parameters
    if not parsed.query:
        return findings

    error_patterns = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"odbc.*driver",
        r"sqlstate",
        r"ora-\d{5}",
        r"pg_query\(\):",
        r"sqlite3\.",
    ]

    params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

    for param, value in params.items():
        for payload in SQL_PAYLOADS[:3]:  # Limit to 3 payloads to be polite
            test_params = {**params, param: value + payload}
            response = make_request(parsed._replace(query="").geturl(), params=test_params)
            if response:
                body_lower = response.text.lower()
                for pattern in error_patterns:
                    if re.search(pattern, body_lower):
                        findings.append({
                            "name": f"Possible SQL Injection — parameter: {param}",
                            "risk": "Critical",
                            "description": (
                                f"The parameter '{param}' may be vulnerable to SQL injection. "
                                "A database error message was returned when a crafted payload was submitted, "
                                "suggesting raw SQL is being executed without sanitization."
                            ),
                            "fix": (
                                "Use parameterized queries or prepared statements. "
                                "Never concatenate user input into SQL strings. "
                                "Apply an ORM if possible and implement input validation."
                            ),
                            "category": "Injection",
                        })
                        return findings  # Report once per URL

    return findings


def check_xss(url):
    """Test for reflected XSS indicators using safe payloads."""
    findings = []
    parsed = urlparse(url)

    if not parsed.query:
        return findings

    params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)

    for param, value in params.items():
        for payload in XSS_PAYLOADS[:3]:
            test_params = {**params, param: payload}
            response = make_request(parsed._replace(query="").geturl(), params=test_params)
            if response and payload in response.text:
                findings.append({
                    "name": f"Possible Reflected XSS — parameter: {param}",
                    "risk": "High",
                    "description": (
                        f"The parameter '{param}' reflects unsanitized user input back in "
                        "the page response. An attacker can craft a malicious URL that executes "
                        "arbitrary JavaScript in the victim's browser."
                    ),
                    "fix": (
                        "Encode all user-supplied output using context-aware escaping "
                        "(HTML entity encoding). Implement a strong Content-Security-Policy "
                        "and validate/sanitize all input server-side."
                    ),
                    "category": "Cross-Site Scripting (XSS)",
                })
                return findings

    return findings


def check_open_redirect(url):
    """Test for open redirect vulnerabilities."""
    findings = []
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto", "dest", "destination"]
    parsed = urlparse(url)
    base = parsed._replace(query="", fragment="").geturl()

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS[:2]:
            test_params = {param: payload}
            response = make_request(base, params=test_params, allow_redirects=False)
            if response and response.status_code in (301, 302, 307, 308):
                location = response.headers.get("Location", "")
                if "evil.com" in location or location.startswith("//"):
                    findings.append({
                        "name": f"Open Redirect — parameter: {param}",
                        "risk": "Medium",
                        "description": (
                            f"The '{param}' parameter accepts arbitrary external URLs as a redirect destination. "
                            "Attackers can craft links that appear legitimate but redirect users to phishing sites."
                        ),
                        "fix": (
                            "Whitelist allowed redirect destinations server-side. "
                            "Reject absolute URLs or those pointing off-domain. "
                            "Use a signed token to validate redirect targets."
                        ),
                        "category": "Open Redirect",
                    })
                    return findings

    return findings


def check_sensitive_info(response, url):
    """Detect accidental exposure of sensitive information in the page body."""
    findings = []
    body = response.text.lower()

    patterns = {
        "Error / Stack Trace Exposure": {
            "pattern": r"(traceback|stack trace|exception in|fatal error|parse error|syntax error|at line \d+)",
            "risk": "Medium",
            "description": (
                "The page appears to expose stack traces or detailed error messages. "
                "This reveals internal paths, library versions, and code structure "
                "that can aid an attacker in targeting the application."
            ),
            "fix": (
                "Configure your framework/server to display generic error pages in production. "
                "Log detailed errors server-side only. Disable debug mode."
            ),
        },
        "Private Key / Secret Detected": {
            "pattern": r"(-----begin (rsa|ec|dsa|openssh) private key-----|aws_secret_access_key|api[_-]?key\s*=\s*['\"][a-z0-9]{16,})",
            "risk": "Critical",
            "description": (
                "A private key or API secret appears to be exposed in the page response. "
                "This is a severe breach that could allow complete account or server compromise."
            ),
            "fix": (
                "Remove all secrets from source code and web responses immediately. "
                "Rotate any exposed credentials. Use environment variables or a secrets manager."
            ),
        },
        "Internal IP Address Leaked": {
            "pattern": r"(192\.168\.|10\.\d+\.\d+\.|172\.(1[6-9]|2\d|3[01])\.|127\.0\.0\.1)",
            "risk": "Low",
            "description": (
                "Internal IP addresses are visible in the page response. "
                "This can give attackers information about the internal network topology."
            ),
            "fix": (
                "Sanitize server responses to strip internal network references. "
                "Review proxy and load balancer configurations."
            ),
        },
    }

    for name, check in patterns.items():
        if re.search(check["pattern"], body):
            findings.append({
                "name": name,
                "risk": check["risk"],
                "description": check["description"],
                "fix": check["fix"],
                "category": "Information Disclosure",
            })

    return findings


def check_server_info(response):
    """Detect server/framework version disclosure in response headers."""
    findings = []
    headers = response.headers

    disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
    found = {}
    for h in disclosure_headers:
        val = headers.get(h)
        if val:
            found[h] = val

    if found:
        details = ", ".join(f"{k}: {v}" for k, v in found.items())
        findings.append({
            "name": "Server Version Disclosure",
            "risk": "Low",
            "description": (
                f"The server reveals technology/version information via headers: {details}. "
                "Attackers use this to quickly identify software with known CVEs."
            ),
            "fix": (
                "Remove or obscure version banners. In Apache: ServerTokens Prod. "
                "In Nginx: server_tokens off. Remove X-Powered-By via framework settings."
            ),
            "category": "Information Disclosure",
        })

    return findings


def check_directory_listing(url):
    """Check if directory listing is enabled on common paths."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    listing_indicators = ["index of /", "directory listing for", "parent directory"]

    for path in SENSITIVE_PATHS[:5]:
        test_url = urljoin(base, path)
        response = make_request(test_url)
        if response and response.status_code == 200:
            body_lower = response.text.lower()
            if any(ind in body_lower for ind in listing_indicators):
                findings.append({
                    "name": f"Directory Listing Enabled — {path}",
                    "risk": "Medium",
                    "description": (
                        f"Directory listing is enabled at {test_url}. "
                        "This exposes the file system structure and potentially sensitive files "
                        "to unauthenticated visitors."
                    ),
                    "fix": (
                        "Disable directory listing in your web server. "
                        "Apache: Options -Indexes. Nginx: autoindex off."
                    ),
                    "category": "Information Disclosure",
                })

    return findings


def check_cookie_security(response):
    """Inspect Set-Cookie headers for missing security flags."""
    findings = []
    cookies = response.headers.get_all("Set-Cookie") if hasattr(response.headers, "get_all") else []

    # requests stores cookies differently; parse raw headers
    raw_cookies = []
    for key, val in response.raw.headers.items():
        if key.lower() == "set-cookie":
            raw_cookies.append(val)

    for cookie in raw_cookies:
        cookie_lower = cookie.lower()
        issues = []

        if "httponly" not in cookie_lower:
            issues.append("missing HttpOnly flag")
        if "secure" not in cookie_lower:
            issues.append("missing Secure flag")
        if "samesite" not in cookie_lower:
            issues.append("missing SameSite attribute")

        if issues:
            name_part = cookie.split("=")[0].strip()
            findings.append({
                "name": f"Insecure Cookie — {name_part}",
                "risk": "Medium",
                "description": (
                    f"The cookie '{name_part}' has security issues: {', '.join(issues)}. "
                    "Missing HttpOnly allows JavaScript access (XSS risk). "
                    "Missing Secure sends the cookie over HTTP. "
                    "Missing SameSite enables CSRF attacks."
                ),
                "fix": (
                    f"Set the cookie as: {name_part}=value; HttpOnly; Secure; SameSite=Strict"
                ),
                "category": "Cookie Security",
            })

    return findings


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

RISK_WEIGHTS = {"Critical": 40, "High": 20, "Medium": 10, "Low": 5}

def calculate_risk_score(findings):
    """
    Calculate an overall risk score (0–100) and return
    a label: Safe, Low, Medium, High, or Critical.
    """
    if not findings:
        return {"score": 0, "label": "Safe"}

    raw = sum(RISK_WEIGHTS.get(f["risk"], 0) for f in findings)
    score = min(100, raw)

    if score == 0:
        label = "Safe"
    elif score <= 15:
        label = "Low"
    elif score <= 40:
        label = "Medium"
    elif score <= 70:
        label = "High"
    else:
        label = "Critical"

    return {"score": score, "label": label}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(url):
    """
    Orchestrate all checks and return a structured scan result dict.
    """
    logger.info(f"Starting scan for: {url}")
    findings = []

    # --- Initial request ---
    response = make_request(url)
    if response is None:
        return {
            "success": False,
            "error": f"Unable to reach {url}. Check the URL and try again.",
        }

    # Run checks
    try:
        findings += check_https(url)
        findings += check_security_headers(response)
        findings += check_server_info(response)
        findings += check_sensitive_info(response, url)
        findings += check_cookie_security(response)
        findings += check_sql_injection(url)
        findings += check_xss(url)
        findings += check_open_redirect(url)
        findings += check_directory_listing(url)
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")

    risk = calculate_risk_score(findings)

    # Count by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        severity_counts[f.get("risk", "Low")] = severity_counts.get(f.get("risk", "Low"), 0) + 1

    result = {
        "success": True,
        "url": url,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_vulnerabilities": len(findings),
        "severity_counts": severity_counts,
        "risk_score": risk["score"],
        "risk_label": risk["label"],
        "findings": findings,
        "server": response.headers.get("Server", "Unknown"),
        "status_code": response.status_code,
    }

    logger.info(
        f"Scan complete for {url}: {len(findings)} findings, "
        f"risk={risk['label']} ({risk['score']})"
    )
    return result
