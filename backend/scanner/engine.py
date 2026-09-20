import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "title": "Missing Content-Security-Policy header",
        "description": "A Content-Security-Policy can reduce the impact of script injection and other content-injection attacks.",
        "remediation": "Define a restrictive Content-Security-Policy appropriate for the application."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "title": "Missing Strict-Transport-Security header",
        "description": "HSTS instructs browsers to use HTTPS for future requests.",
        "remediation": "Enable HSTS after confirming the site is fully available over HTTPS."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "title": "Missing X-Content-Type-Options header",
        "description": "Without this header, browsers may MIME-sniff certain responses.",
        "remediation": "Set X-Content-Type-Options to nosniff."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "title": "Missing clickjacking protection",
        "description": "The response does not advertise protection against framing-based clickjacking.",
        "remediation": "Set X-Frame-Options or use frame-ancestors in Content-Security-Policy."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "title": "Missing Referrer-Policy header",
        "description": "A referrer policy controls how much URL information is shared with other sites.",
        "remediation": "Consider a privacy-preserving policy such as strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "title": "Missing Permissions-Policy header",
        "description": "Permissions-Policy can restrict access to sensitive browser capabilities.",
        "remediation": "Define a policy that disables features the application does not need."
    },
}

def severity_weight(level):
    return {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}.get(level, 0)

def add_finding(findings, code, severity, title, description, remediation, evidence=""):
    findings.append({
        "code": code,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence
    })

def inspect_tls(hostname, port=443):
    result = {"available": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as sock:
                cert = sock.getpeercert()
                expires = cert.get("notAfter")
                expiry = None
                if expires:
                    expiry = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result = {
                    "available": True,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires": expiry.isoformat() if expiry else None,
                    "days_remaining": (expiry - datetime.now(timezone.utc)).days if expiry else None
                }
    except Exception as exc:
        result = {"available": False, "error": str(exc)}
    return result

def scan_url(target):
    parsed = urlparse(target if "://" in target else "https://" + target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    normalized = parsed.geturl()
    response = requests.get(
        normalized,
        timeout=12,
        allow_redirects=True,
        headers={"User-Agent": "VulnScan-Lite/2.0 defensive scanner"},
        verify=True
    )
    final_url = response.url
    headers = {k: v for k, v in response.headers.items()}
    findings = []

    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            add_finding(findings, "HDR-" + header.upper().replace("-", "_"),
                        meta["severity"], meta["title"], meta["description"],
                        meta["remediation"], "Header absent from response.")

    if parsed.scheme == "http":
        add_finding(findings, "TLS-001", "High", "Target is using HTTP",
                    "The submitted URL does not use encrypted transport.",
                    "Use HTTPS and redirect HTTP traffic to HTTPS.",
                    normalized)

    for cookie in response.cookies:
        raw = str(cookie)
        if not cookie.secure:
            add_finding(findings, "COOKIE-SECURE", "Medium",
                        "Cookie missing Secure attribute",
                        "A cookie without Secure may be transmitted over an unencrypted connection.",
                        "Set the Secure attribute for session and sensitive cookies.", raw)
        if "httponly" not in raw.lower():
            add_finding(findings, "COOKIE-HTTPONLY", "Medium",
                        "Cookie may be missing HttpOnly",
                        "HttpOnly reduces JavaScript access to cookies.",
                        "Set HttpOnly on cookies that do not need client-side access.", raw)

    body = response.text[:100000]
    soup = BeautifulSoup(body, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if not title:
        add_finding(findings, "HTML-TITLE", "Info", "Page has no HTML title",
                    "A descriptive title improves usability and accessibility.",
                    "Add a meaningful <title> element.")

    if parsed.scheme == "https":
        mixed = [tag.get("src") or tag.get("href") for tag in soup.find_all(["script", "img", "link"])
                 if (tag.get("src") or tag.get("href") or "").startswith("http://")]
        if mixed:
            add_finding(findings, "MIXED-CONTENT", "Medium",
                        "Potential mixed content references",
                        "The HTTPS page references resources over HTTP.",
                        "Serve all page resources over HTTPS or use relative/HTTPS URLs.",
                        ", ".join(mixed[:5]))

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        has_password = form.find("input", {"type": "password"}) is not None
        destination = urljoin(final_url, action)
        if has_password and destination.startswith("http://"):
            add_finding(findings, "FORM-HTTP", "High",
                        "Password form submits over HTTP",
                        "Credentials may be transmitted without encryption.",
                        "Submit authentication forms only to HTTPS endpoints.", destination)
        elif has_password and method == "get":
            add_finding(findings, "FORM-GET", "Medium",
                        "Password form uses GET method",
                        "GET may place sensitive values in URLs, browser history, and logs.",
                        "Use POST for credential submission.", destination)

    security_txt = urljoin(final_url, "/.well-known/security.txt")
    try:
        sec = requests.get(security_txt, timeout=6)
        if sec.status_code >= 400:
            add_finding(findings, "SECURITY-TXT", "Info",
                        "security.txt not detected",
                        "A security.txt file helps researchers report security issues.",
                        "Consider publishing /.well-known/security.txt.", str(sec.status_code))
    except requests.RequestException:
        pass

    tls = inspect_tls(parsed.hostname) if parsed.scheme == "https" else {"available": False}
    if tls.get("days_remaining") is not None and tls["days_remaining"] < 30:
        add_finding(findings, "TLS-EXPIRY", "High",
                    "TLS certificate expires soon",
                    "The certificate has fewer than 30 days remaining.",
                    "Renew the certificate before expiration.",
                    str(tls["days_remaining"]) + " days remaining")

    score = min(100, sum(severity_weight(x["severity"]) for x in findings) * 3)
    risk = "Low"
    if score >= 60: risk = "High"
    elif score >= 30: risk = "Medium"

    counts = {level: sum(1 for x in findings if x["severity"] == level)
              for level in ("Critical", "High", "Medium", "Low", "Info")}

    return {
        "target": target,
        "final_url": final_url,
        "status_code": response.status_code,
        "response_time_ms": round(response.elapsed.total_seconds() * 1000, 2),
        "server": headers.get("Server", "Not disclosed"),
        "title": title,
        "headers": headers,
        "tls": tls,
        "findings": findings,
        "counts": counts,
        "risk_score": score,
        "risk_level": risk,
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }
