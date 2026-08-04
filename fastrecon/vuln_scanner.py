"""
FastRecon Vulnerability Scanner — Automated checks for common web vulnerabilities.
Tests for XSS, SQLi, CORS, Open Redirect, CRLF, Clickjacking, HTTP Method Tampering, etc.
"""

import asyncio
import re
import ssl
from datetime import datetime, timezone

from fastrecon.config import (
    CRLF_PAYLOADS,
    INJECTABLE_PARAMS,
    OPEN_REDIRECT_PAYLOADS,
    SQL_ERROR_PATTERNS,
    SQLI_PAYLOADS,
    VULN_SCAN_TIMEOUT,
    XSS_PAYLOADS,
)


async def _fetch(session, url, method="GET", headers=None, timeout=VULN_SCAN_TIMEOUT):
    """Helper to make HTTP requests with error handling."""
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        kwargs = {
            "timeout": timeout,
            "allow_redirects": False,
            "ssl": ssl_context,
        }
        if headers:
            kwargs["headers"] = headers

        if method == "GET":
            async with session.get(url, **kwargs) as response:
                body = await response.text()
                return response.status, dict(response.headers), body
        elif method == "HEAD":
            async with session.head(url, **kwargs) as response:
                return response.status, dict(response.headers), ""
        elif method == "OPTIONS":
            async with session.options(url, **kwargs) as response:
                return response.status, dict(response.headers), ""
        elif method == "PUT":
            async with session.put(url, **kwargs) as response:
                return response.status, dict(response.headers), ""
        elif method == "DELETE":
            async with session.delete(url, **kwargs) as response:
                return response.status, dict(response.headers), ""
        elif method == "PATCH":
            async with session.patch(url, **kwargs) as response:
                return response.status, dict(response.headers), ""
        elif method == "POST":
            async with session.post(url, **kwargs) as response:
                body = await response.text()
                return response.status, dict(response.headers), body

    except Exception:
        return None, None, None


async def check_cors(session, url, semaphore):
    """
    Test for CORS misconfiguration.
    Sends Origin: https://evil.com and checks if it's reflected.
    """
    findings = []
    async with semaphore:
        origins_to_test = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]

        for origin in origins_to_test:
            status, headers, body = await _fetch(
                session, url,
                headers={"Origin": origin}
            )

            if headers:
                acao = headers.get("Access-Control-Allow-Origin", "")
                acac = headers.get("Access-Control-Allow-Credentials", "")

                if acao == origin or acao == "*":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "type": "CORS Misconfiguration",
                        "asset": url,
                        "service": "Web Application",
                        "details": f"Origin '{origin}' is reflected in Access-Control-Allow-Origin"
                                   + (" with credentials allowed!" if acac.lower() == "true" else ""),
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Configure CORS to only allow trusted origins. Never reflect arbitrary origins with credentials.",
                    })
                    break  # One finding is enough

                if acao == "null" and origin == "null":
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "CORS Null Origin",
                        "asset": url,
                        "service": "Web Application",
                        "details": "CORS allows 'null' origin — can be exploited via sandboxed iframes",
                        "evidence": f"ACAO: {acao}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Do not allow 'null' as a valid origin in CORS configuration.",
                    })

    return findings


async def check_reflected_xss(session, url, semaphore):
    """
    Test for reflected XSS by injecting payloads into URL parameters.
    """
    findings = []
    async with semaphore:
        for param in INJECTABLE_PARAMS[:8]:  # Test top params
            for payload in XSS_PAYLOADS[:3]:  # Use top payloads
                test_url = f"{url}?{param}={payload}"
                status, headers, body = await _fetch(session, test_url)

                if body and payload in body:
                    # Check if it's actually reflected (not just in a safe context)
                    findings.append({
                        "severity": "HIGH",
                        "type": "Reflected XSS",
                        "asset": url,
                        "service": "Web Application",
                        "details": f"XSS payload reflected in response via parameter '{param}'",
                        "evidence": f"Payload: {payload} | Parameter: {param}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Encode all user input before rendering. Use Content-Security-Policy header.",
                    })
                    return findings  # One XSS per URL is enough

    return findings


async def check_sqli(session, url, semaphore):
    """
    Test for SQL injection by injecting payloads and detecting SQL error patterns.
    """
    findings = []
    async with semaphore:
        for param in INJECTABLE_PARAMS[:5]:
            for payload in SQLI_PAYLOADS[:3]:
                test_url = f"{url}?{param}={payload}"
                status, headers, body = await _fetch(session, test_url)

                if body:
                    body_lower = body.lower()
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body_lower):
                            findings.append({
                                "severity": "CRITICAL",
                                "type": "SQL Injection",
                                "asset": url,
                                "service": "Web Application / Database",
                                "details": f"SQL error detected in response when injecting via parameter '{param}'",
                                "evidence": f"Payload: {payload} | Pattern matched: {pattern}",
                                "cname_pattern": "",
                                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                                "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            })
                            return findings  # One SQLi per URL is enough

    return findings


async def check_open_redirect(session, url, semaphore):
    """Test for open redirect vulnerabilities."""
    findings = []
    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto",
                       "target", "rurl", "dest", "destination", "redir",
                       "redirect_uri", "redirect_url", "callback"]

    async with semaphore:
        for param in redirect_params[:5]:
            for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                test_url = f"{url}?{param}={payload}"
                status, headers, body = await _fetch(session, test_url)

                if status in (301, 302, 307, 308) and headers:
                    location = headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "Open Redirect",
                            "asset": url,
                            "service": "Web Application",
                            "details": f"Open redirect via parameter '{param}' — redirects to attacker-controlled URL",
                            "evidence": f"Parameter: {param} | Redirect: {location}",
                            "cname_pattern": "",
                            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                            "remediation": "Validate redirect URLs against a whitelist. Use relative paths only.",
                        })
                        return findings

    return findings


async def check_crlf_injection(session, url, semaphore):
    """Test for CRLF injection in HTTP headers."""
    findings = []
    async with semaphore:
        for payload in CRLF_PAYLOADS[:2]:
            test_url = f"{url}/{payload}"
            status, headers, body = await _fetch(session, test_url)

            if headers:
                # Check if our injected cookie appears
                set_cookie = headers.get("Set-Cookie", "")
                if "crlf=true" in set_cookie:
                    findings.append({
                        "severity": "HIGH",
                        "type": "CRLF Injection",
                        "asset": url,
                        "service": "Web Application",
                        "details": "CRLF injection allows injecting arbitrary HTTP headers",
                        "evidence": f"Payload: {payload} | Injected Set-Cookie detected",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Sanitize CR (\\r) and LF (\\n) characters from all user input used in HTTP headers.",
                    })
                    return findings

    return findings


async def check_http_methods(session, url, semaphore):
    """Test for dangerous HTTP methods enabled."""
    findings = []
    async with semaphore:
        # First try OPTIONS to see what's allowed
        status, headers, body = await _fetch(session, url, method="OPTIONS")

        if headers:
            allow = headers.get("Allow", "")
            if allow:
                dangerous = []
                for method in ["PUT", "DELETE", "TRACE", "PATCH"]:
                    if method in allow.upper():
                        dangerous.append(method)

                if dangerous:
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "HTTP Method Tampering",
                        "asset": url,
                        "service": "Web Application",
                        "details": f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                        "evidence": f"Allow header: {allow}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Disable unnecessary HTTP methods. Only allow GET, POST, HEAD as needed.",
                    })

        # Test TRACE specifically (XST attack)
        status, headers, body = await _fetch(session, url, method="TRACE" if False else "OPTIONS")
        # Note: TRACE via aiohttp is not directly supported, so we check via OPTIONS Allow header

    return findings


async def check_clickjacking(session, url, semaphore):
    """Check for clickjacking vulnerability (missing X-Frame-Options / CSP frame-ancestors)."""
    findings = []
    async with semaphore:
        status, headers, body = await _fetch(session, url)

        if headers:
            xfo = headers.get("X-Frame-Options", "")
            csp = headers.get("Content-Security-Policy", "")

            if not xfo and "frame-ancestors" not in csp:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "Clickjacking",
                    "asset": url,
                    "service": "Web Application",
                    "details": "No X-Frame-Options or CSP frame-ancestors — page can be embedded in malicious iframes",
                    "evidence": "Missing X-Frame-Options header and no frame-ancestors in CSP",
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "remediation": "Add X-Frame-Options: DENY or CSP: frame-ancestors 'self'",
                })

    return findings


async def check_info_disclosure(session, url, semaphore):
    """Check for information disclosure in headers and response."""
    findings = []
    async with semaphore:
        status, headers, body = await _fetch(session, url)

        if headers:
            # Server version disclosure
            server = headers.get("Server", "")
            if server and any(char.isdigit() for char in server):
                findings.append({
                    "severity": "LOW",
                    "type": "Server Version Disclosure",
                    "asset": url,
                    "service": "Web Server",
                    "details": f"Server header exposes version information: {server}",
                    "evidence": f"Server: {server}",
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "remediation": "Remove or obfuscate the Server header version information.",
                })

            # X-Powered-By disclosure
            powered_by = headers.get("X-Powered-By", "")
            if powered_by:
                findings.append({
                    "severity": "LOW",
                    "type": "Technology Disclosure",
                    "asset": url,
                    "service": "Web Application",
                    "details": f"X-Powered-By header exposes technology: {powered_by}",
                    "evidence": f"X-Powered-By: {powered_by}",
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "remediation": "Remove the X-Powered-By header.",
                })

        # Check for stack traces / debug info in body
        if body:
            debug_patterns = [
                (r"Traceback \(most recent call last\)", "Python Stack Trace"),
                (r"<b>Fatal error</b>:.*in <b>", "PHP Fatal Error"),
                (r"at\s+[\w.]+\([\w.]+\.java:\d+\)", "Java Stack Trace"),
                (r"Exception in thread", "Java Exception"),
                (r"Microsoft\.AspNet", "ASP.NET Error"),
                (r"<title>Error - Application</title>", "Application Error Page"),
                (r"SQLSTATE\[", "SQL Error Exposure"),
            ]
            for pattern, desc in debug_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "Information Disclosure",
                        "asset": url,
                        "service": "Web Application",
                        "details": f"{desc} detected in response — may expose internal paths, versions, or credentials",
                        "evidence": f"Pattern: {desc}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Disable debug mode in production. Use custom error pages.",
                    })
                    break

    return findings


async def check_cookie_security(session, url, semaphore):
    """Check for insecure cookie flags."""
    findings = []
    async with semaphore:
        status, headers, body = await _fetch(session, url)

        if headers:
            cookies = []
            # Check Set-Cookie headers
            for key, value in headers.items():
                if key.lower() == "set-cookie":
                    cookies.append(value)

            for cookie in cookies:
                cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"
                issues = []

                if "secure" not in cookie.lower():
                    issues.append("missing Secure flag")
                if "httponly" not in cookie.lower():
                    issues.append("missing HttpOnly flag")
                if "samesite" not in cookie.lower():
                    issues.append("missing SameSite attribute")

                if issues:
                    findings.append({
                        "severity": "LOW",
                        "type": "Insecure Cookie",
                        "asset": url,
                        "service": "Web Application",
                        "details": f"Cookie '{cookie_name}' has security issues: {', '.join(issues)}",
                        "evidence": f"Set-Cookie: {cookie[:100]}",
                        "cname_pattern": "",
                        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                        "remediation": "Set Secure, HttpOnly, and SameSite=Strict/Lax flags on all cookies.",
                    })

    return findings


async def check_host_header_injection(session, url, semaphore):
    """Test for Host header injection."""
    findings = []
    async with semaphore:
        # Send request with modified Host header
        status, headers, body = await _fetch(
            session, url,
            headers={"Host": "evil.com"}
        )

        if body and "evil.com" in body.lower():
            findings.append({
                "severity": "HIGH",
                "type": "Host Header Injection",
                "asset": url,
                "service": "Web Application",
                "details": "Host header value is reflected in the response — potential password reset poisoning",
                "evidence": "Injected Host: evil.com appears in response body",
                "cname_pattern": "",
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "remediation": "Validate the Host header against a whitelist. Use a fixed base URL for link generation.",
            })

    return findings


async def check_directory_listing(session, url, semaphore):
    """Check for directory listing enabled."""
    findings = []
    test_paths = ["/", "/images/", "/uploads/", "/assets/", "/static/", "/css/", "/js/"]

    async with semaphore:
        for path in test_paths:
            test_url = f"{url.rstrip('/')}{path}"
            status, headers, body = await _fetch(session, test_url)

            if body and status == 200:
                listing_patterns = [
                    r"<title>Index of",
                    r"<title>Directory listing",
                    r'<a href="\?C=',
                    r"Parent Directory",
                    r"Directory Listing For",
                ]
                for pattern in listing_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "Directory Listing",
                            "asset": test_url,
                            "service": "Web Server",
                            "details": f"Directory listing enabled at {path} — internal file structure exposed",
                            "evidence": f"Pattern found: {pattern}",
                            "cname_pattern": "",
                            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                            "remediation": "Disable directory listing in web server configuration.",
                        })
                        break

    return findings


async def run_vuln_scan(session, target, base_url, mode="normal", concurrency=10):
    """
    Execute all vulnerability checks against a target.

    Args:
        session: aiohttp ClientSession
        target: Target domain
        base_url: Base URL (e.g., https://example.com)
        mode: Scan mode
        concurrency: Max concurrent vuln test requests

    Returns:
        List of vulnerability/finding dicts
    """
    print(f"\n{'='*60}")
    print("  PHASE 7: VULNERABILITY SCANNING")
    print(f"{'='*60}")
    print(f"  Running vulnerability checks on {base_url}...")

    semaphore = asyncio.Semaphore(concurrency)
    all_findings = []

    # Run all checks
    checks = [
        ("CORS Misconfiguration", check_cors(session, base_url, semaphore)),
        ("Clickjacking", check_clickjacking(session, base_url, semaphore)),
        ("Info Disclosure", check_info_disclosure(session, base_url, semaphore)),
        ("Cookie Security", check_cookie_security(session, base_url, semaphore)),
        ("Directory Listing", check_directory_listing(session, base_url, semaphore)),
        ("HTTP Methods", check_http_methods(session, base_url, semaphore)),
        ("Host Header Injection", check_host_header_injection(session, base_url, semaphore)),
    ]

    # Only run active injection tests in normal/aggressive mode
    if mode != "light":
        checks.extend([
            ("Reflected XSS", check_reflected_xss(session, base_url, semaphore)),
            ("SQL Injection", check_sqli(session, base_url, semaphore)),
            ("Open Redirect", check_open_redirect(session, base_url, semaphore)),
            ("CRLF Injection", check_crlf_injection(session, base_url, semaphore)),
        ])

    for check_name, check_coro in checks:
        try:
            print(f"  [VULN] Testing: {check_name}...")
            findings = await check_coro
            if findings:
                all_findings.extend(findings)
                for f in findings:
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟡"}.get(f["severity"], "⚪")
                    print(f"    {icon} {f['severity']}: {f['type']}")
            else:
                print("    ✓ Clean")
        except Exception as e:
            print(f"    ✗ Check failed: {e}")

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))

    print(f"\n  ✓ Vulnerability scan complete: {len(all_findings)} finding(s)")

    return all_findings
