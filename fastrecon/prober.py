"""
FastRecon Prober — Enhanced async live host probing with robots.txt, sitemap, and CORS checks.
"""

import re
import ssl

from fastrecon.config import DEFAULT_TIMEOUT


async def probe_host(session, subdomain, semaphore):
    """
    Probe a subdomain for HTTP liveness.
    Returns an enriched host dict or None if unreachable.
    """
    async with semaphore:
        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                async with session.get(
                    url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                    ssl=ssl_context,
                ) as response:
                    html_body = await response.text()
                    status = response.status
                    headers = dict(response.headers)

                    # Extract page title
                    title = _extract_title(html_body)

                    # Extract server info
                    server = headers.get("Server", "Unknown")
                    powered_by = headers.get("X-Powered-By", "")
                    content_length = headers.get("Content-Length", len(html_body))

                    # Build redirect chain
                    redirect_chain = []
                    if response.history:
                        for hist in response.history:
                            redirect_chain.append({
                                "url": str(hist.url),
                                "status": hist.status,
                            })

                    host_info = {
                        "url": str(response.url),
                        "originalUrl": url,
                        "subdomain": subdomain,
                        "status": status,
                        "title": title,
                        "server": server,
                        "poweredBy": powered_by,
                        "contentLength": int(content_length) if str(content_length).isdigit() else 0,
                        "redirectChain": redirect_chain,
                        "headers": {
                            k: v for k, v in headers.items()
                            if k.lower() in (
                                "server", "x-powered-by", "content-type",
                                "x-frame-options", "strict-transport-security",
                                "content-security-policy", "x-xss-protection",
                                "x-content-type-options", "referrer-policy",
                                "permissions-policy", "access-control-allow-origin",
                                "set-cookie", "x-permitted-cross-domain-policies",
                            )
                        },
                    }

                    print(f"  [+] Live: {url} → {status} | {title[:40]}")
                    return host_info, html_body

            except Exception:
                continue

        return None, None


async def fetch_robots_txt(session, base_url, semaphore):
    """Fetch and parse robots.txt for hidden paths."""
    paths = []
    async with semaphore:
        url = f"{base_url.rstrip('/')}/robots.txt"
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            async with session.get(url, timeout=DEFAULT_TIMEOUT, ssl=ssl_context) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.split("\n"):
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/" and "*" not in path:
                                paths.append(path)
                        elif line.lower().startswith("allow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                paths.append(path)
        except Exception:
            pass

    return list(set(paths))


async def fetch_sitemap(session, base_url, semaphore):
    """Fetch and parse sitemap.xml for URLs."""
    urls = []
    async with semaphore:
        sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            async with session.get(sitemap_url, timeout=DEFAULT_TIMEOUT, ssl=ssl_context) as response:
                if response.status == 200:
                    text = await response.text()
                    # Extract URLs from <loc> tags
                    loc_pattern = re.compile(r'<loc>(.*?)</loc>', re.IGNORECASE)
                    for match in loc_pattern.finditer(text):
                        url = match.group(1).strip()
                        if url:
                            urls.append(url)
        except Exception:
            pass

    return urls[:200]  # Limit to 200 URLs


async def fetch_well_known(session, base_url, semaphore):
    """Check .well-known endpoints for security and configuration files."""
    findings = {}
    well_known_paths = [
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/change-password",
    ]

    async with semaphore:
        for path in well_known_paths:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                async with session.get(url, timeout=DEFAULT_TIMEOUT, ssl=ssl_context) as response:
                    if response.status == 200:
                        content = await response.text()
                        findings[path] = {
                            "status": response.status,
                            "content_preview": content[:500],
                        }
            except Exception:
                continue

    return findings


def _extract_title(html_body):
    """Extract the <title> tag content from HTML."""
    title = "No Title"
    lower = html_body.lower()
    if "<title>" in lower:
        try:
            start = lower.index("<title>") + 7
            end = lower.index("</title>", start)
            title = html_body[start:end].strip()[:80]
        except (ValueError, IndexError):
            pass
    return title
