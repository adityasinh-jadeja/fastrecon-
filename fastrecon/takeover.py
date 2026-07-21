"""
FastRecon Takeover — Subdomain takeover detection with expanded signatures.
Supports both HTML body fingerprint matching and CNAME resolution + dangling check.
"""

import asyncio
import socket
from datetime import datetime, timezone
from fastrecon.config import TAKEOVER_SIGNATURES


def check_takeover(subdomain, html_body):
    """
    Check if a subdomain's HTTP response matches any known takeover signature.

    Args:
        subdomain: The subdomain being checked.
        html_body: The full HTML response body.

    Returns:
        An alert dict if a takeover vector is found, None otherwise.
    """
    if not html_body:
        return None

    for service, sig in TAKEOVER_SIGNATURES.items():
        fingerprint = sig["fingerprint"]
        if fingerprint in html_body:
            alert = {
                "severity": "CRITICAL",
                "type": "Subdomain Takeover",
                "asset": subdomain,
                "service": service,
                "details": f"Potential {service} takeover — response matches known fingerprint.",
                "evidence": fingerprint[:100],
                "cname_pattern": sig.get("cname", ""),
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            }
            print(f"  [!!!] TAKEOVER: {subdomain} → {service}")
            return alert

    return None


async def resolve_cname(subdomain):
    """
    Resolve CNAME record for a subdomain.
    Returns the CNAME target or None if no CNAME exists.
    """
    loop = asyncio.get_event_loop()
    try:
        def _resolve():
            try:
                cname = socket.getfqdn(subdomain)
                if cname and cname != subdomain and cname != subdomain + ".":
                    return cname
                # Fallback: try getaddrinfo and check canonical name
                infos = socket.getaddrinfo(subdomain, None, socket.AF_INET, socket.SOCK_STREAM)
                if infos:
                    canonical = infos[0][3]  # canonical name field
                    if canonical and canonical != subdomain:
                        return canonical
            except Exception:
                pass
            return None

        return await asyncio.wait_for(
            loop.run_in_executor(None, _resolve),
            timeout=5,
        )
    except (asyncio.TimeoutError, Exception):
        return None


async def check_cname_resolves(hostname):
    """Check if a hostname actually resolves to an IP address."""
    loop = asyncio.get_event_loop()
    try:
        def _resolve():
            try:
                socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                return True
            except socket.gaierror:
                return False

        return await asyncio.wait_for(
            loop.run_in_executor(None, _resolve),
            timeout=5,
        )
    except (asyncio.TimeoutError, Exception):
        return False


async def check_takeover_cname(subdomain):
    """
    Check for subdomain takeover via CNAME resolution.
    Resolves the CNAME chain and checks if:
    1. The CNAME target matches a known vulnerable service pattern
    2. The CNAME target doesn't resolve (dangling CNAME)

    Args:
        subdomain: The subdomain to check

    Returns:
        An alert dict if a dangling CNAME takeover vector is found, None otherwise.
    """
    cname = await resolve_cname(subdomain)
    if not cname:
        return None

    cname_lower = cname.lower().rstrip(".")

    # Check CNAME against known takeover-vulnerable service patterns
    for service, sig in TAKEOVER_SIGNATURES.items():
        cname_pattern = sig.get("cname", "").lower()
        if not cname_pattern:
            continue

        if cname_pattern in cname_lower:
            # CNAME matches a vulnerable service — check if it's dangling
            resolves = await check_cname_resolves(cname_lower)

            if not resolves:
                alert = {
                    "severity": "CRITICAL",
                    "type": "Subdomain Takeover",
                    "asset": subdomain,
                    "service": service,
                    "details": f"Dangling CNAME detected — {subdomain} → {cname} (NXDOMAIN). "
                               f"{service} resource no longer exists, subdomain can be claimed.",
                    "evidence": f"CNAME: {cname} (matches {cname_pattern}, does not resolve)",
                    "cname_pattern": cname_pattern,
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
                print(f"  [!!!] DANGLING CNAME TAKEOVER: {subdomain} → {cname} ({service})")
                return alert

    return None
