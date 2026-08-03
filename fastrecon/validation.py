"""
FastRecon Target Validation — SSRF prevention and domain safety checks.

Validates that scan targets are legitimate public domains, preventing
attacks against internal infrastructure or cloud metadata endpoints
(e.g., 169.254.169.254).
"""

import ipaddress
import re
import socket

# Valid domain: labels separated by dots, each 1-63 chars of [a-zA-Z0-9-],
# must start/end with alphanumeric, at least two labels (TLD required).
DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)


def is_safe_target(target: str) -> bool:
    """
    Validate that a target domain is safe to scan.

    Checks:
      1. Matches valid domain format (no IPs, no protocols, no paths).
      2. Not localhost or a .local domain.
      3. Does not resolve to a private, loopback, link-local, or reserved IP.

    Args:
        target: Domain string (e.g., "example.com"). Should already be
                stripped of protocol/path by the caller.

    Returns:
        True if the target is safe to scan, False otherwise.
    """
    if not target or not isinstance(target, str):
        return False

    target = target.strip().lower()

    # Must match valid domain format
    if not DOMAIN_RE.match(target):
        return False

    # Block well-known internal hostnames
    if target in ("localhost",) or target.endswith(".local"):
        return False

    # Block internal/cloud TLDs that should never be scanned
    if target.endswith((".internal", ".corp", ".home", ".lan")):
        return False

    # DNS resolution check — block private/reserved IPs
    try:
        ip = socket.gethostbyname(target)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False
    except (socket.gaierror, ValueError):
        # Domain doesn't resolve — let the scan fail naturally later.
        # This is acceptable: a non-resolving domain isn't an SSRF risk.
        pass

    return True
