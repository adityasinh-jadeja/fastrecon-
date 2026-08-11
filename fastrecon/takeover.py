"""
FastRecon Takeover — Subdomain takeover detection with expanded signatures.
Supports both HTML body fingerprint matching and CNAME resolution + dangling check.

Uses dnspython for proper CNAME record querying (walks the full chain)
and only flags NXDOMAIN as dangling — not timeouts or transient errors.
"""

import asyncio
from datetime import datetime, timezone

import dns.exception
import dns.name
import dns.resolver

from fastrecon.config import TAKEOVER_SIGNATURES

# Maximum CNAME chain depth to walk before assuming a loop
MAX_CNAME_DEPTH = 10


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


async def resolve_cname_chain(subdomain):
    """
    Resolve the full CNAME chain for a subdomain using dnspython.
    Walks up to MAX_CNAME_DEPTH hops to avoid infinite loops.

    Returns:
        A list of CNAME targets in chain order, e.g.
        ['alias1.example.com', 'alias2.cdn.net', 'final.target.net'].
        Returns an empty list if no CNAME record exists or on timeout/error.
    """
    loop = asyncio.get_event_loop()

    def _resolve():
        chain = []
        current = subdomain
        seen = set()

        for _ in range(MAX_CNAME_DEPTH):
            if current in seen:
                break  # Circular CNAME — stop
            seen.add(current)

            try:
                answers = dns.resolver.resolve(current, "CNAME")
                target = str(answers[0].target).rstrip(".")
                chain.append(target)
                current = target
            except dns.resolver.NoAnswer:
                # No CNAME record for this name — end of chain
                break
            except dns.resolver.NXDOMAIN:
                # The name itself doesn't exist — still record the chain
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                # Transient DNS failure — don't treat as meaningful
                break
            except Exception:
                break

        return chain

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _resolve),
            timeout=10,
        )
    except (asyncio.TimeoutError, Exception):
        return []


async def check_nxdomain(hostname):
    """
    Check if a hostname returns NXDOMAIN (definitively does not exist).
    Only dns.resolver.NXDOMAIN is treated as "dangling."
    Timeouts, NoNameservers, and other errors return None (inconclusive).

    Returns:
        True  — confirmed NXDOMAIN (hostname does not exist)
        False — hostname resolves (exists)
        None  — inconclusive (timeout, transient error)
    """
    loop = asyncio.get_event_loop()

    def _check():
        try:
            # Try to resolve any record type (A/AAAA/CNAME)
            dns.resolver.resolve(hostname, "A")
            return False  # Resolves — not dangling
        except dns.resolver.NXDOMAIN:
            return True  # Confirmed NXDOMAIN — dangling
        except dns.resolver.NoAnswer:
            # Name exists but no A record — try AAAA
            try:
                dns.resolver.resolve(hostname, "AAAA")
                return False  # Has AAAA — not dangling
            except dns.resolver.NXDOMAIN:
                return True
            except Exception:
                return None  # Inconclusive
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return None  # Inconclusive — do NOT flag as dangling
        except Exception:
            return None

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _check),
            timeout=10,
        )
    except (asyncio.TimeoutError, Exception):
        return None


async def check_takeover_cname(subdomain):
    """
    Check for subdomain takeover via CNAME resolution.

    Walks the full CNAME chain using dnspython and checks if:
    1. Any CNAME target in the chain matches a known vulnerable service pattern
    2. The terminal CNAME target is confirmed NXDOMAIN (not just a timeout)

    Only flags a takeover when BOTH conditions are met, eliminating false
    positives from transient DNS failures, IPv6-only records, etc.

    Args:
        subdomain: The subdomain to check

    Returns:
        An alert dict if a dangling CNAME takeover vector is found, None otherwise.
    """
    chain = await resolve_cname_chain(subdomain)
    if not chain:
        return None

    # The terminal CNAME is the last entry in the chain
    terminal_cname = chain[-1].lower().rstrip(".")

    # Check each CNAME in the chain against known takeover-vulnerable service patterns
    for service, sig in TAKEOVER_SIGNATURES.items():
        cname_pattern = sig.get("cname", "").lower()
        if not cname_pattern:
            continue

        # Check if any CNAME in the chain matches the vulnerable pattern
        matching_cname = None
        for cname in chain:
            if cname_pattern in cname.lower().rstrip("."):
                matching_cname = cname
                break

        if matching_cname:
            # CNAME matches a vulnerable service — verify the terminal target is NXDOMAIN
            is_nxdomain = await check_nxdomain(terminal_cname)

            if is_nxdomain is True:
                chain_str = " → ".join(chain)
                alert = {
                    "severity": "CRITICAL",
                    "type": "Subdomain Takeover",
                    "asset": subdomain,
                    "service": service,
                    "details": (
                        f"Dangling CNAME detected — {subdomain} → {chain_str} (NXDOMAIN). "
                        f"{service} resource no longer exists, subdomain can be claimed."
                    ),
                    "evidence": (
                        f"CNAME chain: {chain_str} "
                        f"(matches {cname_pattern}, terminal {terminal_cname} confirmed NXDOMAIN)"
                    ),
                    "cname_chain": chain,
                    "cname_pattern": cname_pattern,
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                }
                print(f"  [!!!] DANGLING CNAME TAKEOVER: {subdomain} → {chain_str} ({service})")
                return alert
            elif is_nxdomain is None:
                # Inconclusive — log but do NOT flag as takeover
                print(f"  [?] CNAME {subdomain} → {terminal_cname} matches {service} "
                      f"but DNS resolution was inconclusive (timeout/error) — skipping")

    return None
