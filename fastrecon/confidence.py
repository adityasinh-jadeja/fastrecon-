"""
FastRecon Confidence Scoring.

Severity answers "how bad if real?". Confidence answers "how sure are we it's
real?". They're orthogonal, and separating them lets a hunter trust the
"confirmed" bucket and triage the rest instead of wading through every finding
with equal suspicion.

Levels:
  - confirmed    : a condition we directly observed and that isn't a heuristic
                   guess (a missing header, a reflected CORS origin, a redirect
                   Location to our payload, an enabled directory listing).
  - probable     : a strong heuristic signal that still needs manual
                   confirmation (an error-based SQLi pattern, a reflected XSS
                   payload, a sensitive path that returned 200).
  - needs-review : a weak or noisy signal worth a glance, not a report
                   (a single broad info-disclosure pattern, generic info items).
"""

CONFIRMED = "confirmed"
PROBABLE = "probable"
NEEDS_REVIEW = "needs-review"

# Directly-observed, non-heuristic conditions.
_CONFIRMED_TYPES = {
    "CORS Misconfiguration",
    "CORS Null Origin",
    "Open Redirect",
    "CRLF Injection",
    "Directory Listing",
    "Clickjacking",
    "Insecure Cookie",
    "HTTP Method Tampering",
    "Server Version Disclosure",
    "Technology Disclosure",
}

# Heuristic signals that strongly suggest a bug but warrant manual confirmation.
_PROBABLE_TYPES = {
    "SQL Injection",
    "Reflected XSS",
}


def assign_confidence(finding):
    """Return the confidence level (str) for a single finding dict."""
    ftype = finding.get("type", "") or ""
    severity = (finding.get("severity", "") or "").upper()

    if ftype in _PROBABLE_TYPES:
        return PROBABLE

    # Host header injection: HIGH means the canary reached a link-generation
    # context (confirmed); MEDIUM means body-only reflection (probable).
    if ftype == "Host Header Injection":
        return CONFIRMED if severity == "HIGH" else PROBABLE

    # Information disclosure: a single broad pattern (LOW) is noisy; stronger
    # or corroborated matches (MEDIUM+) are a probable leak.
    if ftype == "Information Disclosure":
        return NEEDS_REVIEW if severity == "LOW" else PROBABLE

    # Access-control bypasses are strong but need manual confirmation.
    if "Bypass" in ftype:
        return PROBABLE

    if ftype in _CONFIRMED_TYPES:
        return CONFIRMED

    # Endpoint-discovery findings ("Exposed Admin Panel", etc.) are found by
    # status code; content isn't always verified, so treat them as probable.
    if ftype.startswith("Exposed "):
        return PROBABLE

    # Subdomain takeover carries its own strong signal when CRITICAL/HIGH.
    if "Takeover" in ftype:
        return PROBABLE if severity in ("CRITICAL", "HIGH") else NEEDS_REVIEW

    return NEEDS_REVIEW


def annotate_confidence(findings):
    """
    Set finding['confidence'] on each finding in-place (unless already set).
    Returns the same list for convenience.
    """
    for finding in findings:
        if isinstance(finding, dict) and not finding.get("confidence"):
            finding["confidence"] = assign_confidence(finding)
    return findings


def confidence_breakdown(findings):
    """Return {level: count} across findings (for summaries)."""
    counts = {CONFIRMED: 0, PROBABLE: 0, NEEDS_REVIEW: 0}
    for finding in findings:
        level = finding.get("confidence") or assign_confidence(finding)
        counts[level] = counts.get(level, 0) + 1
    return counts
