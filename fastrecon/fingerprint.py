"""
FastRecon Fingerprint — Technology and WAF detection from HTTP responses.

Accuracy improvement: Requires 2+ independent signal types (body, header, meta)
before surfacing medium/high-confidence detections. Single-signal matches are
recorded at low confidence and excluded from the primary detection list.
Confidence scores and levels are exposed in all output.
"""

import re

from fastrecon.config import TECH_SIGNATURES


def fingerprint_technologies(url, headers, body):
    """
    Detect technologies, frameworks, CDNs, and WAFs from HTTP response.

    Requires at least 2 different signal categories (body, header, meta) to
    report at medium/high confidence. Single-category detections are included
    with confidence_level="low" for transparency.

    Args:
        url: Target URL
        headers: HTTP response headers dict
        body: HTTP response body string

    Returns:
        List of detected technology dicts, each with:
        - name, category, confidence (0-100), confidence_level (low/medium/high)
        - signal_types: list of signal categories that matched
        - evidence: list of matched evidence strings
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()} if headers else {}
    body_lower = body.lower() if body else ""

    for tech_name, signatures in TECH_SIGNATURES.items():
        confidence = 0
        evidence = []
        signal_types = set()  # Track which categories contributed

        # Check body patterns
        body_patterns = signatures.get("body", [])
        for pattern in body_patterns:
            if pattern.lower() in body_lower:
                confidence += 30
                evidence.append(f"Body: '{pattern}'")
                signal_types.add("body")
                if confidence >= 60:
                    break

        # Check header patterns
        header_patterns = signatures.get("headers", {})
        for header_key, header_val in header_patterns.items():
            actual_val = headers_lower.get(header_key.lower(), "")
            if actual_val:
                if header_val == "" or header_val.lower() in actual_val:
                    confidence += 50
                    evidence.append(f"Header: {header_key}={actual_val[:50]}")
                    signal_types.add("header")

        # Check meta generator tag
        meta_pattern = signatures.get("meta", "")
        if meta_pattern and body:
            if re.search(meta_pattern, body, re.IGNORECASE):
                confidence += 60
                evidence.append(f"Meta: {meta_pattern}")
                signal_types.add("meta")

        # Determine confidence level based on signal diversity
        if confidence <= 0:
            continue

        num_signal_types = len(signal_types)

        if num_signal_types >= 2 and confidence >= 50:
            confidence_level = "high" if confidence >= 80 else "medium"
        elif num_signal_types >= 2:
            confidence_level = "medium"
        else:
            confidence_level = "low"

        # Only include if confidence >= 50 (requires 2+ signal types normally)
        # OR if it's a single strong signal (header at 50+, or meta at 60+)
        # Single body-only matches (30%) are recorded as low confidence
        if confidence >= 50:
            category = _categorize_tech(tech_name)
            detected.append({
                "name": tech_name,
                "category": category,
                "confidence": min(confidence, 100),
                "confidence_level": confidence_level,
                "signal_types": sorted(signal_types),
                "evidence": evidence,
            })
        elif confidence >= 30:
            # Low confidence — include with "low" marker for transparency
            category = _categorize_tech(tech_name)
            detected.append({
                "name": tech_name,
                "category": category,
                "confidence": min(confidence, 100),
                "confidence_level": "low",
                "signal_types": sorted(signal_types),
                "evidence": evidence,
            })

    # Deduplicate and sort by confidence
    detected.sort(key=lambda x: x["confidence"], reverse=True)

    return detected


def _categorize_tech(tech_name):
    """Categorize a technology into a group."""
    cms = ["WordPress", "Joomla", "Drupal", "Shopify"]
    frameworks = ["React", "Next.js", "Angular", "Vue.js", "Django", "Laravel",
                   "Ruby on Rails", "Express.js", "ASP.NET", "Spring Boot", "Flask"]
    libraries = ["jQuery"]
    servers = ["nginx", "Apache", "IIS", "LiteSpeed"]
    cdns = ["Cloudflare", "AWS CloudFront", "Akamai"]
    wafs = ["Cloudflare", "Sucuri WAF", "AWS WAF"]
    analytics = ["Google Analytics", "Google Tag Manager"]

    if tech_name in cms:
        return "CMS"
    elif tech_name in frameworks:
        return "Framework"
    elif tech_name in libraries:
        return "JavaScript Library"
    elif tech_name in servers:
        return "Web Server"
    elif tech_name in wafs:
        return "WAF / Security"
    elif tech_name in cdns:
        return "CDN"
    elif tech_name in analytics:
        return "Analytics"
    else:
        return "Other"


def generate_tech_insights(technologies):
    """
    Generate security insights based on detected technologies.
    Only considers medium/high confidence detections for insights.
    Returns list of insight/recommendation dicts.
    """
    insights = []

    # Only use medium/high confidence detections for insights
    confident_tech_names = [
        t["name"] for t in technologies
        if t.get("confidence_level", "low") in ("medium", "high")
    ]

    # WordPress specific
    if "WordPress" in confident_tech_names:
        insights.append({
            "technology": "WordPress",
            "insight": "WordPress detected — check for known plugin vulnerabilities, exposed wp-json users endpoint, xmlrpc.php brute force, and wp-config.php backup files.",
            "risk": "MEDIUM",
        })

    # No WAF detected (only from confident detections)
    confident_waf_names = [
        t["name"] for t in technologies
        if t.get("confidence_level", "low") in ("medium", "high")
        and t["category"] in ("WAF / Security", "CDN")
    ]
    if not confident_waf_names:
        insights.append({
            "technology": "None",
            "insight": "No WAF/CDN detected — the application may be directly exposed without DDoS protection or request filtering.",
            "risk": "LOW",
        })

    # Outdated tech warnings
    if "jQuery" in confident_tech_names:
        insights.append({
            "technology": "jQuery",
            "insight": "jQuery detected — check the version for known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023).",
            "risk": "LOW",
        })

    # ASP.NET
    if "ASP.NET" in confident_tech_names:
        insights.append({
            "technology": "ASP.NET",
            "insight": "ASP.NET detected — check for ViewState deserialization vulnerabilities and exposed Elmah error logs.",
            "risk": "MEDIUM",
        })

    # Debug frameworks
    if "Flask" in confident_tech_names:
        insights.append({
            "technology": "Flask",
            "insight": "Flask/Werkzeug detected — check if debug mode is enabled (Werkzeug debugger allows RCE).",
            "risk": "HIGH",
        })

    if "Spring Boot" in confident_tech_names:
        insights.append({
            "technology": "Spring Boot",
            "insight": "Spring Boot detected — check Actuator endpoints (/actuator/env, /actuator/heapdump) for information disclosure.",
            "risk": "HIGH",
        })

    return insights


async def run_fingerprinting(url, headers, body):
    """
    Execute technology fingerprinting.

    Args:
        url: Target URL
        headers: HTTP response headers dict
        body: HTTP response body

    Returns:
        (technologies list, insights list)
    """
    print(f"\n{'='*60}")
    print("  PHASE 5: TECHNOLOGY FINGERPRINTING")
    print(f"{'='*60}")

    technologies = fingerprint_technologies(url, headers, body)
    insights = generate_tech_insights(technologies)

    # Print results, grouped by confidence level
    high_medium = [t for t in technologies if t["confidence_level"] in ("medium", "high")]
    low_conf = [t for t in technologies if t["confidence_level"] == "low"]

    if high_medium:
        print("  Confirmed detections:")
        for tech in high_medium:
            confidence = tech["confidence"]
            level = tech["confidence_level"]
            signals = ", ".join(tech["signal_types"])
            icon = "🟢" if confidence >= 70 else "🟡"
            print(f"    {icon} {tech['name']} ({tech['category']}) — {confidence}% [{level}] via {signals}")

    if low_conf:
        print("  Low confidence (single signal — not confirmed):")
        for tech in low_conf:
            print(f"    ⚪ {tech['name']} ({tech['category']}) — {tech['confidence']}% [low] via {', '.join(tech['signal_types'])}")

    if insights:
        print("\n  Security insights:")
        for insight in insights:
            risk_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(insight["risk"], "⚪")
            print(f"    {risk_icon} [{insight['technology']}] {insight['insight'][:80]}...")

    print(f"\n  ✓ Fingerprinting complete: {len(high_medium)} confirmed, {len(low_conf)} low-confidence, {len(insights)} insights")

    return technologies, insights
