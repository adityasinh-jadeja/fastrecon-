"""
FastRecon Fingerprint — Technology and WAF detection from HTTP responses.
"""

import re

from fastrecon.config import TECH_SIGNATURES


def fingerprint_technologies(url, headers, body):
    """
    Detect technologies, frameworks, CDNs, and WAFs from HTTP response.

    Args:
        url: Target URL
        headers: HTTP response headers dict
        body: HTTP response body string

    Returns:
        List of detected technology dicts
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()} if headers else {}
    body_lower = body.lower() if body else ""

    for tech_name, signatures in TECH_SIGNATURES.items():
        confidence = 0
        evidence = []

        # Check body patterns
        body_patterns = signatures.get("body", [])
        for pattern in body_patterns:
            if pattern.lower() in body_lower:
                confidence += 30
                evidence.append(f"Body: '{pattern}'")
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

        # Check meta generator tag
        meta_pattern = signatures.get("meta", "")
        if meta_pattern and body:
            if re.search(meta_pattern, body, re.IGNORECASE):
                confidence += 60
                evidence.append(f"Meta: {meta_pattern}")

        # Must have at least 30% confidence
        if confidence >= 30:
            category = _categorize_tech(tech_name)
            detected.append({
                "name": tech_name,
                "category": category,
                "confidence": min(confidence, 100),
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
    Returns list of insight/recommendation dicts.
    """
    insights = []

    tech_names = [t["name"] for t in technologies]

    # WordPress specific
    if "WordPress" in tech_names:
        insights.append({
            "technology": "WordPress",
            "insight": "WordPress detected — check for known plugin vulnerabilities, exposed wp-json users endpoint, xmlrpc.php brute force, and wp-config.php backup files.",
            "risk": "MEDIUM",
        })

    # No WAF detected
    waf_names = [t["name"] for t in technologies if t["category"] in ("WAF / Security", "CDN")]
    if not waf_names:
        insights.append({
            "technology": "None",
            "insight": "No WAF/CDN detected — the application may be directly exposed without DDoS protection or request filtering.",
            "risk": "LOW",
        })

    # Outdated tech warnings
    if "jQuery" in tech_names:
        insights.append({
            "technology": "jQuery",
            "insight": "jQuery detected — check the version for known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023).",
            "risk": "LOW",
        })

    # ASP.NET
    if "ASP.NET" in tech_names:
        insights.append({
            "technology": "ASP.NET",
            "insight": "ASP.NET detected — check for ViewState deserialization vulnerabilities and exposed Elmah error logs.",
            "risk": "MEDIUM",
        })

    # Debug frameworks
    if "Flask" in tech_names:
        insights.append({
            "technology": "Flask",
            "insight": "Flask/Werkzeug detected — check if debug mode is enabled (Werkzeug debugger allows RCE).",
            "risk": "HIGH",
        })

    if "Spring Boot" in tech_names:
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

    # Print results
    for tech in technologies:
        confidence = tech["confidence"]
        icon = "🟢" if confidence >= 70 else "🟡"
        print(f"  {icon} {tech['name']} ({tech['category']}) — {confidence}% confidence")

    if insights:
        print("\n  Security insights:")
        for insight in insights:
            risk_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(insight["risk"], "⚪")
            print(f"    {risk_icon} [{insight['technology']}] {insight['insight'][:80]}...")

    print(f"\n  ✓ Fingerprinting complete: {len(technologies)} technologies, {len(insights)} insights")

    return technologies, insights
