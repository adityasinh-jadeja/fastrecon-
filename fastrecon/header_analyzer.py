"""
FastRecon Header Analyzer — Deep HTTP security header analysis with grading.
"""

from datetime import datetime, timezone
from fastrecon.config import SECURITY_HEADERS, HEADER_GRADES


def analyze_headers(url, headers):
    """
    Analyze HTTP security headers and generate a security grade.

    Args:
        url: Target URL
        headers: Dict of HTTP response headers

    Returns:
        (header_report dict, alerts list)
    """
    if not headers:
        return {"grade": "F", "score": 0, "headers": {}}, []

    header_results = {}
    total_score = 0
    max_score = sum(h["weight"] for h in SECURITY_HEADERS.values())
    alerts = []

    for header_name, config in SECURITY_HEADERS.items():
        value = ""
        # Case-insensitive header lookup
        for key, val in headers.items():
            if key.lower() == header_name.lower():
                value = val
                break

        result = {
            "present": bool(value),
            "value": value,
            "weight": config["weight"],
            "description": config["description"],
            "recommendation": config["recommendation"],
            "score": 0,
            "status": "missing",
            "details": "",
        }

        if value:
            # Header is present — check quality
            score = config["weight"]
            status = "good"
            details = ""

            # Check for bad values in CSP
            if header_name == "Content-Security-Policy":
                bad_values = config.get("bad_values", [])
                bad_found = [bv for bv in bad_values if bv in value]
                if bad_found:
                    score = config["weight"] * 0.5  # Half credit for weak CSP
                    status = "weak"
                    details = f"Contains risky directives: {', '.join(bad_found)}"

            # Check HSTS max-age
            elif header_name == "Strict-Transport-Security":
                import re
                max_age_match = re.search(r"max-age=(\d+)", value)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 86400:  # Less than 1 day
                        score = config["weight"] * 0.3
                        status = "weak"
                        details = f"max-age too low ({max_age}s). Should be at least 31536000 (1 year)"
                    elif max_age < 31536000:  # Less than 1 year
                        score = config["weight"] * 0.7
                        status = "acceptable"
                        details = f"max-age is {max_age}s. Recommended: 31536000 (1 year)"
                    if "includesubdomains" not in value.lower():
                        score *= 0.9
                        details += " Missing includeSubDomains."

            # Check X-Frame-Options value
            elif header_name == "X-Frame-Options":
                if value.upper() not in ("DENY", "SAMEORIGIN"):
                    score = config["weight"] * 0.5
                    status = "weak"
                    details = f"Unexpected value: {value}. Use DENY or SAMEORIGIN."

            result["score"] = score
            result["status"] = status
            result["details"] = details
            total_score += score

        else:
            # Header is missing
            result["status"] = "missing"
            result["details"] = f"Header not set — {config['description']}"

            # Generate alert for important missing headers
            if config["weight"] >= 15:
                severity = "MEDIUM"
            elif config["weight"] >= 10:
                severity = "LOW"
            else:
                severity = "INFO"

            alerts.append({
                "severity": severity,
                "type": "Missing Security Header",
                "asset": url,
                "service": "Web Application",
                "details": f"Missing {header_name} header — {config['description']}",
                "evidence": f"Header '{header_name}' not present in response",
                "cname_pattern": "",
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "remediation": config["recommendation"],
            })

        header_results[header_name] = result

    # Calculate percentage and grade
    score_pct = int((total_score / max_score) * 100) if max_score > 0 else 0

    grade = "F"
    grade_color = "#ef476f"
    for threshold, g, color in HEADER_GRADES:
        if score_pct >= threshold:
            grade = g
            grade_color = color
            break

    header_report = {
        "grade": grade,
        "gradeColor": grade_color,
        "score": score_pct,
        "maxScore": 100,
        "headers": header_results,
        "totalPresent": sum(1 for h in header_results.values() if h["present"]),
        "totalMissing": sum(1 for h in header_results.values() if not h["present"]),
        "totalHeaders": len(header_results),
    }

    return header_report, alerts


async def run_header_analysis(url, headers):
    """
    Execute security header analysis.

    Args:
        url: Target URL
        headers: HTTP response headers dict

    Returns:
        (header_report dict, alerts list)
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 8: SECURITY HEADER ANALYSIS")
    print(f"{'='*60}")

    header_report, alerts = analyze_headers(url, headers)

    # Print results
    grade = header_report["grade"]
    score = header_report["score"]
    present = header_report["totalPresent"]
    total = header_report["totalHeaders"]

    grade_emoji = {
        "A+": "🟢", "A": "🟢", "B": "🔵",
        "C": "🟡", "D": "🟠", "F": "🔴",
    }.get(grade, "⚪")

    print(f"\n  {grade_emoji} Security Grade: {grade} ({score}%)")
    print(f"  Headers present: {present}/{total}")

    for header_name, result in header_report["headers"].items():
        if result["present"]:
            status_icon = "✓" if result["status"] == "good" else "⚠"
            print(f"    {status_icon} {header_name}: {result['value'][:60]}")
        else:
            print(f"    ✗ {header_name}: MISSING")

    print(f"\n  ✓ Header analysis complete: {len(alerts)} recommendation(s)")

    return header_report, alerts
