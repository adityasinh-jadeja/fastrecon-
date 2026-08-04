"""
FastRecon Cloud Hunter — Detect misconfigured cloud storage buckets.
"""

import asyncio
import re
import ssl
from datetime import datetime, timezone

from fastrecon.config import BUCKET_SUFFIXES, CLOUD_PROVIDERS, DEFAULT_TIMEOUT


def generate_bucket_permutations(target):
    """
    Generate candidate bucket names from a target domain.
    e.g., example.com -> [example, example.com, example-com, examplecom] × suffixes
    """
    base = target.lower()
    # Strip TLD variations
    name_only = base.split(".")[0]  # "example"
    dotted = base                   # "example.com"
    dashed = base.replace(".", "-") # "example-com"
    joined = base.replace(".", "")  # "examplecom"

    bases = list(dict.fromkeys([name_only, dotted, dashed, joined]))  # dedupe, preserve order

    permutations = []
    for b in bases:
        for suffix in BUCKET_SUFFIXES:
            candidate = f"{b}{suffix}"
            # Sanitize: bucket names must be 3-63 chars, lowercase, no special chars except - and .
            candidate = re.sub(r'[^a-z0-9.\-]', '', candidate)
            if 3 <= len(candidate) <= 63:
                permutations.append(candidate)

    return list(dict.fromkeys(permutations))  # dedupe


async def _check_bucket(session, provider_name, url_template, bucket_name, semaphore):
    """
    Check a single bucket on a specific cloud provider.
    Returns a bucket info dict or None.
    """
    url = url_template.format(bucket=bucket_name)
    async with semaphore:
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
                status = response.status
                body = ""

                # Read body for Firebase-specific detection
                if provider_name.startswith("Firebase") and status == 200:
                    try:
                        body = await response.text()
                    except Exception:
                        pass

                if status == 200:
                    # Firebase RTDB: "null" response means empty but accessible
                    # Firebase RTDB: "Permission Denied" in body means private
                    if provider_name == "Firebase RTDB":
                        if "Permission Denied" in body or "permission_denied" in body.lower():
                            return {
                                "name": bucket_name,
                                "provider": provider_name,
                                "status": "PRIVATE",
                                "url": url,
                                "httpStatus": status,
                            }, None
                        # Even "null" means the DB is publicly accessible
                        return {
                            "name": bucket_name,
                            "provider": provider_name,
                            "status": "PUBLIC",
                            "url": url,
                            "httpStatus": status,
                        }, _make_bucket_alert(bucket_name, provider_name, url, "PUBLIC")

                    # Firebase Storage: check if items listing is returned
                    if provider_name == "Firebase Storage":
                        if "error" in body.lower():
                            return {
                                "name": bucket_name,
                                "provider": provider_name,
                                "status": "PRIVATE",
                                "url": url,
                                "httpStatus": status,
                            }, None

                    # All other providers: 200 = publicly accessible
                    return {
                        "name": bucket_name,
                        "provider": provider_name,
                        "status": "PUBLIC",
                        "url": url,
                        "httpStatus": status,
                    }, _make_bucket_alert(bucket_name, provider_name, url, "PUBLIC")

                elif status == 403:
                    # Exists but access denied — informational
                    return {
                        "name": bucket_name,
                        "provider": provider_name,
                        "status": "PRIVATE",
                        "url": url,
                        "httpStatus": status,
                    }, None

                elif status == 401:
                    # Firebase often returns 401 for private resources
                    return {
                        "name": bucket_name,
                        "provider": provider_name,
                        "status": "PRIVATE",
                        "url": url,
                        "httpStatus": status,
                    }, None

                # 404 or other = does not exist, skip
                return None, None

        except Exception:
            return None, None


def _make_bucket_alert(bucket_name, provider, url, access_status):
    """Create an alert for a misconfigured cloud bucket."""
    return {
        "severity": "CRITICAL" if access_status == "PUBLIC" else "MEDIUM",
        "type": "Cloud Misconfiguration",
        "asset": bucket_name,
        "service": provider,
        "details": f"Publicly accessible {provider} bucket found: {bucket_name}",
        "evidence": url,
        "cname_pattern": "",
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
    }


async def hunt_cloud_storage(session, target, semaphore, wordlist=None):
    """
    Orchestrate cloud storage hunting across all providers.

    Args:
        session: aiohttp ClientSession
        target: Target domain
        semaphore: asyncio.Semaphore for concurrency control
        wordlist: Optional list of custom suffixes (overrides defaults)

    Returns:
        (buckets_found, alerts) — lists of bucket info dicts and alert dicts
    """
    print(f"\n{'='*60}")
    print("  PHASE 9: CLOUD STORAGE HUNTING")
    print(f"{'='*60}")

    # Use custom wordlist if provided
    if wordlist:
        # Use the custom list locally instead of the default BUCKET_SUFFIXES
        permutations = []
        base = target.lower()
        name_only = base.split(".")[0]
        for suffix in wordlist:
            candidate = f"{name_only}{suffix}".strip()
            candidate = re.sub(r'[^a-z0-9.\-]', '', candidate)
            if 3 <= len(candidate) <= 63:
                permutations.append(candidate)
        permutations = list(dict.fromkeys(permutations))
    else:
        permutations = generate_bucket_permutations(target)

    print(f"  Generated {len(permutations)} bucket permutations × {len(CLOUD_PROVIDERS)} providers")
    total_checks = len(permutations) * len(CLOUD_PROVIDERS)
    print(f"  Total checks: {total_checks}")

    # Build all check tasks
    tasks = []
    for bucket_name in permutations:
        for provider_name, url_template in CLOUD_PROVIDERS.items():
            tasks.append(
                _check_bucket(session, provider_name, url_template, bucket_name, semaphore)
            )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    buckets_found = []
    alerts = []
    for result in results:
        if isinstance(result, Exception):
            continue
        if result is None:
            continue
        bucket_info, alert = result
        if bucket_info:
            buckets_found.append(bucket_info)
            status_icon = "🔴" if bucket_info["status"] == "PUBLIC" else "🟡"
            print(f"  {status_icon} {bucket_info['provider']}: {bucket_info['name']} [{bucket_info['status']}]")
        if alert:
            alerts.append(alert)

    public_count = sum(1 for b in buckets_found if b["status"] == "PUBLIC")
    private_count = sum(1 for b in buckets_found if b["status"] == "PRIVATE")
    print(f"\n  ✓ Buckets found: {len(buckets_found)} ({public_count} public, {private_count} private)")

    return buckets_found, alerts
