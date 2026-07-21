"""
FastRecon Discovery — Enhanced passive subdomain enumeration from multiple sources.
Supports 6 built-in OSINT APIs + optional Subfinder and Amass CLI tools.
"""

import asyncio
import shutil
import re
from fastrecon.config import DISCOVERY_TIMEOUT


async def discover_crtsh(session, target):
    """Query crt.sh certificate transparency logs for subdomains."""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    print(f"  [crt.sh] Querying certificate transparency logs...")
    try:
        async with session.get(url, timeout=DISCOVERY_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json(content_type=None)
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(target) and "*" not in name:
                            subdomains.add(name)
                print(f"  [crt.sh] Found {len(subdomains)} subdomains")
            else:
                print(f"  [crt.sh] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [crt.sh] Request timed out")
    except Exception as e:
        print(f"  [crt.sh] Discovery failed: {e}")
    return subdomains


async def discover_hackertarget(session, target):
    """Query HackerTarget API for subdomains (free, no API key)."""
    subdomains = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={target}"
    print(f"  [HackerTarget] Querying host search API...")
    try:
        async with session.get(url, timeout=DISCOVERY_TIMEOUT) as response:
            if response.status == 200:
                text = await response.text()
                # HackerTarget returns CSV: hostname,IP
                if "error" not in text.lower() and "API count" not in text:
                    for line in text.strip().split("\n"):
                        parts = line.split(",")
                        if parts:
                            name = parts[0].strip().lower()
                            if name.endswith(target) and "*" not in name:
                                subdomains.add(name)
                    print(f"  [HackerTarget] Found {len(subdomains)} subdomains")
                else:
                    print(f"  [HackerTarget] API limit reached or error")
            else:
                print(f"  [HackerTarget] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [HackerTarget] Request timed out")
    except Exception as e:
        print(f"  [HackerTarget] Discovery failed: {e}")
    return subdomains


async def discover_alienvault(session, target):
    """Query AlienVault OTX for subdomains (free, no API key)."""
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
    print(f"  [AlienVault OTX] Querying passive DNS...")
    try:
        async with session.get(url, timeout=DISCOVERY_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json(content_type=None)
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname.endswith(target) and "*" not in hostname:
                        subdomains.add(hostname)
                print(f"  [AlienVault OTX] Found {len(subdomains)} subdomains")
            else:
                print(f"  [AlienVault OTX] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [AlienVault OTX] Request timed out")
    except Exception as e:
        print(f"  [AlienVault OTX] Discovery failed: {e}")
    return subdomains


async def discover_urlscan(session, target):
    """Query URLScan.io for subdomains (free, no API key)."""
    subdomains = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=100"
    print(f"  [URLScan.io] Querying URL scan database...")
    try:
        async with session.get(url, timeout=DISCOVERY_TIMEOUT) as response:
            if response.status == 200:
                data = await response.json(content_type=None)
                for result in data.get("results", []):
                    page = result.get("page", {})
                    domain = page.get("domain", "").strip().lower()
                    if domain.endswith(target) and "*" not in domain:
                        subdomains.add(domain)
                print(f"  [URLScan.io] Found {len(subdomains)} subdomains")
            else:
                print(f"  [URLScan.io] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [URLScan.io] Request timed out")
    except Exception as e:
        print(f"  [URLScan.io] Discovery failed: {e}")
    return subdomains


async def discover_rapiddns(session, target):
    """Query RapidDNS for subdomains (free, no API key)."""
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{target}?full=1"
    print(f"  [RapidDNS] Querying subdomain database...")
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        async with session.get(url, timeout=DISCOVERY_TIMEOUT, headers=headers) as response:
            if response.status == 200:
                text = await response.text()
                # Parse HTML table for subdomains
                pattern = re.compile(
                    r'<td>([a-zA-Z0-9._-]+\.' + re.escape(target) + r')</td>',
                    re.IGNORECASE,
                )
                for match in pattern.finditer(text):
                    name = match.group(1).strip().lower()
                    if name.endswith(target) and "*" not in name:
                        subdomains.add(name)
                print(f"  [RapidDNS] Found {len(subdomains)} subdomains")
            else:
                print(f"  [RapidDNS] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [RapidDNS] Request timed out")
    except Exception as e:
        print(f"  [RapidDNS] Discovery failed: {e}")
    return subdomains


async def discover_webarchive(session, target):
    """Query Wayback Machine/Web Archive for historical subdomains."""
    subdomains = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}&output=json&fl=original&collapse=urlkey&limit=200"
    print(f"  [WebArchive] Querying Wayback Machine...")
    try:
        async with session.get(url, timeout=DISCOVERY_TIMEOUT + 10) as response:
            if response.status == 200:
                data = await response.json(content_type=None)
                for entry in data:
                    if isinstance(entry, list) and entry:
                        url_str = entry[0]
                        # Extract domain from URL
                        match = re.search(r'https?://([^/]+)', url_str)
                        if match:
                            domain = match.group(1).strip().lower().split(":")[0]
                            if domain.endswith(target) and "*" not in domain:
                                subdomains.add(domain)
                print(f"  [WebArchive] Found {len(subdomains)} subdomains")
            else:
                print(f"  [WebArchive] Returned status {response.status}")
    except asyncio.TimeoutError:
        print(f"  [WebArchive] Request timed out")
    except Exception as e:
        print(f"  [WebArchive] Discovery failed: {e}")
    return subdomains


async def discover_subfinder(target):
    """Run Subfinder CLI tool for subdomain discovery. Skips gracefully if not installed."""
    subdomains = set()
    if not shutil.which("subfinder"):
        print(f"  [Subfinder] Not installed — skipping (install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")
        return subdomains

    print(f"  [Subfinder] Running passive enumeration...")
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", target, "-silent", "-timeout", "30",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        if stdout:
            for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
                name = line.strip().lower()
                if name and name.endswith(target) and "*" not in name:
                    subdomains.add(name)

        print(f"  [Subfinder] Found {len(subdomains)} subdomains")
    except asyncio.TimeoutError:
        print(f"  [Subfinder] Timed out after 120s")
    except Exception as e:
        print(f"  [Subfinder] Failed: {e}")
    return subdomains


async def discover_amass(target):
    """Run Amass CLI tool for passive subdomain discovery. Skips gracefully if not installed."""
    subdomains = set()
    if not shutil.which("amass"):
        print(f"  [Amass] Not installed — skipping (install: go install github.com/owasp-amass/amass/v4/...@master)")
        return subdomains

    print(f"  [Amass] Running passive enumeration...")
    try:
        proc = await asyncio.create_subprocess_exec(
            "amass", "enum", "-passive", "-d", target, "-timeout", "2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        if stdout:
            for line in stdout.decode("utf-8", errors="replace").strip().split("\n"):
                name = line.strip().lower()
                if name and name.endswith(target) and "*" not in name:
                    subdomains.add(name)

        print(f"  [Amass] Found {len(subdomains)} subdomains")
    except asyncio.TimeoutError:
        print(f"  [Amass] Timed out after 180s")
    except Exception as e:
        print(f"  [Amass] Failed: {e}")
    return subdomains


async def run_discovery(session, target):
    """Run all discovery sources in parallel and merge results."""
    print(f"\n{'='*60}")
    print(f"  PHASE 2: SUBDOMAIN DISCOVERY")
    print(f"{'='*60}")

    # Run all sources in parallel: 6 API sources + 2 CLI tools
    results = await asyncio.gather(
        discover_crtsh(session, target),
        discover_hackertarget(session, target),
        discover_alienvault(session, target),
        discover_urlscan(session, target),
        discover_rapiddns(session, target),
        discover_webarchive(session, target),
        discover_subfinder(target),
        discover_amass(target),
        return_exceptions=True,
    )

    all_subdomains = set()
    source_names = [
        "crt.sh", "HackerTarget", "AlienVault OTX", "URLScan.io",
        "RapidDNS", "WebArchive", "Subfinder", "Amass",
    ]
    for i, result in enumerate(results):
        if isinstance(result, set):
            all_subdomains.update(result)
        elif isinstance(result, Exception):
            print(f"  [{source_names[i]}] Source failed with exception: {result}")

    # Always include the target domain itself
    all_subdomains.add(target)

    print(f"\n  ✓ Total unique subdomains: {len(all_subdomains)} (from {len(source_names)} sources)")
    return all_subdomains
