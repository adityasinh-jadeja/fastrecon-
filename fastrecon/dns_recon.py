"""
FastRecon DNS Recon — DNS record enumeration, zone transfer checks, SPF/DMARC analysis.
Pure Python implementation using socket and asyncio.
"""

import asyncio
import socket
import re
from datetime import datetime, timezone
from fastrecon.config import DNS_TIMEOUT


async def resolve_dns(domain, record_type="A"):
    """Resolve DNS records using socket (A/AAAA only) or system resolver."""
    loop = asyncio.get_event_loop()
    results = []

    try:
        if record_type == "A":
            def _resolve_a():
                return socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            infos = await asyncio.wait_for(
                loop.run_in_executor(None, _resolve_a),
                timeout=DNS_TIMEOUT,
            )
            results = list(set(info[4][0] for info in infos))
        elif record_type == "AAAA":
            def _resolve_aaaa():
                return socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            infos = await asyncio.wait_for(
                loop.run_in_executor(None, _resolve_aaaa),
                timeout=DNS_TIMEOUT,
            )
            results = list(set(info[4][0] for info in infos))
        elif record_type == "CNAME":
            try:
                cname = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.getfqdn, domain),
                    timeout=DNS_TIMEOUT,
                )
                if cname and cname != domain:
                    results = [cname]
            except Exception:
                pass
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        pass

    return results


async def resolve_mx(domain):
    """Attempt MX record resolution via system nslookup."""
    loop = asyncio.get_event_loop()
    records = []
    try:
        def _nslookup_mx():
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=MX", domain],
                capture_output=True, text=True, timeout=DNS_TIMEOUT + 2,
            )
            mx_entries = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "mail exchanger" in line.lower() or "mx preference" in line.lower():
                    mx_entries.append(line)
                elif "=" in line and ("mail" in line.lower() or "mx" in line.lower()):
                    mx_entries.append(line)
            return mx_entries

        records = await asyncio.wait_for(
            loop.run_in_executor(None, _nslookup_mx),
            timeout=DNS_TIMEOUT + 3,
        )
    except Exception:
        pass
    return records


async def resolve_txt(domain):
    """Attempt TXT record resolution via nslookup."""
    loop = asyncio.get_event_loop()
    records = []
    try:
        def _nslookup_txt():
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=TXT", domain],
                capture_output=True, text=True, timeout=DNS_TIMEOUT + 2,
            )
            txt_entries = []
            in_answer = False
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "text =" in line.lower() or line.startswith('"'):
                    # Extract the TXT value
                    match = re.search(r'"(.+?)"', line)
                    if match:
                        txt_entries.append(match.group(1))
                    elif "text =" in line.lower():
                        txt_entries.append(line.split("=", 1)[-1].strip().strip('"'))
            return txt_entries

        records = await asyncio.wait_for(
            loop.run_in_executor(None, _nslookup_txt),
            timeout=DNS_TIMEOUT + 3,
        )
    except Exception:
        pass
    return records


async def resolve_ns(domain):
    """Attempt NS record resolution via nslookup."""
    loop = asyncio.get_event_loop()
    records = []
    try:
        def _nslookup_ns():
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=NS", domain],
                capture_output=True, text=True, timeout=DNS_TIMEOUT + 2,
            )
            ns_entries = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if "nameserver" in line.lower() and "=" in line:
                    ns_entries.append(line.split("=")[-1].strip())
                elif line.endswith(".") and not line.startswith("Server:") and "." in line:
                    ns_entries.append(line)
            return ns_entries

        records = await asyncio.wait_for(
            loop.run_in_executor(None, _nslookup_ns),
            timeout=DNS_TIMEOUT + 3,
        )
    except Exception:
        pass
    return records


async def check_zone_transfer(domain, nameservers):
    """
    Attempt DNS zone transfer (AXFR) against each nameserver.
    This is a common misconfiguration that leaks all DNS records.
    """
    loop = asyncio.get_event_loop()
    findings = []

    for ns in nameservers[:3]:  # Check up to 3 nameservers
        ns = ns.strip().rstrip(".")
        if not ns:
            continue
        try:
            def _try_axfr(ns_server):
                """Try a zone transfer via raw socket."""
                import struct
                try:
                    # Build minimal AXFR query
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(DNS_TIMEOUT)
                    sock.connect((ns_server, 53))

                    # Build DNS AXFR query
                    transaction_id = b'\x12\x34'
                    flags = b'\x00\x00'  # Standard query
                    questions = b'\x00\x01'
                    answer_rr = b'\x00\x00'
                    authority_rr = b'\x00\x00'
                    additional_rr = b'\x00\x00'

                    # Encode domain name
                    qname = b''
                    for part in domain.split('.'):
                        qname += bytes([len(part)]) + part.encode()
                    qname += b'\x00'

                    qtype = b'\x00\xfc'   # AXFR
                    qclass = b'\x00\x01'  # IN

                    dns_query = (transaction_id + flags + questions +
                                answer_rr + authority_rr + additional_rr +
                                qname + qtype + qclass)

                    # TCP DNS requires 2-byte length prefix
                    tcp_msg = struct.pack('>H', len(dns_query)) + dns_query
                    sock.send(tcp_msg)

                    # Read response
                    response = sock.recv(4096)
                    sock.close()

                    if len(response) > 10:
                        # Check if we got actual records back (not just a refusal)
                        rcode = response[5] & 0x0F if len(response) > 5 else 5
                        if rcode == 0 and len(response) > 50:
                            return True  # Zone transfer succeeded
                    return False
                except Exception:
                    return False

            result = await asyncio.wait_for(
                loop.run_in_executor(None, _try_axfr, ns),
                timeout=DNS_TIMEOUT + 2,
            )

            if result:
                findings.append({
                    "severity": "CRITICAL",
                    "type": "DNS Zone Transfer",
                    "asset": domain,
                    "service": f"DNS ({ns})",
                    "details": f"Zone transfer (AXFR) allowed on nameserver {ns} — all DNS records exposed!",
                    "evidence": f"AXFR query to {ns}:53 returned records",
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                })
                print(f"  [!!!] ZONE TRANSFER ALLOWED: {ns}")

        except Exception:
            continue

    return findings


def analyze_spf(txt_records):
    """Analyze SPF record for misconfigurations."""
    findings = []
    spf_found = False

    for txt in txt_records:
        if txt.startswith("v=spf1"):
            spf_found = True
            if "+all" in txt:
                findings.append({
                    "severity": "HIGH",
                    "type": "SPF Misconfiguration",
                    "asset": "SPF Record",
                    "service": "Email Security",
                    "details": "SPF record uses '+all' which allows ANY server to send email — email spoofing possible",
                    "evidence": txt[:200],
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                })
            elif "~all" in txt:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "SPF Soft Fail",
                    "asset": "SPF Record",
                    "service": "Email Security",
                    "details": "SPF uses soft fail (~all) instead of hard fail (-all) — spoofed emails may be delivered",
                    "evidence": txt[:200],
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                })
            break

    if not spf_found:
        findings.append({
            "severity": "MEDIUM",
            "type": "Missing SPF Record",
            "asset": "DNS TXT",
            "service": "Email Security",
            "details": "No SPF record found — domain may be vulnerable to email spoofing",
            "evidence": "No v=spf1 TXT record",
            "cname_pattern": "",
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

    return findings


def analyze_dmarc(txt_records, domain):
    """Check for DMARC record."""
    findings = []
    dmarc_found = False

    for txt in txt_records:
        if txt.startswith("v=DMARC1"):
            dmarc_found = True
            if "p=none" in txt:
                findings.append({
                    "severity": "LOW",
                    "type": "DMARC Policy None",
                    "asset": f"_dmarc.{domain}",
                    "service": "Email Security",
                    "details": "DMARC policy set to 'none' — spoofed emails are not blocked, only reported",
                    "evidence": txt[:200],
                    "cname_pattern": "",
                    "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                })
            break

    if not dmarc_found:
        findings.append({
            "severity": "MEDIUM",
            "type": "Missing DMARC Record",
            "asset": f"_dmarc.{domain}",
            "service": "Email Security",
            "details": "No DMARC record found — domain lacks email authentication policy",
            "evidence": "No v=DMARC1 TXT record",
            "cname_pattern": "",
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

    return findings


async def check_wildcard(domain):
    """Check if wildcard DNS is enabled (*.domain resolves)."""
    import random
    import string
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
    test_domain = f"{random_sub}.{domain}"

    ips = await resolve_dns(test_domain, "A")
    if ips:
        return True, ips
    return False, []


async def run_dns_recon(domain):
    """
    Execute full DNS reconnaissance.
    Returns: (dns_info dict, alerts list)
    """
    print(f"\n{'='*60}")
    print(f"  PHASE 1: DNS RECONNAISSANCE")
    print(f"{'='*60}")

    dns_info = {
        "a_records": [],
        "aaaa_records": [],
        "ns_records": [],
        "mx_records": [],
        "txt_records": [],
        "wildcard": False,
        "wildcard_ips": [],
    }
    alerts = []

    # Resolve A records
    print(f"  [DNS] Resolving A records...")
    dns_info["a_records"] = await resolve_dns(domain, "A")
    if dns_info["a_records"]:
        print(f"  [DNS] A: {', '.join(dns_info['a_records'])}")

    # Resolve AAAA records
    print(f"  [DNS] Resolving AAAA records...")
    dns_info["aaaa_records"] = await resolve_dns(domain, "AAAA")
    if dns_info["aaaa_records"]:
        print(f"  [DNS] AAAA: {', '.join(dns_info['aaaa_records'])}")

    # Resolve NS records
    print(f"  [DNS] Resolving NS records...")
    dns_info["ns_records"] = await resolve_ns(domain)
    if dns_info["ns_records"]:
        print(f"  [DNS] NS: {', '.join(dns_info['ns_records'][:5])}")

    # Resolve MX records
    print(f"  [DNS] Resolving MX records...")
    dns_info["mx_records"] = await resolve_mx(domain)
    if dns_info["mx_records"]:
        print(f"  [DNS] MX: {len(dns_info['mx_records'])} record(s)")

    # Resolve TXT records
    print(f"  [DNS] Resolving TXT records...")
    dns_info["txt_records"] = await resolve_txt(domain)
    if dns_info["txt_records"]:
        print(f"  [DNS] TXT: {len(dns_info['txt_records'])} record(s)")

    # Also check DMARC subdomain
    dmarc_txts = await resolve_txt(f"_dmarc.{domain}")
    dns_info["txt_records"].extend(dmarc_txts)

    # Analyze SPF
    spf_alerts = analyze_spf(dns_info["txt_records"])
    alerts.extend(spf_alerts)

    # Analyze DMARC
    dmarc_alerts = analyze_dmarc(dns_info["txt_records"], domain)
    alerts.extend(dmarc_alerts)

    # Check zone transfer
    if dns_info["ns_records"]:
        print(f"  [DNS] Checking zone transfer (AXFR)...")
        zt_alerts = await check_zone_transfer(domain, dns_info["ns_records"])
        alerts.extend(zt_alerts)
        if not zt_alerts:
            print(f"  [DNS] Zone transfer not allowed (good)")

    # Check wildcard DNS
    print(f"  [DNS] Checking wildcard DNS...")
    is_wildcard, wildcard_ips = await check_wildcard(domain)
    dns_info["wildcard"] = is_wildcard
    dns_info["wildcard_ips"] = wildcard_ips
    if is_wildcard:
        print(f"  [DNS] ⚠ Wildcard DNS detected — subdomain results may include false positives")
    else:
        print(f"  [DNS] No wildcard DNS (good)")

    # Summary
    print(f"\n  ✓ DNS Recon complete — {len(alerts)} finding(s)")

    return dns_info, alerts
