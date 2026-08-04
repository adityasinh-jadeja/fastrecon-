"""
FastRecon Port Scanner — Async TCP port scanning with banner grabbing and risk assessment.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from fastrecon.config import (
    BANNER_READ_TIMEOUT,
    DANGEROUS_PORTS,
    PORT_SCAN_TIMEOUT,
    PORT_SERVICE_MAP,
    TOP_20_PORTS,
    TOP_100_PORTS,
    TOP_1000_PORTS,
)


async def scan_port(host, port, semaphore):
    """
    Attempt TCP connection to a single port.
    Returns port info dict if open, None if closed/filtered.
    """
    async with semaphore:
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=PORT_SCAN_TIMEOUT)

            # Port is open — try banner grabbing
            banner = ""
            service = PORT_SERVICE_MAP.get(port, "Unknown")

            try:
                # Send a generic probe for some protocols
                if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090):
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif port == 22:
                    pass  # SSH sends banner automatically
                elif port in (21,):
                    pass  # FTP sends banner automatically
                elif port == 25 or port == 587:
                    pass  # SMTP sends banner automatically
                else:
                    writer.write(b"\r\n")

                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_READ_TIMEOUT)
                banner = data.decode("utf-8", errors="replace").strip()[:500]

                # Try to identify service from banner
                if banner:
                    service = _identify_service(port, banner, service)

            except (asyncio.TimeoutError, Exception):
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
            }

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def scan_port_ssl(host, port, semaphore):
    """Grab SSL/TLS certificate information from TLS-enabled ports."""
    async with semaphore:
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            future = asyncio.open_connection(host, port, ssl=ssl_context)
            reader, writer = await asyncio.wait_for(future, timeout=PORT_SCAN_TIMEOUT + 1)

            # Get cert info
            ssl_obj = writer.get_extra_info("ssl_object")
            cert_info = {}
            if ssl_obj:
                cert = ssl_obj.getpeercert(binary_form=False)
                if cert:
                    cert_info = {
                        "subject": str(cert.get("subject", "")),
                        "issuer": str(cert.get("issuer", "")),
                        "notBefore": cert.get("notBefore", ""),
                        "notAfter": cert.get("notAfter", ""),
                        "serialNumber": cert.get("serialNumber", ""),
                    }
                else:
                    # Get binary cert for basic info
                    binary_cert = ssl_obj.getpeercert(binary_form=True)
                    if binary_cert:
                        cert_info = {"raw": True, "size": len(binary_cert)}

                # Protocol version
                cert_info["protocol"] = ssl_obj.version()

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return cert_info

        except Exception:
            return None


def _identify_service(port, banner, default_service):
    """Try to identify the service from banner content."""
    banner_lower = banner.lower()

    if "ssh" in banner_lower:
        return "SSH"
    elif "ftp" in banner_lower:
        return "FTP"
    elif "smtp" in banner_lower or "postfix" in banner_lower or "exim" in banner_lower:
        return "SMTP"
    elif "http" in banner_lower:
        if "nginx" in banner_lower:
            return "HTTP (nginx)"
        elif "apache" in banner_lower:
            return "HTTP (Apache)"
        elif "iis" in banner_lower:
            return "HTTP (IIS)"
        return "HTTP"
    elif "mysql" in banner_lower or "mariadb" in banner_lower:
        return "MySQL"
    elif "postgresql" in banner_lower:
        return "PostgreSQL"
    elif "redis" in banner_lower:
        return "Redis"
    elif "mongodb" in banner_lower:
        return "MongoDB"
    elif "elastic" in banner_lower:
        return "Elasticsearch"
    elif "pop3" in banner_lower:
        return "POP3"
    elif "imap" in banner_lower:
        return "IMAP"
    elif "microsoft" in banner_lower and "rdp" in banner_lower:
        return "RDP"

    return default_service


def assess_port_risks(open_ports, target):
    """
    Assess security risks from open ports.
    Returns list of alert dicts.
    """
    alerts = []

    for port_info in open_ports:
        port = port_info["port"]

        if port in DANGEROUS_PORTS:
            service_name, risk_desc = DANGEROUS_PORTS[port]
            alerts.append({
                "severity": "HIGH",
                "type": "Dangerous Port Exposed",
                "asset": f"{target}:{port}",
                "service": service_name,
                "details": risk_desc,
                "evidence": f"Port {port} ({service_name}) is open. Banner: {port_info.get('banner', '')[:100]}",
                "cname_pattern": "",
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            })

    # Check for unencrypted services
    unencrypted_web = [p for p in open_ports if p["port"] == 80]
    encrypted_web = [p for p in open_ports if p["port"] == 443]
    if unencrypted_web and not encrypted_web:
        alerts.append({
            "severity": "MEDIUM",
            "type": "No HTTPS Available",
            "asset": f"{target}:80",
            "service": "HTTP",
            "details": "HTTP (port 80) is open but HTTPS (port 443) is not — all traffic is unencrypted",
            "evidence": "Port 80 open, port 443 closed",
            "cname_pattern": "",
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

    return alerts


async def run_port_scan(target, mode="normal", concurrency=100):
    """
    Execute full port scan against a target.

    Args:
        target: Target hostname or IP
        mode: 'light' (top20), 'normal' (top100), 'aggressive' (top1000)
        concurrency: Max concurrent scan connections

    Returns:
        (open_ports list, ssl_info dict, alerts list)
    """
    print(f"\n{'='*60}")
    print("  PHASE 3: PORT SCANNING")
    print(f"{'='*60}")

    # Select port list based on mode
    if mode == "light":
        ports = TOP_20_PORTS
    elif mode == "aggressive":
        ports = TOP_1000_PORTS
    else:
        ports = TOP_100_PORTS

    print(f"  Scanning {len(ports)} ports on {target} (mode: {mode})...")

    # Resolve hostname to IP for scanning
    try:
        loop = asyncio.get_event_loop()
        def _resolve():
            return socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        infos = await loop.run_in_executor(None, _resolve)
        ip = infos[0][4][0] if infos else target
        print(f"  Resolved: {target} → {ip}")
    except Exception:
        ip = target
        print(f"  Using target directly: {ip}")

    semaphore = asyncio.Semaphore(concurrency)

    # Scan all ports concurrently
    tasks = [scan_port(ip, port, semaphore) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for result in results:
        if isinstance(result, dict) and result is not None:
            open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    # Print open ports
    for p in open_ports:
        banner_preview = p["banner"][:60].replace("\n", " ") if p["banner"] else ""
        print(f"  [+] Port {p['port']:>5}/tcp  OPEN  {p['service']:<20} {banner_preview}")

    # Grab SSL info for TLS ports
    ssl_info = {}
    tls_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443, 993, 995, 465, 636, 4443, 7443, 9443)]
    if tls_ports:
        print(f"\n  Grabbing SSL/TLS certificates from {len(tls_ports)} port(s)...")
        ssl_tasks = [scan_port_ssl(ip, port, semaphore) for port in tls_ports]
        ssl_results = await asyncio.gather(*ssl_tasks, return_exceptions=True)
        for i, port in enumerate(tls_ports):
            if isinstance(ssl_results[i], dict) and ssl_results[i]:
                ssl_info[str(port)] = ssl_results[i]
                proto = ssl_results[i].get("protocol", "Unknown")
                print(f"  [SSL] Port {port}: {proto}")

    # Assess risks
    alerts = assess_port_risks(open_ports, target)

    print(f"\n  ✓ Port scan complete: {len(open_ports)} open port(s), {len(alerts)} alert(s)")

    return open_ports, ssl_info, alerts
