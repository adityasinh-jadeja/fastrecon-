"""
FastRecon Engine v3.1 — Core pipeline orchestrator.
Coordinates all 10 phases: DNS → Discovery → Ports → Probing → Fingerprint →
Endpoints → Vulns → Headers → Cloud → Takeover → Report.
Integrates SQLite state tracking, CNAME takeover detection, and batched webhooks.
"""

import asyncio
import os
import ssl
import time

import aiohttp

from fastrecon.bypass import run_bypass_scan
from fastrecon.cloud_hunter import hunt_cloud_storage
from fastrecon.confidence import annotate_confidence, confidence_breakdown
from fastrecon.config import DEFAULT_CONCURRENCY, SCAN_MODES
from fastrecon.crawler import crawl
from fastrecon.db import ScanDatabase
from fastrecon.discovery import run_discovery
from fastrecon.dns_recon import run_dns_recon
from fastrecon.endpoint_discovery import extract_forms, run_endpoint_discovery
from fastrecon.exposures import run_exposures_scan
from fastrecon.fingerprint import run_fingerprinting
from fastrecon.header_analyzer import run_header_analysis
from fastrecon.port_scanner import run_port_scan
from fastrecon.prober import fetch_robots_txt, fetch_sitemap, fetch_well_known, probe_host
from fastrecon.reporter import (
    generate_csv_report,
    generate_html_report,
    generate_report,
    save_report,
)
from fastrecon.takeover import check_takeover, check_takeover_cname
from fastrecon.vuln_scanner import build_injection_targets, run_vuln_scan
from fastrecon.webhooks import AlertBatcher, send_scan_summary


class ReconEngine:
    """
    Asynchronous reconnaissance pipeline engine v3.1.

    Orchestrates the full scan lifecycle across 10 phases:
      1. DNS Reconnaissance
      2. Passive Subdomain Discovery (8 sources: 6 APIs + Subfinder + Amass)
      3. TCP Port Scanning + Banner Grabbing
      4. Live Host Probing + Robots/Sitemap + CNAME Takeover
      5. Technology Fingerprinting
      6. Endpoint Discovery (Path Fuzzing + JS Parsing)
      7. Vulnerability Scanning (XSS, SQLi, CORS, etc.)
      8. Security Header Analysis
      9. Cloud Storage Hunting (S3/GCP/Azure/Firebase)
      10. Subdomain Takeover Detection + Report Generation
    """

    def __init__(
        self,
        target,
        output_file="recon_results.json",
        concurrency=DEFAULT_CONCURRENCY,
        discord_webhook=None,
        slack_webhook=None,
        skip_cloud=False,
        skip_ports=False,
        skip_vulns=False,
        skip_endpoints=False,
        wordlist=None,
        mode="normal",
        report_format="json",
        progress_callback=None,
    ):
        self.target = target
        self.output_file = output_file
        self.concurrency = concurrency
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.skip_cloud = skip_cloud
        self.skip_ports = skip_ports
        self.skip_vulns = skip_vulns
        self.skip_endpoints = skip_endpoints
        self.wordlist = wordlist
        self.mode = mode
        self.report_format = report_format
        self.progress_callback = progress_callback

        # Apply scan mode settings
        mode_config = SCAN_MODES.get(mode, SCAN_MODES["normal"])
        if not skip_vulns:
            self.skip_vulns = not mode_config.get("vuln_scan", True)

        # Results storage
        self.discovered_subdomains = set()
        self.new_subdomains = set()
        self.live_hosts = []
        self.alerts = []
        self.cloud_buckets = []
        self.dns_info = {}
        self.open_ports = []
        self.ssl_info = {}
        self.technologies = []
        self.tech_insights = []
        self.endpoints = []
        self.js_files = []
        self.api_endpoints = []
        self.html_links = []
        self.vulnerabilities = []
        self.header_report = {}
        self.robots_paths = []
        self.sitemap_urls = []
        self.well_known = {}
        self.primary_url = ""
        self.primary_headers = {}
        self.primary_body = ""

        # Database for state tracking
        self.db = ScanDatabase()

    @property
    def has_webhooks(self):
        return bool(self.discord_webhook or self.slack_webhook)

    def _update_progress(self, phase, phase_num, total_phases, status="running"):
        """Send progress update via callback (used by web UI)."""
        if self.progress_callback:
            self.progress_callback({
                "phase": phase,
                "phaseNum": phase_num,
                "totalPhases": total_phases,
                "status": status,
                "target": self.target,
            })

    async def run(self):
        """Execute the full 10-phase reconnaissance pipeline."""
        start_time = time.time()
        total_phases = 10

        print(f"\n🚀 FastRecon v3.1 targeting: {self.target}")
        print(f"   Mode: {self.mode}")
        print(f"   Concurrency: {self.concurrency}")
        print(f"   Webhooks: {'Discord ' if self.discord_webhook else ''}{'Slack ' if self.slack_webhook else ''}{'None' if not self.has_webhooks else ''}")

        # Auto-save target to database
        self.db.save_target(self.target)

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context, limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            semaphore = asyncio.Semaphore(self.concurrency)

            # Create batched webhook sender
            batcher = AlertBatcher(
                session,
                discord_url=self.discord_webhook,
                slack_url=self.slack_webhook,
            )

            # ── Phase 1: DNS Reconnaissance ──
            self._update_progress("DNS Reconnaissance", 1, total_phases)
            try:
                self.dns_info, dns_alerts = await run_dns_recon(self.target)
                self.alerts.extend(dns_alerts)
                for alert in dns_alerts:
                    await batcher.add(alert)
            except Exception as e:
                print(f"\n  [!] DNS Recon failed: {e}")

            # ── Phase 2: Subdomain Discovery ──
            self._update_progress("Subdomain Discovery", 2, total_phases)
            self.discovered_subdomains = await run_discovery(session, self.target)

            # State tracking: identify NEW subdomains via SQLite diff engine
            self.new_subdomains = self.db.get_new_subdomains(
                self.target, self.discovered_subdomains
            )
            if self.new_subdomains:
                print(f"  🆕 New subdomains this scan: {len(self.new_subdomains)}")
                for sub in sorted(self.new_subdomains)[:10]:
                    print(f"    + {sub}")
                if len(self.new_subdomains) > 10:
                    print(f"    ... and {len(self.new_subdomains) - 10} more")

            # ── Phase 3: Port Scanning ──
            if not self.skip_ports:
                self._update_progress("Port Scanning", 3, total_phases)
                try:
                    self.open_ports, self.ssl_info, port_alerts = await run_port_scan(
                        self.target, mode=self.mode, concurrency=self.concurrency
                    )
                    self.alerts.extend(port_alerts)
                    for alert in port_alerts:
                        await batcher.add(alert)
                except Exception as e:
                    print(f"\n  [!] Port scan failed: {e}")
            else:
                print(f"\n{'='*60}")
                print("  PHASE 3: PORT SCANNING [SKIPPED]")
                print(f"{'='*60}")

            # ── Phase 4: Host Probing + CNAME Takeover ──
            self._update_progress("Host Probing", 4, total_phases)
            await self._probe_and_detect(session, semaphore, batcher)

            # Determine primary URL for further testing
            self._set_primary_url(session, semaphore)

            # Fetch robots.txt, sitemap, .well-known from primary URL
            if self.primary_url:
                print("\n  Fetching robots.txt, sitemap.xml, .well-known...")
                self.robots_paths = await fetch_robots_txt(session, self.primary_url, semaphore)
                self.sitemap_urls = await fetch_sitemap(session, self.primary_url, semaphore)
                self.well_known = await fetch_well_known(session, self.primary_url, semaphore)
                if self.robots_paths:
                    print(f"  [robots.txt] {len(self.robots_paths)} paths found")
                if self.sitemap_urls:
                    print(f"  [sitemap.xml] {len(self.sitemap_urls)} URLs found")
                if self.well_known:
                    print(f"  [.well-known] {len(self.well_known)} endpoint(s) found")

            # ── Phase 5: Technology Fingerprinting ──
            self._update_progress("Technology Fingerprinting", 5, total_phases)
            if self.primary_url and self.primary_headers:
                try:
                    self.technologies, self.tech_insights = await run_fingerprinting(
                        self.primary_url, self.primary_headers, self.primary_body
                    )
                except Exception as e:
                    print(f"\n  [!] Fingerprinting failed: {e}")

            # ── Phase 6: Endpoint Discovery ──
            if not self.skip_endpoints and self.primary_url:
                self._update_progress("Endpoint Discovery", 6, total_phases)
                try:
                    self.endpoints, self.js_files, self.api_endpoints, self.html_links, ep_alerts = \
                        await run_endpoint_discovery(
                            session, self.target, self.primary_url,
                            html_body=self.primary_body, mode=self.mode,
                            concurrency=self.concurrency,
                        )
                    self.alerts.extend(ep_alerts)
                    for alert in ep_alerts:
                        await batcher.add(alert)
                except Exception as e:
                    print(f"\n  [!] Endpoint discovery failed: {e}")
            else:
                print(f"\n{'='*60}")
                print("  PHASE 6: ENDPOINT DISCOVERY [SKIPPED]")
                print(f"{'='*60}")

            # ── Phase 7: Vulnerability Scanning ──
            if not self.skip_vulns and self.primary_url:
                self._update_progress("Vulnerability Scanning", 7, total_phases)
                try:
                    # Recursively crawl the target (depth/page-limited by mode)
                    # to discover real URLs, parameters, and forms across the
                    # whole app — not just the landing page.
                    crawl_links, crawl_forms = await crawl(
                        session, self.primary_url, self.target,
                        seed_html=self.primary_body, mode=self.mode,
                    )
                    if crawl_links or crawl_forms:
                        print(f"  [CRAWL] Discovered {len(crawl_links)} link(s), {len(crawl_forms)} form(s)")

                    # Build an injection corpus from discovered endpoints, JS API
                    # routes, in-page + crawled links, and forms — so injection
                    # tests hit REAL parameters instead of homepage guesses.
                    forms = extract_forms(self.primary_body, self.primary_url) + crawl_forms
                    all_links = sorted(set(self.html_links) | set(crawl_links))
                    injection_targets = build_injection_targets(
                        self.primary_url,
                        self.target,
                        html_links=all_links,
                        api_endpoints=self.api_endpoints,
                        endpoints=self.endpoints,
                        forms=forms,
                    )
                    if injection_targets:
                        print(f"  [VULN] Built {len(injection_targets)} injectable target(s) from recon data")
                    self.vulnerabilities = await run_vuln_scan(
                        session, self.target, self.primary_url,
                        mode=self.mode, targets=injection_targets,
                    )

                    # Probe 401/403 endpoints for access-control bypasses.
                    if self.mode != "light":
                        bypass_findings = await run_bypass_scan(
                            session, self.endpoints, semaphore,
                        )
                        if bypass_findings:
                            self.vulnerabilities.extend(bypass_findings)

                        # GraphQL introspection + content-verified file exposure.
                        exposure_findings = await run_exposures_scan(
                            session, self.primary_url, semaphore,
                        )
                        if exposure_findings:
                            self.vulnerabilities.extend(exposure_findings)

                    self.alerts.extend(self.vulnerabilities)
                    for vuln in self.vulnerabilities:
                        await batcher.add(vuln)
                except Exception as e:
                    print(f"\n  [!] Vulnerability scan failed: {e}")
            else:
                print(f"\n{'='*60}")
                print("  PHASE 7: VULNERABILITY SCANNING [SKIPPED]")
                print(f"{'='*60}")

            # ── Phase 8: Security Header Analysis ──
            self._update_progress("Security Header Analysis", 8, total_phases)
            if self.primary_url and self.primary_headers:
                try:
                    self.header_report, header_alerts = await run_header_analysis(
                        self.primary_url, self.primary_headers
                    )
                    self.alerts.extend(header_alerts)
                except Exception as e:
                    print(f"\n  [!] Header analysis failed: {e}")

            # ── Phase 9: Cloud Storage Hunting ──
            if not self.skip_cloud:
                self._update_progress("Cloud Storage Hunting", 9, total_phases)
                await self._hunt_cloud(session, semaphore, batcher)
            else:
                print(f"\n{'='*60}")
                print("  PHASE 9: CLOUD STORAGE HUNTING [SKIPPED]")
                print(f"{'='*60}")

            # Annotate every finding with a confidence level (confirmed /
            # probable / needs-review) so results can be triaged by trust,
            # not just severity. Mutates the shared alert dicts in place.
            annotate_confidence(self.alerts)
            breakdown = confidence_breakdown(self.alerts)
            print(
                f"\n  Confidence: {breakdown['confirmed']} confirmed, "
                f"{breakdown['probable']} probable, "
                f"{breakdown['needs-review']} needs-review"
            )

            # ── Phase 10: Report Generation ──
            self._update_progress("Generating Report", 10, total_phases)
            elapsed = time.time() - start_time
            scan_duration = f"{elapsed:.1f}s"

            report = generate_report(
                target=self.target,
                scan_duration=scan_duration,
                subdomains=self.discovered_subdomains,
                live_hosts=self.live_hosts,
                alerts=self.alerts,
                cloud_buckets=self.cloud_buckets,
                dns_info=self.dns_info,
                open_ports=self.open_ports,
                ssl_info=self.ssl_info,
                technologies=self.technologies,
                tech_insights=self.tech_insights,
                endpoints=self.endpoints,
                js_files=self.js_files,
                api_endpoints=self.api_endpoints,
                html_links=self.html_links,
                vulnerabilities=self.vulnerabilities,
                header_report=self.header_report,
                robots_paths=self.robots_paths,
                sitemap_urls=self.sitemap_urls,
                well_known=self.well_known,
                scan_mode=self.mode,
            )

            # Add new subdomains count to report
            report["newSubdomains"] = len(self.new_subdomains)
            report["newSubdomainsList"] = sorted(self.new_subdomains)

            save_report(report, self.output_file)

            # Generate HTML report if requested
            if self.report_format in ("html", "both", "all"):
                html_file = self.output_file.replace(".json", ".html")
                generate_html_report(report, html_file)

            # Generate CSV report if requested
            if self.report_format in ("csv", "both", "all"):
                csv_dir = os.path.dirname(os.path.abspath(self.output_file)) or "."
                generate_csv_report(report, output_dir=csv_dir)

            # Always generate HTML for web UI
            self.last_report = report
            self.last_html = generate_html_report(report)

            # Save scan to database
            scan_id = f"{self.target.replace('.', '_')}_{int(start_time)}"
            self.db.save_scan(
                scan_id=scan_id,
                target=self.target,
                mode=self.mode,
                report=report,
                duration=scan_duration,
                new_subdomains_count=len(self.new_subdomains),
            )
            self.db.update_target_last_scanned(self.target)

            # Flush remaining webhook alerts and send summary
            if batcher.has_webhooks:
                await batcher.flush()
                print(f"\n  📡 Sent {batcher.sent_count} alert(s) via webhooks")
                print("  📡 Sending scan summary to webhooks...")
                await send_scan_summary(
                    session, report,
                    discord_url=self.discord_webhook,
                    slack_url=self.slack_webhook,
                )

        # Final Summary
        self._update_progress("Complete", total_phases, total_phases, status="complete")
        self._print_summary(scan_duration, report)

        return report

    def _set_primary_url(self, session, semaphore):
        """Set the primary URL and headers/body for further testing."""
        if self.live_hosts:
            # Prefer the target domain itself
            for host in self.live_hosts:
                if host.get("subdomain") == self.target:
                    self.primary_url = host.get("url", "")
                    self.primary_headers = host.get("headers", {})
                    break

            # Fall back to first live host
            if not self.primary_url and self.live_hosts:
                host = self.live_hosts[0]
                self.primary_url = host.get("url", "")
                self.primary_headers = host.get("headers", {})

        # If no live hosts, construct URL
        if not self.primary_url:
            self.primary_url = f"https://{self.target}"

    async def _probe_and_detect(self, session, semaphore, batcher):
        """Phase 4: Probe live hosts, check for subdomain takeovers (HTML + CNAME)."""
        print(f"\n{'='*60}")
        print("  PHASE 4: HOST PROBING & TAKEOVER DETECTION")
        print(f"{'='*60}")
        print(f"  Probing {len(self.discovered_subdomains)} subdomains...")

        tasks = [
            self._probe_single(session, sub, semaphore, batcher)
            for sub in self.discovered_subdomains
        ]

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        print(f"\n  ✓ Live hosts: {len(self.live_hosts)}")
        takeover_count = sum(1 for a in self.alerts if a.get("type") == "Subdomain Takeover")
        if takeover_count:
            print(f"  ✓ Takeover vectors: {takeover_count}")

    async def _probe_single(self, session, subdomain, semaphore, batcher):
        """Probe a single subdomain and check for takeover (HTML body + CNAME)."""
        result, html_body = await probe_host(session, subdomain, semaphore)

        if result:
            self.live_hosts.append(result)

            # Update subdomain info in database
            self.db.update_subdomain_info(
                target=self.target,
                subdomain=subdomain,
                http_status=result.get("status"),
                title=result.get("title", ""),
                server=result.get("server", ""),
                status="live",
            )

            # Store body for the primary domain
            if subdomain == self.target:
                self.primary_body = html_body or ""
                self.primary_headers = result.get("headers", {})
            elif not self.primary_body and html_body:
                self.primary_body = html_body

            # Check for takeover via HTML fingerprint
            if html_body:
                alert = check_takeover(subdomain, html_body)
                if alert:
                    self.alerts.append(alert)
                    await batcher.add(alert)
        else:
            # Host didn't respond — mark as dead in db
            self.db.update_subdomain_info(
                target=self.target,
                subdomain=subdomain,
                status="dead",
            )

        # CNAME-based takeover check (runs regardless of HTTP response)
        cname_alert = await check_takeover_cname(subdomain)
        if cname_alert:
            # Avoid duplicate if HTML check already found it
            existing = [a for a in self.alerts
                        if a.get("type") == "Subdomain Takeover" and a.get("asset") == subdomain]
            if not existing:
                self.alerts.append(cname_alert)
                await batcher.add(cname_alert)

    async def _hunt_cloud(self, session, semaphore, batcher):
        """Phase 9: Hunt for misconfigured cloud storage."""
        buckets, bucket_alerts = await hunt_cloud_storage(
            session, self.target, semaphore, wordlist=self.wordlist
        )
        self.cloud_buckets = buckets
        self.alerts.extend(bucket_alerts)

        for alert in bucket_alerts:
            await batcher.add(alert)

    def _print_summary(self, scan_duration, report=None):
        """Print the final scan summary."""
        stats = report.get("stats", {}) if report else {}
        risk_level = report.get("riskLevel", "N/A") if report else "N/A"
        risk_score = report.get("riskScore", 0) if report else 0

        print(f"\n{'='*60}")
        print("  SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Target:         {self.target}")
        print(f"  Duration:       {scan_duration}")
        print(f"  Mode:           {self.mode}")
        print(f"  Risk Level:     {risk_level} ({risk_score}/100)")
        print("  ─────────────────────────────────")
        print(f"  Subdomains:     {stats.get('subdomainsDiscovered', 0)}")
        print(f"  New This Scan:  {len(self.new_subdomains)}")
        print(f"  Live Hosts:     {stats.get('liveHosts', 0)}")
        print(f"  Open Ports:     {stats.get('openPorts', 0)}")
        print(f"  Vulnerabilities:{stats.get('vulnerabilities', 0)}")
        print("  ─────────────────────────────────")
        print(f"  🔴 Critical:    {stats.get('criticalAlerts', 0)}")
        print(f"  🟠 High:        {stats.get('highAlerts', 0)}")
        print(f"  🟡 Medium:      {stats.get('mediumAlerts', 0)}")
        print(f"  🟢 Low:         {stats.get('lowAlerts', 0)}")
        print("  ─────────────────────────────────")
        print(f"  Total Alerts:   {stats.get('totalAlerts', 0)}")
        print(f"  Report:         {self.output_file}")
        print(f"{'='*60}\n")
