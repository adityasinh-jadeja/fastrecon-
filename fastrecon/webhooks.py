"""
FastRecon Webhooks — Real-time Discord & Slack alerting with batched delivery.
"""

from datetime import datetime, timezone

# --- Severity color mapping ---
SEVERITY_COLORS = {
    "CRITICAL": 0xEF476F,  # Red
    "HIGH": 0xFFD166,      # Orange/Yellow
    "MEDIUM": 0x118AB2,    # Blue
    "LOW": 0x06D6A0,       # Green
    "INFO": 0x6C757D,      # Gray
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🔵",
    "LOW": "🟢",
    "INFO": "⚪",
}

# Discord max embeds per message
DISCORD_MAX_EMBEDS = 10
# Slack max blocks per message
SLACK_MAX_BLOCKS = 45


class AlertBatcher:
    """
    Batches webhook alerts for efficient delivery.
    Collects alerts and sends in batches of up to 10 (Discord) or 45 blocks (Slack).
    """

    def __init__(self, session, discord_url=None, slack_url=None):
        self.session = session
        self.discord_url = discord_url
        self.slack_url = slack_url
        self._discord_buffer = []
        self._slack_buffer = []
        self._sent_count = 0

    async def add(self, alert):
        """Add an alert to the batch buffer. Auto-flushes when buffer is full."""
        if self.discord_url:
            self._discord_buffer.append(alert)
            if len(self._discord_buffer) >= DISCORD_MAX_EMBEDS:
                await self._flush_discord()

        if self.slack_url:
            self._slack_buffer.append(alert)
            if len(self._slack_buffer) >= 8:  # ~5 blocks per alert
                await self._flush_slack()

    async def flush(self):
        """Send all remaining buffered alerts."""
        if self._discord_buffer:
            await self._flush_discord()
        if self._slack_buffer:
            await self._flush_slack()

    async def _flush_discord(self):
        """Send buffered alerts to Discord as a batch of embeds."""
        if not self._discord_buffer or not self.discord_url:
            return

        embeds = []
        for alert in self._discord_buffer:
            severity = alert.get("severity", "INFO")
            color = SEVERITY_COLORS.get(severity, 0x6C757D)
            emoji = SEVERITY_EMOJI.get(severity, "⚪")

            embed = {
                "title": f"{emoji} {severity}: {alert.get('type', 'Alert')}",
                "color": color,
                "fields": [
                    {"name": "Asset", "value": f"`{alert.get('asset', 'N/A')}`", "inline": True},
                    {"name": "Service", "value": alert.get("service", "N/A"), "inline": True},
                    {"name": "Details", "value": alert.get("details", "No details")[:200], "inline": False},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            if alert.get("evidence"):
                embed["fields"].append({
                    "name": "Evidence",
                    "value": f"```{alert['evidence'][:150]}```",
                    "inline": False,
                })
            embeds.append(embed)

        try:
            await self.session.post(
                self.discord_url,
                json={"embeds": embeds},
                timeout=10,
            )
            self._sent_count += len(self._discord_buffer)
        except Exception as e:
            print(f"  [Webhook] Discord batch send failed: {e}")

        self._discord_buffer.clear()

    async def _flush_slack(self):
        """Send buffered alerts to Slack as combined blocks."""
        if not self._slack_buffer or not self.slack_url:
            return

        blocks = []
        for alert in self._slack_buffer:
            severity = alert.get("severity", "INFO")
            emoji = SEVERITY_EMOJI.get(severity, "⚪")
            blocks.extend([
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{severity}: {alert.get('type', 'Alert')}*\n"
                                f"*Asset:* `{alert.get('asset', 'N/A')}`\n"
                                f"{alert.get('details', '')[:200]}",
                    },
                },
                {"type": "divider"},
            ])

        try:
            await self.session.post(
                self.slack_url,
                json={"blocks": blocks[:SLACK_MAX_BLOCKS]},
                timeout=10,
            )
            self._sent_count += len(self._slack_buffer)
        except Exception as e:
            print(f"  [Webhook] Slack batch send failed: {e}")

        self._slack_buffer.clear()

    @property
    def has_webhooks(self):
        return bool(self.discord_url or self.slack_url)

    @property
    def sent_count(self):
        return self._sent_count


async def send_discord_alert(session, webhook_url, alert):
    """
    Send a single alert to Discord as a rich embed.

    Args:
        session: aiohttp ClientSession
        webhook_url: Discord webhook URL
        alert: Alert dict with severity, type, asset, details, time

    Returns:
        True if sent successfully, False otherwise
    """
    if not webhook_url:
        return False

    severity = alert.get("severity", "INFO")
    color = SEVERITY_COLORS.get(severity, 0x6C757D)
    emoji = SEVERITY_EMOJI.get(severity, "⚪")

    embed = {
        "title": f"{emoji} {severity}: {alert.get('type', 'Alert')}",
        "color": color,
        "fields": [
            {"name": "Asset", "value": f"`{alert.get('asset', 'N/A')}`", "inline": True},
            {"name": "Service", "value": alert.get("service", "N/A"), "inline": True},
            {"name": "Details", "value": alert.get("details", "No details"), "inline": False},
        ],
        "footer": {"text": "FastRecon ⚡ Automated Alert"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Add evidence field if present
    if alert.get("evidence"):
        embed["fields"].append({
            "name": "Evidence",
            "value": f"```{alert['evidence'][:200]}```",
            "inline": False,
        })

    payload = {"embeds": [embed]}

    try:
        async with session.post(
            webhook_url,
            json=payload,
            timeout=10,
        ) as response:
            if response.status in (200, 204):
                return True
            else:
                print(f"  [Webhook] Discord returned {response.status}")
                return False
    except Exception as e:
        print(f"  [Webhook] Discord send failed: {e}")
        return False


async def send_slack_alert(session, webhook_url, alert):
    """
    Send a single alert to Slack using Block Kit.

    Args:
        session: aiohttp ClientSession
        webhook_url: Slack webhook URL
        alert: Alert dict with severity, type, asset, details, time

    Returns:
        True if sent successfully, False otherwise
    """
    if not webhook_url:
        return False

    severity = alert.get("severity", "INFO")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {severity}: {alert.get('type', 'Alert')}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Asset:*\n`{alert.get('asset', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Service:*\n{alert.get('service', 'N/A')}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Details:*\n{alert.get('details', 'No details')}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"FastRecon ⚡ | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                },
            ],
        },
        {"type": "divider"},
    ]

    payload = {"blocks": blocks}

    try:
        async with session.post(
            webhook_url,
            json=payload,
            timeout=10,
        ) as response:
            if response.status == 200:
                return True
            else:
                print(f"  [Webhook] Slack returned {response.status}")
                return False
    except Exception as e:
        print(f"  [Webhook] Slack send failed: {e}")
        return False


async def send_alert(session, alert, discord_url=None, slack_url=None):
    """Dispatch an alert to all configured webhook channels."""
    sent = False
    if discord_url:
        sent = await send_discord_alert(session, discord_url, alert) or sent
    if slack_url:
        sent = await send_slack_alert(session, slack_url, alert) or sent
    return sent


async def send_scan_summary(session, report, discord_url=None, slack_url=None):
    """Send an end-of-scan summary to all configured webhooks."""
    stats = report.get("stats", {})
    target = report.get("target", "Unknown")
    duration = report.get("scanDuration", "N/A")

    # --- Discord Summary ---
    if discord_url:
        embed = {
            "title": "⚡ FastRecon Scan Complete",
            "color": 0x06D6A0,
            "fields": [
                {"name": "Target", "value": f"`{target}`", "inline": True},
                {"name": "Duration", "value": duration, "inline": True},
                {"name": "Subdomains", "value": str(stats.get("subdomainsDiscovered", 0)), "inline": True},
                {"name": "Live Hosts", "value": str(stats.get("liveHosts", 0)), "inline": True},
                {"name": "Takeovers", "value": str(stats.get("takeoversFound", 0)), "inline": True},
                {"name": "Open Buckets", "value": str(stats.get("openBuckets", 0)), "inline": True},
            ],
            "footer": {"text": "FastRecon ⚡ Scan Summary"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        total_alerts = stats.get("totalAlerts", 0)
        if total_alerts > 0:
            embed["color"] = 0xEF476F  # Red if there are alerts

        try:
            await session.post(discord_url, json={"embeds": [embed]}, timeout=10)
        except Exception as e:
            print(f"  [Webhook] Discord summary failed: {e}")

    # --- Slack Summary ---
    if slack_url:
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "⚡ FastRecon Scan Complete", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:* `{target}`"},
                    {"type": "mrkdwn", "text": f"*Duration:* {duration}"},
                    {"type": "mrkdwn", "text": f"*Subdomains:* {stats.get('subdomainsDiscovered', 0)}"},
                    {"type": "mrkdwn", "text": f"*Live Hosts:* {stats.get('liveHosts', 0)}"},
                    {"type": "mrkdwn", "text": f"*Takeovers:* {stats.get('takeoversFound', 0)}"},
                    {"type": "mrkdwn", "text": f"*Open Buckets:* {stats.get('openBuckets', 0)}"},
                ],
            },
            {"type": "divider"},
        ]
        try:
            await session.post(slack_url, json={"blocks": blocks}, timeout=10)
        except Exception as e:
            print(f"  [Webhook] Slack summary failed: {e}")
