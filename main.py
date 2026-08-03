"""
FastRecon ⚡ v3 — CLI Entry Point
Automated reconnaissance & vulnerability scanning pipeline for bug bounty hunters.
"""

import asyncio
import argparse
import os
import sys
import io

from fastrecon import __version__
from fastrecon.config import BANNER, DISCORD_WEBHOOK_PREFIX, SLACK_WEBHOOK_PREFIX
from fastrecon.engine import ReconEngine
from fastrecon.validation import is_safe_target


def _setup_encoding():
    """Ensure UTF-8 output on Windows consoles."""
    if sys.platform == "win32":
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
        except Exception:
            pass


def parse_args():
    parser = argparse.ArgumentParser(
        prog="fastrecon",
        description="FastRecon ⚡ — Automated reconnaissance & vulnerability scanning pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python main.py -t example.com                         # Normal scan
  python main.py -t example.com --mode light             # Quick passive recon
  python main.py -t example.com --mode aggressive        # Deep scan
  python main.py -t example.com --report html            # Generate HTML report
  python main.py --web                                   # Launch web UI
  python main.py --web --port 8080                       # Web UI on custom port
""",
    )

    parser.add_argument(
        "-t", "--target",
        help="Target domain (e.g., example.com)",
    )
    parser.add_argument(
        "-o", "--output",
        default="recon_results.json",
        help="Output JSON report file (default: recon_results.json)",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=50,
        help="Max concurrent requests (default: 50)",
    )
    parser.add_argument(
        "--mode",
        choices=["light", "normal", "aggressive"],
        default="normal",
        help="Scan mode: light (passive only), normal (balanced), aggressive (deep)",
    )
    parser.add_argument(
        "--report",
        choices=["json", "html", "csv", "both", "all"],
        default="json",
        help="Report format: json (default), html, csv, both (json+html), all (json+html+csv)",
    )
    parser.add_argument(
        "--discord-webhook",
        default=None,
        help="Discord webhook URL for real-time alerts",
    )
    parser.add_argument(
        "--slack-webhook",
        default=None,
        help="Slack webhook URL for real-time alerts",
    )
    parser.add_argument(
        "--no-cloud",
        action="store_true",
        help="Skip cloud storage hunting phase",
    )
    parser.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip port scanning phase",
    )
    parser.add_argument(
        "--skip-vulns",
        action="store_true",
        help="Skip vulnerability scanning phase",
    )
    parser.add_argument(
        "--skip-endpoints",
        action="store_true",
        help="Skip endpoint discovery phase",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to custom bucket suffix wordlist (one suffix per line)",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the Flask web UI instead of running a CLI scan",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Web UI host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Web UI port (default: 5000)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"FastRecon ⚡ v{__version__}",
    )

    return parser.parse_args()


def resolve_webhook(cli_value, env_var, prefix, name):
    """Resolve webhook URL from CLI flag or environment variable, with validation."""
    url = cli_value or os.environ.get(env_var)
    if url:
        if not url.startswith(prefix):
            print(f"[!] WARNING: {name} webhook URL doesn't start with {prefix}")
            print(f"    Provided: {url[:60]}...")
            print(f"    Webhook will be skipped for security.")
            return None
    return url


def load_wordlist(path):
    """Load a custom wordlist file (one suffix per line)."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            suffixes = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"  Loaded {len(suffixes)} suffixes from {path}")
        return suffixes
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)


def main():
    _setup_encoding()
    args = parse_args()

    # Web UI mode
    if args.web:
        from fastrecon.web_ui import start_web_ui
        start_web_ui(host=args.host, port=args.port)
        return

    # CLI mode requires target
    if not args.target:
        print("[!] Error: --target is required for CLI scan. Use --web for web UI.")
        sys.exit(1)

    # Validate target (SSRF prevention)
    if not is_safe_target(args.target):
        print(f"[!] Error: '{args.target}' is not a valid or allowed target.")
        print(f"    Targets must be public domains (no IPs, localhost, or internal hosts).")
        sys.exit(1)

    # Print banner
    print(BANNER.format(version=__version__))

    # Resolve webhooks
    discord_url = resolve_webhook(
        args.discord_webhook, "FASTRECON_DISCORD_WEBHOOK",
        DISCORD_WEBHOOK_PREFIX, "Discord",
    )
    slack_url = resolve_webhook(
        args.slack_webhook, "FASTRECON_SLACK_WEBHOOK",
        SLACK_WEBHOOK_PREFIX, "Slack",
    )

    # Load custom wordlist
    wordlist = load_wordlist(args.wordlist)

    # Create and run engine
    engine = ReconEngine(
        target=args.target,
        output_file=args.output,
        concurrency=args.concurrency,
        discord_webhook=discord_url,
        slack_webhook=slack_url,
        skip_cloud=args.no_cloud,
        skip_ports=args.skip_ports,
        skip_vulns=args.skip_vulns,
        skip_endpoints=args.skip_endpoints,
        wordlist=wordlist,
        mode=args.mode,
        report_format=args.report,
    )

    try:
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        print("\n\n[!] Scan aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
