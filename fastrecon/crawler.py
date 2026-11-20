"""
FastRecon Crawler — depth-limited, in-scope recursive crawling.

The vulnerability scanner can only test the parameters it is handed. Crawling
only the homepage (the previous behaviour) starved it of real parameters, so
this module walks the site breadth-first — following in-scope links a few
levels deep — and returns every link and form it finds. Those feed
build_injection_targets(), so injection tests hit real endpoints across the
whole app instead of just the landing page.

Guard rails:
  - Same-host only for *fetching* (never wanders onto other hosts).
  - Depth- and page-capped so a scan can't blow up on a large site.
  - Skips binary/asset URLs (images, fonts, archives, media).
  - Only follows text/html responses.
"""

import asyncio
import ssl
from urllib.parse import urldefrag, urlparse

from fastrecon.config import ENDPOINT_TIMEOUT
from fastrecon.endpoint_discovery import extract_forms, extract_html_links

# Per-mode crawl budgets: (max_depth, max_pages).
CRAWL_BUDGETS = {
    "light": (0, 0),       # no crawling in passive mode
    "normal": (1, 30),
    "aggressive": (2, 80),
}

# URL suffixes we never fetch (not HTML — no links/forms to find).
_SKIP_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".rar",
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".wav", ".doc", ".docx", ".xls",
    ".xlsx", ".ppt", ".pptx", ".dmg", ".exe", ".bin",
)


def _normalize(url):
    """Drop the fragment so #a and #b aren't crawled as two pages."""
    return urldefrag(url)[0]


def _same_host(url, base_host):
    try:
        return (urlparse(url).hostname or "").lower() == base_host
    except ValueError:
        return False


def _is_fetchable(url):
    """True if the URL looks like an HTML page worth fetching."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    path = parsed.path.lower()
    return not path.endswith(_SKIP_EXTENSIONS)


async def _fetch_html(session, url):
    """Fetch a URL and return its body only if it's HTML; else None."""
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        async with session.get(
            url, timeout=ENDPOINT_TIMEOUT, allow_redirects=True, ssl=ssl_context,
        ) as response:
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" not in content_type:
                return None
            return await response.text()
    except Exception:
        return None


async def crawl(session, base_url, target, seed_html="", mode="normal", concurrency=15):
    """
    Breadth-first crawl of the target, depth- and page-limited by mode.

    Args:
        session: aiohttp ClientSession
        base_url: starting URL (e.g. https://example.com)
        target: registered domain, for scope checks
        seed_html: HTML of base_url already fetched during probing (avoids a refetch)
        mode: light / normal / aggressive — selects the crawl budget
        concurrency: max concurrent page fetches

    Returns:
        (links, forms)
        links: sorted list of absolute in-scope-ish URLs discovered (a/href, form action)
        forms: list of form dicts {action, method, params}
    """
    max_depth, max_pages = CRAWL_BUDGETS.get(mode, CRAWL_BUDGETS["normal"])
    if max_pages == 0:
        return [], []

    base_host = (urlparse(base_url).hostname or "").lower()
    semaphore = asyncio.Semaphore(concurrency)

    all_links = set()
    all_forms = []
    visited = set()

    async def process(url, html):
        """Extract links + forms from one page's HTML; return next-hop URLs."""
        links = await extract_html_links(html, base_url)
        for link in links:
            all_links.add(link)
        for form in extract_forms(html, base_url):
            all_forms.append(form)
        return links

    # Seed: process the already-fetched homepage HTML without refetching it.
    base_norm = _normalize(base_url)
    visited.add(base_norm)
    frontier = []
    if seed_html:
        next_links = await process(base_url, seed_html)
        frontier = [link for link in next_links if _is_fetchable(link) and _same_host(link, base_host)]

    depth = 1
    while depth <= max_depth and frontier and len(visited) < max_pages:
        # Dedupe + scope the frontier for this depth level.
        level = []
        for link in frontier:
            norm = _normalize(link)
            if norm in visited:
                continue
            visited.add(norm)
            level.append(norm)
            if len(visited) >= max_pages:
                break

        async def fetch_and_process(url):
            async with semaphore:
                html = await _fetch_html(session, url)
            if not html:
                return []
            return await process(url, html)

        results = await asyncio.gather(
            *(fetch_and_process(u) for u in level), return_exceptions=True,
        )

        next_frontier = []
        for res in results:
            if isinstance(res, list):
                for link in res:
                    if _is_fetchable(link) and _same_host(link, base_host):
                        next_frontier.append(link)
        frontier = next_frontier
        depth += 1

    return sorted(all_links), all_forms
