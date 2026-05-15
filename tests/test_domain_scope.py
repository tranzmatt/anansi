"""Tests for domain scope control (allowed_domains / deny_patterns)."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from anansi.core import Item, Request, Response
from anansi.spider.crawler import Crawler
from anansi.spider.spider import Spider


_HOME_HTML = """
<html><body>
  <a href="https://example.com/page1">internal</a>
  <a href="https://other.com/page2">external</a>
  <a href="https://blog.example.com/post">subdomain</a>
  <a href="https://example.com/admin/secret">admin</a>
</body></html>
"""

_PAGE_HTML = "<html><body><p>leaf</p></body></html>"


class _ScopeSpider(Spider):
    name = "scope_test"
    start_urls = ["https://example.com/"]

    async def parse(self, response: Response):
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin

        soup = BeautifulSoup(response.html, "lxml")
        for a in soup.find_all("a", href=True):
            yield Request(url=urljoin(response.url, str(a["href"])), callback="parse")


async def _run_scope_crawl(tmp_path, *, allowed_domains=None, deny_patterns=None):
    fetched_urls = []

    class _Spider(_ScopeSpider):
        pass

    if allowed_domains is not None:
        _Spider.allowed_domains = allowed_domains
    if deny_patterns is not None:
        _Spider.deny_patterns = deny_patterns

    with respx.mock:
        def record(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            fetched_urls.append(url)
            if url == "https://example.com/":
                return httpx.Response(200, text=_HOME_HTML)
            return httpx.Response(200, text=_PAGE_HTML)

        respx.get(url__regex=r"https://.*").mock(side_effect=record)

        crawler = Crawler(
            _Spider,
            max_depth=None,
            delay=0.0,
            delay_jitter=0.0,
            domain_delay=0.0,
            respect_robots=False,
            auto_browser=False,
            db_path=tmp_path / "crawls.db",
            adaptive_rate_limiting=False,
        )
        # Skip the SSRF DNS check so the mocked (and possibly non-resolving)
        # test domains exercise domain-scope logic in isolation. This mirrors
        # an operator setting ANANSI_ALLOW_PRIVATE_NETWORKS=1.
        with patch("anansi.security.ALLOW_PRIVATE_NETWORKS", True):
            _ = [item async for item in crawler.run()]

    return fetched_urls


async def test_allowed_domains_blocks_external(tmp_path) -> None:
    fetched = await _run_scope_crawl(tmp_path, allowed_domains=["example.com"])
    assert not any("other.com" in u for u in fetched), f"External domain was fetched: {fetched}"


async def test_allowed_domains_permits_subdomain(tmp_path) -> None:
    fetched = await _run_scope_crawl(tmp_path, allowed_domains=["example.com"])
    assert any("blog.example.com" in u for u in fetched), (
        f"Subdomain was unexpectedly blocked: {fetched}"
    )


async def test_deny_patterns_blocks_matching_urls(tmp_path) -> None:
    fetched = await _run_scope_crawl(tmp_path, deny_patterns=[r"/admin/"])
    assert not any("/admin/" in u for u in fetched), f"Admin URL was fetched: {fetched}"


async def test_allowed_domains_empty_permits_all(tmp_path) -> None:
    fetched = await _run_scope_crawl(tmp_path, allowed_domains=[])
    assert any("other.com" in u for u in fetched), (
        f"External domain was blocked when allowed_domains is empty: {fetched}"
    )


async def test_follow_links_respects_allowed_domains() -> None:
    """Spider.follow_links() itself must filter by allowed_domains."""
    from anansi.spider.spider import Spider
    from anansi.core import rule

    class _S(Spider):
        name = "fl_scope"
        allowed_domains = ["example.com"]

        @rule(".*", "parse", True)
        async def parse(self, response):
            return
            yield

    spider = _S()
    response = Response(
        url="https://example.com/",
        status=200,
        html=_HOME_HTML,
        headers={},
    )
    links = spider.follow_links(response)
    urls = [r.url for r in links]
    assert not any("other.com" in u for u in urls)
    assert any("blog.example.com" in u for u in urls)


async def test_parse_yielded_request_filtered_by_scope(tmp_path) -> None:
    """Request objects yielded from parse() should also be filtered."""
    fetched_urls: list[str] = []

    class _YieldExternal(Spider):
        name = "yield_scope"
        start_urls = ["https://example.com/"]
        allowed_domains = ["example.com"]

        async def parse(self, response: Response):
            yield Request(url="https://external.org/bad", callback="parse")
            yield Request(url="https://example.com/good", callback="parse")

    with respx.mock:
        def record(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            fetched_urls.append(url)
            return httpx.Response(200, text="<html><body>ok</body></html>")

        respx.get(url__regex=r"https://.*").mock(side_effect=record)

        crawler = Crawler(
            _YieldExternal,
            delay=0.0,
            delay_jitter=0.0,
            domain_delay=0.0,
            respect_robots=False,
            auto_browser=False,
            db_path=tmp_path / "crawls.db",
            adaptive_rate_limiting=False,
        )
        with patch("anansi.security.ALLOW_PRIVATE_NETWORKS", True):
            _ = [item async for item in crawler.run()]

    assert not any("external.org" in u for u in fetched_urls), (
        f"External URL was fetched despite allowed_domains: {fetched_urls}"
    )
