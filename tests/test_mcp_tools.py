"""Tests for the five new MCP tools added in the ChatGPT integration branch."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from anansi.parser.adaptive import AdaptiveParser


# ── Helpers ───────────────────────────────────────────────────────────────────

_SIMPLE_HTML = """
<html><body>
  <h1 class="title">Hello World</h1>
  <span class="price">$9.99</span>
</body></html>
"""


# ── train_selector ────────────────────────────────────────────────────────────

async def test_train_selector_upserts_at_max_confidence(tmp_sel_db: Path) -> None:
    parser = AdaptiveParser(db_path=tmp_sel_db)
    result = await parser.train("example.com/products/{id}", "price", ".prod-price")

    assert result["confidence"] == 1.0
    assert result["selector"] == ".prod-price"
    assert result["field_name"] == "price"

    # Verify it's retrievable and at top confidence
    selectors = await parser.known_selectors("example.com/products/{id}", "price")
    assert any(s["selector"] == ".prod-price" and s["confidence"] == 1.0 for s in selectors)


async def test_train_selector_overwrites_lower_confidence(tmp_sel_db: Path) -> None:
    parser = AdaptiveParser(db_path=tmp_sel_db)

    # Simulate a previous failure reducing confidence
    await parser.record_failure("example.com/items/{id}", "title", ".item-title")
    selectors_before = await parser.known_selectors("example.com/items/{id}", "title")
    low_conf = next((s for s in selectors_before if s["selector"] == ".item-title"), None)
    assert low_conf is not None
    assert low_conf["confidence"] < 1.0

    # Train should pin it back to 1.0
    await parser.train("example.com/items/{id}", "title", ".item-title")
    selectors_after = await parser.known_selectors("example.com/items/{id}", "title")
    pinned = next((s for s in selectors_after if s["selector"] == ".item-title"), None)
    assert pinned is not None
    assert pinned["confidence"] == 1.0


async def test_train_selector_supports_xpath_type(tmp_sel_db: Path) -> None:
    parser = AdaptiveParser(db_path=tmp_sel_db)
    result = await parser.train(
        "example.com/articles/{id}", "author", "//span[@class='author']", selector_type="xpath"
    )
    assert result["selector_type"] == "xpath"
    assert result["confidence"] == 1.0


# ── clear_cache ───────────────────────────────────────────────────────────────

async def test_clear_cache_all() -> None:
    # Import after server module is loaded so we patch the real dict
    import anansi.mcp_server.server as srv

    srv._page_cache[("https://a.com", "html")] = (["content"], {}, 9999999.0)
    srv._page_cache[("https://b.com", "text")] = (["content2"], {}, 9999999.0)

    result = await srv.clear_cache()
    assert result["cleared"] >= 2
    assert len(srv._page_cache) == 0


async def test_clear_cache_single_url() -> None:
    import anansi.mcp_server.server as srv

    srv._page_cache[("https://target.com", "html")] = (["page"], {}, 9999999.0)
    srv._page_cache[("https://other.com", "html")] = (["other"], {}, 9999999.0)

    result = await srv.clear_cache(url="https://target.com")
    assert result["cleared"] == 1
    assert ("https://target.com", "html") not in srv._page_cache
    assert ("https://other.com", "html") in srv._page_cache
    # Cleanup
    srv._page_cache.pop(("https://other.com", "html"), None)


async def test_clear_cache_nonexistent_url() -> None:
    import anansi.mcp_server.server as srv
    result = await srv.clear_cache(url="https://not-in-cache.example.com")
    assert result["cleared"] == 0


# ── validate_selector ─────────────────────────────────────────────────────────

async def test_validate_selector_returns_per_field_results() -> None:
    import anansi.mcp_server.server as srv

    fetch_response = {
        "content": _SIMPLE_HTML,
        "format": "html",
        "status": 200,
        "via_browser": False,
        "elapsed": 0.1,
    }

    with patch("anansi.mcp_server.server._fetch_one", new=AsyncMock(return_value=fetch_response)):
        result = await srv.validate_selector(
            "https://mcp-test-validate.example.com/unique-test-path-987",
            {"title": ".title", "price": ".price"},
        )

    assert "results" in result
    assert result["results"]["title"]["value"] == "Hello World"
    assert result["results"]["price"]["value"] == "$9.99"


async def test_validate_selector_missing_selector_returns_none() -> None:
    import anansi.mcp_server.server as srv

    fetch_response = {
        "content": _SIMPLE_HTML,
        "format": "html",
        "status": 200,
        "via_browser": False,
        "elapsed": 0.1,
    }

    with patch("anansi.mcp_server.server._fetch_one", new=AsyncMock(return_value=fetch_response)):
        result = await srv.validate_selector(
            "https://mcp-test-validate.example.com/unique-test-path-988",
            {"nonexistent": ".does-not-exist"},
        )

    assert result["results"]["nonexistent"]["value"] is None


# ── cancel_crawl ──────────────────────────────────────────────────────────────

async def test_cancel_crawl_missing_id_returns_error() -> None:
    import anansi.mcp_server.server as srv
    result = await srv.cancel_crawl("no-such-crawl-id")
    assert "error" in result


async def test_cancel_crawl_stops_active_task() -> None:
    import anansi.mcp_server.server as srv

    # Register a fake long-running task
    done_event = asyncio.Event()

    async def _long_running():
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            done_event.set()
            raise

    task = asyncio.create_task(_long_running())
    fake_crawl_id = "test-cancel-00000"
    srv._crawl_tasks[fake_crawl_id] = task

    # Yield so the task reaches its first await before we cancel it.
    await asyncio.sleep(0)
    result = await srv.cancel_crawl(fake_crawl_id)
    await asyncio.wait_for(done_event.wait(), timeout=2.0)

    assert result["status"] == "cancelled"
    assert fake_crawl_id not in srv._crawl_tasks
    assert task.cancelled()


# ── screenshot_url ────────────────────────────────────────────────────────────

async def test_screenshot_url_returns_base64_png() -> None:
    """Mock BrowserFetcher.screenshot() to verify the MCP tool plumbing."""
    import anansi.mcp_server.server as srv

    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100  # minimal fake PNG bytes
    mock_result = {
        "url": "https://example.com",
        "format": "png",
        "width": 1920,
        "height": 1080,
        "elapsed": 0.5,
        "data_b64": base64.b64encode(fake_png).decode(),
    }

    with patch("anansi.fetchers.browser.BrowserFetcher") as MockBF, \
            patch("anansi.mcp_server.server._validate_url"):
        instance = MockBF.return_value
        instance.screenshot = AsyncMock(return_value=mock_result)
        instance.close = AsyncMock()

        result = await srv.screenshot_url("https://example.com")

    assert result["format"] == "png"
    assert result["width"] == 1920
    assert "data_b64" in result
    decoded = base64.b64decode(result["data_b64"])
    assert decoded[:8] == b"\x89PNG\r\n\x1a\n"


async def test_screenshot_url_with_path() -> None:
    import anansi.mcp_server.server as srv

    # A bare filename is confined under the export sandbox; the mock returns
    # whatever path BrowserFetcher would have written.
    mock_result = {
        "url": "https://example.com",
        "format": "png",
        "width": 1280,
        "height": 800,
        "elapsed": 0.3,
        "path": str(srv._EXPORT_ROOT / "shot.png"),
    }

    with patch("anansi.fetchers.browser.BrowserFetcher") as MockBF, \
            patch("anansi.mcp_server.server._validate_url"):
        instance = MockBF.return_value
        instance.screenshot = AsyncMock(return_value=mock_result)
        instance.close = AsyncMock()

        result = await srv.screenshot_url("https://example.com", path="shot.png")

    assert result.get("path", "").endswith("shot.png")
    assert "data_b64" not in result


# ── screenshot_url / train_selector security regression tests ─────────────────

async def test_screenshot_url_rejects_private_ip() -> None:
    """SSRF guard parity with fetch_url: a loopback URL is rejected and the
    browser is never launched. Uses a literal IP so no DNS is needed."""
    import anansi.mcp_server.server as srv

    with patch("anansi.fetchers.browser.BrowserFetcher") as MockBF:
        result = await srv.screenshot_url("http://127.0.0.1/")
        MockBF.assert_not_called()

    assert "error" in result
    assert "unsafe url" in result["error"].lower()


async def test_screenshot_url_rejects_path_traversal() -> None:
    """An absolute path outside the export sandbox is rejected before any
    file write."""
    import anansi.mcp_server.server as srv

    with patch("anansi.fetchers.browser.BrowserFetcher") as MockBF, \
            patch("anansi.mcp_server.server._validate_url"):
        result = await srv.screenshot_url(
            "https://example.com", path="/etc/passwd"
        )
        MockBF.assert_not_called()

    assert "error" in result
    assert "rejected" in result["error"].lower()


async def test_screenshot_url_rejects_non_css_selector() -> None:
    """Playwright engine-prefixed selectors are rejected (CSS only)."""
    import anansi.mcp_server.server as srv

    with patch("anansi.fetchers.browser.BrowserFetcher") as MockBF, \
            patch("anansi.mcp_server.server._validate_url"):
        result = await srv.screenshot_url(
            "https://example.com", selector="xpath=//div"
        )
        MockBF.assert_not_called()

    assert "error" in result
    assert "selector" in result["error"].lower()


async def test_train_selector_rejects_redos_text_selector(tmp_sel_db: Path) -> None:
    """A 'text' selector is compiled as a regex during healing, so a
    catastrophic-backtracking pattern must be rejected at the tool boundary."""
    import anansi.mcp_server.server as srv

    result = await srv.train_selector(
        "example.com/p/{id}", "title", "(a+)+$", selector_type="text"
    )
    assert "error" in result
    assert "unsafe text selector" in result["error"].lower()


async def test_train_selector_rejects_unknown_type() -> None:
    import anansi.mcp_server.server as srv

    result = await srv.train_selector(
        "example.com/p/{id}", "title", ".x", selector_type="jsonpath"
    )
    assert "error" in result
    assert "selector_type" in result["error"]


async def test_fetch_url_no_allow_private_networks_kwarg() -> None:
    """The LLM-visible flag is gone: passing it raises TypeError."""
    import anansi.mcp_server.server as srv

    with pytest.raises(TypeError):
        await srv.fetch_url("https://example.com", allow_private_networks=True)


def test_validate_url_respects_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """_validate_url consults the module-level operator flag, not a kwarg."""
    import anansi.mcp_server.server as srv
    from anansi import security
    from anansi.security import UnsafeURLError

    # Default: loopback rejected.
    monkeypatch.setattr(security, "ALLOW_PRIVATE_NETWORKS", False)
    with pytest.raises(UnsafeURLError):
        srv._validate_url("http://127.0.0.1/")

    # Operator opt-in: loopback allowed.
    monkeypatch.setattr(security, "ALLOW_PRIVATE_NETWORKS", True)
    srv._validate_url("http://127.0.0.1/")  # must not raise


def test_env_bool_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    from anansi.security import _env_bool

    monkeypatch.setenv("ANANSI_TEST_FLAG", "1")
    assert _env_bool("ANANSI_TEST_FLAG") is True
    monkeypatch.setenv("ANANSI_TEST_FLAG", "TrUe")
    assert _env_bool("ANANSI_TEST_FLAG") is True
    monkeypatch.setenv("ANANSI_TEST_FLAG", "0")
    assert _env_bool("ANANSI_TEST_FLAG") is False
    monkeypatch.delenv("ANANSI_TEST_FLAG", raising=False)
    assert _env_bool("ANANSI_TEST_FLAG") is False
