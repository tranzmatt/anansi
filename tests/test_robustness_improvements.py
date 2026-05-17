"""Tests for the five robustness improvements:

1. Network request interception (captured_requests on FetchResult)
2. Cookie consent auto-dismissal
3. Infinite scroll loop (scroll_until_stable action)
4. Enhanced stealth JS (audio, font, battery, touch point fingerprints)
5. Per-request TLS profile rotation in HTTPFetcher
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from anansi.fetchers.base import FetchResult
from anansi.fetchers.browser import BrowserFetcher, _CONSENT_SELECTORS, _STEALTH_JS
from anansi.fetchers.http import HTTPFetcher, _UNSET


# ── 1. FetchResult.captured_requests field ────────────────────────────────────

def test_fetch_result_captured_requests_default_empty() -> None:
    result = FetchResult(url="https://example.com", status=200, html="<html/>")
    assert result.captured_requests == []


def test_fetch_result_captured_requests_stored() -> None:
    payload = [{"url": "https://api.example.com/data", "status": 200, "body": {"k": "v"}}]
    result = FetchResult(
        url="https://example.com", status=200, html="<html/>",
        captured_requests=payload,
    )
    assert result.captured_requests == payload


# ── 2. Cookie consent auto-dismissal ─────────────────────────────────────────

def test_consent_selectors_not_empty() -> None:
    assert len(_CONSENT_SELECTORS) >= 5


def test_consent_selectors_include_major_cmps() -> None:
    joined = " ".join(_CONSENT_SELECTORS)
    assert "onetrust" in joined
    assert "Cookiebot" in joined or "CybotCookiebot" in joined
    assert "didomi" in joined


async def test_dismiss_cookie_consent_skipped_when_antibot_disabled(monkeypatch) -> None:
    from anansi import security
    from anansi.fetchers.browser import _dismiss_cookie_consent

    monkeypatch.setattr(security, "DISABLE_ANTIBOT", True)

    page = MagicMock()
    result = await _dismiss_cookie_consent(page)

    assert result is False
    page.locator.assert_not_called()


async def test_dismiss_cookie_consent_returns_true_on_match(monkeypatch) -> None:
    from anansi import security
    from anansi.fetchers.browser import _dismiss_cookie_consent

    monkeypatch.setattr(security, "DISABLE_ANTIBOT", False)

    clicked = []

    class _FakeLocator:
        def __init__(self):
            self.first = self

        async def click(self, timeout=None):
            clicked.append(True)

    page = MagicMock()
    page.locator.return_value = _FakeLocator()

    result = await _dismiss_cookie_consent(page)

    assert result is True
    assert clicked


async def test_dismiss_cookie_consent_returns_false_when_all_fail(monkeypatch) -> None:
    from anansi import security
    from anansi.fetchers.browser import _dismiss_cookie_consent

    monkeypatch.setattr(security, "DISABLE_ANTIBOT", False)

    class _FailingLocator:
        def __init__(self):
            self.first = self

        async def click(self, timeout=None):
            raise Exception("not found")

    page = MagicMock()
    page.locator.return_value = _FailingLocator()

    result = await _dismiss_cookie_consent(page)

    assert result is False


# ── 3. scroll_until_stable action ────────────────────────────────────────────

async def test_scroll_until_stable_halts_when_height_stable() -> None:
    """Scrolling should stop when scrollHeight is unchanged for 2 consecutive checks."""
    fetcher = BrowserFetcher()
    call_count = 0

    class _FakePage:
        async def evaluate(self, script: str):
            nonlocal call_count
            call_count += 1
            return 1000  # height never changes → stable immediately

    page = _FakePage()
    actions = [{"type": "scroll_until_stable", "max_scrolls": 10, "scroll_delay": 100}]
    await fetcher._run_actions(page, actions)
    # Should have called evaluate: once for initial height, then loop until 2 stable
    # = 1 initial + at least 2 scroll iterations (scroll + check each) before breaking
    assert call_count >= 3  # initial + 2 scroll+check cycles


async def test_scroll_until_stable_respects_max_scrolls() -> None:
    """Loop should stop at max_scrolls even if page height keeps growing."""
    fetcher = BrowserFetcher()
    scroll_count = 0

    class _GrowingPage:
        def __init__(self):
            self._height = 1000

        async def evaluate(self, script: str):
            nonlocal scroll_count
            if "scrollTo" in script:
                scroll_count += 1
                self._height += 1000
            return self._height

    page = _GrowingPage()
    actions = [{"type": "scroll_until_stable", "max_scrolls": 3, "scroll_delay": 50}]
    await fetcher._run_actions(page, actions)
    assert scroll_count <= 3


async def test_scroll_until_stable_budget_stops_loop() -> None:
    """Loop stops when wait budget (60 000 ms) would be exceeded.

    With scroll_delay=5000ms (the enforced max) and _MAX_BUDGET_MS=60_000ms,
    the guard fires at `spent_ms + 5000 > 60_000`, i.e., after 12 scrolls
    (12 × 5000 = 60 000ms, which is NOT > 60 000ms, so scroll 12 runs; the
    13th would be 65 000ms > 60 000ms → break). Verify the loop does not run
    to max_scrolls=30.
    """
    fetcher = BrowserFetcher()
    scroll_count = 0

    class _GrowingPage:
        def __init__(self):
            self._height = 1000

        async def evaluate(self, script: str):
            nonlocal scroll_count
            if "scrollTo" in script:
                scroll_count += 1
                self._height += 500
            return self._height

    page = _GrowingPage()
    # max_scrolls=30; budget stops at 12 (5000ms × 12 = 60 000ms; 13th would exceed)
    actions = [{"type": "scroll_until_stable", "max_scrolls": 30, "scroll_delay": 5000}]
    await fetcher._run_actions(page, actions)
    assert scroll_count <= 12
    assert scroll_count < 30  # budget fired before max_scrolls


# ── 4. Stealth JS content checks ─────────────────────────────────────────────

def test_stealth_js_includes_audio_context_noise() -> None:
    assert "AudioBuffer.prototype.getChannelData" in _STEALTH_JS


def test_stealth_js_includes_font_measurement_noise() -> None:
    assert "measureText" in _STEALTH_JS


def test_stealth_js_includes_battery_spoofing() -> None:
    assert "getBattery" in _STEALTH_JS


def test_stealth_js_includes_touch_points() -> None:
    assert "maxTouchPoints" in _STEALTH_JS


# ── 5. Per-request TLS profile rotation ──────────────────────────────────────

def test_unset_sentinel_is_unique() -> None:
    assert _UNSET is not None
    assert _UNSET is not False


async def test_per_request_impersonate_overrides_instance_default() -> None:
    """When fetch() receives an explicit impersonate kwarg, it should use that
    value instead of the instance-level default."""
    used_impersonates: list[str] = []

    async def _fake_curl_cffi(url, *, method, headers, body, proxy, timeout, impersonate):
        used_impersonates.append(impersonate)
        return FetchResult(url=url, status=200, html="ok")

    fetcher = HTTPFetcher(impersonate="chrome119")
    fetcher._fetch_curl_cffi = _fake_curl_cffi  # type: ignore[method-assign]

    with respx.mock:
        await fetcher.fetch("https://example.com/", impersonate="chrome131")

    assert used_impersonates == ["chrome131"]


async def test_per_request_impersonate_none_forces_httpx() -> None:
    """Passing impersonate=None explicitly overrides an instance-level default
    and routes to the plain httpx path."""
    fetcher = HTTPFetcher(impersonate="chrome124")

    with respx.mock:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="ok")
        )
        result = await fetcher.fetch("https://example.com/", impersonate=None)

    assert result.status == 200
    assert result.via_browser is False


async def test_per_request_impersonate_unset_uses_instance_default() -> None:
    """When no impersonate kwarg is passed, the instance-level default is used."""
    used_impersonates: list[str] = []

    async def _fake_curl_cffi(url, *, method, headers, body, proxy, timeout, impersonate):
        used_impersonates.append(impersonate)
        return FetchResult(url=url, status=200, html="ok")

    fetcher = HTTPFetcher(impersonate="chrome120")
    fetcher._fetch_curl_cffi = _fake_curl_cffi  # type: ignore[method-assign]

    with respx.mock:
        await fetcher.fetch("https://example.com/")  # no impersonate kwarg

    assert used_impersonates == ["chrome120"]


async def test_invalid_per_request_impersonate_raises() -> None:
    """A caller-supplied impersonate value not in the allowlist raises InvalidImpersonateError."""
    from anansi.security import InvalidImpersonateError

    fetcher = HTTPFetcher()
    with pytest.raises(InvalidImpersonateError):
        await fetcher.fetch("https://example.com/", impersonate="not_a_real_browser")


# ── MCP server validation for new action and params ──────────────────────────

def test_validate_actions_accepts_scroll_until_stable() -> None:
    import anansi.mcp_server.server as srv
    srv._validate_actions([
        {"type": "scroll_until_stable", "max_scrolls": 5, "scroll_delay": 1000}
    ])  # must not raise


def test_validate_actions_rejects_bad_max_scrolls() -> None:
    import anansi.mcp_server.server as srv
    with pytest.raises(ValueError, match="max_scrolls"):
        srv._validate_actions([
            {"type": "scroll_until_stable", "max_scrolls": 999}
        ])


def test_validate_actions_rejects_bad_scroll_delay() -> None:
    import anansi.mcp_server.server as srv
    with pytest.raises(ValueError, match="scroll_delay"):
        srv._validate_actions([
            {"type": "scroll_until_stable", "max_scrolls": 5, "scroll_delay": 99}
        ])
