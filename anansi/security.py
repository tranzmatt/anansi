"""Shared security helpers — SSRF guard, log redaction, path sandbox, safe decompression, regex validation.

All helpers in this module are pure and side-effect free except where noted
(``is_url_safe_for_public_fetch`` performs DNS resolution).
"""

from __future__ import annotations

import gzip
import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse, urlunparse

# ── Operator-only environment switches ────────────────────────────────────────
#
# These are read once, at import, from the process environment. They are
# deliberately NOT per-call arguments: an untrusted MCP/LLM client must not be
# able to flip them. Only the operator who launches the process can.


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# When True the SSRF guard skips the private/loopback/metadata range check.
# Off by default so a confused or hostile LLM cannot reach internal services.
ALLOW_PRIVATE_NETWORKS: bool = _env_bool("ANANSI_ALLOW_PRIVATE_NETWORKS")

# When True all anti-bot evasion behaviour is disabled (stealth-JS injection,
# Cloudflare-challenge waiting, curl-cffi TLS impersonation).
DISABLE_ANTIBOT: bool = _env_bool("ANANSI_DISABLE_ANTIBOT")

# ── SSRF guard ────────────────────────────────────────────────────────────────

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


class UnsafeURLError(ValueError):
    """Raised when a URL targets a network range the caller is not allowed to reach."""


def _is_private_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # Explicit cloud-metadata IPs — link_local covers 169.254.169.254 but be paranoid.
        or str(ip) in {"169.254.169.254", "fd00:ec2::254"}
    )


def is_url_safe_for_public_fetch(url: str, *, allow_private: bool = False) -> None:
    """Validate that *url* points to a public, http(s) destination.

    Raises ``UnsafeURLError`` if the scheme is not http/https or if DNS resolves
    the host to a loopback, private, link-local, multicast, reserved, or
    unspecified address. When *allow_private* is True the network-range check
    is skipped (the scheme check still applies).
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise UnsafeURLError(f"Could not parse URL: {url!r}") from exc
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(
            f"URL scheme {parsed.scheme!r} not allowed; only http and https are permitted"
        )
    if allow_private:
        return
    host = parsed.hostname
    if not host:
        raise UnsafeURLError(f"URL has no hostname: {url!r}")
    # Fast path: literal IP in the URL.
    try:
        ipaddress.ip_address(host)
        if _is_private_address(host):
            raise UnsafeURLError(f"URL host {host!r} is in a non-public address range")
        return
    except ValueError:
        pass
    # Hostname — resolve and reject if any A/AAAA result is private.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise UnsafeURLError(f"DNS resolution failed for {host!r}: {exc}") from exc
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        if _is_private_address(ip_str):
            raise UnsafeURLError(
                f"URL host {host!r} resolves to non-public address {ip_str}"
            )


# ── Log redaction ─────────────────────────────────────────────────────────────

def redact_userinfo(url: str) -> str:
    """Replace any ``user[:password]@`` in *url* with ``***@`` for safe logging."""
    try:
        parsed = urlparse(url)
    except Exception:
        return url
    if not parsed.username and not parsed.password:
        return url
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"***@{host}" if host else "***@"
    return urlunparse(parsed._replace(netloc=netloc))


# ── Path sandbox ──────────────────────────────────────────────────────────────

class PathOutsideSandboxError(ValueError):
    """Raised when a path resolves outside its permitted directory."""


def confine_to_dir(path: str | Path, root: Path) -> Path:
    """Resolve *path* and confirm it lives under *root*. Returns the resolved path.

    Raises ``PathOutsideSandboxError`` if the resolved path escapes *root*.
    *root* is created (parents included) if it does not exist.
    """
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PathOutsideSandboxError(
            f"Path {str(path)!r} resolves to {resolved}, which is outside {root}"
        ) from exc
    return resolved


# ── Safe gzip decompression ───────────────────────────────────────────────────

class DecompressionTooLargeError(ValueError):
    """Raised when gzip output would exceed the configured maximum size."""


def safe_gzip_decompress(data: bytes, *, max_output_bytes: int) -> bytes:
    """Decompress gzip *data*, aborting once the cumulative output exceeds the cap.

    Uses streaming reads in fixed chunks rather than ``gzip.decompress`` so a
    decompression bomb cannot allocate gigabytes before the size check fires.
    """
    import io
    chunk = 65_536
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        while True:
            block = gz.read(chunk)
            if not block:
                break
            out.extend(block)
            if len(out) > max_output_bytes:
                raise DecompressionTooLargeError(
                    f"gzip output exceeded {max_output_bytes} bytes"
                )
    return bytes(out)


# ── Regex validation (cheap ReDoS heuristic) ──────────────────────────────────

class UnsafeRegexError(ValueError):
    """Raised when a user-supplied regex is too complex or syntactically invalid."""


_MAX_REGEX_LENGTH = 1_000
# Patterns with nested unbounded quantifiers commonly cause catastrophic backtracking.
_REDOS_HEURISTIC = re.compile(
    r"""
    \([^)]*[+*][^)]*\)[+*]    # e.g. (a+)+ or (a*)*
    | \([^|)]*\|[^|)]*\)[+*]  # alternation under quantifier, e.g. (a|aa)+
    """,
    re.VERBOSE,
)


def validate_regex(pattern: str) -> re.Pattern[str]:
    """Compile *pattern* and reject obviously-pathological constructs.

    This is a cheap heuristic — it cannot prove a regex is safe. It rejects
    patterns longer than ``_MAX_REGEX_LENGTH`` and patterns containing nested
    unbounded quantifiers (the classic ReDoS shape). For stronger guarantees a
    caller should use ``regex.match(..., timeout=...)`` or the ``google-re2``
    library.
    """
    if len(pattern) > _MAX_REGEX_LENGTH:
        raise UnsafeRegexError(
            f"Regex length {len(pattern)} exceeds {_MAX_REGEX_LENGTH}"
        )
    if _REDOS_HEURISTIC.search(pattern):
        raise UnsafeRegexError(
            "Regex contains nested unbounded quantifiers (ReDoS risk); "
            "rewrite using atomic groups or anchored alternatives"
        )
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise UnsafeRegexError(f"Invalid regex {pattern!r}: {exc}") from exc


# ── Registrable-domain helper for credential scoping ──────────────────────────

def same_registrable_domain(host_a: str, host_b: str) -> bool:
    """Cheap heuristic — True if the two hosts share their last two labels.

    Does not use the public-suffix list, so multi-part TLDs (``co.uk``) are
    treated conservatively (a host on ``example.co.uk`` matches ``foo.co.uk``).
    Acceptable for credential-scoping defaults, where false-positive matches
    fail safe (creds withheld) rather than open.
    """
    a = host_a.lower().rstrip(".")
    b = host_b.lower().rstrip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    a_labels = a.split(".")
    b_labels = b.split(".")
    if len(a_labels) < 2 or len(b_labels) < 2:
        return False
    return a_labels[-2:] == b_labels[-2:]


# ── Proxy URL validation ──────────────────────────────────────────────────────

_ALLOWED_PROXY_SCHEMES: frozenset[str] = frozenset({"http", "https", "socks5", "socks5h"})


def validate_proxy_url(proxy: str, *, allow_private: bool = False) -> None:
    """Reject proxy URLs with unsupported schemes or non-public hosts.

    Raises ``UnsafeURLError`` on rejection. Skips the network-range check when
    *allow_private* is True (e.g. operator legitimately routes through an
    internal proxy and accepts the risk).
    """
    try:
        parsed = urlparse(proxy)
    except Exception as exc:
        raise UnsafeURLError(f"Could not parse proxy URL") from exc
    if parsed.scheme.lower() not in _ALLOWED_PROXY_SCHEMES:
        raise UnsafeURLError(
            f"proxy scheme {parsed.scheme!r} not allowed; permitted: "
            f"{sorted(_ALLOWED_PROXY_SCHEMES)}"
        )
    if allow_private:
        return
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("proxy URL has no hostname")
    try:
        ipaddress.ip_address(host)
        if _is_private_address(host):
            raise UnsafeURLError(f"proxy host is in a non-public address range")
        return
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise UnsafeURLError(f"DNS resolution failed for proxy host") from exc
    for info in infos:
        ip_str = info[4][0]
        if _is_private_address(ip_str):
            raise UnsafeURLError(f"proxy host resolves to non-public address {ip_str}")


# ── CSV cell escaping (formula injection) ─────────────────────────────────────

_CSV_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")


def escape_csv_cell(value: object) -> object:
    """Defang spreadsheet-formula prefixes in a CSV cell.

    Excel, Google Sheets, and LibreOffice Calc all interpret cells whose first
    character is ``=``, ``+``, ``-``, ``@``, ``\\t``, or ``\\r`` as formulas.
    Prepending a tab character keeps the cell text-readable for analysts while
    suppressing formula evaluation. Non-string values are returned unchanged.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "\t" + value
    return value


# ── Integer-argument clamping ─────────────────────────────────────────────────

class OutOfRangeError(ValueError):
    """Raised when an integer argument is outside its caller-permitted range."""


def clamp_int(value: int | None, *, name: str, minimum: int, maximum: int) -> int | None:
    """Return *value* if it is in ``[minimum, maximum]``; otherwise raise.

    ``None`` is passed through unchanged so callers can use it as a "no limit"
    sentinel where appropriate.
    """
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise OutOfRangeError(f"{name} must be an integer, got {type(value).__name__}")
    if value < minimum or value > maximum:
        raise OutOfRangeError(
            f"{name}={value} outside permitted range [{minimum}, {maximum}]"
        )
    return value


# ── Playwright selector validation ────────────────────────────────────────────

_FORBIDDEN_SELECTOR_PREFIXES: tuple[str, ...] = (
    "xpath=", "text=", "id=", "css=", "nth=", "role=", "data-testid=", "internal:",
)


def validate_browser_selector(selector: object) -> str:
    """Reject Playwright selector strings that opt into non-CSS engines.

    Playwright accepts engine prefixes (``xpath=//*``, ``text=Foo``) and chained
    selectors via ``>>``. Allowing those broadens what an untrusted caller can
    reach in the DOM well beyond what CSS expresses. This validator rejects any
    such selector and requires plain CSS only.
    """
    if not isinstance(selector, str) or not selector:
        raise ValueError(f"selector must be a non-empty string, got {type(selector).__name__}")
    lowered = selector.lower().lstrip()
    for prefix in _FORBIDDEN_SELECTOR_PREFIXES:
        if lowered.startswith(prefix):
            raise ValueError(
                f"selector prefix {prefix!r} not permitted; use plain CSS"
            )
    if ">>" in selector:
        raise ValueError(
            "chained selectors ('>>') not permitted; use a single CSS selector"
        )
    return selector


# ── Safe redirect resolution ──────────────────────────────────────────────────

class TooManyRedirectsError(Exception):
    """Raised when a redirect chain exceeds the configured cap."""


_DEFAULT_MAX_REDIRECTS = 5


def assert_redirect_safe(location_url: str, *, allow_private: bool) -> None:
    """Re-run the SSRF guard against a redirect target.

    Thin wrapper kept here so callers in fetcher code do not have to import
    ``is_url_safe_for_public_fetch`` themselves; reads more naturally at the
    call site (``assert_redirect_safe(loc, allow_private=...)``).
    """
    is_url_safe_for_public_fetch(location_url, allow_private=allow_private)
