# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

Report vulnerabilities privately via GitHub Security Advisories:

1. Go to the repository's **Security** tab.
2. Click **"Report a vulnerability"** to open a private advisory.
3. Include a description, affected version/commit, reproduction steps, and impact.

We aim to acknowledge reports promptly and will coordinate a fix and disclosure
timeline with the reporter.

## Threat model (summary)

Anansi ships an MCP server that exposes fetch / extract / crawl / screenshot /
export tools to any connected LLM.

**Trusted:** the operator's machine and filesystem; the Python interpreter and
installed packages; the local SQLite databases under `~/.anansi/`.

**Untrusted:**

- The **MCP client / LLM** — treated as a fully attacker-controlled source of
  URLs, regexes, header/cookie dicts, proxy URLs, file paths, browser selectors,
  and tool arguments.
- **Remote HTTP responses**, redirect targets, HTML/JSON bodies, `robots.txt`,
  and `sitemap.xml` (including recursive child sitemaps).
- **Proxies** passed to the fetcher.

Out of scope: DoS against scraped sites, anti-bot ethics, OS-level isolation of
the host (see deployment guidance below), and anything requiring shell access to
the operator's machine before the attack begins.

## Hardening status

All findings from the original whole-codebase audit have been remediated, and a
follow-up review closed two additional MCP entry-point gaps.

| Area | Status | Where enforced |
|---|---|---|
| SSRF (all fetch/crawl/screenshot tools + redirects + sitemap children) | Fixed | `security.is_url_safe_for_public_fetch`; per-hop revalidation in `fetchers/http.py` |
| Arbitrary file write via `export_crawl` / `screenshot_url` paths | Fixed | `security.confine_to_dir` → `~/.anansi/exports/` |
| Cross-origin credential leakage in crawls | Fixed | `Crawler.credential_scope_host`; `crawl_site` registrable-domain default |
| ReDoS via client-supplied regex / `text` selectors | Fixed | `security.validate_regex` (heuristic + length cap) |
| Gzip-bomb on sitemap decompression | Fixed | `security.safe_gzip_decompress` (streamed, 50 MB cap) |
| Browser TLS verification | Fixed | `BrowserFetcher(insecure=False)` default |
| Proxy credentials in logs | Fixed | `security.redact_userinfo` at all proxy log sites |
| HTTP response / page-cache size caps | Fixed | `fetchers/http.py` 50 MB cap; cache entry+byte caps |
| robots `Crawl-delay` clamp | Fixed | `crawler.py` 300 s clamp |
| Playwright action / selector allowlist | Fixed | `_validate_actions`, `security.validate_browser_selector` |
| **R2: `screenshot_url`** missing SSRF / proxy / selector / path validation | Fixed | `screenshot_url` now mirrors `fetch_url`; `BrowserFetcher.screenshot` confines paths |
| **R2: `train_selector`** missing input validation | Fixed | `selector_type` allowlist; `text` selector ReDoS-checked; CSS selector validated |
| LLM-settable `allow_private_networks` | Removed | now operator-only `ANANSI_ALLOW_PRIVATE_NETWORKS` env var |
| Anti-bot evasion kill-switch | Added | operator-only `ANANSI_DISABLE_ANTIBOT` env var |

## Operator controls

These are read once at process start from the environment and **cannot** be set
by the MCP/LLM client:

- `ANANSI_ALLOW_PRIVATE_NETWORKS=1` — allow fetches/crawls to reach
  loopback / RFC1918 / link-local / cloud-metadata addresses. **Off by default.**
  Only enable on a trusted, isolated host where no untrusted LLM can drive the
  server.
- `ANANSI_DISABLE_ANTIBOT=1` — disable stealth-JS injection, the Cloudflare
  challenge wait, and curl-cffi TLS impersonation (the HTTP fetcher warns and
  falls back to a plain request).

## Deployment guidance

- **Do not run the MCP server as root.** Run as a dedicated unprivileged user.
- Prefer running inside a container with a read-only root filesystem and
  `--cap-drop=ALL`; bound CPU/memory (`--cpus`, `--memory`) since the server is
  a long-lived service with no built-in CPU limiter.
- The bundled Chromium uses its own OS sandbox by default
  (`BrowserFetcher(sandbox=True)`); keep it enabled unless your container
  environment requires `--no-sandbox`, in which case ensure the container
  itself provides isolation.
- For organization-wide site allow/deny policy, enforce it at the
  **network-egress layer** (an outbound proxy or firewall in front of the host).
  This is more robust than an in-process allowlist and is inherited by every
  tool automatically.
- Consider a CI job running `pip-audit` (or `uv pip audit`) on every change to
  track dependency advisories; runtime dependencies are pinned with upper bounds
  in `pyproject.toml` to limit supply-chain blast radius.
