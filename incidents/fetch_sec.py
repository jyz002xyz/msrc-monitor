#!/usr/bin/env python3
"""fetch_sec.py — read SEC 8-K Item 1.05 filings from EDGAR full-text search.

WHAT THIS COLLECTS, AND WHY ONLY THIS
-------------------------------------
Item 1.05 ("Material Cybersecurity Incidents") is filed when the REGISTRANT ITSELF has
determined the incident is material. Taking only 1.05 is how "let the subject decide what
counts as big" is implemented: we do not select. Item 8.01 (Other Events) is deliberately
NOT collected — a company filing under 8.01 has decided the incident was not material, and
picking those up would put the materiality judgement back on us.

WHAT IT CANNOT SEE
------------------
Item 1.05 binds SEC registrants (US-listed companies). Private companies, government,
non-profits and most healthcare providers never appear here, and no non-US jurisdiction has
an equivalent per-incident machine-readable feed. See incidents/README.md.

ACCESS RULES (measured 2026-08-07, not assumed)
-----------------------------------------------
- A declared User-Agent is REQUIRED: without one efts.sec.gov returns HTTP 403.
- SEC's stated limit is 10 requests/second. One daily query is far inside it; the throttle
  below exists so a backfill loop cannot drift over the line.
- sec.gov content is public information and may be redistributed; SEC asks for appropriate
  citation as the source.

RECALL / DEDUPE (measured 2026-08-07)
-------------------------------------
Full-text search indexes each DOCUMENT inside a filing, so one filing can come back several
times (the 8-K plus its EX-99.1). Dedupe on `adsh` (the accession number) — the filing id.
Cross-checking `"Item 1.05"` against four other phrasings over a 90-day window found no
filing that the 1.05 query missed once results were keyed by `adsh`.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

FTS_URL = "https://efts.sec.gov/LATEST/search-index"
QUERY = '"Item 1.05"'
FORM = "8-K"
# EDGAR full-text search returns at most this many hits per request. A daily window is far
# below it; a backfill over a long window MUST page (see fetch(), which refuses to guess).
PAGE_SIZE = 100
_MIN_INTERVAL_S = 0.15          # < 10 req/s with margin
_last_request_at = 0.0


class FetchError(RuntimeError):
    """A fetch that must halt the run rather than produce a partial record."""


def user_agent() -> str:
    """The declared User-Agent. Required by SEC; no default is invented.

    Read from the environment so a contact address is never committed to this public repo.
    """
    ua = (os.environ.get("SEC_USER_AGENT") or "").strip()
    if not ua:
        raise FetchError(
            "SEC_USER_AGENT is not set. SEC requires a declared User-Agent with contact "
            "information (without one efts.sec.gov returns HTTP 403). Set it in the "
            "environment / repository secrets; do not hardcode a contact address here.")
    return ua


def _throttle() -> None:
    global _last_request_at
    wait = _MIN_INTERVAL_S - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def _get(url: str, *, timeout: int = 30, retries: int = 3) -> bytes:
    last: Exception | None = None
    for attempt in range(retries):
        _throttle()
        req = urllib.request.Request(url, headers={
            "User-Agent": user_agent(),
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    import gzip
                    raw = gzip.decompress(raw)
                return raw
        except urllib.error.HTTPError as e:
            last = e
            # 403 here almost always means the User-Agent was rejected. Do not retry-storm it.
            if e.code == 403:
                raise FetchError(
                    f"HTTP 403 from {url} — SEC rejected the request. Check SEC_USER_AGENT "
                    f"declares a contact address.") from e
            if 400 <= e.code < 500:
                raise FetchError(f"HTTP {e.code} from {url}") from e
        except Exception as e:                       # network / timeout / decode
            last = e
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    raise FetchError(f"fetch failed after {retries} attempts: {url} ({last})")


def _search_url(start: str, end: str, frm: int) -> str:
    q = urllib.parse.urlencode({
        "q": QUERY, "forms": FORM, "startdt": start, "enddt": end,
        "hits": PAGE_SIZE, "from": frm,
    })
    return f"{FTS_URL}?{q}"


def fetch_raw(start: str, end: str) -> dict:
    """One page of EDGAR full-text search results for [start, end] (YYYY-MM-DD)."""
    return json.loads(_get(_search_url(start, end, 0)))


def _filing_url(adsh: str, cik: str) -> str:
    """The filing's EDGAR index page. `adsh` is dashed (0001193125-26-282946)."""
    return (f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/"
            f"{adsh.replace('-', '')}/{adsh}-index.htm")


def _company_name(display: str) -> str:
    """'RIVER FINANCIAL CORP  (RVRF)  (CIK 0001641601)' -> 'RIVER FINANCIAL CORP'."""
    return (display or "").split("  (")[0].strip()


def parse(payload: dict) -> tuple[list[dict], dict]:
    """Turn a search payload into filings keyed by `adsh`, plus stats.

    Only hits whose structured `items` array actually contains 1.05 are kept: the full-text
    query matches any document mentioning the string, including exhibits of filings made under
    other items. The `items` array is the registrant's own declaration of what was filed.
    """
    hits = ((payload.get("hits") or {}).get("hits")) or []
    total = ((payload.get("hits") or {}).get("total") or {}).get("value")
    by_adsh: dict[str, dict] = {}
    documents = 0
    for h in hits:
        s = h.get("_source") or {}
        items = [str(i) for i in (s.get("items") or [])]
        if "1.05" not in items:
            continue
        adsh = s.get("adsh")
        ciks = s.get("ciks") or []
        if not adsh or not ciks:
            continue
        documents += 1
        # Several documents of one filing collapse onto the same adsh — that is the dedupe.
        by_adsh.setdefault(adsh, {
            "adsh": adsh,
            "cik": str(ciks[0]),
            "company": _company_name((s.get("display_names") or [""])[0]),
            "filing_date": s.get("file_date"),
            "report_date": s.get("period_ending"),
            "form": s.get("file_type"),
            "items": items,
            "url": _filing_url(adsh, str(ciks[0])),
        })
    stats = {
        "hits_returned": len(hits),
        "hits_total": total,
        "documents_with_1_05": documents,
        "filings_after_adsh_dedupe": len(by_adsh),
        "page_size": PAGE_SIZE,
    }
    return sorted(by_adsh.values(), key=lambda f: (f["filing_date"] or "", f["adsh"])), stats


def fetch(start: str, end: str) -> tuple[list[dict], dict]:
    """Filings with Item 1.05 filed in [start, end]. Halts rather than truncating silently.

    A window whose raw hit count reaches the page limit is refused: the caller would get a
    silently partial list. Daily windows never hit this; a backfill must page explicitly.
    """
    payload = fetch_raw(start, end)
    filings, stats = parse(payload)
    if stats["hits_returned"] >= PAGE_SIZE:
        raise FetchError(
            f"window {start}..{end} returned {stats['hits_returned']} hits, at the "
            f"{PAGE_SIZE}-hit page limit — the result would be silently truncated. "
            f"Narrow the window or add paging before trusting this range.")
    stats["window"] = f"{start}..{end}"
    return filings, stats
