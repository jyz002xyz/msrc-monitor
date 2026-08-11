#!/usr/bin/env python3
"""fetch_stateag.py — read US state Attorney General breach-notification registries.

WHY THESE, AND WHY THEY CAME BEFORE A PRESS LAYER
-------------------------------------------------
These are filings an organisation made to a state regulator because the law required it. The
organisation is named by the filer, the numbers are the filer's own, and the record is a public
one. That is the same shape as the SEC layer: the subject decides, we do not.

A press-derived layer was surveyed first and measured worse on every axis that matters here
(2026-08-10, samples in the survey): the organisation could be pulled out of a headline
mechanically only ~24% of the time AND the failures were silent (`Hackers breach TrueConf` ->
"Hackers"); a figure for the scale of the breach was present in 13% of headlines; and every
press source surveyed was all-rights-reserved, several with terms that name the exact activity
("create ... an index", "create or compile ... a collection, compilation, database"). Here the
organisation, the date, and — in Washington — the number affected and the categories of data
are already separate fields, and the terms are public-record terms.

TERMS, AS PUBLISHED (checked 2026-08-10, not assumed)
-----------------------------------------------------
- California, oag.ca.gov/conditions, OWNERSHIP: "Considered in the public domain. It may be
  distributed or copied as permitted by law." The same footing as the SEC layer's source.
- Washington: no conditions-of-use or copyright page was located. atg.wa.gov's privacy notice
  frames site information as "a public record that may be subject to inspection and copying by
  members of the public" under the Public Disclosure Law (RCW 42.17). Recorded as what was
  found, not as an established licence.

ACCESS (measured 2026-08-10)
----------------------------
- Neither site requires a declared User-Agent, and neither needs a browser: both are served as
  plain HTML/CSV. A descriptive User-Agent is sent anyway. It carries a repository URL and no
  contact address, so unlike SEC_USER_AGENT it does not have to be held as a secret.
- California publishes its own CSV export of the whole list (~5,200 rows, one request). The
  rows come from that: it is the publisher's own artifact. Its three columns carry no link,
  though, so the first few pages of the HTML list are read as well, purely to pick up each
  row's link to the notification document the organisation submitted. Without that the
  California rows would have nothing behind them while every Washington row carries the
  filer's own PDF.
- Washington has no export. Its HTML table is paginated with `?page=N`, sorted by Date Reported
  descending, and one page of 50 rows spans roughly three months at the observed rate
  (~0.5 filings/day). A daily run therefore never needs more than the first page; `max_pages`
  exists so a backfill can ask for more deliberately.

WHAT THESE CANNOT SEE
---------------------
Each registry holds only breaches that affected residents of that state, so neither is a
national record and the two overlap. Nothing here is added up across jurisdictions, for the
same reason the SEC layer publishes no totals. See incidents/README.md.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import html
import io
import re
import time
import urllib.error
import urllib.parse
import urllib.request

CA_EXPORT_URL = "https://oag.ca.gov/privacy/databreach/list-export"
CA_LIST_URL = "https://oag.ca.gov/privacy/databreach/list"
WA_LIST_URL = "https://www.atg.wa.gov/data-breach-notifications"

USER_AGENT = ("msrc-monitor incidents collector "
              "(+https://github.com/jyz002xyz/msrc-monitor)")

# Washington's rows are sorted by Date Reported descending. Daily runs read one page; a
# backfill raises this. The cap is a backstop against an unbounded loop, not a coverage choice.
WA_MAX_PAGES = 40
_MIN_INTERVAL_S = 1.0           # deliberately gentle: these are small state web servers
_last_request_at = 0.0


class FetchError(RuntimeError):
    """A fetch that must halt the run rather than produce a partial record."""


def _throttle() -> None:
    global _last_request_at
    wait = _MIN_INTERVAL_S - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def _get(url: str, *, timeout: int = 60, retries: int = 3) -> str:
    last: Exception | None = None
    for attempt in range(retries):
        _throttle()
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,text/csv,*/*",
            "Accept-Encoding": "gzip, deflate",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            last = e
            if 400 <= e.code < 500:
                raise FetchError(f"HTTP {e.code} from {url}") from e
        except Exception as e:                       # network / timeout / decode
            last = e
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    raise FetchError(f"fetch failed after {retries} attempts: {url} ({last})")


def _mdy(value: str) -> str | None:
    """'08/07/2026' -> '2026-08-07'. Returns None for blank or unparseable input.

    The registries print US month/day/year. Storing that string as-is would sort wrongly and
    read ambiguously next to the ISO dates the rest of this section uses.
    """
    v = (value or "").strip()
    if not v:
        return None
    try:
        return dt.datetime.strptime(v, "%m/%d/%Y").date().isoformat()
    except ValueError:
        return None


def _dates(value: str) -> list[str]:
    """'04/21/2026, 04/29/2026' -> ['2026-04-21', '2026-04-29'].

    A filing may name several breach dates, or none ("if known" is part of California's own
    column heading). An unparseable fragment is dropped rather than guessed at.
    """
    out = [_mdy(p) for p in re.split(r"[,;]", value or "")]
    return [d for d in out if d]


def _slug(name: str) -> str:
    """Normalise an organisation name for use inside a key. Display always uses the original."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")


# ---------------------------------------------------------------- California

def parse_ca(text: str, *, since: str | None = None) -> tuple[list[dict], dict]:
    """Parse California's CSV export.

    Header, as published: "Organization Name","Date(s) of Breach  (if known)","Reported Date".
    Columns are located by name, not by position, so a reordered export fails loudly in the
    integrity gate instead of silently swapping two fields.

    California publishes no per-filing identifier, and the CSV carries no link (the HTML list
    does — see parse_ca_links), so the key has to be composed: jurisdiction + reported date + organisation + the breach dates. Two
    filings by one organisation reported on the same day for the same breach dates therefore
    collapse into one.

    Measured on the full export (5,242 rows, 2026-08-10): 10 keys collided, covering 12 rows
    (0.23%), and in EVERY case the colliding rows were identical in all three published fields
    — they are the export's own duplicate rows, so collapsing them discards nothing that the
    source distinguishes. The limitation that remains is hypothetical rather than observed: a
    genuinely separate second filing sharing all three values would be indistinguishable here.
    """
    rdr = csv.DictReader(io.StringIO(text))
    field = {re.sub(r"\s+", " ", (f or "")).strip().lower(): f for f in (rdr.fieldnames or [])}

    def col(*wanted: str) -> str:
        for w in wanted:
            if w in field:
                return field[w]
        raise FetchError(
            f"California export is missing an expected column (looked for {wanted!r}; "
            f"found {list(field)!r}). The export format changed — halting rather than "
            f"recording rows with the wrong fields.")

    c_org = col("organization name")
    c_breach = col("date(s) of breach (if known)", "date(s) of breach")
    c_reported = col("reported date")

    rows: list[dict] = []
    seen_rows = 0
    for r in rdr:
        seen_rows += 1
        org = (r.get(c_org) or "").strip()
        reported = _mdy(r.get(c_reported) or "")
        if not org or not reported:
            continue
        if since and reported < since:
            continue
        breach = _dates(r.get(c_breach) or "")
        rows.append({
            "jurisdiction": "CA",
            "organization": org,
            "reported_date": reported,
            "breach_dates": breach,
            # California's list carries neither of these. Recorded as absent, not as zero.
            "affected": None,
            "data_types": None,
            "notice_url": None,
            "source_url": CA_LIST_URL,
            "key": f"CA:{reported}:{_slug(org)}:{'|'.join(breach)}",
        })
    stats = {"ca_rows_in_export": seen_rows, "ca_rows_kept": len(rows)}
    return rows, stats


_CA_REPORT_HREF = re.compile(r'href="([^"]*/databreach/reports/[^"]+)"')


def parse_ca_links(page_html: str) -> dict[tuple[str, str], str]:
    """(organisation, reported date) -> the state's record of that filing.

    California's CSV export carries three columns and no link, but the HTML list links every
    row to a page holding the notification document the organisation itself submitted. That
    link is the whole reason to read the HTML at all: without it the California rows have
    nothing behind them, while the Washington rows each carry the filer's own PDF.

    Matching is on organisation + reported date because the CSV and the HTML are two renderings
    of the same table; there is no shared id to join on. A row that does not match simply gets
    no link, which is the honest outcome — a wrong link would put another organisation's
    document under this one's name.
    """
    out: dict[tuple[str, str], str] = {}
    for tr in _TR.findall(page_html):
        cells = _TD.findall(tr)
        if len(cells) < 3:
            continue
        org = _text(cells[0])
        reported = _mdy(_text(cells[2]))
        m = _CA_REPORT_HREF.search(tr)
        if org and reported and m:
            out[(org, reported)] = urllib.parse.urljoin(CA_LIST_URL, html.unescape(m.group(1)))
    return out


# The link map has to reach at least as far back as the collection window, or the oldest rows
# in the window are recorded with no link and, because the record is append-only, stay that way.
# Four pages is 200 rows, about 100 days at the observed ~2.0 filings/day, against a 90-day
# window. Measured at three pages: 133 of 135 rows matched — the two misses were the two oldest.
CA_LINK_PAGES = 4


def fetch_ca_links(*, pages: int = CA_LINK_PAGES) -> tuple[dict[tuple[str, str], str], dict]:
    """Link map for the newest `pages` pages of the list, newest first."""
    links: dict[tuple[str, str], str] = {}
    read = 0
    for page in range(max(pages, 1)):
        url = CA_LIST_URL if page == 0 else f"{CA_LIST_URL}?{urllib.parse.urlencode({'page': page})}"
        got = parse_ca_links(_get(url))
        read += 1
        if not got:
            break
        links.update(got)
    return links, {"ca_link_pages_read": read, "ca_links_found": len(links)}


def fetch_ca(*, since: str | None = None, link_pages: int = CA_LINK_PAGES) -> tuple[list[dict], dict]:
    rows, stats = parse_ca(_get(CA_EXPORT_URL), since=since)
    links, lstats = fetch_ca_links(pages=link_pages)
    stats.update(lstats)
    matched = 0
    for r in rows:
        url = links.get((r["organization"], r["reported_date"]))
        if url:
            r["notice_url"] = url
            matched += 1
    stats["ca_rows_with_notice"] = matched
    return rows, stats


# ---------------------------------------------------------------- Washington

_TR = re.compile(r"(?s)<tr[^>]*>(.*?)</tr>")
_TD = re.compile(r"(?s)<td[^>]*>(.*?)</td>")
_TIME = re.compile(r'<time[^>]+datetime="(\d{4}-\d{2}-\d{2})')
_HREF = re.compile(r'<a[^>]+href="([^"]+)"')


def _text(cell: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", cell))).strip()


def _cell_date(cell: str) -> str | None:
    """Prefer the machine-readable <time datetime>; fall back to the printed m/d/Y."""
    m = _TIME.search(cell)
    return m.group(1) if m else _mdy(_text(cell))


def parse_wa(page_html: str) -> tuple[list[dict], dict]:
    """Parse one page of Washington's table.

    Columns, as published: Date Reported | Organization Name | Date of Breach |
    Number of Washingtonians Affected | Information Compromised.

    Two things this source gives that no press feed did: the number affected as its own field,
    and a link on the organisation's name to the notification document the organisation itself
    filed. That link is the primary source, so it is kept as the row's identity: the document
    id (e.g. BreachA42014) is stable, which spares us composing a key out of the display name.
    """
    rows: list[dict] = []
    malformed = 0
    for tr in _TR.findall(page_html):
        cells = _TD.findall(tr)
        if len(cells) < 5:
            if cells:
                malformed += 1
            continue
        reported = _cell_date(cells[0])
        org = _text(cells[1])
        if not org or not reported:
            malformed += 1
            continue
        href = _HREF.search(cells[1])
        notice = href.group(1) if href else None
        breach = _cell_date(cells[2])
        affected_raw = _text(cells[3]).replace(",", "")
        affected = int(affected_raw) if affected_raw.isdigit() else None
        doc_id = None
        if notice:
            doc_id = re.sub(r"\.pdf$", "", notice.rsplit("/", 1)[-1], flags=re.I)
        rows.append({
            "jurisdiction": "WA",
            "organization": org,
            "reported_date": reported,
            "breach_dates": [breach] if breach else [],
            "affected": affected,
            # The state's own wording for the categories of data. Not reworded here.
            "data_types": _text(cells[4]) or None,
            "notice_url": notice,
            "source_url": WA_LIST_URL,
            "key": f"WA:{doc_id}" if doc_id
                   else f"WA:{reported}:{_slug(org)}:{breach or ''}",
        })
    return rows, {"wa_rows": len(rows), "wa_malformed_rows": malformed}


def fetch_wa(*, since: str | None = None, max_pages: int = 1) -> tuple[list[dict], dict]:
    """Read Washington page by page, newest first, stopping once the page predates `since`.

    Rows are sorted by Date Reported descending, so once a whole page lies before the window
    there is nothing older worth reading. Without `since` this reads exactly `max_pages`.

    PAGE BOUNDARIES ARE NOT EXACTLY DISJOINT (measured 2026-08-10)
    -------------------------------------------------------------
    Reading three pages returned 150 rows but only 149 distinct documents: `BreachA36331`
    (2026-01-23) was the last row of page 1 and the first row of page 2. The sort key is the
    reported date alone, so rows sharing a date can straddle a boundary between two requests.

    The duplicate itself is harmless — the store dedupes on the document id. What it means is
    that the same instability could SKIP a row instead of repeating one, so `wa_duplicate_keys`
    is reported rather than quietly discarded: a non-zero value on a backfill is the signal to
    re-run it (the merge is idempotent and append-only, so re-running only adds what was
    missed). The daily path is not exposed to this: it reads page 0 only, which has no boundary
    above it and spans about three months, and it re-reads that whole page every day.
    """
    if max_pages < 1 or max_pages > WA_MAX_PAGES:
        raise FetchError(f"max_pages must be 1..{WA_MAX_PAGES}, got {max_pages}")
    rows: list[dict] = []
    seen_keys: set[str] = set()
    stats = {"wa_rows": 0, "wa_malformed_rows": 0, "wa_pages_read": 0, "wa_duplicate_keys": 0}
    for page in range(max_pages):
        url = WA_LIST_URL if page == 0 else f"{WA_LIST_URL}?{urllib.parse.urlencode({'page': page})}"
        got, s = parse_wa(_get(url))
        stats["wa_pages_read"] += 1
        stats["wa_malformed_rows"] += s["wa_malformed_rows"]
        if not got:
            # An empty page past the first is the end of the table; an empty FIRST page means
            # the parse or the page broke, and that has to reach the integrity gate as zero.
            break
        for r in got:
            if r["key"] in seen_keys:
                stats["wa_duplicate_keys"] += 1
                continue
            seen_keys.add(r["key"])
            if not since or r["reported_date"] >= since:
                rows.append(r)
        stats["wa_rows"] += len(got)
        if since and all(r["reported_date"] < since for r in got):
            break
    return rows, stats


# ---------------------------------------------------------------- both

def fetch(*, since: str | None = None, wa_pages: int = 1) -> tuple[list[dict], dict]:
    """Both registries. Either one failing halts the run; a half-collected day is not recorded.

    Recovering from a missed day costs nothing here, which is why halting is affordable:
    California's export is the full list every time, and one Washington page reaches about
    three months back. Neither source has the press feeds' problem of a 2-4 day window that,
    once missed, is gone for good.
    """
    ca, ca_stats = fetch_ca(since=since)
    wa, wa_stats = fetch_wa(since=since, max_pages=wa_pages)
    stats = {**ca_stats, **wa_stats, "since": since}
    rows = sorted(ca + wa, key=lambda r: (r["reported_date"], r["jurisdiction"], r["key"]))
    stats["rows_total"] = len(rows)
    return rows, stats
