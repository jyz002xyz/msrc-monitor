#!/usr/bin/env python3
"""integrity.py — pre-write guard for the disclosure record (fail-halt).

Same reasoning as kev/integrity.py: the store is append-only, so anything written from a
DEGRADED fetch is permanent. Check the fetch looks whole BEFORE merging; on failure the run
halts with a non-zero exit and writes nothing, leaving the previous record intact so the next
run can recover.

Why the checks are shaped this way: Item 1.05 is genuinely low-volume (nine incidents across
fourteen filings in a 90-day window, measured 2026-08-07). "Zero filings today" is therefore
the NORMAL case and must not be treated as a failure — an emptiness check would fire almost
every day and train everyone to ignore it. What we can check is that the response was
structurally sound and that the record never shrinks.

TWO GATES, BECAUSE EMPTINESS MEANS OPPOSITE THINGS
--------------------------------------------------
`evaluate()` guards the SEC layer, where a query legitimately returns nothing.

`evaluate_registry()` guards the state AG layer, where it does not. Those collectors do not
run a dated query — they read California's full CSV export and Washington's first table page,
both of which always carry rows. Zero rows RETURNED there means the export, the page or the
parser broke, so it is a failure. Zero rows NEW is still perfectly normal (a weekend), and is
still not checked. Keeping both gates in one file is deliberate: the difference between them
is the interesting part, and splitting them would hide it.
"""
from __future__ import annotations

import os

REQUIRED_FIELDS = ("adsh", "cik", "filing_date", "form")
REGISTRY_REQUIRED_FIELDS = ("key", "jurisdiction", "organization", "reported_date")


def _envi(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


# A single day should never legitimately produce a flood; a large number means the window or
# the query is wrong. Well above the observed rate (~9 incidents / 90 days).
MAX_NEW_PER_RUN = _envi("INCIDENTS_MAX_NEW_PER_RUN", 40)

# Registry equivalents. Observed 2026-08-10: California ~2.0 filings/day, Washington ~0.49.
# A daily run seeing more than this many NEW rows means the window widened by accident (or a
# backfill is running, which is what the override is for).
REGISTRY_MAX_NEW_PER_RUN = _envi("INCIDENTS_REGISTRY_MAX_NEW_PER_RUN", 200)

# Floors for rows RETURNED by each source, not rows new. California's export carried ~5,200
# rows and Washington's first page 50 when measured; these floors sit far below both, so they
# fire on a broken export/page/parser rather than on a quiet week. They are compared only
# against an unfiltered read — a `--since` window legitimately keeps fewer rows, so the floor
# is applied to what the SOURCE returned.
REGISTRY_MIN_CA_ROWS = _envi("INCIDENTS_REGISTRY_MIN_CA_ROWS", 500)
REGISTRY_MIN_WA_ROWS = _envi("INCIDENTS_REGISTRY_MIN_WA_ROWS", 10)


def evaluate(filings: list[dict] | None, stats: dict | None, prev_counts: dict | None,
             new_counts: dict | None, *, max_new: int = MAX_NEW_PER_RUN) -> tuple[list[str], dict]:
    """Return (failures, stats). Empty failures == safe to write.

    - filings: parsed filings from this run (an empty list is fine and expected).
    - stats: fetch statistics (must be present — its absence means the fetch never ran).
    - prev_counts / new_counts: store.counts() before and after the merge.
    """
    failures: list[str] = []
    out: dict = dict(stats or {})

    if filings is None or stats is None:
        failures.append("fetch did not complete (no result to evaluate)")
        return failures, out

    # Structural soundness of what we are about to record. A schema change upstream shows up
    # here rather than as silently blank columns on the published page.
    for f in filings:
        missing = [k for k in REQUIRED_FIELDS if not str(f.get(k) or "").strip()]
        if missing:
            failures.append(f"filing {f.get('adsh') or '(no adsh)'} missing {', '.join(missing)}")
        if "1.05" not in (f.get("items") or []):
            failures.append(f"filing {f.get('adsh')} kept without item 1.05 in its items array")

    # The page-limit condition is caught in fetch(); if a caller bypassed it, catch it here too.
    if stats.get("hits_returned", 0) >= stats.get("page_size", 10 ** 9):
        failures.append(
            f"result reached the page limit ({stats.get('hits_returned')}) — possibly truncated")

    if prev_counts and new_counts:
        for k in ("incidents", "statements"):
            if new_counts[k] < prev_counts[k]:
                failures.append(
                    f"{k} shrank {prev_counts[k]} -> {new_counts[k]}; the record is append-only")
        added = new_counts["statements"] - prev_counts["statements"]
        out["new_statements"] = added
        if added > max_new:
            failures.append(
                f"{added} new statements in one run exceeds {max_new} — check the window/query "
                f"before recording (set INCIDENTS_MAX_NEW_PER_RUN to override deliberately)")

    return failures, out


def evaluate_registry(rows: list[dict] | None, stats: dict | None, prev_counts: dict | None,
                      new_counts: dict | None, *,
                      max_new: int = REGISTRY_MAX_NEW_PER_RUN,
                      min_ca: int = REGISTRY_MIN_CA_ROWS,
                      min_wa: int = REGISTRY_MIN_WA_ROWS) -> tuple[list[str], dict]:
    """Fail-halt gate for the state AG layer. Empty failures == safe to write.

    - rows: parsed rows from this run. Unlike the SEC gate, an empty list is NOT automatically
      fine — see the emptiness floors below.
    - stats: fetch statistics (its absence means the fetch never ran).
    - prev_counts / new_counts: stateag_store.counts() before and after the merge.
    """
    failures: list[str] = []
    out: dict = dict(stats or {})

    if rows is None or stats is None:
        failures.append("registry fetch did not complete (no result to evaluate)")
        return failures, out

    # Emptiness IS a failure here. Both sources return rows unconditionally, so a zero means
    # the export/page/parser broke — the opposite of the SEC gate's premise.
    ca_seen = stats.get("ca_rows_in_export")
    if ca_seen is not None and ca_seen < min_ca:
        failures.append(
            f"California export returned {ca_seen} rows, below the floor of {min_ca} — the "
            f"export or the parser is broken (the full list is thousands of rows)")
    wa_seen = stats.get("wa_rows")
    if wa_seen is not None and wa_seen < min_wa:
        failures.append(
            f"Washington returned {wa_seen} rows, below the floor of {min_wa} — the page or "
            f"the parser is broken (one page carries 50 rows)")

    # A page whose <tr> count and <td> count disagree with the published table means the
    # columns moved. Recording rows under moved columns would put one state's figures in
    # another field, so any malformed row halts rather than being skipped quietly.
    malformed = stats.get("wa_malformed_rows") or 0
    if malformed:
        failures.append(
            f"{malformed} Washington row(s) did not match the expected 5-column layout — the "
            f"table structure changed; halting rather than recording mismatched fields")

    # Structural soundness of what is about to be recorded.
    for r in rows:
        missing = [k for k in REGISTRY_REQUIRED_FIELDS if not str(r.get(k) or "").strip()]
        if missing:
            failures.append(
                f"row {r.get('key') or '(no key)'} missing {', '.join(missing)}")
        if r.get("jurisdiction") not in ("CA", "WA"):
            failures.append(
                f"row {r.get('key')} has jurisdiction {r.get('jurisdiction')!r}, which this "
                f"layer does not collect")

    if prev_counts and new_counts:
        for k in ("filings",):
            if new_counts[k] < prev_counts[k]:
                failures.append(
                    f"{k} shrank {prev_counts[k]} -> {new_counts[k]}; the record is append-only")
        added = new_counts["filings"] - prev_counts["filings"]
        out["new_filings"] = added
        if added > max_new:
            failures.append(
                f"{added} new registry filings in one run exceeds {max_new} — check the window "
                f"before recording (set INCIDENTS_REGISTRY_MAX_NEW_PER_RUN to override "
                f"deliberately, as a backfill does)")

    return failures, out
