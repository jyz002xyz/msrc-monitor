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
"""
from __future__ import annotations

import os

REQUIRED_FIELDS = ("adsh", "cik", "filing_date", "form")


def _envi(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


# A single day should never legitimately produce a flood; a large number means the window or
# the query is wrong. Well above the observed rate (~9 incidents / 90 days).
MAX_NEW_PER_RUN = _envi("INCIDENTS_MAX_NEW_PER_RUN", 40)


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
