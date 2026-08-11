#!/usr/bin/env python3
"""run.py — daily: fetch the automatic layers, guard each, append, render docs/incidents/.

Two automatic sources, guarded separately because "no rows" means opposite things in them:

- SEC Form 8-K Item 1.05 (fetch_sec + integrity.evaluate). Zero filings is the ordinary day.
- California and Washington AG breach registries (fetch_stateag + integrity.evaluate_registry).
  Zero rows RETURNED is a failure there; zero rows NEW is still ordinary.

Halts (non-zero exit, writes nothing) if either fetch looks degraded. The records are
append-only, so anything written from a bad fetch is permanent — each guard runs before its
own merge, not after.

Halting the whole run on either source is affordable because a missed day costs nothing to
recover here: EDGAR takes --since, California's export is the whole list every time, and one
Washington page reaches about three months back. That is not a general property of daily
collection — it is a property of these three sources, and it is why they were chosen.

Nothing is published or pushed here; the workflow opens a PR and merges it.

Usage:
    python -m incidents.run                       # SEC: 2-day window; registries: 90 days
    python -m incidents.run --since 2026-05-09 --until 2026-08-07
    python -m incidents.run --registry-since 2024-01-01 --wa-pages 40   # deliberate backfill
    python -m incidents.run --render-only         # re-render from the stored records
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import (fetch_sec, fetch_stateag, filers, integrity, publish, records,
               stateag_store, store)

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"
DISCLOSURES = DATA / "disclosures.json"
RECORDS = DATA / "records.json"
REGISTRY = DATA / "state_ag.json"
DECISIONS = DATA / "filer_decisions.json"
QUEUE = DATA / "filer_pending.json"
DOCS = ROOT / "docs" / "incidents"

# How far back the registry layer reaches on an ordinary run. Both sources hand back far more
# than this for free, so this window is about keeping the published table proportionate, not
# about what can be fetched. A backfill widens it with --registry-since; coverage.since only
# ever widens, so a later narrow run cannot shrink what a backfill collected.
REGISTRY_DEFAULT_DAYS = 90


def _today() -> dt.date:
    return dt.date.today()


def _collect_sec(st: dict, args, today: dt.date) -> tuple[dict, int]:
    """Fetch, guard and merge the SEC layer. Returns (store, exit code)."""
    before = store.counts(st)
    # A two-day window absorbs a missed run and timezone skew; duplicates are dropped by
    # adsh, so overlap costs nothing.
    since = args.since or (today - dt.timedelta(days=2)).isoformat()
    until = args.until or today.isoformat()
    try:
        filings, fstats = fetch_sec.fetch(since, until)
    except fetch_sec.FetchError as e:
        print(f"[incidents] HALT: {e}", file=sys.stderr)
        return st, 1

    st, added = store.merge(st, filings, seen_date=today.isoformat())
    store.note_coverage(st, since)
    failures, gstats = integrity.evaluate(filings, fstats, before, store.counts(st))
    if failures:
        print("[incidents] HALT: integrity gate failed — nothing written:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return st, 1
    print(f"[incidents] integrity stats: {json.dumps(gstats, ensure_ascii=False)}")
    for a in added:
        print(f"[incidents] NEW  {a['filing_date']}  {a['form']:6} {a['company']}  "
              f"{a['adsh']}  (incident {a['key']})")
    if not added:
        print("[incidents] no new Item 1.05 filings in the window "
              "(the ordinary case — these filings are rare)")
    store.save(DISCLOSURES, st)
    return st, 0


def _collect_registry(reg: dict, decisions: dict, queue: dict, args,
                      today: dt.date) -> tuple[dict, dict, int]:
    """Fetch, guard, filter and merge the state AG layer. Returns (store, queue, exit code)."""
    before = stateag_store.counts(reg)
    since = args.registry_since
    if not since and args.backfill_notice_urls:
        # A backfill has to reach everything already recorded, or the oldest rows — the ones
        # that have been blank longest — are the ones it silently skips. The record knows how
        # far back it goes; ask it rather than making the operator work the date out.
        since = (reg.get("coverage") or {}).get("since")
    if not since:
        since = (today - dt.timedelta(days=REGISTRY_DEFAULT_DAYS)).isoformat()
    try:
        rows, rstats = fetch_stateag.fetch(since=since, wa_pages=args.wa_pages)
    except fetch_stateag.FetchError as e:
        print(f"[incidents] HALT: {e}", file=sys.stderr)
        return reg, queue, 1

    # Filter BEFORE the merge, not before the render. This repository is public, so a name
    # written into data/state_ag.json is published as surely as one written into the HTML —
    # withholding at render time would withhold nothing.
    rows, withheld = filers.split(rows, decisions)
    queue, newly = filers.update_queue(queue, withheld, decisions, seen_date=today.isoformat())
    queue = filers.resolved_organisations(queue, decisions)
    rstats["rows_withheld_pending_filer_check"] = len(withheld)
    rstats["filer_names_pending"] = len(queue.get("pending") or [])

    reg, added = stateag_store.merge(reg, rows, seen_date=today.isoformat())
    if args.backfill_notice_urls:
        n = stateag_store.fill_missing(reg, rows, "notice_url")
        print(f"[incidents] backfilled notice_url on {n} already-recorded row(s) "
              f"(blanks only; stored links untouched)")
    stateag_store.note_coverage(reg, since)
    failures, gstats = integrity.evaluate_registry(
        rows, rstats, before, stateag_store.counts(reg))
    if failures:
        print("[incidents] HALT: registry integrity gate failed — nothing written:",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return reg, queue, 1
    print(f"[incidents] registry integrity stats: {json.dumps(gstats, ensure_ascii=False)}")
    for a in added:
        aff = "" if a.get("affected") is None else f"  {a['affected']:,} affected"
        print(f"[incidents] NEW-REG  {a['reported_date']}  {a['jurisdiction']}  "
              f"{a['organization']}{aff}")
    if not added:
        print("[incidents] no new state AG filings in the window "
              "(ordinary — the sources publish on business days, with a lag)")
    # Printed only for names that are newly pending, so a name already waiting does not
    # re-open a notice every day. The name appears in the run log and the notice issue —
    # a decision prompt — and in neither the published page nor the permanent record.
    for r in newly:
        print(f"[incidents] PENDING-FILER  {r['jurisdiction']}  {r['reported_date']}  "
              f"{r['organization']}")
    if withheld:
        # 「保留中」と「個人と確定済み」は別物。決着済みの行を pending と呼ぶと、
        # キューが空でも件数が出続けて読み手が混乱する。
        waiting = len(queue.get("pending") or [])
        decided = len(withheld) - sum(
            1 for r in withheld
            if filers.name_hash((r.get("organization") or "").strip())
            in {p["hash"] for p in queue.get("pending", [])})
        parts = []
        if waiting:
            parts.append(f"{len(withheld) - decided} row(s) awaiting a filer decision "
                         f"({waiting} name(s))")
        if decided:
            parts.append(f"{decided} row(s) withheld permanently (filer decided to be an "
                         f"individual)")
        print("[incidents] " + "; ".join(parts))
    stateag_store.save(REGISTRY, reg)
    filers.save_queue(QUEUE, queue)
    return reg, queue, 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="collect disclosed cybersecurity incidents (facts and links only)")
    ap.add_argument("--since", help="SEC window start, YYYY-MM-DD (default: 2 days ago)")
    ap.add_argument("--until", help="SEC window end, YYYY-MM-DD (default: today)")
    ap.add_argument("--registry-since",
                    help=f"state AG window start, YYYY-MM-DD "
                         f"(default: {REGISTRY_DEFAULT_DAYS} days ago)")
    ap.add_argument("--backfill-notice-urls", action="store_true",
                    help="fill notice_url on already-recorded rows that have none. Only fills "
                         "blanks — a stored link is never replaced. Needed once, because the "
                         "California rows were collected from the CSV export before the "
                         "collector started reading the links off the state's HTML list.")
    ap.add_argument("--wa-pages", type=int, default=1,
                    help="Washington pages to read, newest first (default 1; one page spans "
                         "about three months). Raise only for a deliberate backfill.")
    ap.add_argument("--render-only", action="store_true",
                    help="re-render the site from the stored records; no network")
    ap.add_argument("--skip-sec", action="store_true",
                    help="do not collect the SEC layer this run (the stored record is still "
                         "rendered)")
    ap.add_argument("--skip-registry", action="store_true",
                    help="do not collect the state AG layer this run (the stored record is "
                         "still rendered)")
    ap.add_argument("--docs", default=str(DOCS), help="output directory")
    args = ap.parse_args(argv)

    recs = records.load(RECORDS)
    rerrs = records.validate(recs)
    if rerrs:
        print("[incidents] HALT: the curated records file does not validate:", file=sys.stderr)
        for e in rerrs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    decisions = filers.load_decisions(DECISIONS)
    derrs = filers.validate_decisions(decisions)
    if derrs:
        print("[incidents] HALT: the filer decisions file does not validate:", file=sys.stderr)
        for e in derrs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    st = store.load(DISCLOSURES)
    reg = stateag_store.load(REGISTRY)
    queue = filers.load_queue(QUEUE)

    if not args.render_only:
        today = _today()
        if not args.skip_sec:
            st, rc = _collect_sec(st, args, today)
            if rc:
                return rc
        if not args.skip_registry:
            reg, queue, rc = _collect_registry(reg, decisions, queue, args, today)
            if rc:
                return rc

    written = publish.build_site(st, recs, Path(args.docs), reg, queue)
    c = store.counts(st)
    g = stateag_store.counts(reg)
    rc_ = records.counts(recs)
    print(f"[incidents] record: {c['incidents']} incident(s) / {c['statements']} statement(s) "
          f"/ {c['companies']} company(ies); curated: {rc_['records']} record(s)")
    print(f"[incidents] registry: {g['filings']} filing(s) "
          f"(CA {g['ca']} / WA {g['wa']}) across {g['organizations']} organisation(s); "
          f"{len(queue.get('pending') or [])} filer name(s) pending a decision")
    print(f"[incidents] wrote {len(written)} page(s) into {args.docs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
