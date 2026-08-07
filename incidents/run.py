#!/usr/bin/env python3
"""run.py — daily: fetch SEC Item 1.05 filings, guard, append, render docs/incidents/.

Halts (non-zero exit, writes nothing) if the fetch looks degraded. The record is append-only,
so anything written from a bad fetch is permanent — the guard runs before the merge, not after.

Nothing is published or pushed here; the workflow opens a PR and merges it.

Usage:
    python -m incidents.run                       # yesterday..today
    python -m incidents.run --since 2026-05-09 --until 2026-08-07
    python -m incidents.run --render-only         # re-render from the stored record
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import fetch_sec, integrity, publish, records, store

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(__file__).resolve().parent / "data"
DISCLOSURES = DATA / "disclosures.json"
RECORDS = DATA / "records.json"
DOCS = ROOT / "docs" / "incidents"


def _today() -> dt.date:
    return dt.date.today()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="collect SEC Item 1.05 disclosures (facts only)")
    ap.add_argument("--since", help="YYYY-MM-DD (default: 2 days ago)")
    ap.add_argument("--until", help="YYYY-MM-DD (default: today)")
    ap.add_argument("--render-only", action="store_true",
                    help="re-render the site from the stored record; no network")
    ap.add_argument("--docs", default=str(DOCS), help="output directory")
    args = ap.parse_args(argv)

    recs = records.load(RECORDS)
    rerrs = records.validate(recs)
    if rerrs:
        print("[incidents] HALT: the curated records file does not validate:", file=sys.stderr)
        for e in rerrs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    st = store.load(DISCLOSURES)
    before = store.counts(st)

    if not args.render_only:
        today = _today()
        # A two-day window absorbs a missed run and timezone skew; duplicates are dropped by
        # adsh, so overlap costs nothing.
        since = args.since or (today - dt.timedelta(days=2)).isoformat()
        until = args.until or today.isoformat()
        try:
            filings, fstats = fetch_sec.fetch(since, until)
        except fetch_sec.FetchError as e:
            print(f"[incidents] HALT: {e}", file=sys.stderr)
            return 1

        st, added = store.merge(st, filings, seen_date=today.isoformat())
        after = store.counts(st)
        failures, gstats = integrity.evaluate(filings, fstats, before, after)
        if failures:
            print("[incidents] HALT: integrity gate failed — nothing written:", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print(f"[incidents] integrity stats: {json.dumps(gstats, ensure_ascii=False)}")
        for a in added:
            print(f"[incidents] NEW  {a['filing_date']}  {a['form']:6} {a['company']}  "
                  f"{a['adsh']}  (incident {a['key']})")
        if not added:
            print("[incidents] no new Item 1.05 filings in the window "
                  "(the ordinary case — these filings are rare)")
        store.save(DISCLOSURES, st)

    written = publish.build_site(st, recs, Path(args.docs))
    c = store.counts(st)
    rc = records.counts(recs)
    print(f"[incidents] record: {c['incidents']} incident(s) / {c['statements']} statement(s) "
          f"/ {c['companies']} company(ies); curated: {rc['records']} record(s)")
    print(f"[incidents] wrote {len(written)} page(s) into {args.docs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
