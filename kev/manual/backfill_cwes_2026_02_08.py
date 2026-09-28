#!/usr/bin/env python3
"""backfill_cwes_2026_02_08.py — ONE-OFF, run by hand: add `cwes` to the sealed months that
were sealed before the field was recorded (2026-02 .. 2026-08; 2026-08 is the 31-row re-seal).

    python3 kev/manual/backfill_cwes_2026_02_08.py        # from the repo root; needs network

Values come from the KEV catalog AS OF THE DAY THIS RUNS, not from seal time — the catalog's
version and release date and the fetch time are written into each month's `migrations`
record. Evidence that the two agree: across 82 daily catalog versions from 2026-06 on, no
entry's `cwes` changed after listing; for 2026-02..05 the evidence is monthly samples only
(2025-06, 2026-02/03/05, 0 changes).

Existing fields are left byte-for-byte as they are; only the `cwes` key is added to each row.
Refuses the whole run (nothing written) if any sealed CVE is missing from the catalog — a
person decides what to do with that.

Not called by run.py. The daily job's diff-scope check refuses any change to an existing seal,
so this lands only through a reviewed PR. Running it again does nothing (every row already
has the key).
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import kevtrack  # noqa: E402

MONTHS = ["2026-02", "2026-03", "2026-04", "2026-05", "2026-06", "2026-07", "2026-08"]


def fetch_catalog_with_meta(timeout: int = 60) -> dict:
    with urllib.request.urlopen(kevtrack.KEV_URL, timeout=timeout) as r:
        return json.load(r)


def main() -> int:
    todo = [m for m in MONTHS
            if any("cwes" not in r for r in (kevtrack.load_sealed(m) or {}).get("kev_added", []))]
    if not todo:
        print("[backfill-cwes] every row of 2026-02..08 already has cwes — nothing to do")
        return 0
    fetched_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    cat = fetch_catalog_with_meta()
    source = {"catalogVersion": cat.get("catalogVersion"), "dateReleased": cat.get("dateReleased"),
              "fetched_at": fetched_at}
    by_cve = {v.get("cveID"): v for v in cat.get("vulnerabilities", [])}
    # all-or-nothing: check every month before writing any
    for m in todo:
        miss = [r["cve"] for r in kevtrack.load_sealed(m)["kev_added"] if r["cve"] not in by_cve]
        if miss:
            print(f"[backfill-cwes] {m}: {miss} not in the current catalog — refusing, nothing "
                  f"written", file=sys.stderr)
            return 1
    for m in todo:
        n = kevtrack.migrate_sealed_add_cwes(m, by_cve, source=source)
        print(f"[backfill-cwes] {m}: added cwes to {n} row(s) "
              f"(catalog {source['catalogVersion']}, fetched {fetched_at})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
