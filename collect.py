#!/usr/bin/env python3
"""
collect.py — fetch MSRC CVRF and save a fact summary to state/ (idempotent)

Makes no judgment and no attribution. Just fetches the raw data and folds it.
Runs monthly on the Pi via a systemd timer.

Idempotency:
    Re-fetching the same month is safe. However, fetched_at is updated
    (to pick up newly added credits). Use --no-clobber to protect existing files.

Usage:
    python3 collect.py                # fetch the current month
    python3 collect.py 2026-Jul       # a specific month
    python3 collect.py --backfill 2026-Jan 2026-Jul   # a whole range at once
    python3 collect.py 2026-Jul --no-clobber          # skip if it already exists

Environment variables:
    MSRC_MONITOR_HOME  … parent of state/. Defaults to the script location.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import requests

import cvrf_parse as cp

CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    d = home() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def current_month_tag() -> str:
    now = dt.datetime.now()
    return f"{now.year}-{MONTHS[now.month - 1]}"


def expand_range(start: str, end: str) -> list[str]:
    """'2026-Jan' '2026-Jul' -> list of month tags"""
    def parse(tag):
        y, m = tag.split("-")
        return int(y), MONTHS.index(m)
    sy, sm = parse(start)
    ey, em = parse(end)
    out = []
    y, m = sy, sm
    while (y, m) <= (ey, em):
        out.append(f"{y}-{MONTHS[m]}")
        m += 1
        if m == 12:
            m = 0
            y += 1
    return out


def fetch(month: str, timeout: int = 90, retries: int = 3) -> dict:
    """Fetch CVRF as JSON. Retries with exponential backoff."""
    url = CVRF_URL.format(month=month)
    last = None
    for attempt in range(retries):
        try:
            r = requests.get(url, headers={"Accept": "application/json"}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last = e
            if attempt < retries - 1:
                wait = 2 ** attempt * 5
                print(f"  [retry {attempt+1}/{retries}] {month}: {e} — waiting {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
    raise RuntimeError(f"{month}: fetch failed ({retries} attempts) — {last}")


# Axes for comparing a frozen snapshot against a re-fetched value (only counts robust to fetch lag)
REVISION_KEYS = ["cve_total", "core_total", "credited", "kugelblitz", "ms_internal"]


def revisions_dir() -> Path:
    d = state_dir() / ".revisions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def detect_revision(frozen: dict, fresh: dict, detected_at: str) -> dict | None:
    """Return the diff between frozen and re-fetched values (None if no diff). Never overwrites frozen."""
    diff = {}
    for k in REVISION_KEYS:
        fv = frozen.get(k)
        nv = fresh.get(k)
        if fv is not None and nv is not None and fv != nv:
            diff[k] = {"frozen": fv, "revised": nv, "delta": nv - fv}
    # Also compare severity (Critical) and the heavy tiers (T2+T3) (the report's main axes)
    fc = (frozen.get("severity_count") or {}).get("Critical", 0)
    nc = (fresh.get("severity_count") or {}).get("Critical", 0)
    if fc != nc:
        diff["critical"] = {"frozen": fc, "revised": nc, "delta": nc - fc}
    ft = frozen.get("tier_count") or {}
    nt = fresh.get("tier_count") or {}
    fh = ft.get("T2", 0) + ft.get("T3", 0)
    nh = nt.get("T2", 0) + nt.get("T3", 0)
    if fh != nh:
        diff["heavy"] = {"frozen": fh, "revised": nh, "delta": nh - fh}
    if not diff:
        return None
    return {
        "month": frozen.get("month"),
        "snapshot_date": frozen.get("snapshot_date"),
        "detected_at": detected_at,
        "diff": diff,
        "_note": ("Detected that MSRC revised this month after it was frozen. "
                  "The frozen values are kept; the revision is recorded here "
                  "(report figures stay unchanged)."),
    }


def collect_month(month: str, no_clobber: bool = False) -> dict | None:
    path = state_dir() / f"{month}.json"
    if no_clobber and path.exists():
        print(f"  skip (exists): {month}")
        return json.loads(path.read_text())

    # If the existing file is frozen, never overwrite it. Only re-fetch to detect and record revisions.
    existing = json.loads(path.read_text()) if path.exists() else None
    is_frozen = bool(existing and existing.get("frozen"))

    fetched_at = dt.datetime.now().isoformat(timespec="seconds")
    doc = fetch(month)
    summary = cp.summarize(doc, month, fetched_at)

    if is_frozen:
        rev = detect_revision(existing, summary, fetched_at)
        if rev:
            rp = revisions_dir() / f"{month}.json"
            rp.write_text(json.dumps(rev, ensure_ascii=False, indent=2))
            print(f"  FROZEN {month}: keeping frozen values. MSRC revision detected -> {rp.name} "
                  f"({', '.join(rev['diff'].keys())})")
        else:
            print(f"  FROZEN {month}: keeping frozen values (no revision)")
        return existing

    # Unfrozen (current month) is overwritten as usual. Set frozen:false explicitly.
    summary["frozen"] = False
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    tmp.replace(path)

    zd = len(summary["zero_days"])
    print(f"  OK  {month}: CVE {summary['cve_total']} / "
          f"credited {summary['credited']} / zero-days {zd} "
          f"-> {path.name}")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch MSRC CVRF and save a summary (no judgment)")
    ap.add_argument("months", nargs="*", help="e.g. 2026-Jul (defaults to current month)")
    ap.add_argument("--backfill", nargs=2, metavar=("START", "END"),
                    help="fetch a whole range e.g. --backfill 2026-Jan 2026-Jul")
    ap.add_argument("--no-clobber", action="store_true",
                    help="skip if the month file already exists")
    args = ap.parse_args()

    if args.backfill:
        targets = expand_range(*args.backfill)
    elif args.months:
        targets = args.months
    else:
        targets = [current_month_tag()]

    print(f"[collect] state: {state_dir()}")
    print(f"[collect] targets: {', '.join(targets)}")

    failed = []
    for m in targets:
        try:
            collect_month(m, no_clobber=args.no_clobber)
        except Exception as e:
            print(f"  FAIL {m}: {e}", file=sys.stderr)
            failed.append(m)
        time.sleep(1)  # be polite to the API

    if failed:
        print(f"[collect] failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("[collect] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
