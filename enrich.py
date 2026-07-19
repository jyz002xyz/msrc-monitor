#!/usr/bin/env python3
"""
enrich.py — KEV/EPSS generation layer (a live layer, separate from frozen state)

Division of roles (the heart of Phase 2):
    - CISA KEV = notification trigger (a discrete event; doesn't wobble on listed/not-listed).
      -> Edge-triggers a notification on the diff from the previous run's kev_listed (new additions).
    - FIRST EPSS = analysis material inside the report (updated daily; a time series that wobbles).
      -> Never used as a notification trigger (principle #2: don't trigger on values that break with fetch lag).
      -> Presented in the report "with a fetch timestamp (epss_asof)". Keep only the latest + one prior generation.

Strict adherence to the freeze principle:
    Never rewrite the monthly frozen state (state/2026-*.json). KEV/EPSS live in
    state/enrichment.json (gitignored, live). Target CVEs are re-derived from the raw
    CVRF every time and do not depend on frozen state.

No attribution or causation:
    Never assert a finder or "AI-discovered" etc. from KEV/EPSS numbers. Only the facts of the numbers and their timestamps.

Usage:
    python enrich.py 2026-Jul            # match target CVEs against KEV/EPSS and update enrichment.json
    python enrich.py 2026-Jul --fixture  # use a fixture for the raw CVRF (frozen months / offline)

When unreachable (AI sandbox etc.) it skips fetching and leaves asof=null (does not crash).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

import requests

import cvrf_parse as cp

CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100  # max CVEs per request (guards load and URL length)

FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "2026-Jul-cvrf-reduced.json"


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    d = home() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def enrichment_path() -> Path:
    return state_dir() / "enrichment.json"


# --- Fetch (returns None if unreachable. Does not crash) ----------------------
def fetch_kev(timeout: int = 30) -> set[str] | None:
    """Set of CVE-IDs in the entire CISA KEV catalog. None if unreachable."""
    try:
        r = requests.get(CISA_KEV_URL, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as e:
        print(f"[enrich] skipping KEV fetch (unreachable): {e}", file=sys.stderr)
        return None


def fetch_epss(cve_ids: list[str], timeout: int = 30) -> dict | None:
    """Fetch EPSS for the target CVEs. {cve: {epss, percentile}} plus date. None if unreachable.

    Returns: (scores: dict, date: str) / None on failure
    """
    if not cve_ids:
        return {"scores": {}, "date": None}
    scores: dict[str, dict] = {}
    date = None
    try:
        for i in range(0, len(cve_ids), EPSS_BATCH):
            batch = cve_ids[i:i + EPSS_BATCH]
            r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            for row in data.get("data", []):
                cve = row.get("cve")
                if not cve:
                    continue
                scores[cve] = {
                    "epss": float(row.get("epss", 0) or 0),
                    "percentile": float(row.get("percentile", 0) or 0),
                }
                date = row.get("date") or date
        return {"scores": scores, "date": date}
    except Exception as e:
        print(f"[enrich] skipping EPSS fetch (unreachable): {e}", file=sys.stderr)
        return None


def load_prev() -> dict:
    p = enrichment_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def _now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def build_enrichment(month: str, targets: list[dict], kev_all: set[str] | None,
                     epss: dict | None, prev: dict, now_iso: str) -> dict:
    """Assemble the enrichment dict from target CVEs, KEV, and EPSS.

    KEV diff (kev_new) = this run's kev_listed - previous run's kev_listed (for edge-triggering).
    EPSS keeps only the latest (epss) and one prior generation (epss_prev). The delta is not used for notifications.
    """
    target_ids = [t["cve"] for t in targets]

    # --- KEV match (target CVEs already listed in KEV) ---
    if kev_all is None:
        kev_listed = None
        kev_asof = None
    else:
        kev_listed = sorted(c for c in target_ids if c in kev_all)
        kev_asof = now_iso
    prev_kev = set(prev.get("kev_listed") or [])
    kev_new = sorted(set(kev_listed or []) - prev_kev) if kev_listed is not None else []

    # --- EPSS (latest + one prior generation) ---
    if epss is None:
        epss_scores, epss_asof = None, None
    else:
        epss_scores, epss_asof = epss["scores"], epss["date"]
    # one prior generation = the previous run's epss (nothing older is kept = avoid a standalone metric)
    epss_prev = prev.get("epss")
    epss_prev_asof = prev.get("epss_asof")

    return {
        "month": month,
        "generated_at": now_iso,
        "target_count": len(targets),
        "target_cves": targets,
        # --- KEV: notification trigger (discrete) ---
        "kev_asof": kev_asof,
        "kev_listed": kev_listed,
        "kev_new": kev_new,
        # --- EPSS: report reference (timestamped; not used for notifications) ---
        "epss_asof": epss_asof,
        "epss": epss_scores,
        "epss_prev": epss_prev,
        "epss_prev_asof": epss_prev_asof,
        "_note": ("KEV=notification trigger (discrete event). EPSS=report reference "
                  "(timestamped; varies daily; never used alone for notifications or trend lines). "
                  "Frozen state is immutable. Do not assert a finder or causation from KEV/EPSS numbers."),
    }


def get_raw_doc(month: str, use_fixture: bool, fetch_fn=None) -> dict | None:
    """Raw CVRF for deriving target CVEs. Uses the fixture when specified, otherwise fetches."""
    if use_fixture:
        return json.loads(FIXTURE.read_text())
    try:
        import collect
        return (fetch_fn or collect.fetch)(month)
    except Exception as e:
        print(f"[enrich] skipping CVRF fetch (unreachable): {e}", file=sys.stderr)
        return None


def enrich(month: str, use_fixture: bool = False, raw_doc: dict | None = None,
           kev_all=None, epss=None, fetch_kev_fn=fetch_kev,
           fetch_epss_fn=fetch_epss) -> dict | None:
    """Match the month's target CVEs against KEV/EPSS and update enrichment.json.

    raw_doc / kev_all / epss can be injected for testing. If not injected, they are fetched live (skipped when unreachable).
    """
    doc = raw_doc if raw_doc is not None else get_raw_doc(month, use_fixture)
    if doc is None:
        print("[enrich] aborting: raw CVRF unavailable (enrichment not updated)")
        return None
    targets = cp.target_cves_from_doc(doc)
    target_ids = [t["cve"] for t in targets]

    if kev_all is None:
        kev_all = fetch_kev_fn()
    if epss is None:
        epss = fetch_epss_fn(target_ids)

    prev = load_prev()
    now_iso = _now_iso()
    enr = build_enrichment(month, targets, kev_all, epss, prev, now_iso)

    # atomic write
    p = enrichment_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(enr, ensure_ascii=False, indent=2))
    tmp.replace(p)

    kev_n = len(enr["kev_new"])
    kl = "n/a" if enr["kev_listed"] is None else str(len(enr["kev_listed"]))
    ep = "n/a" if enr["epss"] is None else str(len(enr["epss"]))
    print(f"[enrich] {month}: target {enr['target_count']} / KEV listed {kl} "
          f"(new {kev_n}) / EPSS {ep} (asof {enr['epss_asof']})")
    return enr


def main() -> int:
    ap = argparse.ArgumentParser(description="KEV/EPSS enrichment (KEV=notification, EPSS=reference)")
    ap.add_argument("month", help="target month e.g. 2026-Jul")
    ap.add_argument("--fixture", action="store_true",
                    help="use a fixture for the raw CVRF (frozen months / offline)")
    args = ap.parse_args()
    enr = enrich(args.month, use_fixture=args.fixture)
    return 0 if enr is not None else 1


if __name__ == "__main__":
    sys.exit(main())
