#!/usr/bin/env python3
"""kevtrack.py — cross-vendor KEV/EPSS tracker (Phase 1 THROWAWAY prototype).

Purpose: learn the shape of a cross-vendor KEV/EPSS report. NOT production. Outside the
msrc_monitor tree; local only; does not touch msrc_monitor's enrichment/state/notifications.

Window lifecycle (calendar month, keyed by dateAdded):
  - OPEN (current month): accumulates KEV additions as the month runs. EPSS is recorded at
    each CVE's FIRST observation and not overwritten later (observed-time value). Stored as
    {month}.open.json.gz and REGENERATED each run — not immutable.
  - SEALED (a month that has closed): built once after the month ends and frozen as
    {month}.json.gz — immutable, never overwritten.
Sealing after month-end (vs Patch Tuesday) is what makes "EPSS at observation time" and
"complete window" coexist.

A sealed snapshot found for the CURRENT month is an invalid mid-month seal; it is corrected
(re-opened) once, and the correction is recorded (never silent). Already-sealed PAST months
are never rebuilt.

Backfilled past windows (rebuilt from the current catalog's dateAdded) leave EPSS BLANK
(historical EPSS is not reconstructed).
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAP_DIR = HERE / "snapshots"

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SLEEP = 6.5   # no API key: NVD limit is 5 req / 30s -> ~6s between per-CVE queries

KEEP = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
        "dueDate", "knownRansomwareCampaignUse", "shortDescription", "cwes"]


# --- fetch (reachability-tolerant) ------------------------------------------
def fetch_kev_full(timeout: int = 30) -> list[dict] | None:
    try:
        with urllib.request.urlopen(KEV_URL, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"[kevtrack] KEV fetch failed (unreachable): {e}", file=sys.stderr)
        return None
    return [{k: v.get(k) for k in KEEP} for v in data.get("vulnerabilities", [])]


def fetch_epss(cve_ids: list[str], timeout: int = 30) -> dict | None:
    if not cve_ids:
        return {"scores": {}, "date": None}
    scores: dict[str, dict] = {}
    date = None
    try:
        for i in range(0, len(cve_ids), EPSS_BATCH):
            batch = cve_ids[i:i + EPSS_BATCH]
            q = urllib.parse.urlencode({"cve": ",".join(batch)})
            with urllib.request.urlopen(f"{EPSS_URL}?{q}", timeout=timeout) as r:
                data = json.load(r)
            for row in data.get("data", []):
                cve = row.get("cve")
                if cve:
                    scores[cve] = {"epss": float(row.get("epss", 0) or 0),
                                   "percentile": float(row.get("percentile", 0) or 0)}
                    date = row.get("date") or date
        return {"scores": scores, "date": date}
    except Exception as e:  # noqa: BLE001
        print(f"[kevtrack] EPSS fetch failed (unreachable): {e}", file=sys.stderr)
        return None


def fetch_nvd_published(cve_ids: list[str], timeout: int = 30, sleep: float = NVD_SLEEP) -> dict:
    """NVD CVE API 2.0: {cve: published-datetime-str} for each resolvable CVE. No API key
    (respects the 5 req/30s limit via `sleep`). An unresolved/failed CVE is simply absent
    (never guessed). NVD `published` is when NVD published the CVE record — a proxy for
    disclosure, NOT the vendor's original disclosure date (label accordingly)."""
    import time
    out: dict[str, str] = {}
    for i, cve in enumerate(cve_ids):
        if i:
            time.sleep(sleep)
        try:
            with urllib.request.urlopen(f"{NVD_URL}?cveId={cve}", timeout=timeout) as r:
                d = json.load(r)
            vulns = d.get("vulnerabilities") or []
            if vulns:
                pub = (vulns[0].get("cve") or {}).get("published")
                if pub:
                    out[cve] = pub
        except Exception as e:  # noqa: BLE001 — unresolved -> absent, not guessed
            print(f"[kevtrack] NVD {cve} unresolved: {e}", file=sys.stderr)
    return out


def fill_nvd(snap: dict, fetch_nvd_fn, prev_rows: list[dict] | None = None) -> dict:
    """Add nvd_published to rows that lack it. nvd_published is a STABLE past fact, so it is
    filled for any window (open or sealed/backfill). fetch_nvd_fn=None skips (offline).
    prev_rows preserves already-known values (avoids re-querying)."""
    if fetch_nvd_fn is None:
        return snap
    prev = {r["cve"]: r.get("nvd_published") for r in (prev_rows or []) if r.get("nvd_published")}
    need = [r["cve"] for r in snap["kev_added"]
            if r["cve"] and not (r.get("nvd_published") or prev.get(r["cve"]))]
    fetched = fetch_nvd_fn(need) if need else {}
    for r in snap["kev_added"]:
        if not r.get("nvd_published"):
            r["nvd_published"] = prev.get(r["cve"]) or fetched.get(r["cve"])
    return snap


def days_to_kev(row: dict) -> int | None:
    """Whole days from NVD publication to KEV listing (dateAdded). None if either is absent.
    Label: 'NVD publication -> KEV listing', NOT 'time to exploitation'."""
    pub, added = row.get("nvd_published"), row.get("date_added")
    if not pub or not added:
        return None
    try:
        p = dt.date.fromisoformat(pub[:10])
        a = dt.date.fromisoformat(added[:10])
        return (a - p).days
    except ValueError:
        return None


# --- calendar helpers --------------------------------------------------------
def current_month(today: dt.date | None = None) -> str:
    d = today or dt.date.today()
    return f"{d.year:04d}-{d.month:02d}"


def window_of(kev_full: list[dict], month: str) -> list[dict]:
    return sorted((e for e in kev_full if (e.get("dateAdded") or "").startswith(month + "-")),
                  key=lambda e: (e.get("dateAdded") or "", e.get("cveID") or ""))


def _ransom(v) -> bool:
    return str(v or "").strip().lower() == "known"


def _base_row(e: dict) -> dict:
    return {"cve": e.get("cveID"), "vendor": e.get("vendorProject"),
            "product": e.get("product"), "name": e.get("vulnerabilityName"),
            "date_added": e.get("dateAdded"), "due_date": e.get("dueDate"),
            "ransomware": _ransom(e.get("knownRansomwareCampaignUse")),
            "short": e.get("shortDescription"),
            "epss": None, "percentile": None, "epss_asof": None,
            "nvd_published": None}


def _snapshot(month, state, rows, now_iso, corrections=None, migrations=None) -> dict:
    return {
        "window": month,
        "state": state,                      # "open" | "sealed"
        "generated_at": now_iso,
        "epss_observed": any(r["epss"] is not None for r in rows),
        "count": len(rows),
        "kev_added": rows,
        "corrections": corrections or [],
        "migrations": migrations or [],      # recorded schema migrations (e.g. nvd_published added)
        "_note": ("Cross-vendor KEV/EPSS. KEV=CISA-confirmed exploitation (not a complete "
                  "record). EPSS=probability of exploitation within 30 days (not severity), "
                  "recorded at observation time. Vendor counts reflect federal deployment + "
                  "CISA visibility, NOT security quality; do not rank vendors by count. "
                  "Facts machine-generated; interpretation human. Sealed snapshots immutable."),
    }


# --- build: open (accumulating) vs sealed backfill ---------------------------
def build_open(month: str, kev_full: list[dict], prev_rows: list[dict] | None = None, *,
               fetch_epss_fn=fetch_epss, fetch_nvd_fn=None, now_iso: str | None = None,
               corrections: list | None = None) -> dict:
    """Open (in-progress) window: accumulate KEV additions; observe EPSS at FIRST sighting
    of each CVE and keep that value on later runs."""
    now_iso = now_iso or dt.datetime.now().isoformat(timespec="seconds")
    prev_by_cve = {r["cve"]: r for r in (prev_rows or []) if r.get("epss") is not None}
    window = window_of(kev_full, month)
    need = [e["cveID"] for e in window if e.get("cveID") and e["cveID"] not in prev_by_cve]
    fetched = (fetch_epss_fn(need) or {"scores": {}, "date": None}) if need else {"scores": {}, "date": None}
    rows = []
    for e in window:
        row = _base_row(e)
        cve = row["cve"]
        if cve in prev_by_cve:                              # keep first-observed value
            p = prev_by_cve[cve]
            row.update(epss=p["epss"], percentile=p["percentile"], epss_asof=p.get("epss_asof"))
        else:
            s = fetched["scores"].get(cve)
            if s:
                row.update(epss=s["epss"], percentile=s["percentile"], epss_asof=fetched["date"])
        rows.append(row)
    snap = _snapshot(month, "open", rows, now_iso, corrections)
    return fill_nvd(snap, fetch_nvd_fn, prev_rows)   # nvd_published (stable) — preserve prev


def build_backfill(month: str, kev_full: list[dict], *, fetch_nvd_fn=None,
                   now_iso: str | None = None) -> dict:
    """A past window rebuilt from the catalog with EPSS BLANK (never observed live). NVD
    publication dates ARE filled (stable past fact, unlike observed-time EPSS)."""
    now_iso = now_iso or dt.datetime.now().isoformat(timespec="seconds")
    snap = _snapshot(month, "sealed", [_base_row(e) for e in window_of(kev_full, month)], now_iso)
    return fill_nvd(snap, fetch_nvd_fn)


def migrate_sealed_add_nvd(month: str, fetch_nvd_fn, *, snap_dir: Path = SNAP_DIR,
                           now_iso: str | None = None) -> bool:
    """Add nvd_published to an already-sealed month (a recorded schema migration — the
    authorized exception to immutability, like the 2026-07 re-seal). Idempotent: if every
    row already has nvd_published, do nothing. Returns True if the sealed file was rewritten."""
    snap = load_sealed(month, snap_dir)
    if snap is None:
        return False
    if all(r.get("nvd_published") for r in snap["kev_added"]):
        return False                                  # already migrated -> idempotent
    now_iso = now_iso or dt.datetime.now().isoformat(timespec="seconds")
    fill_nvd(snap, fetch_nvd_fn)
    snap.setdefault("migrations", []).append(
        f"added nvd_published to sealed window at {now_iso} (schema migration; existing "
        f"facts — CVE/vendor/product/dateAdded/dueDate/ransomware/EPSS — unchanged)")
    _write(sealed_path(month, snap_dir), snap)
    return True


# --- storage: open (mutable) + sealed (immutable) ----------------------------
def open_path(month: str, snap_dir: Path = SNAP_DIR) -> Path:
    return snap_dir / f"{month}.open.json.gz"


def sealed_path(month: str, snap_dir: Path = SNAP_DIR) -> Path:
    return snap_dir / f"{month}.json.gz"


def _read(p: Path) -> dict | None:
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        d = json.load(f)
    d.setdefault("state", "sealed")          # backward-compat: old-schema files are sealed
    d.setdefault("corrections", [])
    d.setdefault("migrations", [])
    for r in d.get("kev_added", []):
        r.setdefault("epss_asof", None)
        r.setdefault("nvd_published", None)
    return d


def _write(p: Path, snap: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(p, "wt", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2)


def load_open(month: str, snap_dir: Path = SNAP_DIR) -> dict | None:
    return _read(open_path(month, snap_dir))


def load_sealed(month: str, snap_dir: Path = SNAP_DIR) -> dict | None:
    return _read(sealed_path(month, snap_dir))


def write_open(snap: dict, snap_dir: Path = SNAP_DIR) -> Path:
    p = open_path(snap["window"], snap_dir)
    _write(p, snap)                          # mutable: overwrite each run
    return p


def seal(snap: dict, snap_dir: Path = SNAP_DIR) -> tuple[Path, bool]:
    """Freeze a snapshot as the immutable sealed file. Never overwrite an existing seal.
    Removes any open file for the month. Returns (path, written)."""
    p = sealed_path(snap["window"], snap_dir)
    if p.exists():
        return p, False
    sealed = dict(snap, state="sealed")
    _write(p, sealed)
    op = open_path(snap["window"], snap_dir)
    if op.exists():
        op.unlink()
    return p, True
