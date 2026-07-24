#!/usr/bin/env python3
"""integrity.py — pre-generation / pre-seal guards for the KEV catalog (fail-halt).

Why: run.py seals a past month as immutable once it closes. kevtrack.seal() never overwrites
an existing seal, so a month sealed from a DEGRADED-but-non-empty catalog (partial fetch,
upstream schema change) would be *permanently* confirmed as incomplete. Before generating or
sealing, evaluate() checks the catalog is whole; run.py halts (non-zero exit, writes nothing)
if it is not, leaving the open window intact so the next run can recover.

Evaluated on EVERY run (not only at month boundaries) — an anomalous catalog must not be
silently published. Thresholds live here (one place), overridable via env for tuning; the
observed catalog on 2026-07 is ~1653 entries with 100% required-field coverage and ~23
additions in the current month, which sets the sane ranges below.
"""
from __future__ import annotations

import os

REQUIRED_FIELDS = ("cveID", "vendorProject", "product", "dateAdded")


def _envi(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _envf(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


# Absolute floor: a whole catalog is ~1653 (2026-07). Anything far below is a partial fetch.
MIN_CATALOG = _envi("KEV_MIN_CATALOG", 1200)
# KEV is essentially monotonic (entries are added, rarely removed). A drop past this fraction
# versus the last successful run is a strong upstream-anomaly signal.
MAX_DECREASE_FRAC = _envf("KEV_MAX_DECREASE_FRAC", 0.02)
# Required fields are ~100% present in a healthy catalog; tolerate a tiny amount of noise.
MAX_MISSING_FRAC = _envf("KEV_MAX_MISSING_FRAC", 0.01)


def _allow_empty_seal() -> set[str]:
    return {m.strip() for m in os.environ.get("KEV_ALLOW_EMPTY_SEAL", "").split(",") if m.strip()}


def evaluate(kev_full: list[dict] | None, *, prev_count: int | None = None,
             seal_months: tuple[str, ...] | list[str] = (),
             min_catalog: int = MIN_CATALOG,
             max_decrease_frac: float = MAX_DECREASE_FRAC,
             max_missing_frac: float = MAX_MISSING_FRAC,
             allow_empty_seal: set[str] | None = None) -> tuple[list[str], dict]:
    """Return (failures, stats). Empty failures list == catalog passes the integrity gate.

    - kev_full: the fetched catalog (None/[] means the fetch failed or is empty).
    - prev_count: catalog size at the last successful run (for the decrease-rate check); None
      on first run skips that check.
    - seal_months: months about to be sealed this run; each must have >0 window entries
      (an empty month being frozen forever is the exact failure this guards). Override a
      genuinely-empty month via KEV_ALLOW_EMPTY_SEAL.
    """
    failures: list[str] = []
    stats: dict = {}
    allow_empty = allow_empty_seal if allow_empty_seal is not None else _allow_empty_seal()

    if kev_full is None:
        failures.append("catalog fetch failed (None)")
        return failures, stats
    n = len(kev_full)
    stats["count"] = n
    stats["prev_count"] = prev_count

    if n == 0:
        failures.append("catalog empty (0 entries)")
        return failures, stats  # nothing else is meaningful on an empty catalog

    if n < min_catalog:
        failures.append(f"catalog count {n} below floor {min_catalog}")
    if prev_count is not None and prev_count > 0 and n < prev_count * (1 - max_decrease_frac):
        failures.append(
            f"catalog count {n} dropped >{max_decrease_frac:.0%} vs last successful {prev_count}")

    for field in REQUIRED_FIELDS:
        missing = sum(1 for e in kev_full if not str(e.get(field) or "").strip())
        stats[f"missing_{field}"] = missing
        if missing / n > max_missing_frac:
            failures.append(
                f"required field {field} missing in {missing}/{n} "
                f"({missing / n:.1%} > {max_missing_frac:.0%})")

    for m in seal_months:
        wc = sum(1 for e in kev_full if str(e.get("dateAdded") or "").startswith(m + "-"))
        stats[f"window_{m}"] = wc
        if wc == 0 and m not in allow_empty:
            failures.append(
                f"month {m} about to be sealed has 0 window entries "
                f"(set KEV_ALLOW_EMPTY_SEAL={m} to override a genuinely empty month)")

    return failures, stats
