#!/usr/bin/env python3
"""test_integrity.py — offline tests for the pre-seal integrity gate (no network).

Proves the fail-halt guard: a degraded catalog (count crash, empty, missing required fields,
empty seal window) produces failures so run.py halts and does NOT seal; a healthy catalog
passes; and the seal-when-degraded path leaves the month unsealed (recoverable next run).

実行: python test_integrity.py
"""
import sys
import tempfile
from pathlib import Path

import integrity
import kevtrack


def _entry(cve, month="2026-07", day="03", vendor="Acme", product="Web"):
    return {"cveID": cve, "vendorProject": vendor, "product": product,
            "dateAdded": f"{month}-{day}", "dueDate": f"{month}-24",
            "knownRansomwareCampaignUse": "Unknown", "shortDescription": "x", "cwes": []}


def _catalog(n, month="2026-06", day="10"):
    # n healthy entries in a past month (so it is a valid seal window)
    return [_entry(f"CVE-{i:04d}", month=month, day=day) for i in range(n)]


def test_healthy_catalog_passes():
    kev = _catalog(1500)
    failures, stats = integrity.evaluate(kev, prev_count=1490, seal_months=["2026-06"],
                                         min_catalog=1200)
    assert failures == [], f"healthy catalog should pass, got {failures}"
    assert stats["count"] == 1500 and stats["window_2026-06"] == 1500


def test_none_catalog_fails():
    failures, _ = integrity.evaluate(None)
    assert failures and "fetch failed" in failures[0]


def test_empty_catalog_fails():
    failures, _ = integrity.evaluate([], min_catalog=1200)
    assert any("empty" in f for f in failures)


def test_below_floor_fails():
    failures, _ = integrity.evaluate(_catalog(50), min_catalog=1200)
    assert any("below floor" in f for f in failures)


def test_decrease_rate_fails_but_small_drop_ok():
    # 3% drop vs last successful run -> anomaly (KEV is ~monotonic)
    big_drop, _ = integrity.evaluate(_catalog(1455), prev_count=1500, min_catalog=1200,
                                     max_decrease_frac=0.02)
    assert any("dropped" in f for f in big_drop), "3% drop must fail"
    # 1% drop is within tolerance
    small_drop, _ = integrity.evaluate(_catalog(1485), prev_count=1500, min_catalog=1200,
                                       max_decrease_frac=0.02)
    assert small_drop == [], f"1% drop should pass, got {small_drop}"


def test_missing_required_field_fails():
    kev = _catalog(1500)
    for e in kev[:100]:               # ~6.7% missing product, over the 1% tolerance
        e["product"] = ""
    failures, _ = integrity.evaluate(kev, min_catalog=1200, max_missing_frac=0.01)
    assert any("product" in f and "missing" in f for f in failures)


def test_empty_seal_window_fails_and_override():
    # a healthy catalog, but the month about to be sealed has zero entries
    kev = _catalog(1500, month="2026-05")           # entries only in 2026-05
    failures, _ = integrity.evaluate(kev, min_catalog=1200, seal_months=["2026-06"])
    assert any("2026-06" in f and "0 window" in f for f in failures), "empty seal month must fail"
    ok, _ = integrity.evaluate(kev, min_catalog=1200, seal_months=["2026-06"],
                               allow_empty_seal={"2026-06"})
    assert ok == [], "override must allow a genuinely empty month"


def test_degraded_catalog_does_not_seal():
    # Mirror run.py's gate: on failures we must NOT reach kevtrack.seal(); the month stays open.
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        open_snap = kevtrack.build_open("2026-06", _catalog(1, month="2026-06"), None,
                                        fetch_epss_fn=lambda cves: {"scores": {}, "date": None},
                                        now_iso="t")
        kevtrack.write_open(open_snap, d)
        degraded = _catalog(10, month="2026-06")     # count crash: 10 << floor
        failures, _ = integrity.evaluate(degraded, prev_count=1500, seal_months=["2026-06"],
                                         min_catalog=1200)
        assert failures, "degraded catalog must produce failures"
        if not failures:                              # the gate run.py enforces
            kevtrack.seal(kevtrack.load_open("2026-06", d), d)
        assert kevtrack.load_sealed("2026-06", d) is None, "must NOT seal on integrity failure"
        assert kevtrack.load_open("2026-06", d) is not None, "open window preserved for recovery"


def test_normal_catalog_still_seals():
    # Counterpart: a healthy catalog passes the gate, so sealing proceeds as before.
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        open_snap = kevtrack.build_open("2026-06", _catalog(20, month="2026-06"), None,
                                        fetch_epss_fn=lambda cves: {"scores": {}, "date": None},
                                        now_iso="t")
        kevtrack.write_open(open_snap, d)
        healthy = _catalog(1500, month="2026-06")
        failures, _ = integrity.evaluate(healthy, prev_count=1490, seal_months=["2026-06"],
                                         min_catalog=1200)
        assert failures == []
        if not failures:
            kevtrack.seal(kevtrack.load_open("2026-06", d), d)
        assert kevtrack.load_sealed("2026-06", d) is not None, "healthy catalog seals normally"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}"); failed += 1
        except Exception:
            print(f"  ERROR {t.__name__}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
