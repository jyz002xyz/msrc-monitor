#!/usr/bin/env python3
"""
test_diff.py — lock in diff.py's threshold checks and new-credit detection

Synthetic state JSON is generated inside the test (no real API is hit).
Like test_regression.py, it ships a runner that works without pytest.

Run:
    cd ~/msrc_monitor
    python tests/test_diff.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import diff


# --- synthetic state helper -------------------------------------------------
def mk_state(month, cve_total=1000, t2=10, t3=2, critical=50,
             credit_counts=None, zero_days=None):
    return {
        "month": month,
        "fetched_at": f"{month}-fake",
        "cve_total": cve_total,
        "credited": 0,
        "uncredited": 0,
        "tier_count": {"T0/T1": cve_total - t2 - t3, "T2": t2, "T3": t3},
        "severity_count": {"Critical": critical, "Important": 1, "Unrated": 1},
        "credit_counts": credit_counts or {},
        "zero_days": zero_days or [],
    }


TH = dict(diff.DEFAULT_THRESHOLDS)


def diff_of(now, prev):
    return diff.compute_diff(now, prev, now["month"], prev["month"], TH)


# ===========================================================================
# Boundary where total CVE change over ±50% does/does not raise the flag
# ===========================================================================
def test_cve_total_flag_over_threshold():
    now = mk_state("2026-Jul", cve_total=1600)   # +60% > 50%
    prev = mk_state("2026-Jun", cve_total=1000)
    r = diff_of(now, prev)
    assert r["changes"]["cve_total"]["flag"] is True
    assert abs(r["changes"]["cve_total"]["pct"] - 0.6) < 1e-9


def test_cve_total_no_flag_under_threshold():
    now = mk_state("2026-Jul", cve_total=1400)   # +40% < 50%
    prev = mk_state("2026-Jun", cve_total=1000)
    r = diff_of(now, prev)
    assert r["changes"]["cve_total"]["flag"] is False


def test_cve_total_boundary_exactly_50pct_no_flag():
    # exactly 50% is not "over", so the flag stays down
    now = mk_state("2026-Jul", cve_total=1500)   # exactly +50%
    prev = mk_state("2026-Jun", cve_total=1000)
    r = diff_of(now, prev)
    assert r["changes"]["cve_total"]["flag"] is False


def test_cve_total_drop_flags():
    # even a decrease raises the flag if its absolute value exceeds 50%
    now = mk_state("2026-Jul", cve_total=400)    # -60%
    prev = mk_state("2026-Jun", cve_total=1000)
    r = diff_of(now, prev)
    assert r["changes"]["cve_total"]["flag"] is True


# ===========================================================================
# Boundary where the heavy tier (T2+T3) reaches 1.5x
# ===========================================================================
def test_heavy_flag_over_ratio():
    now = mk_state("2026-Jul", t2=20, t3=5)      # 25
    prev = mk_state("2026-Jun", t2=10, t3=2)     # 12 -> 25/12=2.08 > 1.5
    r = diff_of(now, prev)
    assert r["changes"]["heavy"]["flag"] is True


def test_heavy_no_flag_under_ratio():
    now = mk_state("2026-Jul", t2=12, t3=2)      # 14
    prev = mk_state("2026-Jun", t2=10, t3=2)     # 12 -> 1.17 < 1.5
    r = diff_of(now, prev)
    assert r["changes"]["heavy"]["flag"] is False


def test_heavy_boundary_exactly_1_5x_no_flag():
    now = mk_state("2026-Jul", t2=15, t3=3)      # 18
    prev = mk_state("2026-Jun", t2=10, t3=2)     # 12 -> exactly 1.5
    r = diff_of(now, prev)
    assert r["changes"]["heavy"]["ratio"] == 1.5
    assert r["changes"]["heavy"]["flag"] is False


def test_heavy_zero_prev_jump_flags():
    # prev 0 -> now N cannot be expressed as a ratio but matters, so flag it
    now = mk_state("2026-Jul", t2=3, t3=1)       # 4
    prev = mk_state("2026-Jun", t2=0, t3=0)      # 0
    r = diff_of(now, prev)
    assert r["changes"]["heavy"]["ratio"] is None
    assert r["changes"]["heavy"]["flag"] is True


# ===========================================================================
# New credits: only names absent last month and present this month enter new_credits.
#              Only counts over 20 get a flag. Names present last month are not "new".
# ===========================================================================
def test_new_credit_detection_and_flag():
    prev = mk_state("2026-Jun", credit_counts={"Alice": 5, "Bob": 100})
    now = mk_state("2026-Jul", credit_counts={
        "Alice": 8,                          # present last month -> not new
        "Kugelblitz with Microsoft": 39,     # new, over 20 -> flag
        "Newbie": 3,                         # new, 20 or under -> no flag
    })
    r = diff_of(now, prev)
    names = {c["name"]: c for c in r["new_credits"]}
    assert "Alice" not in names, "a name present last month leaked into new"
    assert "Bob" not in names
    assert names["Kugelblitz with Microsoft"]["flag"] is True
    assert names["Kugelblitz with Microsoft"]["count"] == 39
    assert names["Newbie"]["flag"] is False
    # all entries surface (the machine does not silently drop any)
    assert len(r["new_credits"]) == 2


def test_new_credit_boundary_exactly_20_no_flag():
    prev = mk_state("2026-Jun", credit_counts={})
    now = mk_state("2026-Jul", credit_counts={"X": 20})   # exactly 20 is not "over"
    r = diff_of(now, prev)
    assert r["new_credits"][0]["flag"] is False


def test_new_credits_sorted_desc():
    prev = mk_state("2026-Jun", credit_counts={})
    now = mk_state("2026-Jul", credit_counts={"A": 3, "B": 30, "C": 10})
    r = diff_of(now, prev)
    counts = [c["count"] for c in r["new_credits"]]
    assert counts == sorted(counts, reverse=True)


# ===========================================================================
# Counting uncredited zero-days
# ===========================================================================
def test_zero_day_uncredited_count():
    zds = [
        {"cve": "A", "credited": True},
        {"cve": "B", "credited": False},
        {"cve": "C", "credited": False},
    ]
    now = mk_state("2026-Jul", zero_days=zds)
    prev = mk_state("2026-Jun")
    r = diff_of(now, prev)
    assert r["changes"]["zero_days_total"] == 3
    assert r["changes"]["zero_days_uncredited"]["count"] == 2
    assert r["changes"]["zero_days_uncredited"]["flag"] is True


def test_zero_day_all_credited_no_flag():
    zds = [{"cve": "A", "credited": True}]
    now = mk_state("2026-Jul", zero_days=zds)
    prev = mk_state("2026-Jun")
    r = diff_of(now, prev)
    assert r["changes"]["zero_days_uncredited"]["count"] == 0
    assert r["changes"]["zero_days_uncredited"]["flag"] is False


# ===========================================================================
# Missing previous-month file: return "no comparison target" instead of raising
# ===========================================================================
def test_missing_prev_no_exception():
    now = mk_state("2026-Jul")
    r = diff.compute_diff(now, None, "2026-Jul", "2026-Jun", TH)
    assert r["prev_available"] is False
    assert r["any_flag"] is False
    assert r["changes"] is None
    assert r["new_credits"] == []
    assert "比較対象なし" in r["note"]


# ===========================================================================
# any_flag is the OR of the individual flags
# ===========================================================================
def test_any_flag_aggregation():
    # nothing exceeds a threshold -> any_flag False
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2)
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2)
    r = diff_of(now, prev)
    assert r["any_flag"] is False

    # one uncredited zero-day makes any_flag True
    now2 = mk_state("2026-Jul", cve_total=1050,
                    zero_days=[{"cve": "X", "credited": False}])
    r2 = diff_of(now2, prev)
    assert r2["any_flag"] is True


# ===========================================================================
# prev_month_tag helper (including year rollover)
# ===========================================================================
def test_prev_month_tag():
    assert diff.prev_month_tag("2026-Jul") == "2026-Jun"
    assert diff.prev_month_tag("2026-Jan") == "2025-Dec"


# --- runner that also works without pytest ----------------------------------
if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception:
            print(f"  ERROR {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
