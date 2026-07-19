#!/usr/bin/env python3
"""
test_snapshot_freeze.py — lock in the mechanism of the monthly snapshot freeze policy.

Same idea as closing the books in accounting: once a past month has been fetched and
reviewed, it is frozen as a final value and never overwritten by a later MSRC revision.
Revisions are recorded separately in .revisions (the numbers stay unchanged).

*Runs on synthetic data*
    Real MSRC primary data (which contains researchers' personal information) is not
    bundled, so the finalized past-month data itself is not verified. Instead, the freeze /
    revision-detection mechanism is verified with synthetic data / in-memory values
    (this is the reusable logic).

Run:
    python tests/fixtures/make_synthetic_cvrf.py   # generate the synthetic fixture
    python tests/test_snapshot_freeze.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import collect
import cvrf_parse as cp

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "2026-Jul-cvrf-reduced.json")


# ===========================================================================
# summarize produces a freezable structure (a full set of aggregate fields)
# ===========================================================================
def test_summary_has_freezable_structure():
    doc = json.load(open(FIXTURE, encoding="utf-8"))
    s = cp.summarize(doc, "2026-Jul", "synthetic")
    for k in ("cve_total", "core_total", "severity_count", "tier_count",
              "product_count", "finder_bucket", "zero_days"):
        assert k in s, f"aggregate field {k} is missing"
    assert isinstance(s["product_count"], dict) and s["product_count"]
    assert isinstance(s["finder_bucket"], dict) and s["finder_bucket"]
    # conservation: the population partition equals the total
    assert s["core_total"] + s["excluded_total"] == s["cve_total"]


# ===========================================================================
# Revision detection: a re-fetch that differs from the frozen value records a diff,
# and the frozen dict stays unchanged
# ===========================================================================
def test_revision_detection_records_without_overwrite():
    frozen = {
        "month": "2026-Jun", "snapshot_date": "2026-07-15",
        "cve_total": 1281, "core_total": 724, "credited": 215,
        "kugelblitz": 0, "ms_internal": 34,
        "severity_count": {"Critical": 89}, "tier_count": {"T2": 42, "T3": 3},
    }
    # assume MSRC revised it after the fact (cve down, core down, critical changed)
    fresh = {
        "cve_total": 1205, "core_total": 648, "credited": 215,
        "kugelblitz": 0, "ms_internal": 34,
        "severity_count": {"Critical": 85}, "tier_count": {"T2": 42, "T3": 3},
    }
    rev = collect.detect_revision(frozen, fresh, "2026-07-16T00:00:00")
    assert rev is not None
    assert rev["diff"]["cve_total"]["frozen"] == 1281
    assert rev["diff"]["cve_total"]["revised"] == 1205
    assert rev["diff"]["cve_total"]["delta"] == -76
    assert rev["diff"]["core_total"]["delta"] == -76
    assert rev["diff"]["critical"]["delta"] == -4
    # the frozen dict is not mutated
    assert frozen["cve_total"] == 1281


def test_revision_detection_no_change_returns_none():
    frozen = {
        "month": "2026-Jan", "cve_total": 310, "core_total": 287,
        "credited": 118, "kugelblitz": 0, "ms_internal": 19,
        "severity_count": {"Critical": 30}, "tier_count": {"T2": 6, "T3": 3},
    }
    same = dict(frozen)
    assert collect.detect_revision(frozen, same, "2026-07-16T00:00:00") is None


# ===========================================================================
# collect_month records the revision without overwriting a frozen month (mocked in a temp home)
# ===========================================================================
def test_collect_month_preserves_frozen():
    home = tempfile.mkdtemp(prefix="msrc_freeze_test_")
    os.environ["MSRC_MONITOR_HOME"] = home
    try:
        sd = collect.state_dir()
        frozen = {
            "month": "2026-Jun", "frozen": True, "snapshot_date": "2026-07-15",
            "cve_total": 1281, "core_total": 724, "credited": 215,
            "kugelblitz": 0, "ms_internal": 34,
            "severity_count": {"Critical": 89}, "tier_count": {"T2": 42, "T3": 3},
            "zero_days": [],
        }
        (sd / "2026-Jun.json").write_text(json.dumps(frozen, ensure_ascii=False))

        # mock fetch to return "revised" data (empty = cve_total 0)
        orig_fetch = collect.fetch
        collect.fetch = lambda m, **kw: {"Vulnerability": []}
        try:
            collect.collect_month("2026-Jun")
        finally:
            collect.fetch = orig_fetch

        # the frozen values are preserved
        after = json.loads((sd / "2026-Jun.json").read_text())
        assert after["cve_total"] == 1281, "the frozen month was overwritten"
        assert after["frozen"] is True
        # the revision was recorded
        rp = sd / ".revisions" / "2026-Jun.json"
        assert rp.exists(), "no revision record was created"
        rev = json.loads(rp.read_text())
        assert rev["diff"]["cve_total"]["revised"] == 0
    finally:
        os.environ.pop("MSRC_MONITOR_HOME", None)


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
