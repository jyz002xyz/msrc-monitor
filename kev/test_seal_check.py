#!/usr/bin/env python3
"""test_seal_check.py — offline tests for the seal-time check (no network, no gh).

実行: python test_seal_check.py
"""
import sys
import tempfile
from pathlib import Path

import kevtrack
import seal_check


def _e(cve, day, cwes=None, month="2026-09"):
    e = {"cveID": cve, "vendorProject": "Acme", "product": "Web", "dateAdded": f"{month}-{day}",
         "dueDate": f"{month}-28", "knownRansomwareCampaignUse": "Unknown",
         "shortDescription": "x", "cwes": [] if cwes is None else cwes}
    return e


A, B, C = _e("CVE-A", "03", ["CWE-79"]), _e("CVE-B", "10"), _e("CVE-C", "30", ["CWE-502"])
NO_EPSS = lambda c: {"scores": {}, "date": None}  # noqa: E731


class FakeIssues:
    def __init__(self):
        self.titles = []

    def list_titles(self):
        return list(self.titles)

    def create(self, title, body):
        assert title and body
        self.titles.append(title)


def _seal(d, entries, month="2026-09", drop_cwes=()):
    s = kevtrack.build_open(month, entries, None, fetch_epss_fn=NO_EPSS, now_iso="seal")
    for r in s["kev_added"]:
        if r["cve"] in drop_cwes:
            r.pop("cwes")
    kevtrack.seal(s, d)


def test_a_normal_seal_passes():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _seal(d, [A, B, C])
        res = seal_check.check("2026-09", [A, B, C], d)
        assert res["checked"] and res["problems"] == [], res
        assert res["sealed_count"] == res["window_count"] == 3
        assert res["cwes_list"] == 3 and res["cwes_empty"] == 1 and res["cwes_null"] == []
        assert seal_check.summary(res).startswith("seal check 2026-09: OK — 3 rows")
        gh = FakeIssues()
        assert seal_check.notify([res], gh.list_titles, gh.create) == [] and gh.titles == []


def test_a_seal_missing_a_row_fails_and_files_exactly_one_issue():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _seal(d, [A, B])                              # the seal lacks C ...
        before = kevtrack.sealed_path("2026-09", d).read_bytes()
        res = seal_check.check("2026-09", [A, B, C], d)   # ... which the catalog window has
        assert len(res["problems"]) == 1 and "CVE-C" in res["problems"][0], res
        assert seal_check.summary(res).startswith("SEAL CHECK FAILED 2026-09")
        gh = FakeIssues()
        for _ in range(3):                            # the next runs retry and fail the same way
            seal_check.notify([seal_check.check("2026-09", [A, B, C], d)],
                              gh.list_titles, gh.create)
        assert len(gh.titles) == 1 and "[seal-check:" in gh.titles[0], gh.titles
        assert kevtrack.sealed_path("2026-09", d).read_bytes() == before, "never repaired"


def test_a_row_without_cwes_fails_but_null_is_reported_not_failed():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _seal(d, [A, B, C], drop_cwes=("CVE-B",))
        res = seal_check.check("2026-09", [A, B, C], d)
        assert len(res["problems"]) == 1 and "without the cwes key" in res["problems"][0]
        assert "CVE-B" in res["problems"][0]
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        nofield = {k: v for k, v in B.items() if k != "cwes"}   # KEV entry lacking the field
        _seal(d, [A, nofield, C])
        res = seal_check.check("2026-09", [A, nofield, C], d)
        assert res["problems"] == [] and res["cwes_null"] == ["CVE-B"], res


def test_months_before_2026_09_are_not_checked():
    for month in ("2026-02", "2026-05", "2026-08"):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            a, b = _e("CVE-X", "03", month=month), _e("CVE-Y", "04", month=month)
            _seal(d, [a], month=month, drop_cwes=("CVE-X",))   # a gap AND no cwes
            res = seal_check.check(month, [a, b], d)
            assert res["checked"] is False and res["problems"] == [], res
            assert "skipped" in seal_check.summary(res)
    assert seal_check.applies("2026-09") and seal_check.applies("2027-01")


def test_notify_cli_without_a_result_file_or_failure_files_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        assert seal_check.main(["notify", str(Path(tmp) / "absent.json")]) == 0
        p = Path(tmp) / "r.json"
        seal_check.write_results([{"month": "2026-09", "checked": True, "problems": []}], p)
        assert seal_check.main(["notify", str(p)]) == 0


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
