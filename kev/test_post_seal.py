#!/usr/bin/env python3
"""test_post_seal.py — offline tests for post-seal gap detection (no network, no gh).

実行: python test_post_seal.py
"""
import sys
import tempfile
from pathlib import Path

import kevtrack
import post_seal

A = {"cveID": "CVE-A", "vendorProject": "Acme", "product": "Web", "dateAdded": "2026-08-03",
     "dueDate": "2026-08-24", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "x",
     "cwes": []}
LATE = dict(A, cveID="CVE-LATE", dateAdded="2026-08-31")   # listed after the sealing run
LATER = dict(A, cveID="CVE-LATER", dateAdded="2026-08-30")
SEPT = dict(A, cveID="CVE-SEPT", dateAdded="2026-09-02")


class FakeIssues:
    """Stands in for GitHub: remembers created titles, like the repo's issue list."""
    def __init__(self):
        self.titles = []

    def list_titles(self):
        return list(self.titles)

    def create(self, title, body):
        assert title and body
        self.titles.append(title)


def _sealed(d, entries, month="2026-08"):
    s = kevtrack.build_open(month, entries, None,
                            fetch_epss_fn=lambda c: {"scores": {}, "date": None}, now_iso="seal")
    kevtrack.seal(s, d)


def _sealed_bytes(d, month="2026-08"):
    return kevtrack.sealed_path(month, d).read_bytes()


def test_late_entry_is_notified_exactly_once():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _sealed(d, [A])                                   # sealed with {A}
        before = _sealed_bytes(d)
        gh = FakeIssues()
        catalog = [A, LATE, SEPT]                         # CISA later lists LATE dated 08-31
        g = post_seal.gap("2026-08", catalog, d)
        assert g["missing"] == ["CVE-LATE"] and g["extra"] == [] and g["window_count"] == 2
        first = post_seal.notify(g, gh.list_titles, gh.create)
        assert first and "CVE" not in first and "[post-seal:" in first and len(gh.titles) == 1
        for _ in range(3):                                # following days: same gap, silent
            again = post_seal.notify(post_seal.gap("2026-08", catalog, d), gh.list_titles, gh.create)
            assert again is None
        assert len(gh.titles) == 1, "same gap must not be filed again"
        assert _sealed_bytes(d) == before, "detection must not touch the seal"


def test_no_gap_files_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _sealed(d, [A])
        gh = FakeIssues()
        g = post_seal.gap("2026-08", [A, SEPT], d)        # next month's entry is not a gap
        assert not post_seal.has_gap(g)
        assert post_seal.notify(g, gh.list_titles, gh.create) is None and gh.titles == []
        # an unsealed month is "no check", not a gap
        assert post_seal.gap("2026-07", [A], d) is None
        assert post_seal.notify(None, gh.list_titles, gh.create) is None and gh.titles == []


def test_a_changed_gap_is_filed_again_and_extra_entries_count():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _sealed(d, [A])
        gh = FakeIssues()
        post_seal.notify(post_seal.gap("2026-08", [A, LATE], d), gh.list_titles, gh.create)
        post_seal.notify(post_seal.gap("2026-08", [A, LATE, LATER], d), gh.list_titles, gh.create)
        assert len(gh.titles) == 2, "a different gap is new information"
        # a sealed entry that left the catalog window is a gap too
        g = post_seal.gap("2026-08", [LATE], d)
        assert g["extra"] == ["CVE-A"] and g["missing"] == ["CVE-LATE"]


def test_signature_is_stable_and_order_independent():
    g1 = {"month": "2026-08", "missing": ["CVE-2", "CVE-1"], "extra": [], "sealed_count": 1,
          "window_count": 3}
    g2 = dict(g1, missing=sorted(g1["missing"]), sealed_count=9)
    # gap() always sorts; counts are not part of the identity of a gap
    assert post_seal.signature(dict(g1, missing=sorted(g1["missing"]))) == post_seal.signature(g2)


def test_notify_cli_treats_a_missing_gap_file_as_failure():
    with tempfile.TemporaryDirectory() as tmp:
        assert post_seal.main(["notify", str(Path(tmp) / "absent.json")]) == 1
        p = Path(tmp) / "g.json"
        post_seal.write_gap(None, p)                       # previous month not sealed
        assert post_seal.main(["notify", str(p)]) == 0


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
