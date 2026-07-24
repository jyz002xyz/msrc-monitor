#!/usr/bin/env python3
"""test_kevtrack.py — offline tests for the prototype (no network).

Covers the open/sealed window lifecycle: open accumulation with EPSS-at-first-observation,
seal immutability + open cleanup, month-boundary open->sealed transition, mid-month-seal
correction, plus regressions (Known+Unknown=total, no evaluative wording, backfill blank).

実行: python test_kevtrack.py
"""
import sys
import tempfile
from pathlib import Path

import kevtrack
import report

A = {"cveID": "CVE-A", "vendorProject": "Acme", "product": "Web", "dateAdded": "2026-07-03",
     "dueDate": "2026-07-24", "knownRansomwareCampaignUse": "Known", "shortDescription": "x", "cwes": []}
B = {"cveID": "CVE-B", "vendorProject": "Globex", "product": "OS", "dateAdded": "2026-07-19",
     "dueDate": "2026-08-09", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "y", "cwes": []}
OLD = {"cveID": "CVE-OLD", "vendorProject": "Acme", "product": "Web", "dateAdded": "2026-06-10",
       "dueDate": "2026-07-01", "knownRansomwareCampaignUse": "Unknown", "shortDescription": "z", "cwes": []}


def _epss(scores):
    seen = []
    def fn(cves):
        seen.extend(cves)
        return {"scores": {c: scores[c] for c in cves if c in scores}, "date": "2026-07-22"}
    fn.seen = seen
    return fn


def test_window_is_calendar_month():
    assert [r["cveID"] for r in kevtrack.window_of([A, B, OLD], "2026-07")] == ["CVE-A", "CVE-B"]
    assert [r["cveID"] for r in kevtrack.window_of([A, B, OLD], "2026-06")] == ["CVE-OLD"]


def test_open_observes_epss_at_first_sight_and_accumulates():
    fn1 = _epss({"CVE-A": {"epss": 0.02, "percentile": 0.10}})
    s1 = kevtrack.build_open("2026-07", [A], None, fetch_epss_fn=fn1, now_iso="t1")
    assert s1["state"] == "open" and s1["kev_added"][0]["epss"] == 0.02
    # next run: B appears; A must NOT be re-queried, its first-observed value is kept
    fn2 = _epss({"CVE-A": {"epss": 0.99, "percentile": 0.99},  # would change A if (wrongly) used
                 "CVE-B": {"epss": 0.50, "percentile": 0.80}})
    s2 = kevtrack.build_open("2026-07", [A, B], s1["kev_added"], fetch_epss_fn=fn2, now_iso="t2")
    a = next(r for r in s2["kev_added"] if r["cve"] == "CVE-A")
    b = next(r for r in s2["kev_added"] if r["cve"] == "CVE-B")
    assert a["epss"] == 0.02, "first-observed EPSS must be preserved"
    assert b["epss"] == 0.50 and "CVE-A" not in fn2.seen, "only the new CVE is queried"


def test_backfill_is_sealed_with_blank_epss():
    s = kevtrack.build_backfill("2026-06", [A, B, OLD], now_iso="t")
    assert s["state"] == "sealed" and s["count"] == 1
    assert s["kev_added"][0]["epss"] is None and not s["epss_observed"]


def test_seal_is_immutable_and_removes_open():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        s = kevtrack.build_open("2026-07", [A], None, fetch_epss_fn=_epss({"CVE-A": {"epss": 0.02, "percentile": 0.1}}), now_iso="first")
        kevtrack.write_open(s, d)
        assert kevtrack.open_path("2026-07", d).exists()
        p, w1 = kevtrack.seal(s, d)
        assert w1 and not kevtrack.open_path("2026-07", d).exists(), "seal removes the open file"
        # second seal must not overwrite; original preserved
        s2 = kevtrack.build_open("2026-07", [A, B], None, fetch_epss_fn=_epss({}), now_iso="SECOND")
        _, w2 = kevtrack.seal(s2, d)
        assert not w2 and kevtrack.load_sealed("2026-07", d)["generated_at"] == "first"


def test_month_boundary_open_to_sealed_transition():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        s = kevtrack.build_open("2026-07", [A, B], None,
                                fetch_epss_fn=_epss({"CVE-A": {"epss": 0.02, "percentile": 0.1},
                                                     "CVE-B": {"epss": 0.5, "percentile": 0.8}}), now_iso="t")
        kevtrack.write_open(s, d)
        # month closes -> seal the open snapshot; observed EPSS carries into the sealed one
        kevtrack.seal(kevtrack.load_open("2026-07", d), d)
        sealed = kevtrack.load_sealed("2026-07", d)
        assert sealed["state"] == "sealed" and sealed["epss_observed"]
        assert next(r for r in sealed["kev_added"] if r["cve"] == "CVE-A")["epss"] == 0.02


def test_old_schema_file_loads_as_sealed():
    # a pre-lifecycle snapshot (no 'state') must read back as sealed, per-row epss_asof filled
    import gzip, json
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        p = kevtrack.sealed_path("2026-05", d); p.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(p, "wt", encoding="utf-8") as f:
            json.dump({"window": "2026-05", "count": 1,
                       "kev_added": [{"cve": "CVE-X", "ransomware": False, "epss": None,
                                      "percentile": None, "vendor": "V", "product": "P",
                                      "date_added": "2026-05-01", "due_date": "", "name": "", "short": ""}]}, f)
        s = kevtrack.load_sealed("2026-05", d)
        assert s["state"] == "sealed" and s["kev_added"][0]["epss_asof"] is None


# --- report regressions ------------------------------------------------------
def _july_open():
    return kevtrack.build_open("2026-07", [A, B], None,
                               fetch_epss_fn=_epss({"CVE-A": {"epss": 0.02, "percentile": 0.10},
                                                    "CVE-B": {"epss": 0.80, "percentile": 0.95}}),
                               now_iso="t", corrections=["re-opened test note"])


def test_report_shows_state_and_corrections():
    md = report.render_markdown(_july_open())
    assert "OPEN" in md and "進行中" in md and "訂正記録" in md and "re-opened test note" in md
    html = report.render_html(_july_open())
    assert "OPEN" in html and "corrections" in html


def test_ransomware_split_and_arithmetic():
    snap = _july_open()
    known, unknown = report.ransomware_split(snap)
    assert (known, unknown) == (1, 1) and known + unknown == snap["count"]
    assert "Known 1 件 / Unknown 1 件" in report.render_markdown(snap)


def test_no_evaluative_wording():
    for md in (report.render_markdown(_july_open()),
               report.render_markdown(kevtrack.build_backfill("2026-06", [OLD], now_iso="t"))):
        for banned in ("盲点", "捉え損ね", "予測力", "見逃", "miss", "blind"):
            assert banned not in md, f"evaluative wording leaked: {banned}"
    assert "深刻度ではない" in report.render_markdown(_july_open())


# --- bilingual publish (Phase 移植-1) ---------------------------------------
def test_publish_month_is_bilingual_and_stateful():
    import publish
    snap = _july_open()
    ja = publish.render_month(snap, "ja")
    en = publish.render_month(snap, "en")
    assert 'lang="ja"' in ja and "定義・注記" in ja and "進行中" in ja
    assert 'lang="en"' in en and "Definitions" in en and "in progress" in en
    # both carry the KEV-not-complete confounder, in each language
    assert "悪用の完全な記録ではない" in ja
    assert "not a complete record of exploitation" in en
    # language switch + home links present
    assert 'href="en.html"' in ja and 'href="ja.html"' in en
    # no evaluative wording leaks into either
    for page in (ja, en):
        for banned in ("盲点", "predictive failure", "blind spot", "見逃"):
            assert banned not in page


def test_publish_index_lists_state_both_langs():
    import publish
    idx = publish.render_index([_july_open(), kevtrack.build_backfill("2026-06", [OLD], now_iso="t")])
    assert "進行中" in idx and "sealed" in idx
    assert "2026-07/ja.html" in idx and "2026-06/en.html" in idx


# --- NVD publication enrichment (path B) ------------------------------------
def _nvd(m):
    return lambda cves: {c: m[c] for c in cves if c in m}


def test_days_to_kev_computation():
    assert kevtrack.days_to_kev({"nvd_published": "2026-06-30T16:00:00", "date_added": "2026-07-07"}) == 7
    # KEV can list before NVD publishes -> negative is shown as-is (not clamped)
    assert kevtrack.days_to_kev({"nvd_published": "2026-07-10", "date_added": "2026-07-07"}) == -3
    assert kevtrack.days_to_kev({"nvd_published": None, "date_added": "2026-07-07"}) is None


def test_fill_nvd_blank_when_unresolved_and_none_skips():
    snap = {"kev_added": [{"cve": "CVE-A", "nvd_published": None},
                          {"cve": "CVE-B", "nvd_published": None}]}
    kevtrack.fill_nvd(snap, _nvd({"CVE-A": "2026-01-01T00:00:00"}))
    got = {r["cve"]: r["nvd_published"] for r in snap["kev_added"]}
    assert got["CVE-A"] == "2026-01-01T00:00:00" and got["CVE-B"] is None   # unresolved -> blank
    snap2 = {"kev_added": [{"cve": "CVE-C", "nvd_published": None}]}
    kevtrack.fill_nvd(snap2, None)
    assert snap2["kev_added"][0]["nvd_published"] is None                    # None fn -> skip


def test_backfill_fills_nvd_even_though_epss_blank():
    s = kevtrack.build_backfill("2026-06", [OLD], fetch_nvd_fn=_nvd({"CVE-OLD": "2026-05-01T00:00:00"}),
                                now_iso="t")
    assert not s["epss_observed"]                                           # EPSS still blank
    assert s["kev_added"][0]["nvd_published"] == "2026-05-01T00:00:00"      # nvd IS filled


def test_migrate_sealed_add_nvd_records_and_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # seal a month WITHOUT nvd (simulate an already-published old-schema sealed month)
        kevtrack.seal(kevtrack.build_backfill("2026-05", [{"cveID": "CVE-M", "dateAdded": "2026-05-10",
            "vendorProject": "V", "product": "P", "knownRansomwareCampaignUse": "Unknown"}], now_iso="t"), d)
        assert kevtrack.load_sealed("2026-05", d)["kev_added"][0]["nvd_published"] is None
        # migrate: fills nvd + records a migration note
        assert kevtrack.migrate_sealed_add_nvd("2026-05", _nvd({"CVE-M": "2026-04-01T00:00:00"}), snap_dir=d)
        s = kevtrack.load_sealed("2026-05", d)
        assert s["kev_added"][0]["nvd_published"] == "2026-04-01T00:00:00"
        assert s["migrations"] and "nvd_published" in s["migrations"][0]
        # idempotent: second migrate is a no-op (already has nvd)
        assert kevtrack.migrate_sealed_add_nvd("2026-05", _nvd({"CVE-M": "1999-01-01"}), snap_dir=d) is False
        assert kevtrack.load_sealed("2026-05", d)["kev_added"][0]["nvd_published"] == "2026-04-01T00:00:00"


def test_publish_shows_nvd_column_and_notes():
    import publish
    snap = kevtrack.build_open("2026-07", [A, B], None,
                               fetch_epss_fn=_epss({"CVE-A": {"epss": 0.02, "percentile": 0.1}}),
                               fetch_nvd_fn=_nvd({"CVE-A": "2026-06-25T00:00:00"}), now_iso="t")
    ja, en = publish.render_month(snap, "ja"), publish.render_month(snap, "en")
    # column + value + the "not time-to-exploitation" caveat, in each language
    assert "NVD 公開日" in ja and "2026-06-25" in ja and "悪用までの時間" in ja
    assert "NVD published" in en and "2026-06-25" in en and "time-to-exploitation" in en
    # the no-summary-statistics stance is stated (per policy: per-CVE values only)
    assert "要約統計" in ja and "No summary statistics" in en


# --- bilingual UX (single index table + language pill + inline caveat) -------
def test_index_is_single_bilingual_table_both_links_per_row():
    import publish
    idx = publish.render_index([_july_open(), kevtrack.build_backfill("2026-06", [OLD], now_iso="t")])
    assert idx.count("<table") == 1, "index must have exactly ONE table"
    for m in ("2026-07", "2026-06"):                       # each row links to BOTH languages
        assert f"{m}/ja.html" in idx and f"{m}/en.html" in idx
    # English-first bilingual index: headers, lang, links, state cell, topbar
    assert 'lang="en"' in idx and "Month / 年月" in idx and "Report / レポート" in idx
    assert idx.index("English") < idx.index("日本語")        # link order English · 日本語 (per row)
    assert "in progress / 進行中" in idx and "Home / トップへ" in idx


def test_month_language_pill_and_inline_caveat():
    import publish
    snap = kevtrack.build_open("2026-07", [A, B], None, fetch_epss_fn=_epss({}),
                               fetch_nvd_fn=_nvd({"CVE-A": "2026-06-25T00:00:00"}), now_iso="t")
    ja = publish.render_month(snap, "ja")
    assert 'class="langpill"' in ja and 'href="en.html"' in ja      # distinct switch, not a nav link
    assert 'class="tablecaveat"' in ja and "悪用までの時間" in ja    # end-caveat near the table
    en = publish.render_month(snap, "en")
    assert 'class="langpill"' in en and 'href="ja.html"' in en and "NOT time-to-exploitation" in en


# --- default descending sort + column-click sort -----------------------------
def test_month_table_default_desc_and_sortable():
    import publish
    snap = kevtrack.build_open("2026-07", [A, B], None, fetch_epss_fn=_epss({}),
                               fetch_nvd_fn=_nvd({}), now_iso="t")   # A=07-03, B=07-19
    h = publish.render_month(snap, "en")
    assert h.index("CVE-B") < h.index("CVE-A"), "default order = dateAdded descending"
    assert 'class="sortable"' in h and "data-sort=" in h and 'aria-sort="descending"' in h
    assert 'data-sort=""' in h                 # blank NVD/days/EPSS sort keys (A,B have none here)
    assert "getElementById('kevtable')" in h   # JS present; rows already desc in HTML (JS-off ok)


def test_month_table_tiebreak_is_deterministic():
    import publish
    C = {"cveID": "CVE-C", "vendorProject": "V", "product": "P", "dateAdded": "2026-07-03",
         "knownRansomwareCampaignUse": "Unknown"}                    # same date as A (07-03)
    h1 = publish.render_month(kevtrack.build_open("2026-07", [C, A], None, fetch_epss_fn=_epss({}),
                                                  fetch_nvd_fn=_nvd({}), now_iso="t"), "en")
    h2 = publish.render_month(kevtrack.build_open("2026-07", [A, C], None, fetch_epss_fn=_epss({}),
                                                  fetch_nvd_fn=_nvd({}), now_iso="t"), "en")
    # same date -> CVE id ascending, regardless of input order (stable, reproducible)
    assert h1.index("CVE-A") < h1.index("CVE-C")
    assert h2.index("CVE-A") < h2.index("CVE-C")


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
