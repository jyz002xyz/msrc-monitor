#!/usr/bin/env python3
"""test_incidents.py — offline tests for the disclosure record. No network.

Run: python incidents/test_incidents.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from incidents import fetch_sec, integrity, publish, records, store  # noqa: E402

# A reduced but REAL search payload: the River Financial 8-K/A chain (one incident, five
# filings), one unrelated 1.05 filing, one hit whose items do not include 1.05 (an exhibit of
# a filing made under other items), and the same filing returned twice as two documents.
FIXTURE = {
    "hits": {"total": {"value": 8}, "hits": [
        {"_source": {"adsh": "0001193125-26-282946", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-06-25", "period_ending": "2026-06-19",
                     "file_type": "8-K", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0001193125-26-282946", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-06-25", "period_ending": "2026-06-19",
                     "file_type": "EX-99.1", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0001193125-26-295704", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-07-06", "period_ending": "2026-06-19",
                     "file_type": "8-K/A", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0001193125-26-300763", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-07-10", "period_ending": "2026-06-19",
                     "file_type": "8-K/A", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0001193125-26-307288", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-07-17", "period_ending": "2026-06-19",
                     "file_type": "8-K/A", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0001193125-26-325324", "ciks": ["0001641601"],
                     "display_names": ["River Financial Corp  (RVRF)  (CIK 0001641601)"],
                     "file_date": "2026-07-30", "period_ending": "2026-06-19",
                     "file_type": "8-K/A", "items": ["1.05", "9.01"]}},
        {"_source": {"adsh": "0000318154-26-000119", "ciks": ["0000318154"],
                     "display_names": ["AMGEN INC  (AMGN)  (CIK 0000318154)"],
                     "file_date": "2026-07-31", "period_ending": "2026-07-29",
                     "file_type": "8-K", "items": ["1.05"]}},
        # Mentions "Item 1.05" in its text but was filed under other items -> must be dropped.
        {"_source": {"adsh": "0002033770-26-000004", "ciks": ["0002033770"],
                     "display_names": ["CID Holdco, Inc.  (DAIC)  (CIK 0002033770)"],
                     "file_date": "2026-07-22", "period_ending": "2026-07-21",
                     "file_type": "EX-10.1", "items": ["1.01", "9.01"]}},
    ]}
}


# --- parsing / dedupe --------------------------------------------------------
def test_adsh_dedupe_and_item_filter():
    filings, stats = fetch_sec.parse(FIXTURE)
    assert stats["documents_with_1_05"] == 7, stats
    assert stats["filings_after_adsh_dedupe"] == 6, stats     # 8-K + EX-99.1 collapse to one
    adsh = [f["adsh"] for f in filings]
    assert len(adsh) == len(set(adsh)), "adsh must be unique"
    assert "0002033770-26-000004" not in adsh, "a filing without item 1.05 must be dropped"


def test_company_name_and_url():
    filings, _ = fetch_sec.parse(FIXTURE)
    f = next(x for x in filings if x["adsh"] == "0000318154-26-000119")
    assert f["company"] == "AMGEN INC", f["company"]
    assert f["url"] == ("https://www.sec.gov/Archives/edgar/data/318154/"
                        "000031815426000119/0000318154-26-000119-index.htm"), f["url"]


def test_user_agent_is_required_and_not_hardcoded():
    saved = os.environ.pop("SEC_USER_AGENT", None)
    try:
        raised = False
        try:
            fetch_sec.user_agent()
        except fetch_sec.FetchError:
            raised = True
        assert raised, "a missing SEC_USER_AGENT must halt (SEC returns 403 without one)"
    finally:
        if saved is not None:
            os.environ["SEC_USER_AGENT"] = saved
    src = Path(fetch_sec.__file__).read_text(encoding="utf-8")
    assert "@" not in src.split("ACCESS RULES")[0].split('"""')[-1], \
        "no contact address may be hardcoded in this public repo"


# --- incident key / append-only ---------------------------------------------
def test_amendment_chain_is_one_incident():
    filings, _ = fetch_sec.parse(FIXTURE)
    st, added = store.merge(store.empty(), filings, seen_date="2026-08-08")
    c = store.counts(st)
    assert c["incidents"] == 2, c            # River Financial + Amgen
    assert c["statements"] == 6, c
    river = next(i for i in st["incidents"] if i["cik"] == "0001641601")
    assert river["key"] == "0001641601:2026-06-19"
    assert len(river["statements"]) == 5, "the 8-K/A chain belongs to one incident"
    assert {s["form"] for s in river["statements"]} == {"8-K", "8-K/A"}


def test_same_company_different_report_date_is_a_second_incident():
    filings, _ = fetch_sec.parse(FIXTURE)
    st, _ = store.merge(store.empty(), filings, seen_date="2026-08-08")
    second = [{"adsh": "0001193125-26-999999", "cik": "0001641601",
               "company": "River Financial Corp", "filing_date": "2026-08-05",
               "report_date": "2026-08-01", "form": "8-K", "items": ["1.05"],
               "url": "https://example.invalid/x"}]
    st, added = store.merge(st, second, seen_date="2026-08-08")
    assert len(added) == 1
    keys = {i["key"] for i in st["incidents"] if i["cik"] == "0001641601"}
    assert keys == {"0001641601:2026-06-19", "0001641601:2026-08-01"}, keys


def test_merge_is_idempotent_and_never_rewrites():
    filings, _ = fetch_sec.parse(FIXTURE)
    st, _ = store.merge(store.empty(), filings, seen_date="2026-08-08")
    snapshot = json.dumps(st, ensure_ascii=False, sort_keys=True)
    st2, added = store.merge(st, filings, seen_date="2026-09-01")
    assert added == [], "re-running the same window must add nothing"
    assert json.dumps(st2, ensure_ascii=False, sort_keys=True) == snapshot, \
        "an existing statement must never be rewritten (first_seen must not move)"


def test_store_output_carries_no_run_timestamp():
    """A no-op run has to produce a byte-identical file, or no-op detection cannot work."""
    filings, _ = fetch_sec.parse(FIXTURE)
    st, _ = store.merge(store.empty(), filings, seen_date="2026-08-08")
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "d.json"
        store.save(p, st)
        a = p.read_bytes()
        st2 = store.load(p)
        st2, _ = store.merge(st2, filings, seen_date="2026-12-31")
        store.save(p, st2)
        assert p.read_bytes() == a, "a second run with no new data changed the file"


# --- integrity guard ---------------------------------------------------------
def test_guard_allows_an_empty_day():
    failures, _ = integrity.evaluate([], {"hits_returned": 0, "page_size": 100},
                                     {"incidents": 3, "statements": 5},
                                     {"incidents": 3, "statements": 5})
    assert failures == [], failures       # zero filings is the ordinary case, not a fault


def test_guard_halts_on_missing_fetch():
    failures, _ = integrity.evaluate(None, None, None, None)
    assert failures and "fetch did not complete" in failures[0]


def test_guard_halts_on_shrinking_record():
    failures, _ = integrity.evaluate([], {"hits_returned": 0, "page_size": 100},
                                     {"incidents": 3, "statements": 5},
                                     {"incidents": 3, "statements": 4})
    assert any("append-only" in f for f in failures), failures


def test_guard_halts_at_the_page_limit():
    failures, _ = integrity.evaluate([], {"hits_returned": 100, "page_size": 100},
                                     {"incidents": 0, "statements": 0},
                                     {"incidents": 0, "statements": 0})
    assert any("page limit" in f for f in failures), failures


def test_guard_halts_on_a_flood():
    prev = {"incidents": 0, "statements": 0}
    new = {"incidents": 60, "statements": 60}
    failures, _ = integrity.evaluate([], {"hits_returned": 60, "page_size": 100}, prev, new)
    assert any("exceeds" in f for f in failures), failures


def test_fetch_refuses_a_truncated_window():
    saved = fetch_sec.fetch_raw
    fetch_sec.fetch_raw = lambda s, e: {"hits": {"total": {"value": 500}, "hits": [
        {"_source": {"adsh": f"x-{i}", "ciks": ["1"], "display_names": ["A  (CIK 1)"],
                     "file_date": "2026-01-01", "period_ending": "2026-01-01",
                     "file_type": "8-K", "items": ["1.05"]}} for i in range(100)]}}
    try:
        raised = False
        try:
            fetch_sec.fetch("2026-01-01", "2026-12-31")
        except fetch_sec.FetchError as e:
            raised = "page limit" in str(e)
        assert raised, "a window at the page limit must halt, not truncate silently"
    finally:
        fetch_sec.fetch_raw = saved


# --- curated layer -----------------------------------------------------------
def _rec(**over):
    r = {"id": "r1", "organization": "Example Corp", "type": "ransomware",
         "statements": [{"date": "2026-08-01", "kind": "organization",
                         "source": "Example Corp announcement",
                         "url": "https://example.invalid/a"}]}
    r.update(over)
    return {"schema": 1, "records": [r]}


def test_records_empty_file_validates():
    assert records.validate(records.empty()) == []


def test_records_reject_personal_name_fields():
    doc = _rec()
    doc["records"][0]["statements"][0]["person"] = "Someone"
    errs = records.validate(doc)
    assert any("forbidden field" in e for e in errs), errs


def test_records_reject_attacker_as_fact():
    doc = _rec()
    doc["records"][0]["attacker"] = "SomeGroup"
    errs = records.validate(doc)
    assert any("forbidden field" in e for e in errs), errs


def test_attacker_claim_requires_who_claimed_it():
    doc = _rec(attacker_claims=[{"date": "2026-08-02", "claim": "posted a listing",
                                 "url": "https://example.invalid/c"}])
    errs = records.validate(doc)
    assert any("claimed_by" in e for e in errs), errs
    doc = _rec(attacker_claims=[{"date": "2026-08-02", "claimed_by": "a leak-site posting",
                                 "claim": "posted a listing", "url": "https://example.invalid/c"}])
    assert records.validate(doc) == []


def test_retraction_must_name_what_it_retracts():
    doc = _rec()
    doc["records"][0]["statements"].append(
        {"date": "2026-08-05", "kind": "retraction", "source": "Outlet",
         "url": "https://example.invalid/r"})
    assert any("retracts" in e for e in records.validate(doc)), records.validate(doc)


def test_statement_needs_a_checkable_url():
    doc = _rec()
    doc["records"][0]["statements"][0]["url"] = ""
    assert any("url" in e for e in records.validate(doc))


# --- rendering ---------------------------------------------------------------
def _pages(since: str | None = "2026-05-09"):
    filings, _ = fetch_sec.parse(FIXTURE)
    st, _ = store.merge(store.empty(), filings, seen_date="2026-08-08")
    if since:
        store.note_coverage(st, since)
    return {lang: publish.render(st, records.empty(), lang) for lang in ("en", "ja")}


# --- coverage ----------------------------------------------------------------
def test_coverage_start_is_stated_next_to_the_table():
    """A table with no start reads as the complete history of Item 1.05, which it is not."""
    for lang, page in _pages().items():
        assert "2026-05-09" in page, f"{lang}: the collected-from date is not on the page"
        assert page.index('class="coverage"') < page.index("<table"), \
            f"{lang}: the coverage note must precede the table it qualifies"
    assert "not a complete history" in _pages()["en"]
    assert "全履歴ではありません" in _pages()["ja"]


def test_amendment_only_rows_are_explained():
    """An 8-K/A with no original above it has two possible causes; both are named.

    Observed live: STRYKER CORP filed under Item 8.01 on 2026-03-11 and switched to Item 1.05
    in an 8-K/A on 2026-04-09, so the record legitimately holds an amendment with no original.
    Leaving that unexplained reads as a gap in the collection, which it is not.
    """
    en, ja = _pages()["en"], _pages()["ja"]
    assert "switched to Item 1.05" in en and "before the date this record begins" in en, en[:0]
    assert "Item 1.05 に切り替えた場合" in ja and "開始日より前に提出された場合" in ja


def test_coverage_widens_but_never_narrows():
    st = store.note_coverage(store.empty(), "2026-05-09")
    assert st["coverage"]["since"] == "2026-05-09"
    store.note_coverage(st, "2026-08-01")           # a later, narrower daily window
    assert st["coverage"]["since"] == "2026-05-09", "a later window must not narrow coverage"
    store.note_coverage(st, "2026-01-01")           # an earlier backfill
    assert st["coverage"]["since"] == "2026-01-01", "an earlier backfill must widen coverage"


def test_coverage_absent_says_so_rather_than_implying_completeness():
    import re
    for lang, page in _pages(since=None).items():
        m = re.search(r'<div class="coverage">(.*?)</div>', page, re.S)
        assert m, f"{lang}: the coverage block must still be present"
        assert not re.search(r"\d{4}-\d{2}-\d{2}", m.group(1)), \
            f"{lang}: must not invent a start date when none is recorded: {m.group(1)}"


def test_scope_is_stated_before_any_table():
    for lang, page in _pages().items():
        assert page.index('class="scope"') < page.index("<table"), \
            f"{lang}: the scope must be readable before the first table"


def test_scope_states_the_specific_exclusions():
    en, ja = _pages()["en"], _pages()["ja"]
    for needle in ("OAIC", "Item 1.05", "healthcare"):
        assert needle in en, f"missing from the EN scope: {needle}"
    for needle in ("OAIC", "Item 1.05", "医療"):
        assert needle in ja, f"missing from the JA scope: {needle}"
    assert "cannot be retrieved" in en and "取得できない" in ja


def test_no_totals_are_rendered():
    """Counts across sources are not comparable, so no aggregate is shown.

    Checked structurally rather than by banned words: the scope text has to be free to SAY
    "no totals and no per-region counts are shown", which a substring ban would flag.
    """
    import re
    for lang, page in _pages().items():
        # No summary/aggregate element is emitted at all.
        for marker in ('class="total', 'class="count', "<tfoot"):
            assert marker not in page, f"{lang}: aggregate element {marker}"
        # Outside the tables and the static definitional prose (scope / layer notes, which
        # other tests pin), no "N incidents / N 件" summary of the data.
        body = re.sub(r"<table.*?</table>", "", page, flags=re.S)
        body = re.sub(r'<div class="scope">.*?</ul></div>', "", body, flags=re.S)
        body = re.sub(r'<div class="layer">.*?</div>', "", body, flags=re.S)
        body = re.sub(r"<[^>]+>", " ", body)
        for pat in (r"\d+\s+incidents\b", r"\d+\s*件"):
            assert not re.search(pat, body), f"{lang}: rendered a count: {re.search(pat, body)[0]}"


def test_the_no_totals_commitment_is_stated():
    en, ja = _pages()["en"], _pages()["ja"]
    assert "no totals and no per-region counts" in en, "EN must state that no totals are shown"
    assert "合計件数も地域別件数も示しません" in ja, "JA must state that no totals are shown"


def test_empty_curated_layer_says_so():
    for lang, page in _pages().items():
        assert 'class="empty"' in page, f"{lang}: an empty layer must say it is empty"


def test_topbar_reaches_this_sections_own_index():
    """en.html / ja.html are sub-pages; without this link the section landing page is
    unreachable from them. The KEV month pages already work this way."""
    import re
    for lang, label in (("en", "Disclosed incidents"), ("ja", "開示インシデント")):
        nav = re.search(r'<div class="nav">.*?</div>', _pages()[lang], re.S).group(0)
        assert 'href="index.html"' in nav, f"{lang}: no link to the section index"
        assert label in nav, f"{lang}: section label missing from the nav"
        # single-language page -> single-language labels (SITE_BILINGUAL_CONVENTION rule 2)
        other = "開示インシデント" if lang == "en" else "Disclosed incidents"
        assert other not in nav, f"{lang}: the other language leaked into the nav"


def test_both_languages_link_to_each_other():
    pages = _pages()
    assert 'href="ja.html"' in pages["en"]
    assert 'href="en.html"' in pages["ja"]


def test_sec_trademark_and_affiliation_line():
    for lang, page in _pages().items():
        assert ("not affiliated" in page) or ("提携しておらず" in page), lang


def test_render_only_needs_no_network():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "incidents"
        written = publish.build_site(store.empty(), records.empty(), out)
        assert len(written) == 3
        assert (out / "index.html").exists()


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
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
