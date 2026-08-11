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

from incidents import (fetch_sec, fetch_stateag, filers, integrity,  # noqa: E402
                       publish, records, stateag_store, store)

# Real rows, trimmed. California's export header is reproduced exactly as published — the
# double space inside "Date(s) of Breach  (if known)" is not a typo here, it is in the file,
# and the parser has to survive it.
CA_CSV = (
    '"Organization Name","Date(s) of Breach  (if known)","Reported Date"\r\n'
    '"American Addiction Centers","05/12/2026","08/07/2026"\r\n'
    '"Cushman & Wakefield","04/21/2026, 04/29/2026","08/07/2026"\r\n'
    '"Hamill & Kaplan","","08/06/2026"\r\n'
    '"Old Filing, Inc.","01/02/2020","03/04/2020"\r\n'
)

# One Washington page, trimmed to three rows. The <time datetime> attributes, the notice link
# on the organisation name and the &#039;/&amp; entities are all as served.
WA_HTML = """
<table><thead><tr><th>Date Reported</th><th>Organization Name</th><th>Date of Breach</th>
<th>Number of Washingtonians Affected</th><th>Information Compromised</th></tr></thead><tbody>
<tr><td><time datetime="2026-07-28T12:00:00Z">07/28/2026</time></td>
<td><a href="https://agportal-s3bucket.s3.amazonaws.com/databreach/BreachA42014.pdf">ADT, Inc.</a></td>
<td><time datetime="2026-04-20T12:00:00Z">04/20/2026</time></td>
<td>5129</td><td>Name; Social Security Number; Full Date of Birth</td></tr>
<tr><td><time datetime="2026-07-27T12:00:00Z">07/27/2026</time></td>
<td><a href="https://agportal-s3bucket.s3.amazonaws.com/databreach/BreachA42008.pdf">JRK Property Holdings, Inc.</a></td>
<td><time datetime="2026-03-26T12:00:00Z">03/26/2026</time></td>
<td>5,667</td><td>Name; Driver&#039;s License; Financial &amp; Banking Information</td></tr>
<tr><td><time datetime="2020-01-05T12:00:00Z">01/05/2020</time></td>
<td><a href="https://agportal-s3bucket.s3.amazonaws.com/databreach/BreachA00001.pdf">Ancient Co.</a></td>
<td><time datetime="2019-12-01T12:00:00Z">12/01/2019</time></td>
<td></td><td>Name</td></tr>
</tbody></table>
"""

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


# --- state AG registries: parsing --------------------------------------------
def test_ca_parses_columns_by_name_not_position():
    rows, stats = fetch_stateag.parse_ca(CA_CSV)
    assert stats["ca_rows_in_export"] == 4
    by = {r["organization"]: r for r in rows}
    aac = by["American Addiction Centers"]
    assert aac["reported_date"] == "2026-08-07", "m/d/Y must be stored as ISO"
    assert aac["breach_dates"] == ["2026-05-12"]
    assert aac["jurisdiction"] == "CA"


def test_ca_reordered_or_renamed_columns_halt_rather_than_misfile():
    """A silently reordered export would put breach dates in the reported-date field."""
    bad = '"Org","When","Reported Date"\r\n"X","01/01/2026","01/02/2026"\r\n'
    try:
        fetch_stateag.parse_ca(bad)
    except fetch_stateag.FetchError as e:
        assert "missing an expected column" in str(e)
    else:
        raise AssertionError("a renamed column must halt the run, not be guessed at")


def test_ca_handles_several_breach_dates_and_none_at_all():
    rows, _ = fetch_stateag.parse_ca(CA_CSV)
    by = {r["organization"]: r for r in rows}
    assert by["Cushman & Wakefield"]["breach_dates"] == ["2026-04-21", "2026-04-29"]
    assert by["Hamill & Kaplan"]["breach_dates"] == [], "an empty cell is not a date"


def test_ca_records_absent_fields_as_absent_not_as_zero():
    """California publishes no affected count. Storing 0 would assert nobody was affected."""
    rows, _ = fetch_stateag.parse_ca(CA_CSV)
    assert all(r["affected"] is None for r in rows)
    assert all(r["data_types"] is None for r in rows)
    assert all(r["notice_url"] is None for r in rows)


def test_ca_since_window_drops_older_rows():
    rows, stats = fetch_stateag.parse_ca(CA_CSV, since="2026-01-01")
    assert stats["ca_rows_in_export"] == 4, "the floor must see the whole export"
    assert stats["ca_rows_kept"] == 3
    assert all(r["reported_date"] >= "2026-01-01" for r in rows)


def test_wa_parses_five_columns_with_entities_and_thousands_separators():
    rows, stats = fetch_stateag.parse_wa(WA_HTML)
    assert stats["wa_rows"] == 3 and stats["wa_malformed_rows"] == 0
    by = {r["organization"]: r for r in rows}
    assert by["ADT, Inc."]["affected"] == 5129
    assert by["JRK Property Holdings, Inc."]["affected"] == 5667, "5,667 must parse"
    assert "Driver's License" in by["JRK Property Holdings, Inc."]["data_types"]
    assert "&amp;" not in by["JRK Property Holdings, Inc."]["data_types"]


def test_wa_prefers_the_machine_readable_time_attribute():
    rows, _ = fetch_stateag.parse_wa(WA_HTML)
    assert {r["reported_date"] for r in rows} >= {"2026-07-28", "2026-07-27"}
    assert all(len(r["reported_date"]) == 10 for r in rows)


def test_wa_keeps_the_notice_document_the_organisation_itself_filed():
    """That link is the primary source, and its id is the row's identity."""
    rows, _ = fetch_stateag.parse_wa(WA_HTML)
    adt = [r for r in rows if r["organization"] == "ADT, Inc."][0]
    assert adt["notice_url"].endswith("BreachA42014.pdf")
    assert adt["key"] == "WA:BreachA42014", "the source's own id, not a composed one"


def test_wa_blank_affected_stays_blank():
    rows, _ = fetch_stateag.parse_wa(WA_HTML)
    ancient = [r for r in rows if r["organization"] == "Ancient Co."][0]
    assert ancient["affected"] is None


def test_wa_a_changed_column_layout_is_counted_not_swallowed():
    broken = "<table><tr><td>07/28/2026</td><td>Org</td><td>x</td></tr></table>"
    _, stats = fetch_stateag.parse_wa(broken)
    assert stats["wa_malformed_rows"] == 1


def test_registry_guard_passes_through_a_page_boundary_duplicate():
    """Measured live: one document straddled a page boundary. Benign, but it must be reported,
    because the same instability could skip a row instead of repeating one."""
    f, out = integrity.evaluate_registry([], _rstats(wa_duplicate_keys=1),
                                         {"filings": 1}, {"filings": 1})
    assert f == [], "a boundary duplicate is not a halt — the store dedupes on the document id"
    assert out["wa_duplicate_keys"] == 1, "but it must reach the run log"


# --- state AG registries: the store ------------------------------------------
def _reg(rows=None, seen="2026-08-10"):
    rows = rows if rows is not None else fetch_stateag.parse_wa(WA_HTML)[0]
    return stateag_store.merge(stateag_store.empty(), rows, seen_date=seen)


def test_registry_merge_is_idempotent_and_never_rewrites():
    reg, added = _reg()
    assert len(added) == 3
    reg["filings"][0]["organization"] = "EDITED"
    reg, added2 = stateag_store.merge(reg, fetch_stateag.parse_wa(WA_HTML)[0],
                                      seen_date="2026-09-01")
    assert added2 == [], "a second run must add nothing"
    assert reg["filings"][0]["organization"] == "EDITED", "recorded rows are never rewritten"
    assert reg["filings"][0]["first_seen"] == "2026-08-10", "first_seen is written once"


def test_registry_output_carries_no_run_timestamp():
    """A day with nothing new must produce a byte-identical file or no-op detection breaks."""
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "state_ag.json"
        reg, _ = _reg()
        stateag_store.save(p, reg)
        first = p.read_bytes()
        again, added = stateag_store.merge(stateag_store.load(p),
                                           fetch_stateag.parse_wa(WA_HTML)[0],
                                           seen_date="2027-01-01")
        stateag_store.save(p, again)
        assert added == []
        assert p.read_bytes() == first, "a no-op run rewrote the file"


def test_registry_coverage_widens_but_never_narrows():
    reg = stateag_store.note_coverage(stateag_store.empty(), "2026-05-01")
    stateag_store.note_coverage(reg, "2026-07-01")
    assert reg["coverage"]["since"] == "2026-05-01"
    stateag_store.note_coverage(reg, "2026-01-01")
    assert reg["coverage"]["since"] == "2026-01-01"


def test_the_same_breach_filed_in_two_states_stays_two_rows():
    """Merging them would be deciding they are the same event. This section does not decide."""
    ca, _ = fetch_stateag.parse_ca(
        '"Organization Name","Date(s) of Breach  (if known)","Reported Date"\r\n'
        '"ADT, Inc.","04/20/2026","07/28/2026"\r\n')
    wa, _ = fetch_stateag.parse_wa(WA_HTML)
    reg, added = stateag_store.merge(stateag_store.empty(), ca + wa, seen_date="2026-08-10")
    adt = [f for f in reg["filings"] if f["organization"] == "ADT, Inc."]
    assert len(adt) == 2
    assert {f["jurisdiction"] for f in adt} == {"CA", "WA"}


def test_registry_store_records_only_declared_fields():
    """An extra key in a parser must not leak into the permanent record."""
    rows = fetch_stateag.parse_wa(WA_HTML)[0]
    rows[0]["scratch_note"] = "an internal value that must not be stored"
    reg, _ = stateag_store.merge(stateag_store.empty(), rows, seen_date="2026-08-10")
    assert all("scratch_note" not in f for f in reg["filings"])


# --- state AG registries: the integrity gate ---------------------------------
def _rstats(**over):
    s = {"ca_rows_in_export": 5000, "ca_rows_kept": 100, "wa_rows": 50,
         "wa_malformed_rows": 0, "wa_pages_read": 1}
    s.update(over)
    return s


def test_registry_guard_allows_a_day_with_nothing_new():
    """Zero NEW rows is ordinary — the sources publish on business days, with a lag."""
    f, _ = integrity.evaluate_registry([], _rstats(), {"filings": 10}, {"filings": 10})
    assert f == []


def test_registry_guard_halts_when_a_source_returns_nothing():
    """The inversion of the SEC gate: these sources always return rows, so zero is a break."""
    f, _ = integrity.evaluate_registry([], _rstats(ca_rows_in_export=0),
                                       {"filings": 10}, {"filings": 10})
    assert any("California export returned 0 rows" in x for x in f)
    f, _ = integrity.evaluate_registry([], _rstats(wa_rows=0),
                                       {"filings": 10}, {"filings": 10})
    assert any("Washington returned 0 rows" in x for x in f)


def test_registry_guard_halts_on_a_changed_table_layout():
    f, _ = integrity.evaluate_registry([], _rstats(wa_malformed_rows=3),
                                       {"filings": 1}, {"filings": 1})
    assert any("5-column layout" in x for x in f)


def test_registry_guard_halts_on_missing_fetch():
    f, _ = integrity.evaluate_registry(None, None, None, None)
    assert any("did not complete" in x for x in f)


def test_registry_guard_halts_on_a_shrinking_record():
    f, _ = integrity.evaluate_registry([], _rstats(), {"filings": 20}, {"filings": 19})
    assert any("append-only" in x for x in f)


def test_registry_guard_halts_on_a_flood():
    f, _ = integrity.evaluate_registry([], _rstats(), {"filings": 0}, {"filings": 5000})
    assert any("exceeds" in x for x in f)


def test_registry_guard_rejects_a_jurisdiction_this_layer_does_not_collect():
    row = dict(fetch_stateag.parse_wa(WA_HTML)[0][0], jurisdiction="ME")
    f, _ = integrity.evaluate_registry([row], _rstats(), {"filings": 0}, {"filings": 1})
    assert any("does not collect" in x for x in f)


def test_registry_guard_halts_on_a_row_missing_its_organisation():
    row = dict(fetch_stateag.parse_wa(WA_HTML)[0][0], organization="")
    f, _ = integrity.evaluate_registry([row], _rstats(), {"filings": 0}, {"filings": 1})
    assert any("organization" in x for x in f)


# --- state AG registries: rendering ------------------------------------------
def _reg_pages(reg=None, since="2026-05-01"):
    reg = reg if reg is not None else _reg()[0]
    if since:
        stateag_store.note_coverage(reg, since)
    return {lang: publish.render(store.empty(), records.empty(), lang, reg)
            for lang in ("en", "ja")}


def test_registry_section_renders_the_facts_the_source_publishes():
    for lang, page in _reg_pages().items():
        assert "ADT, Inc." in page, lang
        assert "5,129" in page, f"{lang}: the affected count must be shown"
        assert "BreachA42014.pdf" in page, f"{lang}: the notice link must be reachable"
        assert "Social Security Number" in page, f"{lang}: the state's own wording"


def test_registry_blank_cells_are_left_blank_not_filled_with_a_value():
    """California publishes no count; a 0 or a dash would state something the source does not."""
    ca, _ = fetch_stateag.parse_ca(CA_CSV)
    reg, _ = stateag_store.merge(stateag_store.empty(), ca, seen_date="2026-08-10")
    for lang, page in _reg_pages(reg).items():
        assert "American Addiction Centers" in page, lang
        assert ">0<" not in page, f"{lang}: an absent count was rendered as zero"


def test_registry_says_a_blank_means_not_published_not_zero():
    en, ja = _reg_pages()["en"], _reg_pages()["ja"]
    assert "never that the value is zero" in en
    assert "値が0という意味ではありません" in ja


def test_registry_coverage_start_is_stated():
    for lang, page in _reg_pages().items():
        assert "2026-05-01" in page, f"{lang}: the collected-from date is not on the page"


def test_registry_publication_lag_is_stated():
    """An absent recent incident means "not published yet", and the page has to say so."""
    en = _reg_pages()["en"]
    # Asserted without the apostrophe: _h() escapes it, and the point is the measurement.
    assert "newest entry was 3 days old" in en
    assert "has not been published yet" in en
    assert "まだ公開されていない" in _reg_pages()["ja"]


def test_registry_display_limit_states_what_is_not_shown():
    rows = []
    for i in range(publish.REGISTRY_DISPLAY_LIMIT + 5):
        rows.append({"key": f"WA:B{i}", "jurisdiction": "WA", "organization": f"Org {i}",
                     "reported_date": "2026-07-01", "breach_dates": [], "affected": None,
                     "data_types": None, "notice_url": None, "source_url": "x"})
    reg, _ = stateag_store.merge(stateag_store.empty(), rows, seen_date="2026-08-10")
    en = _reg_pages(reg)["en"]
    assert f"{publish.REGISTRY_DISPLAY_LIMIT} most recent" in en
    assert en.count("<tr>") <= publish.REGISTRY_DISPLAY_LIMIT + 4, "more rows rendered than stated"


def test_registry_scope_denies_the_two_states_are_a_country():
    en, ja = _reg_pages()["en"], _reg_pages()["ja"]
    assert "two states, not a country" in en
    assert "forty-eight states are absent" in en
    assert "2州であって、米国全体ではありません" in ja


def test_registry_states_are_never_added_together():
    """Same commitment as the SEC layer: no totals, because the units are not comparable."""
    en, ja = _reg_pages()["en"], _reg_pages()["ja"]
    assert "never added together" in en
    assert "足し合わせることはせず" in ja


def test_registry_terms_are_stated_per_source_not_merged():
    """California is public domain; Washington's terms were not found. Not the same footing."""
    en = _reg_pages()["en"]
    assert "public domain" in en
    assert "No conditions-of-use or copyright page was found" in en
    ja = _reg_pages()["ja"]
    assert "パブリックドメイン" in ja
    assert "利用条件・著作権のページが見当たらず" in ja


def test_registry_organisation_names_are_escaped():
    rows = [{"key": "WA:X", "jurisdiction": "WA",
             "organization": '<script>alert("x")</script> & Co.',
             "reported_date": "2026-07-01", "breach_dates": [], "affected": None,
             "data_types": "a & b", "notice_url": None, "source_url": "x"}]
    reg, _ = stateag_store.merge(stateag_store.empty(), rows, seen_date="2026-08-10")
    en = _reg_pages(reg)["en"]
    assert "<script>alert" not in en
    assert "&lt;script&gt;" in en


# --- state AG registries: filer names that might be people ---------------------
def test_obvious_organisations_are_never_queued():
    """The queue has to stay small or it stops being read. Corporate forms pass straight through."""
    for n in ("ADT, Inc.", "Station Casinos, LLC", "UCLA Health", "Cushman & Wakefield",
              "Fresno County Department of Social Services", "JRK Property Holdings, Inc.",
              "American Addiction Centers", "Baylor Genetics", "Lumexa Imaging"):
        assert not filers.looks_like_person(n), n


def test_person_shaped_names_are_queued_for_a_human():
    for n in ("Robert Arshagouni", "Amin Dean, CPA", "Andrea Yaley, DDS", "Bill Pollard CPA",
              "Dr. Jane Smith", "John A. Doe", "Maria de Silva", "Sarah Chen, M.D."):
        assert filers.looks_like_person(n), n


def test_a_post_nominal_outweighs_a_corporate_word():
    """`Andrew Lundholm CPA Inc` is still a practitioner's practice — ask about it."""
    assert filers.looks_like_person("Andrew Lundholm CPA Inc")


def test_the_heuristic_only_asks_and_never_concludes():
    """A flagged name is undecided, not "an individual"."""
    assert filers.decide("Brooks Brothers", filers.empty_decisions()) == "undecided"
    approved = {"schema": 1, "organisations": ["Brooks Brothers"], "individual_hashes": []}
    assert filers.decide("Brooks Brothers", approved) == "organisation"


def test_a_decided_individual_is_recorded_as_a_hash_not_a_name():
    d = {"schema": 1, "organisations": [],
         "individual_hashes": [filers.name_hash("Robert Arshagouni")]}
    assert filers.decide("Robert Arshagouni", d) == "individual"
    assert "Robert Arshagouni" not in json.dumps(d), \
        "deciding 'this is a person' must not write the person's name into a public file"


def test_decisions_file_rejects_a_name_pasted_into_the_hash_list():
    errs = filers.validate_decisions(
        {"schema": 1, "organisations": [], "individual_hashes": ["Robert Arshagouni"]})
    assert any("sha256" in e for e in errs)


def test_withheld_rows_never_reach_the_record():
    """The published page is not the only public surface — this repo is public too."""
    rows = [
        {"key": "CA:2026-08-05:robert-arshagouni:", "jurisdiction": "CA",
         "organization": "Robert Arshagouni", "reported_date": "2026-08-05",
         "breach_dates": [], "affected": None, "data_types": None, "notice_url": None,
         "source_url": "x"},
        {"key": "WA:B1", "jurisdiction": "WA", "organization": "ADT, Inc.",
         "reported_date": "2026-07-28", "breach_dates": [], "affected": 5129,
         "data_types": None, "notice_url": None, "source_url": "x"},
    ]
    keep, held = filers.split(rows, filers.empty_decisions())
    assert [r["organization"] for r in keep] == ["ADT, Inc."]
    assert [r["organization"] for r in held] == ["Robert Arshagouni"]
    reg, _ = stateag_store.merge(stateag_store.empty(), keep, seen_date="2026-08-10")
    assert "Arshagouni" not in json.dumps(reg, ensure_ascii=False)


def test_the_queue_holds_no_names():
    _, held = filers.split(
        [{"key": "CA:x", "jurisdiction": "CA", "organization": "Robert Arshagouni",
          "reported_date": "2026-08-05", "breach_dates": [], "affected": None,
          "data_types": None, "notice_url": None, "source_url": "x"}],
        filers.empty_decisions())
    q, new = filers.update_queue(filers.empty_queue(), held, filers.empty_decisions(),
                                 seen_date="2026-08-10")
    assert len(q["pending"]) == 1 and len(new) == 1
    assert "Arshagouni" not in json.dumps(q, ensure_ascii=False)
    assert q["pending"][0]["hash"] == filers.name_hash("Robert Arshagouni")


def test_a_name_already_waiting_does_not_re_notify_every_day():
    """A notice that fires daily for the same name trains the reader to ignore it."""
    held = [{"key": "CA:x", "jurisdiction": "CA", "organization": "Robert Arshagouni",
             "reported_date": "2026-08-05", "breach_dates": [], "affected": None,
             "data_types": None, "notice_url": None, "source_url": "x"}]
    d = filers.empty_decisions()
    q, new1 = filers.update_queue(filers.empty_queue(), held, d, seen_date="2026-08-10")
    q, new2 = filers.update_queue(q, held, d, seen_date="2026-08-11")
    assert len(new1) == 1 and new2 == []
    assert len(q["pending"]) == 1


def test_the_queue_empties_when_a_decision_lands():
    """A queue that never shrinks is not a queue. This file is a work list, not a record."""
    held = [{"key": "CA:x", "jurisdiction": "CA", "organization": "Nickey Kehoe",
             "reported_date": "2026-05-26", "breach_dates": [], "affected": None,
             "data_types": None, "notice_url": None, "source_url": "x"}]
    q, _ = filers.update_queue(filers.empty_queue(), held, filers.empty_decisions(),
                               seen_date="2026-08-10")
    assert len(q["pending"]) == 1
    approved = {"schema": 1, "organisations": ["Nickey Kehoe"], "individual_hashes": []}
    assert filers.resolved_organisations(q, approved)["pending"] == []
    q2, _ = filers.update_queue(filers.empty_queue(), held,
                                {"schema": 1, "organisations": [],
                                 "individual_hashes": [filers.name_hash("Nickey Kehoe")]},
                                seen_date="2026-08-10")
    assert q2["pending"] == []


def test_an_approved_organisation_publishes_from_then_on():
    rows = [{"key": "CA:x", "jurisdiction": "CA", "organization": "Brooks Brothers",
             "reported_date": "2026-08-05", "breach_dates": [], "affected": None,
             "data_types": None, "notice_url": None, "source_url": "x"}]
    approved = {"schema": 1, "organisations": ["Brooks Brothers"], "individual_hashes": []}
    keep, held = filers.split(rows, approved)
    assert len(keep) == 1 and held == []


def test_the_page_says_how_many_names_are_held_back():
    """A table that quietly omits rows reads as complete. This one says what is missing."""
    q = {"schema": 1, "pending": [{"hash": "a" * 64, "jurisdiction": "CA",
                                   "reported_date": "2026-08-05", "first_seen": "2026-08-10"}]}
    reg, _ = _reg()
    en = publish.render(store.empty(), records.empty(), "en", reg, q)
    ja = publish.render(store.empty(), records.empty(), "ja", reg, q)
    assert "1 filer name(s) are held back" in en
    assert "held back from this table, and from the record behind it" in en
    assert "この表からも背後の記録からも保留しています" in ja


def test_nothing_is_said_about_withholding_when_nothing_is_withheld():
    reg, _ = _reg()
    en = publish.render(store.empty(), records.empty(), "en", reg, filers.empty_queue())
    assert "held back" not in en


def test_registry_layer_is_absent_when_nothing_is_recorded():
    for lang, page in {l: publish.render(store.empty(), records.empty(), l)
                       for l in ("en", "ja")}.items():
        assert ("No state filing has been recorded yet" in page
                or "州への届出はまだ記録されていません" in page), lang


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
