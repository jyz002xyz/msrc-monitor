#!/usr/bin/env python3
"""
test_epss_percentile_display.py — pin the display format of the EPSS table.

Fixed spec (display layer only; internal data stays as decimals):
    - percentile column: percent format, 1 decimal place (e.g. 0.97192 -> "97.2%").
    - epss column:       kept as a decimal (probability, e.g. "0.2035"). Not percentized.
    - Japanese label:    "パーセンタイル" (formerly "百分位"). English stays "Percentile".

Inspects the generated docx (drafts/report_{ja,en}.docx). Effective after build.sh runs.
Skips if not generated (same policy as the real-chart check in test_anonymize_gate).
"""
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRAFTS = os.path.join(ROOT, "drafts")

PCT_RE = re.compile(r"^\d{1,3}\.\d%$")      # 97.2% / 75.0% / 100.0%
EPSS_RE = re.compile(r"^0\.\d{4}$")          # 0.2035 (4-decimal, non-percent)
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _rows(docx_path):
    """Return all table rows of the docx as a list of cell arrays (naive XML parse)."""
    with zipfile.ZipFile(docx_path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    rows = []
    for tr in re.findall(r"<w:tr\b.*?</w:tr>", xml, re.S):
        cells = []
        for tc in re.findall(r"<w:tc\b.*?</w:tc>", tr, re.S):
            # Only <w:t> / <w:t ...> (require whitespace or '>' to avoid matching w:tcPr etc.)
            txt = "".join(re.findall(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", tc, re.S))
            cells.append(txt.strip())
        if cells:
            rows.append(cells)
    return rows


DEC_RE = re.compile(r"^0\.\d+$")  # identify the epss score column (distinct from KEV severity column)


def _epss_data_rows(rows):
    """Return only the EPSS table data rows. Columns = CVE/category/EPSS/percentile.
    The KEV table (CVE/product/severity/tier) is also a 4-column CVE row, so pick
    only rows whose 3rd column is an epss decimal."""
    return [r for r in rows if len(r) == 4 and CVE_RE.match(r[0]) and DEC_RE.match(r[2])]


def _check(lang, label_expected, label_forbidden):
    path = os.path.join(DRAFTS, f"report_{lang}.docx")
    if not os.path.exists(path):
        print(f"  SKIP  {lang}: {path} not generated (build.sh not run)")
        return
    rows = _rows(path)
    data = _epss_data_rows(rows)
    assert data, f"{lang}: no EPSS table data rows found"

    # percentile column = %, epss column = decimal
    for r in data:
        _, _, epss, pctile = r
        assert EPSS_RE.match(epss), f"{lang}: epss column is not a 4-decimal value: {epss!r} (row {r})"
        assert PCT_RE.match(pctile), f"{lang}: percentile column is not % format (1 decimal): {pctile!r} (row {r})"
        assert "%" not in epss, f"{lang}: epss column has been percentized: {epss!r}"

    # Labels: the expected label exists and the forbidden label does not (in the header row)
    flat = [c for r in rows for c in r]
    assert label_expected in flat, f"{lang}: label {label_expected!r} is missing"
    if label_forbidden:
        assert label_forbidden not in flat, f"{lang}: old label {label_forbidden!r} still present"

    print(f"  PASS  {lang}: percentile=% / epss=decimal / label={label_expected}")


def test_ja_percentile_is_percent_and_label_renamed():
    _check("ja", "パーセンタイル", "百分位")


def test_en_percentile_is_percent_and_label_unchanged():
    _check("en", "Percentile", None)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
