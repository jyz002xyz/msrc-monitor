#!/usr/bin/env python3
"""
test_epss_percentile_display.py — EPSS表の表示形式を固定する。

確定仕様 (表示層のみ。内部データ=小数は不変):
    - percentile 列: パーセント表示・小数1桁 (例 0.97192 -> "97.2%")。
    - epss 列:       小数のまま (確率値。例 "0.2035")。パーセント化しない。
    - 日本語ラベル:  "パーセンタイル" (旧 "百分位")。英語は "Percentile" 不変。

生成済み docx (drafts/report_{ja,en}.docx) を検査する。build.sh 実行後に有効。
未生成ならスキップ (test_anonymize_gate の実チャート検査と同じ方針)。
"""
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRAFTS = os.path.join(ROOT, "drafts")

PCT_RE = re.compile(r"^\d{1,3}\.\d%$")      # 97.2% / 75.0% / 100.0%
EPSS_RE = re.compile(r"^0\.\d{4}$")          # 0.2035 (小数4桁, 非パーセント)
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _rows(docx_path):
    """docx の全テーブル行をセル配列のリストで返す (素朴な XML パース)。"""
    with zipfile.ZipFile(docx_path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    rows = []
    for tr in re.findall(r"<w:tr\b.*?</w:tr>", xml, re.S):
        cells = []
        for tc in re.findall(r"<w:tc\b.*?</w:tc>", tr, re.S):
            # <w:t> / <w:t ...> のみ (w:tcPr 等に誤マッチしないよう空白or'>'を要求)
            txt = "".join(re.findall(r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", tc, re.S))
            cells.append(txt.strip())
        if cells:
            rows.append(cells)
    return rows


DEC_RE = re.compile(r"^0\.\d+$")  # epss スコア列の判別 (KEV表の深刻度列と区別)


def _epss_data_rows(rows):
    """EPSS表のデータ行のみ返す。列 = CVE/カテゴリ/EPSS/percentile。
    KEV表(CVE/製品名/深刻度/tier)も4列CVE行なので、3列目が epss 小数の行だけ選ぶ。"""
    return [r for r in rows if len(r) == 4 and CVE_RE.match(r[0]) and DEC_RE.match(r[2])]


def _check(lang, label_expected, label_forbidden):
    path = os.path.join(DRAFTS, f"report_{lang}.docx")
    if not os.path.exists(path):
        print(f"  SKIP  {lang}: {path} 未生成 (build.sh 未実行)")
        return
    rows = _rows(path)
    data = _epss_data_rows(rows)
    assert data, f"{lang}: EPSS表のデータ行が見つからない"

    # percentile 列 = %, epss 列 = 小数
    for r in data:
        _, _, epss, pctile = r
        assert EPSS_RE.match(epss), f"{lang}: epss 列が小数4桁でない: {epss!r} (行 {r})"
        assert PCT_RE.match(pctile), f"{lang}: percentile 列が %表示(小数1桁)でない: {pctile!r} (行 {r})"
        assert "%" not in epss, f"{lang}: epss 列がパーセント化されている: {epss!r}"

    # ラベル: 期待ラベルが存在し、禁止ラベルが存在しない (ヘッダ行に出る)
    flat = [c for r in rows for c in r]
    assert label_expected in flat, f"{lang}: ラベル {label_expected!r} が無い"
    if label_forbidden:
        assert label_forbidden not in flat, f"{lang}: 旧ラベル {label_forbidden!r} が残存"

    print(f"  PASS  {lang}: percentile=% / epss=小数 / ラベル={label_expected}")


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
