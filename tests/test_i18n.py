#!/usr/bin/env python3
"""
test_i18n.py — 英語版レポートに日本語を出さない仕組みを固定する (恒久ガード)。

恒久方針 (案1):
    製品カテゴリは言語中立の内部キー(英数字)で持ち、日英の表示は
    report/category_labels.json のマップ経由でのみ描画する。
    → 英語版に日本語(その他 等)が混入しない。将来カテゴリが増えても、
      マップ未登録なら「テスト失敗」で検出できる (虫食い再発を防ぐ)。

検査 (生成物のビルドではなく、英語版描画に使う文字列群を静的に検査する):
    1. カテゴリ内部キーが英数字のみ (言語非依存)。
    2. product_cat が出しうる全キーが labels に登録済み (未登録キー検出)。
    3. 凍結 state の product_count キー(旧表示名)が legacy_aliases 経由で解決する。
    4. 英語版に流れる文字列(カテゴリen・chart_labels_en・gen_report.js の en ブロック)
       に日本語が無い。

実行:
    python tests/test_i18n.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cvrf_parse as cp

# ひらがな/カタカナ/半角カナ/CJK統合漢字
JP = re.compile(r"[぀-ヿ㐀-䶿一-鿿ｦ-ﾟ]")
KEY_RE = re.compile(r"^[a-z0-9_]+$")


def _catmap():
    with open(os.path.join(ROOT, "report", "category_labels.json"), encoding="utf-8") as f:
        return json.load(f)


def _all_product_cat_keys():
    """product_cat が返しうる全内部キー (PRODUCT_CATS + フォールバック)。"""
    return {name for name, _ in cp.PRODUCT_CATS} | {cp.PRODUCT_CAT_FALLBACK}


# ---------------------------------------------------------------------------
# 1. 内部キーは言語中立 (英数字のみ)
# ---------------------------------------------------------------------------
def test_category_keys_are_language_neutral():
    for k in _all_product_cat_keys():
        assert KEY_RE.match(k), f"product_cat の内部キーに英数字以外: {k!r}"
    for k in _catmap()["labels"]:
        assert KEY_RE.match(k), f"labels キーに英数字以外: {k!r}"


# ---------------------------------------------------------------------------
# 2. マップ完全性: 未登録キーを検出する
# ---------------------------------------------------------------------------
def test_every_category_key_is_registered():
    cm = _catmap()
    labels = cm["labels"]
    missing = sorted(k for k in _all_product_cat_keys() if k not in labels)
    assert not missing, f"labels 未登録の内部キー (英語版が壊れる): {missing}"
    # legacy_aliases の指す先も全て labels に存在
    bad = sorted(v for v in cm["legacy_aliases"].values() if v not in labels)
    assert not bad, f"legacy_aliases が未登録キーを指す: {bad}"
    # 各ラベルは ja/en を持つ
    for k, e in labels.items():
        assert "ja" in e and "en" in e, f"{k} に ja/en 欠落"


# ---------------------------------------------------------------------------
# 3. product_count のキー(内部キー、および凍結 state に残りうる旧表示名)が
#    labels/legacy_aliases で全て解決できる (凍結データは書き換えず参照時に正規化)。
#    実 state は同梱しないため、合成 fixture 由来 + 旧表示名(legacy)の両方で検証する。
# ---------------------------------------------------------------------------
def test_product_count_keys_resolve():
    cm = _catmap()
    labels, legacy = cm["labels"], cm["legacy_aliases"]

    def resolve(k):
        return legacy.get(k, k) in labels

    # (a) 合成 fixture を summarize した product_count の内部キー
    fixture = os.path.join(ROOT, "tests", "fixtures", "2026-Jul-cvrf-reduced.json")
    with open(fixture, encoding="utf-8") as f:
        s = cp.summarize(json.load(f), "2026-Jul", "synthetic")
    for k in s["product_count"]:
        assert resolve(k), f"合成 product_count キー {k!r} が解決できない"

    # (b) 旧表示名(凍結 state 由来を模す)も legacy_aliases 経由で解決する
    for legacy_name in legacy:
        assert resolve(legacy_name), f"旧表示名 {legacy_name!r} が解決できない"


# ---------------------------------------------------------------------------
# 4. 英語版に流れる文字列に日本語が無い
# ---------------------------------------------------------------------------
def test_english_category_labels_have_no_japanese():
    for k, e in _catmap()["labels"].items():
        assert not JP.search(e["en"]), f"英語カテゴリラベルに日本語: {k} -> {e['en']!r}"


def test_english_chart_labels_have_no_japanese():
    with open(os.path.join(ROOT, "report", "chart_labels_en.json"), encoding="utf-8") as f:
        text = f.read()
    hits = JP.findall(text)
    assert not hits, f"chart_labels_en.json に日本語: {sorted(set(hits))}"


def test_gen_report_en_block_has_no_japanese():
    """gen_report.js の en: ラベルブロック(英語版描画文字列)に日本語が無いこと。"""
    with open(os.path.join(ROOT, "report", "gen_report.js"), encoding="utf-8") as f:
        js = f.read()
    m = re.search(r"\n  en: \{(.*)\n  \},\n\};", js, re.S)
    assert m, "gen_report.js の en: ブロックが特定できない (構造変更?)"
    hits = JP.findall(m.group(1))
    assert not hits, f"gen_report.js の en ブロックに日本語: {sorted(set(hits))}"


# ---------------------------------------------------------------------------
# ランナー (他テストと同じ素朴な形式)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
