#!/usr/bin/env python3
"""
test_i18n.py — permanent guard ensuring the English report never emits Japanese.

Design (permanent policy):
    Product categories are held as language-neutral internal keys (alphanumeric),
    and the JA/EN display text is rendered only through the map in
    report/category_labels.json.
    -> No Japanese (e.g. "other") leaks into the English report. If a new
      category is added later without a map entry, the test fails and flags it
      (prevents regressions from creeping back in).

Checks (static inspection of the strings used for English rendering, not a full build):
    1. Category internal keys are alphanumeric only (language-independent).
    2. Every key product_cat can emit is registered in labels (unregistered-key check).
    3. product_count keys from frozen state (legacy display names) resolve via legacy_aliases.
    4. The strings that flow into the English report (category en, chart_labels_en,
       and the en block of gen_report.js) contain no Japanese.

Run:
    python tests/test_i18n.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cvrf_parse as cp

# Hiragana / Katakana / half-width Katakana / CJK unified ideographs
JP = re.compile(r"[぀-ヿ㐀-䶿一-鿿ｦ-ﾟ]")
KEY_RE = re.compile(r"^[a-z0-9_]+$")


def _catmap():
    with open(os.path.join(ROOT, "report", "category_labels.json"), encoding="utf-8") as f:
        return json.load(f)


def _all_product_cat_keys():
    """All internal keys product_cat can return (PRODUCT_CATS + fallback)."""
    return {name for name, _ in cp.PRODUCT_CATS} | {cp.PRODUCT_CAT_FALLBACK}


# ---------------------------------------------------------------------------
# 1. Internal keys are language-neutral (alphanumeric only)
# ---------------------------------------------------------------------------
def test_category_keys_are_language_neutral():
    for k in _all_product_cat_keys():
        assert KEY_RE.match(k), f"non-alphanumeric char in product_cat internal key: {k!r}"
    for k in _catmap()["labels"]:
        assert KEY_RE.match(k), f"non-alphanumeric char in labels key: {k!r}"


# ---------------------------------------------------------------------------
# 2. Map completeness: detect unregistered keys
# ---------------------------------------------------------------------------
def test_every_category_key_is_registered():
    cm = _catmap()
    labels = cm["labels"]
    missing = sorted(k for k in _all_product_cat_keys() if k not in labels)
    assert not missing, f"internal keys not registered in labels (breaks English report): {missing}"
    # Every target of legacy_aliases must also exist in labels
    bad = sorted(v for v in cm["legacy_aliases"].values() if v not in labels)
    assert not bad, f"legacy_aliases points to an unregistered key: {bad}"
    # Each label must have both ja and en
    for k, e in labels.items():
        assert "ja" in e and "en" in e, f"{k} is missing ja/en"


# ---------------------------------------------------------------------------
# 3. product_count keys (internal keys, plus legacy display names that may
#    linger in frozen state) all resolve via labels/legacy_aliases (frozen data
#    is normalized at read time, not rewritten).
#    Real state is not bundled, so verify with both synthetic-fixture keys and
#    legacy display names.
# ---------------------------------------------------------------------------
def test_product_count_keys_resolve():
    cm = _catmap()
    labels, legacy = cm["labels"], cm["legacy_aliases"]

    def resolve(k):
        return legacy.get(k, k) in labels

    # (a) Internal keys of product_count from summarizing the synthetic fixture
    fixture = os.path.join(ROOT, "tests", "fixtures", "2026-Jul-cvrf-reduced.json")
    with open(fixture, encoding="utf-8") as f:
        s = cp.summarize(json.load(f), "2026-Jul", "synthetic")
    for k in s["product_count"]:
        assert resolve(k), f"synthetic product_count key {k!r} does not resolve"

    # (b) Legacy display names (mimicking frozen state) also resolve via legacy_aliases
    for legacy_name in legacy:
        assert resolve(legacy_name), f"legacy display name {legacy_name!r} does not resolve"


# ---------------------------------------------------------------------------
# 4. Strings that flow into the English report contain no Japanese
# ---------------------------------------------------------------------------
def test_english_category_labels_have_no_japanese():
    for k, e in _catmap()["labels"].items():
        assert not JP.search(e["en"]), f"Japanese in English category label: {k} -> {e['en']!r}"


def test_english_chart_labels_have_no_japanese():
    with open(os.path.join(ROOT, "report", "chart_labels_en.json"), encoding="utf-8") as f:
        text = f.read()
    hits = JP.findall(text)
    assert not hits, f"Japanese in chart_labels_en.json: {sorted(set(hits))}"


def test_gen_report_en_block_has_no_japanese():
    """The en: label block of gen_report.js (English render strings) has no Japanese."""
    with open(os.path.join(ROOT, "report", "gen_report.js"), encoding="utf-8") as f:
        js = f.read()
    m = re.search(r"\n  en: \{(.*)\n  \},\n\};", js, re.S)
    assert m, "cannot locate the en: block in gen_report.js (structure changed?)"
    hits = JP.findall(m.group(1))
    assert not hits, f"Japanese in the en block of gen_report.js: {sorted(set(hits))}"


# ---------------------------------------------------------------------------
# Runner (same minimal form as the other tests)
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
