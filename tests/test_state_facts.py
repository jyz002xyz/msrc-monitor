#!/usr/bin/env python3
"""
test_state_facts.py — cvrf_parse の分類ロジック (母集団分離・製品カテゴリ・
発見者バケット・深刻度/再起動クラス集計) の不変条件を固定する。

★合成データで動作する★
    実 MSRC 一次データ (研究者の個人情報を含む) は同梱しないため、
    tests/fixtures/make_synthetic_cvrf.py が生成する合成 CVRF を使う。
    具体的な件数は合成データ由来だが、分類ロジックが満たすべき構造的不変条件
    (母集団の保存・バケットの排他性・カテゴリの内部キー化 等) を検証する。

実行:
    python tests/fixtures/make_synthetic_cvrf.py   # 合成 fixture を生成
    python tests/test_state_facts.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cvrf_parse as cp

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "2026-Jul-cvrf-reduced.json")
FINDER_BUCKETS = {"external", "ms_internal", "uncredited", "anonymous", "hash_anon"}
KEY_RE = re.compile(r"^[a-z0-9_]+$")


def _summ():
    doc = json.load(open(FIXTURE, encoding="utf-8"))
    return cp.summarize(doc, "2026-Jul", "synthetic")


# --- 総数・母集団分離: core + excluded == 総数 (保存則) -----------------------
def test_totals_and_population():
    s = _summ()
    assert s["cve_total"] == 50, s["cve_total"]           # 合成 fixture の規模
    assert s["core_total"] + s["excluded_total"] == s["cve_total"]
    assert s["credited"] + s["uncredited"] == s["cve_total"]
    assert s["excluded_total"] > 0, "Edge/Cloud 等の除外母集団が空"


# --- 深刻度: バケット合計 == 総数 --------------------------------------------
def test_severity_sums():
    s = _summ()
    assert sum(s["severity_count"].values()) == s["cve_total"]
    assert sum(s["severity_core"].values()) == s["core_total"]
    assert s["severity_count"].get("Critical", 0) > 0


# --- 再起動クラス: 合計 == 総数、重い層(T2/T3)を集計できる ---------------------
def test_tier_sums():
    s = _summ()
    t = s["tier_count"]
    assert sum(t.values()) == s["cve_total"]
    assert (t.get("T2", 0) + t.get("T3", 0)) >= 1, "重い層(T2/T3)が検出されない"
    assert sum(s["tier_core"].values()) == s["core_total"]


# --- 発見者バケット: 排他・網羅 (合計==総数)、バケット名のみ(実名を焼き込まない) ---
def test_finder_buckets_partition_and_no_names():
    f = _summ()["finder_bucket"]
    assert sum(f.values()) == 50
    assert set(f) <= FINDER_BUCKETS, f"未知のバケット: {set(f) - FINDER_BUCKETS}"
    # 合成データでは外部研究者(実名クレジット)が最多
    assert max(f, key=f.get) == "external", f


# --- Kugelblitz: クレジットを含む CVE を数えるが Critical には出さない (面のみ) ---
def test_kugelblitz_surface_only():
    s = _summ()
    assert s["kugelblitz"] > 0, "Kugelblitz クレジットが集計されていない"
    assert s["kugelblitz_in_critical"] == 0, "Kugelblitz が Critical に混入"


# --- Critical の発見者内訳: 件数のみ・実名なし。合計は Critical 総数と一致 -------
def test_critical_by_finder_counts_only():
    s = _summ()
    cbf = s["critical_by_finder"]
    assert sum(cbf.values()) == s["severity_count"]["Critical"], cbf
    assert max(cbf, key=cbf.get) == "external", cbf
    assert cbf["external"] > cbf.get("ms_internal", 0), cbf
    for key in cbf:
        assert key in FINDER_BUCKETS, f"バケット名以外(実名?)が混入: {key!r}"


# --- 製品カテゴリ: 内部キー(英数字)・Edge が最多・"other" は 12% 未満 -----------
def test_product_categories_internal_keys():
    s = _summ()
    p = s["product_count"]
    for k in p:
        assert KEY_RE.match(k), f"カテゴリキーが内部キー(英数字)でない: {k!r}"
    assert max(p, key=p.get) == "edge_chromium", "Edge が最多カテゴリでない"
    other = p.get("other", 0)
    assert other / s["cve_total"] < 0.12, f"other {other} が 12% 超"


# --- pytest 無し環境でも動くランナー ----------------------------------------
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
