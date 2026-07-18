#!/usr/bin/env python3
"""
test_snapshot_freeze.py — 月次スナップショット凍結ポリシー(の仕組み)を固定する。

会計の締めと同じ発想。一度取得・レビューした過去月は確定値として凍結し、
後の MSRC 改訂で上書きしない。改訂は別途 .revisions に記録する(数値は不変)。

★合成データで動作する★
    実 MSRC 一次データ (研究者の個人情報を含む) は同梱しないため、確定した
    過去月データそのものは検証しない。代わりに凍結・改訂検知の「仕組み」を、
    合成データ/インメモリ値で検証する (これが再利用可能なロジック)。

実行:
    python tests/fixtures/make_synthetic_cvrf.py   # 合成 fixture を生成
    python tests/test_snapshot_freeze.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import collect
import cvrf_parse as cp

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "2026-Jul-cvrf-reduced.json")


# ===========================================================================
# summarize は凍結可能な構造 (集計フィールド一式) を生成する
# ===========================================================================
def test_summary_has_freezable_structure():
    doc = json.load(open(FIXTURE, encoding="utf-8"))
    s = cp.summarize(doc, "2026-Jul", "synthetic")
    for k in ("cve_total", "core_total", "severity_count", "tier_count",
              "product_count", "finder_bucket", "zero_days"):
        assert k in s, f"集計フィールド {k} が無い"
    assert isinstance(s["product_count"], dict) and s["product_count"]
    assert isinstance(s["finder_bucket"], dict) and s["finder_bucket"]
    # 保存則: 母集団の分割が総数に一致
    assert s["core_total"] + s["excluded_total"] == s["cve_total"]


# ===========================================================================
# 改訂検知: 凍結値と異なる再取得値で差分が記録され、凍結 dict は不変
# ===========================================================================
def test_revision_detection_records_without_overwrite():
    frozen = {
        "month": "2026-Jun", "snapshot_date": "2026-07-15",
        "cve_total": 1281, "core_total": 724, "credited": 215,
        "kugelblitz": 0, "ms_internal": 34,
        "severity_count": {"Critical": 89}, "tier_count": {"T2": 42, "T3": 3},
    }
    # MSRC が事後改訂した想定 (cve 減少・core 減少・critical 変化)
    fresh = {
        "cve_total": 1205, "core_total": 648, "credited": 215,
        "kugelblitz": 0, "ms_internal": 34,
        "severity_count": {"Critical": 85}, "tier_count": {"T2": 42, "T3": 3},
    }
    rev = collect.detect_revision(frozen, fresh, "2026-07-16T00:00:00")
    assert rev is not None
    assert rev["diff"]["cve_total"]["frozen"] == 1281
    assert rev["diff"]["cve_total"]["revised"] == 1205
    assert rev["diff"]["cve_total"]["delta"] == -76
    assert rev["diff"]["core_total"]["delta"] == -76
    assert rev["diff"]["critical"]["delta"] == -4
    # frozen dict は改変されない
    assert frozen["cve_total"] == 1281


def test_revision_detection_no_change_returns_none():
    frozen = {
        "month": "2026-Jan", "cve_total": 310, "core_total": 287,
        "credited": 118, "kugelblitz": 0, "ms_internal": 19,
        "severity_count": {"Critical": 30}, "tier_count": {"T2": 6, "T3": 3},
    }
    same = dict(frozen)
    assert collect.detect_revision(frozen, same, "2026-07-16T00:00:00") is None


# ===========================================================================
# collect_month は凍結月を上書きせず改訂を記録する (一時 home でモック)
# ===========================================================================
def test_collect_month_preserves_frozen():
    home = tempfile.mkdtemp(prefix="msrc_freeze_test_")
    os.environ["MSRC_MONITOR_HOME"] = home
    try:
        sd = collect.state_dir()
        frozen = {
            "month": "2026-Jun", "frozen": True, "snapshot_date": "2026-07-15",
            "cve_total": 1281, "core_total": 724, "credited": 215,
            "kugelblitz": 0, "ms_internal": 34,
            "severity_count": {"Critical": 89}, "tier_count": {"T2": 42, "T3": 3},
            "zero_days": [],
        }
        (sd / "2026-Jun.json").write_text(json.dumps(frozen, ensure_ascii=False))

        # fetch をモックして「改訂後」データを返させる (空 = cve_total 0)
        orig_fetch = collect.fetch
        collect.fetch = lambda m, **kw: {"Vulnerability": []}
        try:
            collect.collect_month("2026-Jun")
        finally:
            collect.fetch = orig_fetch

        # 凍結値は保持されている
        after = json.loads((sd / "2026-Jun.json").read_text())
        assert after["cve_total"] == 1281, "凍結月が上書きされた"
        assert after["frozen"] is True
        # 改訂が記録された
        rp = sd / ".revisions" / "2026-Jun.json"
        assert rp.exists(), "改訂記録が作られていない"
        rev = json.loads(rp.read_text())
        assert rev["diff"]["cve_total"]["revised"] == 0
    finally:
        os.environ.pop("MSRC_MONITOR_HOME", None)


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
