#!/usr/bin/env python3
"""
test_enrich.py — KEV/EPSS 統合 (Phase 2) の設計原則を固定する。

★最重要★ KEV = 通知トリガー / EPSS = 通知に絶対使わない (原則②)。
合成データ・注入で実 API を叩かない。凍結 state は触らない。

実行:
    cd ~/msrc_monitor
    python tests/test_enrich.py
"""
import json
import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cvrf_parse as cp
import enrich
from test_regression import mk_vuln, ack


# --- 合成 CVRF: T2 / Critical / external / 非対象(Edge低tail) ----------------
def synth_doc():
    return {"Vulnerability": [
        mk_vuln("CVE-2026-1", "Microsoft SharePoint Server RCE", sev="Important"),      # T2
        mk_vuln("CVE-2026-2", "Windows Kernel RCE", sev="Critical"),                    # Critical
        mk_vuln("CVE-2026-3", "Microsoft Edge (Chromium-based) RCE", sev="Important",
                acks=ack("Jane Researcher")),                                           # external
        mk_vuln("CVE-2026-4", "Microsoft Edge (Chromium-based) RCE", sev="Important"),  # 非対象
    ]}


# ===========================================================================
# 対象CVE絞り込み: T2/T3 ∨ Critical ∨ external のいずれか
# ===========================================================================
def test_target_filter():
    tg = cp.target_cves_from_doc(synth_doc())
    ids = {t["cve"] for t in tg}
    assert ids == {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}, ids
    assert "CVE-2026-4" not in ids, "Edge低tail・uncredited が対象に混入"
    # 行に tier/severity/finder が入る (帰属判断ではなく機械分類)
    row = {t["cve"]: t for t in tg}
    assert row["CVE-2026-1"]["tier"] == "T2"
    assert row["CVE-2026-2"]["severity"] == "Critical"
    assert row["CVE-2026-3"]["finder"] == "external"


# ===========================================================================
# 製品名/カテゴリ結合: title(具体・KEV表用) と category(EPSS表用) が CVRF由来で付く
# ===========================================================================
def test_target_product_and_category_from_cvrf():
    row = {t["cve"]: t for t in cp.target_cves_from_doc(synth_doc())}
    # 具体タイトル (KEV表の製品名の元。KEV/EPSS の値とは別ソース=CVRF由来)
    assert row["CVE-2026-1"]["title"] == "Microsoft SharePoint Server RCE"
    # category は表5と同一の product_cat() 分類 (言語中立の内部キー。表示は日英マップ経由)
    assert row["CVE-2026-1"]["category"] == "sharepoint"
    assert row["CVE-2026-2"]["category"] == "kernel_driver"
    assert row["CVE-2026-3"]["category"] == "edge_chromium"
    # 分類ロジックの単一ソース: category は product_cat(title) と常に一致する
    for t in row.values():
        assert t["category"] == cp.product_cat(t["title"])


def test_category_graceful_on_unmatched_title():
    # 引けない/空タイトルでも落ちず内部キー 'other' に収まる (レポート側の "—"/マップ変換の土台)
    assert cp.product_cat("") == "other"
    assert cp.product_cat("wholly unmatched gibberish") == "other"


# ===========================================================================
# KEV 新規収載が edge-triggered で検知される (state差分)
# ===========================================================================
def test_kev_new_edge_trigger():
    targets = cp.target_cves_from_doc(synth_doc())
    kev_all = {"CVE-2026-2"}   # Critical が KEV 収載
    # 初回: prev 空 -> 新規に出る
    e1 = enrich.build_enrichment("2026-Jul", targets, kev_all, None, {}, "T0")
    assert e1["kev_listed"] == ["CVE-2026-2"]
    assert e1["kev_new"] == ["CVE-2026-2"]
    # 2回目: prev に既収載 -> 新規なし (edge-triggered)
    e2 = enrich.build_enrichment("2026-Jul", targets, kev_all, None, e1, "T1")
    assert e2["kev_listed"] == ["CVE-2026-2"]
    assert e2["kev_new"] == [], "既収載が再び新規扱い (edge-triggered 破綻)"
    # さらに KEV が増えた -> その差分だけ新規
    kev_all2 = {"CVE-2026-2", "CVE-2026-1"}
    e3 = enrich.build_enrichment("2026-Jul", targets, kev_all2, None, e2, "T2")
    assert e3["kev_new"] == ["CVE-2026-1"]


# ===========================================================================
# ★負のテスト★ EPSS が変化しても通知トリガーにならない (原則②)
# ===========================================================================
def test_epss_never_triggers_notification():
    import notify
    targets = cp.target_cves_from_doc(synth_doc())
    kev_all = {"CVE-2026-2"}
    # EPSS 世代1
    epss_a = {"scores": {"CVE-2026-2": {"epss": 0.10, "percentile": 0.8}}, "date": "2026-07-16"}
    e1 = enrich.build_enrichment("2026-Jul", targets, kev_all, epss_a, {}, "T0")
    # EPSS 世代2 (値だけ変化、KEV は不変)
    epss_b = {"scores": {"CVE-2026-2": {"epss": 0.55, "percentile": 0.95}}, "date": "2026-07-17"}
    e2 = enrich.build_enrichment("2026-Jul", targets, kev_all, epss_b, e1, "T1")

    home = tempfile.mkdtemp(prefix="msrc_epss_test_")
    env = {"MSRC_MONITOR_HOME": home, "PUSHOVER_TOKEN": "x", "PUSHOVER_USER": "y"}
    with mock.patch.dict(os.environ, env), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        # 1回目: KEV 新規 -> 通知される (1回)
        notify.notify_kev(e1)
        assert post.call_count == 1
        # 2回目: KEV 不変・EPSS だけ変化 -> 通知されない
        notify.notify_kev(e2)
        assert post.call_count == 1, "EPSS 変化で通知が出た (原則②違反)"
        # 送信本文に EPSS 値が入っていないこと
        _, kwargs = post.call_args
        blob = kwargs["data"]["title"] + kwargs["data"]["message"]
        assert "0.10" not in blob and "0.55" not in blob and "epss" not in blob.lower()


# ===========================================================================
# KEV 新規で post が呼ばれる / 認証未設定で落ちない
# ===========================================================================
def test_kev_notify_posts_and_missing_creds_safe():
    import notify
    targets = cp.target_cves_from_doc(synth_doc())
    e = enrich.build_enrichment("2026-Jul", targets, {"CVE-2026-2"}, None, {}, "T0")

    home = tempfile.mkdtemp(prefix="msrc_kev_test_")
    # 認証あり -> 1回 post
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home,
                                      "PUSHOVER_TOKEN": "x", "PUSHOVER_USER": "y"}), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        notify.notify_kev(e)
        assert post.call_count == 1

    # 認証なし -> 落ちず post も呼ばれない
    home2 = tempfile.mkdtemp(prefix="msrc_kev_test2_")
    for k in ("PUSHOVER_TOKEN", "PUSHOVER_USER"):
        os.environ.pop(k, None)
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home2}), \
         mock.patch.object(notify.requests, "post") as post:
        rc = notify.notify_kev(e)
        assert post.call_count == 0 and rc == 0


# ===========================================================================
# KEV 未取得 (到達不能) は通知トリガーにならず落ちない
# ===========================================================================
def test_kev_unreachable_no_notify():
    import notify
    targets = cp.target_cves_from_doc(synth_doc())
    e = enrich.build_enrichment("2026-Jul", targets, None, None, {}, "T0")  # kev_all=None
    assert e["kev_listed"] is None and e["kev_new"] == []
    home = tempfile.mkdtemp(prefix="msrc_kevun_")
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home,
                                      "PUSHOVER_TOKEN": "x", "PUSHOVER_USER": "y"}), \
         mock.patch.object(notify.requests, "post") as post:
        notify.notify_kev(e)
        assert post.call_count == 0


# ===========================================================================
# EPSS: 最新 + 1世代前のみ保持、epss_asof を記録
# ===========================================================================
def test_epss_prev_retention_and_asof():
    targets = cp.target_cves_from_doc(synth_doc())
    epss_a = {"scores": {"CVE-2026-2": {"epss": 0.10, "percentile": 0.8}}, "date": "2026-07-16"}
    e1 = enrich.build_enrichment("2026-Jul", targets, set(), epss_a, {}, "T0")
    assert e1["epss"]["CVE-2026-2"]["epss"] == 0.10
    assert e1["epss_asof"] == "2026-07-16"
    assert e1["epss_prev"] is None  # 初回は1世代前なし

    epss_b = {"scores": {"CVE-2026-2": {"epss": 0.55, "percentile": 0.95}}, "date": "2026-07-17"}
    e2 = enrich.build_enrichment("2026-Jul", targets, set(), epss_b, e1, "T1")
    assert e2["epss"]["CVE-2026-2"]["epss"] == 0.55
    assert e2["epss_asof"] == "2026-07-17"
    # 1世代前 = e1 の epss (それ以前は持たない)
    assert e2["epss_prev"]["CVE-2026-2"]["epss"] == 0.10
    assert e2["epss_prev_asof"] == "2026-07-16"


# ===========================================================================
# enrich(): 到達不能 (fetch が None) でも落ちず enrichment を書く
# ===========================================================================
def test_enrich_skips_on_unreachable():
    home = tempfile.mkdtemp(prefix="msrc_enrich_")
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home}):
        enr = enrich.enrich("2026-Jul", raw_doc=synth_doc(),
                            fetch_kev_fn=lambda **k: None,
                            fetch_epss_fn=lambda ids, **k: None)
        assert enr is not None
        assert enr["kev_listed"] is None and enr["epss"] is None
        assert enr["kev_asof"] is None and enr["epss_asof"] is None
        # enrichment.json が書かれている
        p = os.path.join(home, "state", "enrichment.json")
        assert os.path.exists(p)
        assert enr["target_count"] == 3


# ===========================================================================
# 凍結 state を触らないこと (enrich は state/2026-*.json を書き換えない)
# ===========================================================================
def test_enrich_does_not_touch_frozen_state():
    # 一時 home に凍結 state/2026-Jul.json を置き、enrich 前後でハッシュ不変を確認。
    # (実データは同梱しないため合成の凍結 state を使う。enrich は enrichment.json のみ書く)
    import hashlib
    home = tempfile.mkdtemp(prefix="msrc_frozen_")
    state = os.path.join(home, "state")
    os.makedirs(state, exist_ok=True)
    p = os.path.join(state, "2026-Jul.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"month": "2026-Jul", "frozen": True, "cve_total": 50}, f, ensure_ascii=False)
    before = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home}):
        enrich.enrich("2026-Jul", raw_doc=synth_doc(),
                     fetch_kev_fn=lambda **k: set(), fetch_epss_fn=lambda ids, **k: None)
    after = hashlib.sha256(open(p, "rb").read()).hexdigest()
    assert before == after, "enrich が凍結 state を書き換えた"
    # enrich は enrichment.json を生成する (state/2026-*.json とは別ファイル)
    assert os.path.exists(os.path.join(state, "enrichment.json"))


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
