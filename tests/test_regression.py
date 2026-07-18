#!/usr/bin/env python3
"""
test_regression.py — 2026-07 の調査で判明したバグを固定する回帰テスト

このテストの目的は「性能」ではなく「同じ罠に二度落ちないこと」。
各テストは、実際に起きた誤りに1対1で対応する。
スクリプトを変更したら必ず実行すること (run_monthly.sh も先頭で実行する)。

実行:
    cd ~/msrc_monitor
    python3 -m pytest tests/ -v
    # pytest が無ければ: python3 tests/test_regression.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cvrf_parse as cp


# --- テスト用ヘルパ: 最小のCVRF vuln dict を作る -----------------------------
def mk_vuln(cve, title, sev="Important", acks=None, exploit="", impact="Remote Code Execution"):
    v = {
        "CVE": cve,
        "Title": {"Value": title},
        "Threats": [
            {"Type": cp.THREAT_IMPACT, "Description": {"Value": impact}},
            {"Type": cp.THREAT_SEVERITY, "Description": {"Value": sev}},
        ],
    }
    if exploit:
        v["Threats"].append({"Type": cp.THREAT_EXPLOIT_STATUS, "Description": {"Value": exploit}})
    if acks is not None:
        v["Acknowledgments"] = acks
    return v


def ack(*names):
    """Name の Value に文字列を持つ Acknowledgment を1つ作る"""
    return [{"Name": [{"Value": n} for n in names]}]


# ===========================================================================
# 教訓#1: HTML混入 — クレジット文字列の <a href> を除去してから判定する
# ===========================================================================
def test_html_stripped_from_credit():
    # 実データでは 'Name with <a href="https://org.example/">Org</a>' の形で
    # クレジット文字列に HTML が混入する。除去してから氏名判定する (合成例)。
    v = mk_vuln("CVE-2026-48561", "Windows RDP RCE",
                acks=ack('Researcher Name with <a href="https://example.com/">Example Org</a>'))
    names = cp.credit_names(v)
    assert len(names) == 1
    assert "<a href" not in names[0], "HTMLタグが除去されていない"
    assert "example.com" not in names[0], "URL断片が残っている"
    assert "Researcher Name" in names[0]


# ===========================================================================
# 教訓#2: 二重掲載 — 1つのCVEに同名が2回載っても、CVE件数は1
#          (これを誤って78件と数えた。正しくは39件)
# ===========================================================================
def test_double_listing_counts_once():
    # Kugelblitz が同一CVEに2回載る実データパターン
    vulns = [
        mk_vuln(f"CVE-2026-{n}", "Microsoft Edge (Chromium-based) RCE",
                acks=ack("Kugelblitz with Microsoft", "Kugelblitz with Microsoft"))
        for n in range(57974, 57994)  # 20件
    ]
    doc = {"Vulnerability": vulns}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    # 20 CVE それぞれに Kugelblitz が2回 → 生カウントなら40だが、正しくは20
    assert s["credit_counts"]["Kugelblitz with Microsoft"] == 20, \
        f"二重掲載が重複カウントされている: {s['credit_counts']}"


def test_double_listing_credited_flag():
    # 二重掲載でも credited は1回だけ数える
    v = mk_vuln("CVE-2026-57974", "Edge RCE",
                acks=ack("Kugelblitz with Microsoft", "Kugelblitz with Microsoft"))
    doc = {"Vulnerability": [v]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["credited"] == 1
    assert s["cve_total"] == 1


# ===========================================================================
# 教訓#3: クレジット無し判定 — フィールド欠落/空 = uncredited (binary)
# ===========================================================================
def test_no_acknowledgments_is_uncredited():
    # Acknowledgments フィールドそのものが無い (実データ: 画像1のCVE)
    v = mk_vuln("CVE-2026-90001", "Windows Kernel RCE", sev="Critical",
                exploit="Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely")
    assert cp.is_credited(v) is False
    assert cp.credit_names(v) == []


def test_empty_name_is_uncredited():
    # Acknowledgments はあるが Name の Value が空
    v = mk_vuln("CVE-2026-90002", "Windows RCE", acks=[{"Name": [{"Value": ""}]}])
    assert cp.is_credited(v) is False


def test_credited_vs_uncredited_counts():
    doc = {"Vulnerability": [
        mk_vuln("CVE-2026-1", "A", acks=ack("Alice")),
        mk_vuln("CVE-2026-2", "B"),                       # 無し
        mk_vuln("CVE-2026-3", "C", acks=ack("Bob")),
        mk_vuln("CVE-2026-4", "D", acks=[{"Name": [{"Value": ""}]}]),  # 空=無し
    ]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["cve_total"] == 4
    assert s["credited"] == 2
    assert s["uncredited"] == 2


# ===========================================================================
# 教訓#4: 取得タイミングの記録 — fetched_at が必ずサマリに入る
# ===========================================================================
def test_fetched_at_recorded():
    doc = {"Vulnerability": [mk_vuln("CVE-2026-1", "A")]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["fetched_at"] == "2026-07-15T07:00:00", "取得日時が記録されていない"


# ===========================================================================
# 教訓#5: 帰属の禁止 — サマリに帰属判断が混入していないことの確認
#          (credit_counts はただの文字列→件数。'is_mdash' 等のフラグは無い)
# ===========================================================================
def test_no_attribution_flags_in_summary():
    v = mk_vuln("CVE-2026-57974", "Edge RCE", acks=ack("Kugelblitz with Microsoft"))
    doc = {"Vulnerability": [v]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    # サマリのキーに帰属を示唆するものが無いこと
    flat = str(s).lower()
    for forbidden in ["mdash", "is_ai", "is_tool", "attributed"]:
        assert forbidden not in [k.lower() for k in s.keys()], \
            f"帰属フラグ '{forbidden}' がサマリに混入"
    # _note に警告が入っていること
    assert "kugelblitz" in s["_note"].lower()


# ===========================================================================
# 再起動クラス分類 (三層モデルの土台)
# ===========================================================================
def test_tier_classification():
    assert cp.tier_of(mk_vuln("x", "Windows Secure Boot Security Feature Bypass")) == "T3"
    assert cp.tier_of(mk_vuln("x", "Microsoft SharePoint Server RCE")) == "T2"
    assert cp.tier_of(mk_vuln("x", "Microsoft Edge (Chromium-based) RCE")) == "T0/T1"
    assert cp.tier_of(mk_vuln("x", "Windows BitLocker Bypass")) == "T3"


# ===========================================================================
# ゼロデイの発見者記録 (H3: 悪用脆弱性は人間発見か)
# ===========================================================================
def test_zero_day_credit_capture():
    doc = {"Vulnerability": [
        mk_vuln("CVE-2026-56155", "AD FS EoP", sev="Important",
                acks=ack("Test Analyst, Microsoft DART"),
                exploit="Publicly Disclosed:No;Exploited:Yes", impact="Elevation of Privilege"),
        mk_vuln("CVE-2026-90001", "Windows Kernel RCE", sev="Critical"),  # 通常
    ]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert len(s["zero_days"]) == 1
    zd = s["zero_days"][0]
    assert zd["exploited"] is True
    assert zd["credited"] is True
    assert "DART" in zd["credits"][0]


# --- pytest 無し環境でも動くランナー ----------------------------------------

# ===========================================================================
# 追加(2026-07): ハッシュクレジットの分離
#   実データで "0123456789abcdef0123456789abcdef" のような32桁ハッシュが
#   47件クレジットされていた。これを実名研究者(external)と混ぜない。
#   ※このテストは msrc_action.py(帰属版)側のロジック確認用のメモ。
#     cvrf_parse.py には finder_bucket は無い(集計は帰属版が担当)。
# ===========================================================================
def test_hash_credit_shape():
    """ハッシュ識別子の形状判定(参照実装のメモ)"""
    import re
    HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
    assert HASH_RE.match("0123456789abcdef0123456789abcdef")
    assert not HASH_RE.match("Sample Researcher")
    assert not HASH_RE.match("abc")       # 短い名を誤判定しない
    assert not HASH_RE.match("Anonymous")


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
