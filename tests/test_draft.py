#!/usr/bin/env python3
"""
test_draft.py — draft.py が事実のみを出し、解釈・帰属を出さないことを固定する

帰属禁止をテストで保証する: draft.py が emit する本文に評価語・帰属語が
出現しないことを assert する。

合成 state を使い、file IO を避けて render() を直接叩く。
既存テスト同様、pytest 無しでも動くランナー付き。

実行:
    cd ~/msrc_monitor
    python tests/test_draft.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import diff
import draft
from test_diff import mk_state


def build(now, prev):
    """合成 state から (下書き全文, 本文=固定ヘッダ除去後) を返す。"""
    rep = diff.compute_diff(now, prev, now["month"], prev["month"],
                            diff.DEFAULT_THRESHOLDS)
    full = draft.render(now["month"], rep, now)
    header = draft.FIXED_HEADER.format(fetched_at=now.get("fetched_at"))
    body = full.replace(header, "", 1)
    return full, body


# ===========================================================================
# 固定ヘッダが含まれる
# ===========================================================================
def test_fixed_header_present():
    now = mk_state("2026-Jul")
    prev = mk_state("2026-Jun")
    full, _ = build(now, prev)
    assert "これは機械生成の事実記録です" in full
    assert "Kugelblitz=MDASH" in full          # 教訓の明示
    assert "取得日" in full


# ===========================================================================
# 本文 (ヘッダ除く) に評価語・帰属語が出現しない
#   ※ ヘッダは警告として意図的にこれらの語を含むので除外して判定する
# ===========================================================================
def test_no_evaluative_or_attribution_words_in_body():
    # クレジット名は forbidden な部分文字列を含まない合成値にする
    # (実データの "AIフィジカル..." 等は事実として通すが、ここでは
    #  draft.py 自身が語を足していないことを検証したいので clean にする)
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,
                   credit_counts={"Kugelblitz with Microsoft": 39, "Newbie": 3},
                   zero_days=[{"cve": "CVE-2026-1", "severity": "Critical",
                               "exploited": True, "disclosed": False,
                               "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={"Alice": 5})
    _, body = build(now, prev)

    forbidden = ["危険", "MDASH", "考えられる", "と思われる", "推測",
                 "帰属", "AI が", "AIが", "だろう", "懸念", "深刻な"]
    for w in forbidden:
        assert w not in body, f"本文に評価語/帰属語 '{w}' が混入: draft.py が語を足している"


def test_no_bare_AI_word_when_data_clean():
    # データ側に AI を含む名が無ければ、本文にも AI は出ない
    # (draft.py が勝手に 'AI' を書かないことの確認)
    now = mk_state("2026-Jul", credit_counts={"Kugelblitz with Microsoft": 39})
    prev = mk_state("2026-Jun", credit_counts={})
    _, body = build(now, prev)
    assert "AI" not in body


# ===========================================================================
# flag が立った項目が太字になっている
# ===========================================================================
def test_flagged_items_bold():
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,   # cve +60%, heavy 2x
                   credit_counts={"Kugelblitz with Microsoft": 39},
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={})
    _, body = build(now, prev)
    # 閾値超過は太字 + 「閾値超過」表記。評価語は付けない。
    assert "**" in body
    assert "閾値超過" in body
    # 新規クレジット (39件, 20超) が太字で出る
    assert "**Kugelblitz with Microsoft（閾値超過）**" in body


def test_unflagged_not_bold():
    # 何も閾値を超えない場合、「閾値超過」表記が本文に出ない
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2,
                   credit_counts={"Newbie": 3}, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={"Alice": 5})
    _, body = build(now, prev)
    assert "閾値超過" not in body


# ===========================================================================
# 前月ファイル欠落時も下書きは生成される (比較対象なしと明示)
# ===========================================================================
def test_draft_when_no_prev():
    now = mk_state("2026-Jul")
    rep = diff.compute_diff(now, None, "2026-Jul", "2026-Jun",
                            diff.DEFAULT_THRESHOLDS)
    full = draft.render("2026-Jul", rep, now)
    assert "比較対象なし" in full
    assert "これは機械生成の事実記録です" in full   # ヘッダは必ず付く


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
