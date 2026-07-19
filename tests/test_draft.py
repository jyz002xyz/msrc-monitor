#!/usr/bin/env python3
"""
test_draft.py — lock in that draft.py emits facts only, with no interpretation or attribution

Enforce the no-attribution rule via tests: assert that no evaluative or
attribution words appear in the body draft.py emits. (The draft body is
intentionally Japanese, so the words checked here are Japanese.)

Uses synthetic state and calls render() directly, avoiding file IO.
Like the other tests, it ships with a runner that works without pytest.

Run:
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
    """Return (full draft, body=after removing the fixed header) from synthetic state."""
    rep = diff.compute_diff(now, prev, now["month"], prev["month"],
                            diff.DEFAULT_THRESHOLDS)
    full = draft.render(now["month"], rep, now)
    header = draft.FIXED_HEADER.format(fetched_at=now.get("fetched_at"))
    body = full.replace(header, "", 1)
    return full, body


# ===========================================================================
# the fixed header is present
# ===========================================================================
def test_fixed_header_present():
    now = mk_state("2026-Jul")
    prev = mk_state("2026-Jun")
    full, _ = build(now, prev)
    assert "これは機械生成の事実記録です" in full
    assert "Kugelblitz=MDASH" in full          # the lesson is spelled out
    assert "取得日" in full


# ===========================================================================
# the body (excluding the header) contains no evaluative or attribution words
#   note: the header intentionally contains these words as a warning, so it is
#   excluded before checking
# ===========================================================================
def test_no_evaluative_or_attribution_words_in_body():
    # use synthetic credit names that contain no forbidden substrings
    # (real-data names would pass through as facts, but here we want to verify
    #  draft.py itself does not add any such words, so we keep them clean)
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,
                   credit_counts={"Kugelblitz with Microsoft": 39, "Newbie": 3},
                   zero_days=[{"cve": "CVE-2026-1", "severity": "Critical",
                               "exploited": True, "disclosed": False,
                               "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={"Alice": 5})
    _, body = build(now, prev)

    # forbidden words are Japanese because the draft body is Japanese output
    forbidden = ["危険", "MDASH", "考えられる", "と思われる", "推測",
                 "帰属", "AI が", "AIが", "だろう", "懸念", "深刻な"]
    for w in forbidden:
        assert w not in body, f"evaluative/attribution word '{w}' in the body: draft.py is adding words"


def test_no_bare_AI_word_when_data_clean():
    # if no name on the data side contains 'AI', 'AI' must not appear in the body
    # (verifies draft.py does not write 'AI' on its own)
    now = mk_state("2026-Jul", credit_counts={"Kugelblitz with Microsoft": 39})
    prev = mk_state("2026-Jun", credit_counts={})
    _, body = build(now, prev)
    assert "AI" not in body


# ===========================================================================
# flagged items are shown in bold
# ===========================================================================
def test_flagged_items_bold():
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,   # cve +60%, heavy 2x
                   credit_counts={"Kugelblitz with Microsoft": 39},
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={})
    _, body = build(now, prev)
    # threshold-exceeded items are bold + carry the "閾値超過" marker. No evaluative words.
    assert "**" in body
    assert "閾値超過" in body
    # the new credit (39, over 20) is shown in bold
    assert "**Kugelblitz with Microsoft（閾値超過）**" in body


def test_unflagged_not_bold():
    # when nothing exceeds a threshold, the "閾値超過" marker does not appear in the body
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2,
                   credit_counts={"Newbie": 3}, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={"Alice": 5})
    _, body = build(now, prev)
    assert "閾値超過" not in body


# ===========================================================================
# the draft is still generated when the previous-month file is missing
# (explicitly marked as "no comparison target")
# ===========================================================================
def test_draft_when_no_prev():
    now = mk_state("2026-Jul")
    rep = diff.compute_diff(now, None, "2026-Jul", "2026-Jun",
                            diff.DEFAULT_THRESHOLDS)
    full = draft.render("2026-Jul", rep, now)
    assert "比較対象なし" in full
    assert "これは機械生成の事実記録です" in full   # the header is always present


# --- runner that also works without pytest ----------------------------------
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
