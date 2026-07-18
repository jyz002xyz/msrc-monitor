#!/usr/bin/env python3
"""
test_notify.py — notify.py の edge-triggered 通知を固定する

requests.post をモックし、実 API を叩かない。
一時 state ディレクトリ (MSRC_MONITOR_HOME) に合成 state を書いて評価する。

実行:
    cd ~/msrc_monitor
    python tests/test_notify.py
"""
import json
import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_diff import mk_state


def _write_states(home, now, prev=None):
    sd = os.path.join(home, "state")
    os.makedirs(sd, exist_ok=True)
    with open(os.path.join(sd, f"{now['month']}.json"), "w") as f:
        json.dump(now, f)
    if prev is not None:
        with open(os.path.join(sd, f"{prev['month']}.json"), "w") as f:
            json.dump(prev, f)


def run_notify(now, prev, force=False, creds=True, clear_home=None):
    """一時 home に state を書き、notify.notify を実行。post モックを返す。

    diff/notify は import 済みだが home() は毎回 env を読むので、
    MSRC_MONITOR_HOME を差し替えるだけで一時ディレクトリを向く。
    """
    home = clear_home or tempfile.mkdtemp(prefix="msrc_notify_test_")
    _write_states(home, now, prev)

    env = {"MSRC_MONITOR_HOME": home}
    if creds:
        env["PUSHOVER_TOKEN"] = "fake-token-do-not-log"
        env["PUSHOVER_USER"] = "fake-user-do-not-log"
    else:
        # 認証情報を確実に消す
        for k in ("PUSHOVER_TOKEN", "PUSHOVER_USER"):
            os.environ.pop(k, None)

    # import はテスト先頭で1回だけ (キャッシュ汚染を避けるため関数内 import)
    import notify

    with mock.patch.dict(os.environ, env, clear=False), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        rc = notify.notify(now["month"], force=force)
    return post, rc, home


# ===========================================================================
# flag 無しで --force なしなら post が呼ばれない
# ===========================================================================
def test_no_flag_no_force_no_post():
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2)
    post, rc, _ = run_notify(now, prev, force=False)
    assert post.call_count == 0
    assert rc == 0


# ===========================================================================
# flag ありで post が1回呼ばれる
# ===========================================================================
def test_flag_posts_once():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    post, rc, _ = run_notify(now, prev, force=False)
    assert post.call_count == 1
    assert rc == 0


# ===========================================================================
# --force なら flag 無しでも post が呼ばれる
# ===========================================================================
def test_force_posts_without_flag():
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2)
    post, rc, _ = run_notify(now, prev, force=True)
    assert post.call_count == 1


# ===========================================================================
# 認証情報未設定で例外を投げず正常終了 (post も呼ばれない)
# ===========================================================================
def test_missing_creds_no_exception_no_post():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    post, rc, _ = run_notify(now, prev, force=False, creds=False)
    assert post.call_count == 0
    assert rc == 0


# ===========================================================================
# edge-triggered: 同じ flag セットは再通知しない
# ===========================================================================
def test_edge_triggered_no_duplicate():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    home = tempfile.mkdtemp(prefix="msrc_notify_edge_")
    post1, _, _ = run_notify(now, prev, force=False, clear_home=home)
    assert post1.call_count == 1
    # 同じ内容で再実行 -> 再通知しない
    post2, _, _ = run_notify(now, prev, force=False, clear_home=home)
    assert post2.call_count == 0


# ===========================================================================
# 通知本文に評価語・帰属語が含まれない
# ===========================================================================
def test_notify_body_no_evaluative_words():
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,
                   credit_counts={"Kugelblitz with Microsoft": 39},
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={})
    post, _, _ = run_notify(now, prev, force=False)
    assert post.call_count == 1
    # 送信引数を検査
    _, kwargs = post.call_args
    data = kwargs["data"]
    blob = data["title"] + "\n" + data["message"]
    forbidden = ["危険", "MDASH", "考えられる", "と思われる", "推測",
                 "帰属", "AI が", "AIが", "だろう", "懸念"]
    for w in forbidden:
        assert w not in blob, f"通知本文に評価語/帰属語 '{w}' が混入"
    # priority は通常(0)
    assert data["priority"] == 0
    # 秘匿値が message/title に漏れていない
    assert "fake-token" not in blob
    assert "fake-user" not in blob


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
