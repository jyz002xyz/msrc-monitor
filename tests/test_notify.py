#!/usr/bin/env python3
"""
test_notify.py — lock in notify.py's edge-triggered notification behavior

Mocks requests.post so the real API is never called. Writes synthetic state
into a temp state directory (MSRC_MONITOR_HOME) and evaluates against it.

Run:
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
    """Write state into a temp home and run notify.notify. Returns the post mock.

    diff/notify are already imported, but home() reads env each time, so pointing
    MSRC_MONITOR_HOME at a temp directory is enough to redirect it there.
    """
    home = clear_home or tempfile.mkdtemp(prefix="msrc_notify_test_")
    _write_states(home, now, prev)

    env = {"MSRC_MONITOR_HOME": home}
    if creds:
        env["PUSHOVER_TOKEN"] = "fake-token-do-not-log"
        env["PUSHOVER_USER"] = "fake-user-do-not-log"
    else:
        # make sure the credentials are cleared
        for k in ("PUSHOVER_TOKEN", "PUSHOVER_USER"):
            os.environ.pop(k, None)

    # import once at the top of the test (function-local import to avoid cache pollution)
    import notify

    with mock.patch.dict(os.environ, env, clear=False), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        rc = notify.notify(now["month"], force=force)
    return post, rc, home


# ===========================================================================
# no flag and no --force -> post is not called
# ===========================================================================
def test_no_flag_no_force_no_post():
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2)
    post, rc, _ = run_notify(now, prev, force=False)
    assert post.call_count == 0
    assert rc == 0


# ===========================================================================
# with a flag, post is called once
# ===========================================================================
def test_flag_posts_once():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    post, rc, _ = run_notify(now, prev, force=False)
    assert post.call_count == 1
    assert rc == 0


# ===========================================================================
# with --force, post is called even without a flag
# ===========================================================================
def test_force_posts_without_flag():
    now = mk_state("2026-Jul", cve_total=1050, t2=10, t3=2, zero_days=[])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2)
    post, rc, _ = run_notify(now, prev, force=True)
    assert post.call_count == 1


# ===========================================================================
# missing credentials: exit normally without raising (and no post)
# ===========================================================================
def test_missing_creds_no_exception_no_post():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    post, rc, _ = run_notify(now, prev, force=False, creds=False)
    assert post.call_count == 0
    assert rc == 0


# ===========================================================================
# edge-triggered: the same flag set is not re-notified
# ===========================================================================
def test_edge_triggered_no_duplicate():
    now = mk_state("2026-Jul", cve_total=1050,
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000)
    home = tempfile.mkdtemp(prefix="msrc_notify_edge_")
    post1, _, _ = run_notify(now, prev, force=False, clear_home=home)
    assert post1.call_count == 1
    # re-run with identical content -> not re-notified
    post2, _, _ = run_notify(now, prev, force=False, clear_home=home)
    assert post2.call_count == 0


# ===========================================================================
# the notification body contains no evaluative or attribution words
# ===========================================================================
def test_notify_body_no_evaluative_words():
    now = mk_state("2026-Jul", cve_total=1600, t2=20, t3=5,
                   credit_counts={"Kugelblitz with Microsoft": 39},
                   zero_days=[{"cve": "X", "credited": False, "credits": []}])
    prev = mk_state("2026-Jun", cve_total=1000, t2=10, t3=2,
                    credit_counts={})
    post, _, _ = run_notify(now, prev, force=False)
    assert post.call_count == 1
    # inspect the send arguments
    _, kwargs = post.call_args
    data = kwargs["data"]
    blob = (data["title"] + "\n" + data["message"]).lower()
    # evaluative / attribution / speculation words that must never appear
    forbidden = ["dangerous", "mdash", "likely", "probably", "attribut",
                 "speculat", "suspect", "concern", "ai did", "believe"]
    for w in forbidden:
        assert w not in blob, f"evaluative/attribution word '{w}' leaked into the notification body"
    # priority is normal (0)
    assert data["priority"] == 0
    # secrets are not leaking into message/title
    assert "fake-token" not in blob
    assert "fake-user" not in blob


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
