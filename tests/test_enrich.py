#!/usr/bin/env python3
"""
test_enrich.py — lock in the design principles of the KEV/EPSS integration (Phase 2).

*Most important* KEV = notification trigger / EPSS = never used for notifications (principle 2).
Synthetic data and injection keep the real API untouched. Frozen state is never modified.

Run:
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


# --- synthetic CVRF: T2 / Critical / external / out-of-scope (low-tail Edge) -
def synth_doc():
    return {"Vulnerability": [
        mk_vuln("CVE-2026-1", "Microsoft SharePoint Server RCE", sev="Important"),      # T2
        mk_vuln("CVE-2026-2", "Windows Kernel RCE", sev="Critical"),                    # Critical
        mk_vuln("CVE-2026-3", "Microsoft Edge (Chromium-based) RCE", sev="Important",
                acks=ack("Jane Researcher")),                                           # external
        mk_vuln("CVE-2026-4", "Microsoft Edge (Chromium-based) RCE", sev="Important"),  # out of scope
    ]}


# ===========================================================================
# Target-CVE filter: any of T2/T3, Critical, or external
# ===========================================================================
def test_target_filter():
    tg = cp.target_cves_from_doc(synth_doc())
    ids = {t["cve"] for t in tg}
    assert ids == {"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}, ids
    assert "CVE-2026-4" not in ids, "low-tail uncredited Edge leaked into the target set"
    # each row carries tier/severity/finder (mechanical classification, not attribution)
    row = {t["cve"]: t for t in tg}
    assert row["CVE-2026-1"]["tier"] == "T2"
    assert row["CVE-2026-2"]["severity"] == "Critical"
    assert row["CVE-2026-3"]["finder"] == "external"


# ===========================================================================
# Product/category join: title (specific, for the KEV table) and category (for the
# EPSS table) are attached from CVRF
# ===========================================================================
def test_target_product_and_category_from_cvrf():
    row = {t["cve"]: t for t in cp.target_cves_from_doc(synth_doc())}
    # specific title (source of the KEV table's product name; a different source from
    # the KEV/EPSS values = CVRF)
    assert row["CVE-2026-1"]["title"] == "Microsoft SharePoint Server RCE"
    # category uses the same product_cat() classification as table 5 (a language-neutral
    # internal key; display goes through the JP/EN map)
    assert row["CVE-2026-1"]["category"] == "sharepoint"
    assert row["CVE-2026-2"]["category"] == "kernel_driver"
    assert row["CVE-2026-3"]["category"] == "edge_chromium"
    # single source for the classification logic: category always matches product_cat(title)
    for t in row.values():
        assert t["category"] == cp.product_cat(t["title"])


def test_category_graceful_on_unmatched_title():
    # an unmatched/empty title does not crash and falls into the internal key 'other'
    # (the basis for the report side's "—"/map conversion)
    assert cp.product_cat("") == "other"
    assert cp.product_cat("wholly unmatched gibberish") == "other"


# ===========================================================================
# New KEV listings are detected edge-triggered (state diff)
# ===========================================================================
def test_kev_new_edge_trigger():
    targets = cp.target_cves_from_doc(synth_doc())
    kev_all = {"CVE-2026-2"}   # the Critical one is listed in KEV
    # first run: prev empty -> shows up as new
    e1 = enrich.build_enrichment("2026-Jul", targets, kev_all, None, {}, "T0")
    assert e1["kev_listed"] == ["CVE-2026-2"]
    assert e1["kev_new"] == ["CVE-2026-2"]
    # second run: already listed in prev -> nothing new (edge-triggered)
    e2 = enrich.build_enrichment("2026-Jul", targets, kev_all, None, e1, "T1")
    assert e2["kev_listed"] == ["CVE-2026-2"]
    assert e2["kev_new"] == [], "an already-listed entry was treated as new again (edge-trigger broken)"
    # KEV grew further -> only the delta is new
    kev_all2 = {"CVE-2026-2", "CVE-2026-1"}
    e3 = enrich.build_enrichment("2026-Jul", targets, kev_all2, None, e2, "T2")
    assert e3["kev_new"] == ["CVE-2026-1"]


# ===========================================================================
# *Negative test* a change in EPSS never triggers a notification (principle 2)
# ===========================================================================
def test_epss_never_triggers_notification():
    import notify
    targets = cp.target_cves_from_doc(synth_doc())
    kev_all = {"CVE-2026-2"}
    # EPSS generation 1
    epss_a = {"scores": {"CVE-2026-2": {"epss": 0.10, "percentile": 0.8}}, "date": "2026-07-16"}
    e1 = enrich.build_enrichment("2026-Jul", targets, kev_all, epss_a, {}, "T0")
    # EPSS generation 2 (only the values change; KEV is unchanged)
    epss_b = {"scores": {"CVE-2026-2": {"epss": 0.55, "percentile": 0.95}}, "date": "2026-07-17"}
    e2 = enrich.build_enrichment("2026-Jul", targets, kev_all, epss_b, e1, "T1")

    home = tempfile.mkdtemp(prefix="msrc_epss_test_")
    env = {"MSRC_MONITOR_HOME": home, "PUSHOVER_TOKEN": "x", "PUSHOVER_USER": "y"}
    with mock.patch.dict(os.environ, env), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        # first: new KEV -> notification fires (once)
        notify.notify_kev(e1)
        assert post.call_count == 1
        # second: KEV unchanged, only EPSS changed -> no notification
        notify.notify_kev(e2)
        assert post.call_count == 1, "an EPSS change triggered a notification (violates principle 2)"
        # the sent body must not contain any EPSS value
        _, kwargs = post.call_args
        blob = kwargs["data"]["title"] + kwargs["data"]["message"]
        assert "0.10" not in blob and "0.55" not in blob and "epss" not in blob.lower()


# ===========================================================================
# A new KEV listing calls post / missing credentials do not crash
# ===========================================================================
def test_kev_notify_posts_and_missing_creds_safe():
    import notify
    targets = cp.target_cves_from_doc(synth_doc())
    e = enrich.build_enrichment("2026-Jul", targets, {"CVE-2026-2"}, None, {}, "T0")

    home = tempfile.mkdtemp(prefix="msrc_kev_test_")
    # with credentials -> one post
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home,
                                      "PUSHOVER_TOKEN": "x", "PUSHOVER_USER": "y"}), \
         mock.patch.object(notify.requests, "post") as post:
        post.return_value.raise_for_status = lambda: None
        notify.notify_kev(e)
        assert post.call_count == 1

    # without credentials -> no crash and post is not called
    home2 = tempfile.mkdtemp(prefix="msrc_kev_test2_")
    for k in ("PUSHOVER_TOKEN", "PUSHOVER_USER"):
        os.environ.pop(k, None)
    with mock.patch.dict(os.environ, {"MSRC_MONITOR_HOME": home2}), \
         mock.patch.object(notify.requests, "post") as post:
        rc = notify.notify_kev(e)
        assert post.call_count == 0 and rc == 0


# ===========================================================================
# KEV not fetched (unreachable) neither triggers a notification nor crashes
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
# EPSS: keep only the latest + one prior generation, and record epss_asof
# ===========================================================================
def test_epss_prev_retention_and_asof():
    targets = cp.target_cves_from_doc(synth_doc())
    epss_a = {"scores": {"CVE-2026-2": {"epss": 0.10, "percentile": 0.8}}, "date": "2026-07-16"}
    e1 = enrich.build_enrichment("2026-Jul", targets, set(), epss_a, {}, "T0")
    assert e1["epss"]["CVE-2026-2"]["epss"] == 0.10
    assert e1["epss_asof"] == "2026-07-16"
    assert e1["epss_prev"] is None  # no prior generation on the first run

    epss_b = {"scores": {"CVE-2026-2": {"epss": 0.55, "percentile": 0.95}}, "date": "2026-07-17"}
    e2 = enrich.build_enrichment("2026-Jul", targets, set(), epss_b, e1, "T1")
    assert e2["epss"]["CVE-2026-2"]["epss"] == 0.55
    assert e2["epss_asof"] == "2026-07-17"
    # prior generation = e1's epss (anything older is not kept)
    assert e2["epss_prev"]["CVE-2026-2"]["epss"] == 0.10
    assert e2["epss_prev_asof"] == "2026-07-16"


# ===========================================================================
# enrich(): even when unreachable (fetch returns None), it writes enrichment without crashing
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
        # enrichment.json has been written
        p = os.path.join(home, "state", "enrichment.json")
        assert os.path.exists(p)
        assert enr["target_count"] == 3


# ===========================================================================
# Do not touch frozen state (enrich must not modify state/2026-*.json)
# ===========================================================================
def test_enrich_does_not_touch_frozen_state():
    # Place a frozen state/2026-Jul.json in a temp home and confirm its hash is unchanged
    # before/after enrich. (Real data is not bundled, so use synthetic frozen state.
    # enrich writes only enrichment.json.)
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
    assert before == after, "enrich modified the frozen state"
    # enrich generates enrichment.json (a separate file from state/2026-*.json)
    assert os.path.exists(os.path.join(state, "enrichment.json"))


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
