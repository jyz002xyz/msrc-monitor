#!/usr/bin/env python3
"""
test_anonymize_gate.py — pin that the anonymization gate detects personal
identifiers and causal implications.

Regression test for the recent leak (a personal name appeared in
interpretation/*.md comments, a PR body, and a commit message, and slipped
past the gate because it only inspected the docx). Confirms the gate fires on
cases that deliberately include a personal name / MDASH.
Note: the test uses a synthetic placeholder ("Testperson") instead of a real
name (no real name is embedded in a tracked file, so this test itself follows
the scrub policy).

Run:
    cd ~/msrc_monitor
    python tests/test_anonymize_gate.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "report"))

import anonymize_gate as g


def _tmpfile(suffix: str) -> Path:
    """Create a temp file securely (mkstemp avoids mktemp's TOCTOU) and return its path."""
    fd, name = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return Path(name)


# ===========================================================================
# deny_terms: detect personal identifiers inside text/md files
# ===========================================================================
def test_personal_name_detected_in_md():
    p = _tmpfile(".md")
    p.write_text("<!-- APPROVED (Testperson, 2026-07-17) -->\n人間（Testperson）が確認。",
                 encoding="utf-8")
    try:
        # A bare given name present in deny_terms should be detected
        hits = g.check_file(p, ["testperson", "otherterm"])
        assert "testperson" in hits, hits
    finally:
        os.unlink(p)


def test_bare_given_name_requires_bare_term():
    # 'testpersonx' (username-like) cannot catch a bare 'Testperson' (reproduces the blind spot)
    p = _tmpfile(".md")
    p.write_text("approved by Testperson", encoding="utf-8")
    try:
        assert g.check_file(p, ["testpersonx"]) == [], "username term false-matched a given name"
        assert g.check_file(p, ["testperson"]) == ["testperson"], "bare term should have matched"
    finally:
        os.unlink(p)


def test_clean_text_no_hit():
    p = _tmpfile(".md")
    p.write_text("reviewed and approved by the repository owner on 2026-07-17",
                 encoding="utf-8")
    try:
        assert g.check_file(p, ["testperson", "accountx"]) == []
    finally:
        os.unlink(p)


# ===========================================================================
# Chart annotations: detect a causal-implying MDASH; _note (ops memo) is exempt
# ===========================================================================
def test_chart_labels_catch_mdash():
    p = _tmpfile(".json")
    p.write_text(json.dumps({"c4": {"note": "Surge (coincides with MDASH rollout)"}}))
    try:
        probs = g.check_chart_labels(p)
        assert probs and "mdash" in probs[0].lower(), probs
    finally:
        os.unlink(p)


def test_chart_labels_note_field_ignored():
    # _note is a policy-explanation memo, so it is exempt even if it contains MDASH
    p = _tmpfile(".json")
    p.write_text(json.dumps({"_note": "do not put MDASH causal claims here",
                             "c1": {"title": "Total CVE trend"}}))
    try:
        assert g.check_chart_labels(p) == []
    finally:
        os.unlink(p)


def test_chart_labels_clean():
    p = _tmpfile(".json")
    p.write_text(json.dumps({"c4": {"note": "Surge in July ({prev}->{now})"}}))
    try:
        assert g.check_chart_labels(p) == []
    finally:
        os.unlink(p)


# ===========================================================================
# The real chart config files pass (no MDASH causal implication)
# ===========================================================================
def test_real_chart_labels_pass():
    for lang in ("ja", "en"):
        p = Path(ROOT) / "report" / f"chart_labels_{lang}.json"
        if p.exists():
            assert g.check_chart_labels(p) == [], f"{lang} has a causal implication"


# --- Runner that also works without pytest ----------------------------------
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
