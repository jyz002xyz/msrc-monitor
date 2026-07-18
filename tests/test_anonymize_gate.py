#!/usr/bin/env python3
"""
test_anonymize_gate.py — 匿名化ゲートが個人特定語・因果示唆を検出することを固定する。

今回の漏洩 (個人名が interpretation/*.md コメント・PR本文・commit message に入り、
docx しか見ないゲートを素通りした) の再発防止テスト。意図的に個人名/MDASH を入れた
ケースでゲートが発火することを確認する。
※テスト内では実名を使わず合成プレースホルダ ("Testperson") を用いる
  (実名を追跡ファイルに埋め込まない=このテスト自体がスクラブ方針を守る)。

実行:
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


# ===========================================================================
# deny_terms: text/md ファイル内の個人特定語を検出する
# ===========================================================================
def test_personal_name_detected_in_md():
    p = Path(tempfile.mktemp(suffix=".md"))
    p.write_text("<!-- APPROVED (Testperson, 2026-07-17) -->\n人間（Testperson）が確認。",
                 encoding="utf-8")
    try:
        # 素の given name が deny_terms にあれば検出されること
        hits = g.check_file(p, ["testperson", "otherterm"])
        assert "testperson" in hits, hits
    finally:
        os.unlink(p)


def test_bare_given_name_requires_bare_term():
    # 'testpersonx' (username 相当) では bare 'Testperson' を捕捉できない (今回の盲点の再現)
    p = Path(tempfile.mktemp(suffix=".md"))
    p.write_text("approved by Testperson", encoding="utf-8")
    try:
        assert g.check_file(p, ["testpersonx"]) == [], "username term が given name を誤検出"
        assert g.check_file(p, ["testperson"]) == ["testperson"], "bare term で検出されるべき"
    finally:
        os.unlink(p)


def test_clean_text_no_hit():
    p = Path(tempfile.mktemp(suffix=".md"))
    p.write_text("reviewed and approved by the repository owner on 2026-07-17",
                 encoding="utf-8")
    try:
        assert g.check_file(p, ["testperson", "accountx"]) == []
    finally:
        os.unlink(p)


# ===========================================================================
# チャート注記: 因果を含意する MDASH を検出、_note (運用メモ) は対象外
# ===========================================================================
def test_chart_labels_catch_mdash():
    p = Path(tempfile.mktemp(suffix=".json"))
    p.write_text(json.dumps({"c4": {"note": "Surge (coincides with MDASH rollout)"}}))
    try:
        probs = g.check_chart_labels(p)
        assert probs and "mdash" in probs[0].lower(), probs
    finally:
        os.unlink(p)


def test_chart_labels_note_field_ignored():
    # _note は方針説明メモなので MDASH を含んでも対象外
    p = Path(tempfile.mktemp(suffix=".json"))
    p.write_text(json.dumps({"_note": "do not put MDASH causal claims here",
                             "c1": {"title": "Total CVE trend"}}))
    try:
        assert g.check_chart_labels(p) == []
    finally:
        os.unlink(p)


def test_chart_labels_clean():
    p = Path(tempfile.mktemp(suffix=".json"))
    p.write_text(json.dumps({"c4": {"note": "Surge in July ({prev}->{now})"}}))
    try:
        assert g.check_chart_labels(p) == []
    finally:
        os.unlink(p)


# ===========================================================================
# 実際のチャート設定ファイルは合格 (MDASH 因果示唆なし)
# ===========================================================================
def test_real_chart_labels_pass():
    for lang in ("ja", "en"):
        p = Path(ROOT) / "report" / f"chart_labels_{lang}.json"
        if p.exists():
            assert g.check_chart_labels(p) == [], f"{lang} に因果示唆"


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
