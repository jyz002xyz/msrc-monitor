#!/usr/bin/env python3
"""test_archive.py — Phase A archive generator (report/gen_archive.py).

Verifies: idempotency (an archived month is immutable on re-run), link integrity
(every referenced image exists; cross-language + nav links resolve), and count-meta
consistency (index reflects the manifest). Builds a throwaway docs/ so the real site
is never touched.

実行: python tests/test_archive.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "report" / "gen_archive.py"


def _fake_site(docs: Path):
    """Minimal stand-in for a published site: index + two report pages + assets."""
    (docs / "assets" / "ja").mkdir(parents=True)
    (docs / "assets" / "en").mkdir(parents=True)
    (docs / "assets" / "ja" / "c1.png").write_bytes(b"\x89PNG\r\n")
    (docs / "assets" / "en" / "c1.png").write_bytes(b"\x89PNG\r\n")
    (docs / "index.html").write_text("<!DOCTYPE html><html><body>latest</body></html>", encoding="utf-8")
    for lang, other in (("ja", "en"), ("en", "ja")):
        (docs / f"report_{lang}.html").write_text(
            f'<!DOCTYPE html><html><head><style>.x{{}}</style></head><body>'
            f'<div class="topbar"><a href="index.html">top</a>'
            f'<a href="report_{other}.html">other</a></div>'
            f'<img src="assets/{lang}/c1.png">'
            f'<div class="footer"><a href="index.html">top</a></div>'
            f'</body></html>', encoding="utf-8")


def _run(docs: Path, *args):
    return subprocess.run([sys.executable, str(GEN), "--docs", str(docs), *args],
                          capture_output=True, text=True, check=True)


def _run_nocheck(docs: Path, *args):
    """Run the generator without raising on non-zero exit (for halt assertions)."""
    return subprocess.run([sys.executable, str(GEN), "--docs", str(docs), *args],
                          capture_output=True, text=True, check=False)


def test_backfill_creates_selfcontained_month_and_index():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-07", "--count", "1281")
        month = docs / "archive" / "2026-07"
        assert (month / "ja.html").exists() and (month / "en.html").exists()
        assert (month / "assets" / "ja" / "c1.png").exists(), "assets must be copied in (self-contained)"
        assert (docs / "archive" / "index.html").exists()
        # live pages untouched
        assert (docs / "index.html").read_text(encoding="utf-8") == \
            "<!DOCTYPE html><html><body>latest</body></html>"


def test_links_rewritten_and_resolve():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-07")
        month = docs / "archive" / "2026-07"
        ja = (month / "ja.html").read_text(encoding="utf-8")
        # cross-language link points to sibling en.html; top points up to live root
        assert 'href="en.html"' in ja and "report_en.html" not in ja
        assert 'href="../../index.html"' in ja
        # every referenced image resolves within the month dir
        for img in re.findall(r'src="([^"]+\.png)"', ja):
            assert (month / img).exists(), f"missing archived image {img}"


def test_idempotent_rerun_leaves_month_unchanged():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-07", "--count", "1281")
        sig1 = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        # change the "live" report, then re-run: the frozen month must NOT change
        (docs / "report_ja.html").write_text("<html><body>CHANGED</body></html>", encoding="utf-8")
        _run(docs, "--month", "2026-07", "--count", "1281")
        sig2 = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        assert sig1 == sig2, "an already-archived month must be immutable on re-run"


def test_index_two_value_counts_subject_and_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        # slot 2026-07 but the report is ABOUT June, snapshot 2026-07-15, two-value counts
        _run(docs, "--month", "2026-07", "--subject", "2026-06", "--snapshot", "2026-07-15",
             "--count-cvrf", "1281", "--count-core", "724")
        idx = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        assert "1,281 CVRF / 724 本体相当・core" in idx, "two-value count must render"
        # bilingual order is English first, then Japanese (site convention)
        assert "June 2026 / 2026年6月" in idx, "subject month must render English-first"
        assert "snapshot 2026-07-15 / スナップショット 2026-07-15" in idx
        assert idx.index(">English<") < idx.index(">日本語<"), "report links English-first"
        # links still use the slot key, not the subject
        assert 'href="2026-07/ja.html"' in idx and 'href="2026-07/en.html"' in idx


def test_index_unknown_count_is_em_dash_not_fabricated():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-05")   # no counts
        idx = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        assert "—" in idx, "unknown count must render as em dash, not a fabricated number"


def test_rerun_updates_index_metadata_but_not_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        # slot 2026-07 for a June report; first pass sets subject but no counts -> —
        _run(docs, "--month", "2026-07", "--subject", "2026-06")
        snap = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        # a later pass (SAME subject-month) can set display counts; the frozen snapshot
        # must not change. Changing the subject-month mid-slot is a collision, tested
        # separately in test_slot_collision_different_subject_halts.
        _run(docs, "--month", "2026-07", "--subject", "2026-06", "--count-cvrf", "1281", "--count-core", "724")
        snap2 = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        assert snap == snap2, "updating index metadata must not touch the frozen snapshot"
        idx = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        assert "1,281 CVRF / 724 本体相当・core" in idx


def test_slot_collision_same_subject_is_a_safe_skip():
    """A genuine re-run (same slot, same subject-month) skips the copy and exits 0."""
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-06", "--subject", "2026-06")
        snap = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-06").rglob("*") if p.is_file()}
        r = _run_nocheck(docs, "--month", "2026-06", "--subject", "2026-06")
        assert r.returncode == 0, f"same-subject re-run must succeed, got {r.returncode}: {r.stderr}"
        assert "skipping copy" in (r.stdout + r.stderr)
        snap2 = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-06").rglob("*") if p.is_file()}
        assert snap == snap2, "a safe skip must leave the frozen snapshot unchanged"


def test_slot_collision_different_subject_halts():
    """An occupied slot whose subject-month differs from the incoming one must HALT
    (non-zero exit), not silently skip — otherwise the incoming report is dropped."""
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        # slot 2026-07 occupied by a June report (the pre-re-key collision scenario)
        _run(docs, "--month", "2026-07", "--subject", "2026-06")
        snap = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        # Phase B tries to freeze the July report (subject 2026-07) into the same slot
        r = _run_nocheck(docs, "--month", "2026-07", "--subject", "2026-07")
        assert r.returncode != 0, "a subject-month collision must halt, not skip"
        assert "HALT" in r.stderr and "2026-06" in r.stderr and "2026-07" in r.stderr
        snap2 = {p.name: p.read_bytes() for p in (docs / "archive" / "2026-07").rglob("*") if p.is_file()}
        assert snap == snap2, "a halted run must not mutate the occupying snapshot"


def test_slot_collision_no_recorded_subject_halts():
    """An occupied slot that records no subject-month (legacy) must HALT rather than
    skip — we cannot prove it is a genuine re-run of the same month."""
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-07", "--subject", "2026-06")
        # simulate a legacy snapshot: strip the recorded subject from meta.json
        meta_p = docs / "archive" / "2026-07" / "meta.json"
        meta_p.write_text('{"month": "2026-07", "count": null}\n', encoding="utf-8")
        r = _run_nocheck(docs, "--month", "2026-07", "--subject", "2026-06")
        assert r.returncode != 0, "an occupied slot with no recorded subject must halt"
        assert "HALT" in r.stderr and "no" in r.stderr.lower()


def test_rekey_frees_slot_for_normal_operation():
    """After the June report lives under 2026-06, freezing the July report (subject
    2026-07) into the now-free 2026-07 slot works normally."""
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-06", "--subject", "2026-06")   # June re-keyed home
        r = _run_nocheck(docs, "--month", "2026-07", "--subject", "2026-07")  # July freeze
        assert r.returncode == 0, f"July freeze into a free slot must succeed: {r.stderr}"
        july = docs / "archive" / "2026-07"
        assert (july / "ja.html").exists() and (july / "en.html").exists()
        import json as _json
        assert _json.loads((july / "meta.json").read_text())["subject"] == "2026-07"
        idx = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        # both months now listed, each linking its own slot
        assert 'href="2026-06/en.html"' in idx and 'href="2026-07/en.html"' in idx


def test_index_renders_revision_note_link_when_present():
    """A manifest entry with a bilingual `notes` field renders a revision-note link in
    the index row (outside the frozen snapshot dir); absent it renders nothing."""
    import json
    with tempfile.TemporaryDirectory() as tmp:
        docs = Path(tmp) / "docs"; docs.mkdir()
        _fake_site(docs)
        _run(docs, "--month", "2026-07", "--subject", "2026-07",
             "--count-cvrf", "1150", "--count-core", "665")
        idx0 = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        assert "notes-2026-07.en.html" not in idx0, "no note link without a notes field"
        # add a notes field to the manifest, then rebuild the index only
        mp = docs / "archive" / "manifest.json"
        man = json.loads(mp.read_text(encoding="utf-8"))
        man["months"][0]["notes"] = {"en": "notes-2026-07.en.html",
                                     "ja": "notes-2026-07.ja.html"}
        mp.write_text(json.dumps(man, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _run(docs, "--rebuild-index-only")
        idx = (docs / "archive" / "index.html").read_text(encoding="utf-8")
        assert 'href="notes-2026-07.en.html"' in idx and 'href="notes-2026-07.ja.html"' in idx
        assert "Source data revised after publication" in idx  # English first
        assert idx.index("Source data revised") < idx.index("公開後に元データが改訂")
        # the frozen snapshot dir must not contain the note files
        assert not (docs / "archive" / "2026-07" / "notes-2026-07.en.html").exists()


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
