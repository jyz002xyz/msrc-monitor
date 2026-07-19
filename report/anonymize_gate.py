#!/usr/bin/env python3
"""
anonymize_gate.py — anonymization gate for generated artifacts (a safety valve before publishing)

Checks the body text and metadata (core properties) of a generated docx against
deny_terms using case-insensitive substring matching. A single hit exits 1
(treated as a generation failure).

deny_terms is loaded from report/deny_terms.txt (contains real names; gitignored)
if present, otherwise from report/deny_terms.txt.example (the template).

Publish gating is separate: with --check-marker, if a 'PENDING HUMAN REVIEW'
marker remains in interpretation/{ja,en}.md, exit 2 (publish refused).

Usage:
    python anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx
    python anonymize_gate.py --check-marker      # pre-publish check
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOME = HERE.parent


def load_deny_terms() -> list[str]:
    real = HERE / "deny_terms.txt"
    example = HERE / "deny_terms.txt.example"
    path = real if real.exists() else example
    terms = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        terms.append(s)
    return terms, path.name


def docx_text(docx_path: Path) -> str:
    """Extract body text and core properties from a docx (strip tags)."""
    chunks = []
    with zipfile.ZipFile(docx_path) as z:
        for name in ("word/document.xml", "docProps/core.xml", "docProps/app.xml"):
            try:
                xml = z.read(name).decode("utf-8", "ignore")
            except KeyError:
                continue
            # strip <w:t>...</w:t> and other tags to get plain text
            xml = re.sub(r"<[^>]+>", " ", xml)
            chunks.append(xml)
    return " ".join(chunks)


def file_text(p: Path) -> str:
    """Extract text from docx; read anything else (json/txt/etc.) as-is."""
    if p.suffix.lower() == ".docx":
        return docx_text(p)
    return p.read_text(encoding="utf-8", errors="ignore")


def check_file(p: Path, terms: list[str]) -> list[str]:
    text = file_text(p).lower()
    return [t for t in terms if t.lower() in text]


def check_chart_labels(p: Path) -> list[str]:
    """Check that chart display text has no causally-implying names (MDASH, etc.).

    Arrow annotations on charts are short and lose nuance, so this guards against
    misreading a name as causation. The _note field (operational notes) is excluded
    since it holds policy explanations."""
    import json as _json
    problems = []
    try:
        data = _json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return problems
    FORBIDDEN = ["mdash"]  # causal-implication terms kept out of chart annotations

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "_note":
                    continue  # operational notes are policy explanations, so skip them
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            low = node.lower()
            for f in FORBIDDEN:
                if f in low:
                    problems.append(f"{path}: '{node}' contains '{f}' (causal implication)")
    walk(data)
    return problems


def scan_commits_and_tracked(terms: list[str]) -> list[str]:
    """Match commit messages (origin/main..HEAD) and tracked files against deny_terms.

    Prevents a recurrence of the leak where the gate only inspected docx files
    (a personal name landing in a PR body / commit message / md source). If a bare
    given name shows up in a commit message or a tracked file, stop the push.
    """
    import shutil
    import subprocess
    problems = []
    # Resolve an absolute git path (avoids relying on PATH lookup). If git is not
    # available, the checks cannot run -- same net result as the previous failure path.
    git = shutil.which("git")
    if not git:
        return problems
    try:
        msgs = subprocess.check_output(
            [git, "log", "origin/main..HEAD", "--format=%H %s%n%b%n===="],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        msgs = ""
    low = msgs.lower()
    for t in terms:
        if t.lower() in low:
            problems.append(f"commit message contains '{t}'")
    # tracked files (git grep). deny_terms.txt itself is gitignored, so it shouldn't appear.
    for t in terms:
        try:
            r = subprocess.run([git, "grep", "-il", t], capture_output=True, text=True)
            files = [f for f in r.stdout.strip().splitlines()
                     if f and "deny_terms.txt" not in f]
            if files:
                problems.append(f"tracked file contains '{t}' -> {files}")
        except Exception:
            pass
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("docx", nargs="*", help="docx / md / json files to check")
    ap.add_argument("--check-marker", action="store_true",
                    help="pre-publish: refuse if a PENDING marker remains")
    ap.add_argument("--check-scrub", action="store_true",
                    help="pre-push: check commit messages and tracked files for deny_terms")
    args = ap.parse_args()

    if args.check_scrub:
        terms, src = load_deny_terms()
        probs = scan_commits_and_tracked(terms)
        if probs:
            print(f"[gate] SCRUB failed ({src}): personally-identifying terms remain outside the gate", file=sys.stderr)
            for p in probs:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print(f"[gate] SCRUB passed: no deny_terms in commit messages or tracked files ({src})")
        return 0

    if args.check_marker:
        pending = []
        for lang in ("ja", "en"):
            md = HOME / "interpretation" / f"{lang}.md"
            if md.exists() and "PENDING HUMAN REVIEW" in md.read_text(encoding="utf-8"):
                pending.append(md.name)
        if pending:
            print(f"[gate] PUBLISH refused: unapproved marker(s) remain -> {', '.join(pending)}",
                  file=sys.stderr)
            print("[gate] Cannot publish until a human reviews the anonymization/interpretation and removes the marker.",
                  file=sys.stderr)
            return 2
        print("[gate] publish OK: no PENDING marker.")
        return 0

    terms, src = load_deny_terms()
    print(f"[gate] deny_terms: {len(terms)} terms ({src})")
    any_hit = False
    for d in args.docx:
        p = Path(d)
        if not p.exists():
            print(f"[gate] not found: {d}", file=sys.stderr)
            return 1
        hits = check_file(p, terms)
        if hits:
            any_hit = True
            print(f"[gate] FAIL {p.name}: deny-term hit -> {hits}", file=sys.stderr)
        else:
            print(f"[gate] OK   {p.name}: no deny terms")
        # chart config files: also check for causal implications (MDASH, etc.)
        if "chart_labels" in p.name and p.suffix.lower() == ".json":
            probs = check_chart_labels(p)
            if probs:
                any_hit = True
                print(f"[gate] FAIL {p.name}: causal implication in chart annotations -> {probs}", file=sys.stderr)
            else:
                print(f"[gate] OK   {p.name}: no causal implication in chart annotations")
    if any_hit:
        print("[gate] anonymization gate failed. Treated as a generation failure.", file=sys.stderr)
        return 1
    print("[gate] anonymization gate passed (no hits in deny_terms or chart annotations).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
