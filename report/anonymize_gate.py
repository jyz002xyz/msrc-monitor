#!/usr/bin/env python3
"""
anonymize_gate.py — 生成物の匿名化ゲート (公開前提の安全弁)

生成された docx の本文テキストとメタデータ(コアプロパティ)を、deny_terms に対して
case-insensitive の部分文字列一致でチェックする。1件でもヒットしたら exit 1
(生成失敗扱い)。

deny_terms は report/deny_terms.txt (実名含む・gitignore) を優先し、無ければ
report/deny_terms.txt.example (雛形) を使う。

publish 判定は別: --check-marker で interpretation/{ja,en}.md に
'PENDING HUMAN REVIEW' マーカーが残っていれば exit 2 (publish 拒否)。

使い方:
    python anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx
    python anonymize_gate.py --check-marker      # publish 前チェック
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
    """docx から本文テキストとコアプロパティを抽出 (タグ除去)。"""
    chunks = []
    with zipfile.ZipFile(docx_path) as z:
        for name in ("word/document.xml", "docProps/core.xml", "docProps/app.xml"):
            try:
                xml = z.read(name).decode("utf-8", "ignore")
            except KeyError:
                continue
            # <w:t>...</w:t> や一般タグを除去してテキスト化
            xml = re.sub(r"<[^>]+>", " ", xml)
            chunks.append(xml)
    return " ".join(chunks)


def file_text(p: Path) -> str:
    """docx はテキスト抽出、それ以外 (json/txt 等) は素で読む。"""
    if p.suffix.lower() == ".docx":
        return docx_text(p)
    return p.read_text(encoding="utf-8", errors="ignore")


def check_file(p: Path, terms: list[str]) -> list[str]:
    text = file_text(p).lower()
    return [t for t in terms if t.lower() in text]


def check_chart_labels(p: Path) -> list[str]:
    """チャート表示テキストに因果を含意する名前 (MDASH 等) が無いか。

    チャートの矢印注記は短くニュアンスが落ちるため、名前からの因果誤読を防ぐ。
    _note フィールド (運用メモ) は方針説明のため除外。"""
    import json as _json
    problems = []
    try:
        data = _json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return problems
    FORBIDDEN = ["mdash"]  # チャート注記に置かない因果示唆語

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "_note":
                    continue  # 運用メモは方針説明なので対象外
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            low = node.lower()
            for f in FORBIDDEN:
                if f in low:
                    problems.append(f"{path}: '{node}' に '{f}' (因果示唆)")
    walk(data)
    return problems


def scan_commits_and_tracked(terms: list[str]) -> list[str]:
    """コミットメッセージ (origin/main..HEAD) と追跡ファイルを deny_terms で照合。

    ゲートが docx しか見ていなかった漏洩 (PR本文/コミットmsg/md source に個人名) の
    再発防止。素の given name が commit message や追跡ファイルに入ったら push を止める。
    """
    import subprocess
    problems = []
    try:
        msgs = subprocess.check_output(
            ["git", "log", "origin/main..HEAD", "--format=%H %s%n%b%n===="],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        msgs = ""
    low = msgs.lower()
    for t in terms:
        if t.lower() in low:
            problems.append(f"commit-message に '{t}'")
    # 追跡ファイル (git grep)。deny_terms.txt 自体は gitignore なので出ない前提。
    for t in terms:
        try:
            r = subprocess.run(["git", "grep", "-il", t], capture_output=True, text=True)
            files = [f for f in r.stdout.strip().splitlines()
                     if f and "deny_terms.txt" not in f]
            if files:
                problems.append(f"追跡ファイル '{t}' -> {files}")
        except Exception:
            pass
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("docx", nargs="*", help="チェックする docx / md / json")
    ap.add_argument("--check-marker", action="store_true",
                    help="publish 前: PENDING マーカー残存で拒否")
    ap.add_argument("--check-scrub", action="store_true",
                    help="pre-push: コミットmsg・追跡ファイルに deny_terms が無いか")
    args = ap.parse_args()

    if args.check_scrub:
        terms, src = load_deny_terms()
        probs = scan_commits_and_tracked(terms)
        if probs:
            print(f"[gate] SCRUB 不合格 ({src}): 個人特定語がゲート外に残存", file=sys.stderr)
            for p in probs:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print(f"[gate] SCRUB 合格: commit message・追跡ファイルに deny_terms なし ({src})")
        return 0

    if args.check_marker:
        pending = []
        for lang in ("ja", "en"):
            md = HOME / "interpretation" / f"{lang}.md"
            if md.exists() and "PENDING HUMAN REVIEW" in md.read_text(encoding="utf-8"):
                pending.append(md.name)
        if pending:
            print(f"[gate] PUBLISH 拒否: 未承認マーカーが残存 -> {', '.join(pending)}",
                  file=sys.stderr)
            print("[gate] 人間が匿名化・解釈を確認し、マーカーを外すまで publish 不可。",
                  file=sys.stderr)
            return 2
        print("[gate] publish 可: PENDING マーカーなし。")
        return 0

    terms, src = load_deny_terms()
    print(f"[gate] deny_terms: {len(terms)} 語 ({src})")
    any_hit = False
    for d in args.docx:
        p = Path(d)
        if not p.exists():
            print(f"[gate] 見つからない: {d}", file=sys.stderr)
            return 1
        hits = check_file(p, terms)
        if hits:
            any_hit = True
            print(f"[gate] FAIL {p.name}: 禁止語ヒット -> {hits}", file=sys.stderr)
        else:
            print(f"[gate] OK   {p.name}: 禁止語なし")
        # チャート設定ファイルは因果示唆 (MDASH 等) もチェック
        if "chart_labels" in p.name and p.suffix.lower() == ".json":
            probs = check_chart_labels(p)
            if probs:
                any_hit = True
                print(f"[gate] FAIL {p.name}: チャート注記の因果示唆 -> {probs}", file=sys.stderr)
            else:
                print(f"[gate] OK   {p.name}: チャート注記に因果示唆なし")
    if any_hit:
        print("[gate] 匿名化ゲート不合格。生成失敗扱い。", file=sys.stderr)
        return 1
    print("[gate] 匿名化ゲート合格 (deny_terms・チャート注記ともヒットなし)。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
