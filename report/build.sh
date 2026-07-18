#!/usr/bin/env bash
#
# build.sh — ドラフト4形式 (日Word/英Word/日PDF/英PDF) を生成する。
#
# 事実は凍結 state から、解釈は interpretation/{ja,en}.md から。
# テンプレート固定注記 (日付分離ヘッダ/MSRC改訂/§14中立性/§13免責) は生成側。
# 匿名化ゲート (deny_terms) を通す。ヒットで生成失敗。
#
# ★このスクリプトは publish しない。★ 公開は report/publish.sh (人間承認) が別途行う。
#
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root
# shellcheck disable=SC1091
source .venv312/bin/activate 2>/dev/null || true

SOFFICE="${SOFFICE:-/Applications/LibreOffice.app/Contents/MacOS/soffice}"

echo "[build] 1/5 charts from frozen state"
python report/gen_charts.py

echo "[build] 2/5 docx (ja/en) from state + interpretation"
node report/gen_report.js --lang ja
node report/gen_report.js --lang en

echo "[build] 3/5 anonymization gate on docx + chart labels + interpretation源 (deny_terms + 因果示唆)"
python report/anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx \
    report/chart_labels_ja.json report/chart_labels_en.json \
    interpretation/ja.md interpretation/en.md

echo "[build] 4/5 PDF via LibreOffice"
if [ -x "$SOFFICE" ]; then
  "$SOFFICE" --headless --convert-to pdf --outdir drafts drafts/report_ja.docx >/dev/null
  "$SOFFICE" --headless --convert-to pdf --outdir drafts drafts/report_en.docx >/dev/null
else
  echo "[build] 警告: soffice が見つからない ($SOFFICE)。PDF をスキップ。" >&2
fi

echo "[build] 5/5 done. draft 4 formats:"
ls -la drafts/report_*.docx drafts/report_*.pdf 2>/dev/null || true
echo "[build] NOTE: これはドラフト。publish はしていない。"
echo "[build]       公開は report/publish.sh (人間承認 + PENDING マーカー除去が必須)。"
