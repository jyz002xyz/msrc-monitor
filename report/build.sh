#!/usr/bin/env bash
#
# build.sh — generates the draft in 4 formats (JA Word / EN Word / JA PDF / EN PDF).
#
# Facts come from the frozen state; interpretation from interpretation/{ja,en}.md.
# Fixed template annotations (separated-date header / MSRC revision / §14 neutrality / §13 disclaimer)
# are added at generation time.
# Everything passes through the anonymization gate (deny_terms). A hit fails the build.
#
# *** This script does NOT publish. *** Publishing is handled separately by
# report/publish.sh (human approval).
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

echo "[build] 3/5 anonymization gate on docx + chart labels + interpretation sources (deny_terms + causal-implication check)"
python report/anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx \
    report/chart_labels_ja.json report/chart_labels_en.json \
    interpretation/ja.md interpretation/en.md

echo "[build] 4/5 PDF via LibreOffice"
if [ -x "$SOFFICE" ]; then
  "$SOFFICE" --headless --convert-to pdf --outdir drafts drafts/report_ja.docx >/dev/null
  "$SOFFICE" --headless --convert-to pdf --outdir drafts drafts/report_en.docx >/dev/null
else
  echo "[build] Warning: soffice not found ($SOFFICE). Skipping PDF." >&2
fi

echo "[build] 5/5 done. draft 4 formats:"
ls -la drafts/report_*.docx drafts/report_*.pdf 2>/dev/null || true
echo "[build] NOTE: this is a draft. It has NOT been published."
echo "[build]       Publishing goes through report/publish.sh (requires human approval + removal of the PENDING marker)."
