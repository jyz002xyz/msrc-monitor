#!/usr/bin/env bash
#
# publish.sh — publish only when a human has explicitly approved. Claude Code never runs this.
#
# Safety checks (two layers):
#   1. Reject if the 'PENDING HUMAN REVIEW' marker still remains in interpretation/{ja,en}.md.
#      → Cannot publish until a human has visually reviewed the anonymization and interpretation
#        and removed the marker (§13).
#   2. Re-run the deny_terms anonymization gate. Reject on a hit.
#   3. Explicitly prompt to confirm that the interpretation reflects the latest facts.
#
# Even after these pass, the actual distribution (git push / copy to a distribution target, etc.)
# is done manually by the operator. This script only acts as the gatekeeper for publish approval.
#
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv312/bin/activate 2>/dev/null || true

echo "[publish] Gate 1: check the PENDING marker"
python report/anonymize_gate.py --check-marker

echo "[publish] Gate 2: deny_terms anonymization gate (docx)"
python report/anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx

cat <<'EOF'

[publish] Gate 3: final human confirmation (not automated)
  □ Does the interpretation reflect the latest facts (frozen 2026-07-15)?
  □ Have you checked the date gap between facts and interpretation (header)?
  □ Have you visually confirmed the anonymization (people, organizations, environment)?
  □ Are the §13 disclaimer and §14 neutrality statement present?

Once a human has confirmed the above, you may run the distribution (git push / copy to a
distribution target, etc.) manually.
This script only acts as the gatekeeper. It does not perform the actual distribution.
EOF
echo "[publish] Gate passed. The operator distributes manually."
