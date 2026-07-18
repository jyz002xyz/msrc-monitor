#!/usr/bin/env bash
#
# publish.sh — 公開は人間が明示承認したときだけ。Claude Code は実行しない。
#
# 安全弁 (二重):
#   1. interpretation/{ja,en}.md に 'PENDING HUMAN REVIEW' マーカーが残っていたら拒否。
#      → 人間が匿名化・解釈を目視確認し、マーカーを外すまで公開不可 (§13)。
#   2. deny_terms 匿名化ゲートを再チェック。ヒットで拒否。
#   3. 解釈が最新の事実を反映しているかの確認を明示的に促す。
#
# これらを通っても、実際の配布 (git push / 配布先へのコピー等) は
# オペレータが手動で行う。本スクリプトは「公開可否の門番」まで。
#
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source .venv312/bin/activate 2>/dev/null || true

echo "[publish] 門番1: PENDING マーカー確認"
python report/anonymize_gate.py --check-marker

echo "[publish] 門番2: deny_terms 匿名化ゲート (docx)"
python report/anonymize_gate.py drafts/report_ja.docx drafts/report_en.docx

cat <<'EOF'

[publish] 門番3: 人間の最終確認 (自動化しない)
  □ 解釈は最新の事実 (2026-07-15 凍結) を反映しているか
  □ 事実と解釈の日付差 (ヘッダ) を確認したか
  □ 匿名化 (個人・組織・環境) を目視で確認したか
  □ §13 免責・§14 中立性が入っているか

上記を人間が確認済みなら、配布 (git push / 配布先コピー等) を手動で実行してよい。
本スクリプトは門番まで。実際の配布はここでは行わない。
EOF
echo "[publish] 門番通過。配布はオペレータが手動で。"
