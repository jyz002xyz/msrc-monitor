#!/usr/bin/env bash
#
# run_monthly.sh — 月次実行のオーケストレーション (systemd から呼ばれる)
#
# 処理順:
#   0. テストを先に走らせ、壊れていたら中止 (安全弁)
#   1. 当月を収集 (冪等)
#   2. 差分を算出 (JSON)
#   3. 下書きを生成
#   4. flag があれば通知 (edge-triggered)
#   5. healthchecks.io に成功を ping (dead-man's switch)
#
# 設計原則: テストが壊れていたら収集も通知もしない (壊れた状態で走らせない)。
#
# 環境変数 (env.sh / EnvironmentFile から供給。git 管理外):
#   PUSHOVER_TOKEN / PUSHOVER_USER … Pushover 通知の秘匿値 (未設定なら通知スキップ)
#   HEALTHCHECK_URL               … 成功 ping 先 (未設定ならスキップ)
#
set -euo pipefail
cd "$(dirname "$0")"

# Pi では pyenv の 3.12 系 venv。仮想環境があれば有効化する。
if [ -f .venv312/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv312/bin/activate
fi

# Patch Tuesday (第2火曜) の翌日だけ実行する。
# 第2火曜は毎月 8〜14 日のどこか。その翌日 (水曜) は 9〜15 日のどこか。
# 9〜15 日の 7 連日には水曜がちょうど1つだけ入り、それが必ず第2火曜の翌日になる。
# timer も同じ範囲 (09..15 Wed) で起動するが、念のためスクリプト側でも確認する
# (bot 群の NTP guard と同様、ロジックはスクリプト側に持たせる)。
# --force で門番を無視できる (手動実行用)。
FORCE_RUN="${1:-}"
DOM="$(date +%-d)"
DOW="$(date +%u)"   # 1=月 ... 3=水 ... 7=日
if [ "$FORCE_RUN" != "--force" ]; then
  if [ "$DOW" != "3" ] || [ "$DOM" -lt 9 ] || [ "$DOM" -gt 15 ]; then
    echo "[run_monthly] 第2水曜 (Patch Tuesday 翌日) ではないので何もしない "
    echo "              (DOM=$DOM DOW=$DOW)。手動実行は --force を付ける。"
    exit 0
  fi
fi

# 0. テスト (壊れていたら即中止) ---------------------------------------------
echo "[run_monthly] テスト実行 (安全弁)"
python tests/test_regression.py
python tests/test_diff.py
python tests/test_draft.py
python tests/test_notify.py

# 1. 当月を収集 (冪等) -------------------------------------------------------
MONTH="$(python -c 'import collect; print(collect.current_month_tag())')"
echo "[run_monthly] 当月: $MONTH"
python collect.py "$MONTH"

# 2. 差分を算出 --------------------------------------------------------------
python diff.py "$MONTH" --json > "state/.diff_${MONTH}.json"

# 3. 下書きを生成 ------------------------------------------------------------
mkdir -p drafts
python draft.py "$MONTH" --out "drafts/${MONTH}.md"

# 4. flag があれば通知 -------------------------------------------------------
python notify.py "$MONTH"

# 5. healthchecks.io に成功を ping (dead-man's switch) -----------------------
#    URL は環境変数。未設定ならスキップ。失敗しても全体は落とさない。
if [ -n "${HEALTHCHECK_URL:-}" ]; then
  curl -fsS -m 10 "$HEALTHCHECK_URL" >/dev/null || true
fi

echo "[run_monthly] 完了: $MONTH"
