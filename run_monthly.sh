#!/usr/bin/env bash
#
# run_monthly.sh — orchestrates the monthly run (invoked by systemd).
#
# Steps:
#   0. Run the tests first and abort if anything is broken (safety check)
#   1. Collect the current month (idempotent)
#   2. Compute the diff (JSON)
#   3. Generate the draft
#   4. Notify if a flag is set (edge-triggered)
#   5. Ping healthchecks.io on success (dead-man's switch)
#
# Design principle: if the tests are broken, don't collect or notify (never run in a broken state).
#
# Environment variables (supplied via env.sh / EnvironmentFile; not under git control):
#   PUSHOVER_TOKEN / PUSHOVER_USER … Pushover notification secrets (skip notifications if unset)
#   HEALTHCHECK_URL               … success ping target (skip if unset)
#
set -euo pipefail
cd "$(dirname "$0")"

# On the Pi this is a pyenv 3.12 venv. Activate the virtualenv if present.
if [ -f .venv312/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv312/bin/activate
fi

# Only run on the day after Patch Tuesday (the second Wednesday).
# The second Tuesday (Patch Tuesday) always falls on the 8th-14th of the month, so the
# following day (Wednesday) falls on the 9th-15th.
# Any 7-day span from the 9th to the 15th contains exactly one Wednesday, and it is always
# the day after the second Tuesday.
# The timer fires over the same range (09..15 Wed), but we double-check here in the script
# just in case (like the NTP guard on the bots, keep the logic in the script).
# Use --force to bypass the gate (for manual runs).
FORCE_RUN="${1:-}"
DOM="$(date +%-d)"
DOW="$(date +%u)"   # 1=Mon ... 3=Wed ... 7=Sun
if [ "$FORCE_RUN" != "--force" ]; then
  if [ "$DOW" != "3" ] || [ "$DOM" -lt 9 ] || [ "$DOM" -gt 15 ]; then
    echo "[run_monthly] Not the second Wednesday (the day after Patch Tuesday), so nothing to do "
    echo "              (DOM=$DOM DOW=$DOW). Use --force for a manual run."
    exit 0
  fi
fi

# 0. Tests (abort immediately if broken) -------------------------------------
echo "[run_monthly] Running tests (safety check)"
python tests/test_regression.py
python tests/test_diff.py
python tests/test_draft.py
python tests/test_notify.py

# 1. Collect the current month (idempotent) ----------------------------------
MONTH="$(python -c 'import collect; print(collect.current_month_tag())')"
echo "[run_monthly] Current month: $MONTH"
python collect.py "$MONTH"

# 2. Compute the diff --------------------------------------------------------
python diff.py "$MONTH" --json > "state/.diff_${MONTH}.json"

# 3. Generate the draft ------------------------------------------------------
mkdir -p drafts
python draft.py "$MONTH" --out "drafts/${MONTH}.md"

# 4. Notify if a flag is set -------------------------------------------------
python notify.py "$MONTH"

# 5. Ping healthchecks.io on success (dead-man's switch) ---------------------
#    URL comes from an environment variable. Skip if unset. Don't fail the whole run if it errors.
if [ -n "${HEALTHCHECK_URL:-}" ]; then
  curl -fsS -m 10 "$HEALTHCHECK_URL" >/dev/null || true
fi

echo "[run_monthly] Done: $MONTH"
