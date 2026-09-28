#!/usr/bin/env bash
# check_diff_scope.sh — what the daily bot may change (run from the repo root, after run.py).
#
# Allowed:
#   docs/kev/**                          the published site
#   kev/snapshots/YYYY-MM.open.json.gz   the current month (rewritten daily; deleted when sealed)
#   kev/snapshots/catalog_meta.json      last catalog size for the integrity gate
#   kev/snapshots/YYYY-MM.json.gz        ONLY as a new file: the month being sealed
#
# Refused: modifying or deleting an existing sealed snapshot (YYYY-MM.json.gz), and anything
# outside the paths above. A sealed month changes only through a migration PR a person opens
# and reviews (see kev/README.md) — never through the auto-merged daily PR, where it would
# pass unreviewed.
#
# Exit 0 = in scope, 1 = refused (each offending path is printed as a GitHub error).
set -euo pipefail

bad=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  st=${line:0:2}
  path=${line:3}
  case "$path" in
    docs/kev/*|kev/snapshots/catalog_meta.json) ;;
    kev/snapshots/[0-9][0-9][0-9][0-9]-[0-9][0-9].open.json.gz) ;;
    kev/snapshots/[0-9][0-9][0-9][0-9]-[0-9][0-9].json.gz)
      if [ "$st" != "??" ]; then
        echo "::error::sealed snapshot changed ($st): $path — sealed months change only via a reviewed migration PR"
        bad=1
      fi ;;
    *) echo "::error::out-of-scope change not allowed for auto-update: $path"; bad=1 ;;
  esac
done < <(git status --porcelain --untracked-files=all)

exit "$bad"
