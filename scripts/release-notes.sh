#!/usr/bin/env bash
set -euo pipefail

PREV=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)
RANGE="${PREV:+$PREV..}HEAD"

git log --first-parent --no-merges --pretty=%s $RANGE \
| sed -nE 's/^([A-Za-z]+) \(([^)]*)\): (.*) \(#([0-9]+)\)$/\1|\2|\3|\4/p' \
| sort -t'|' -k1,1 -k2,2 \
| awk -F'|' '
    $1 != last { printf "\n### %s\n", $1; last = $1 }
    { printf "- **%s** : %s (#%s)\n", $2, $3, $4 }
'