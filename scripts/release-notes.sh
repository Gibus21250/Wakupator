#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

PREV=$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)
RANGE="${PREV:+$PREV..}HEAD"

git log --first-parent --pretty=%s "$RANGE" \
| sed -nE 's/^([A-Za-z]+) ?\(([^)]*)\)!?: (.*) \(#([0-9]+)\)$/\1\t\2\t\3\t\4/p' \
| awk -F'\t' '
    function norm(t) {
        t = tolower(t)
        if (t == "feature") return "feat"
        if (t == "bugfix")  return "fix"
        return t
    }
    BEGIN {
        n = split("feat fix perf refactor docs", order, " ")
        title["feat"] = "Features";   title["fix"]      = "Bug fixes"
        title["perf"] = "Performance"; title["refactor"] = "Refactoring"
        title["docs"] = "Documentation"
    }
    { t = norm($1); out[t] = out[t] sprintf("- **%s** : %s (#%s)\n", $2, $3, $4) }
    END {
        for (i = 1; i <= n; i++)
            if (order[i] in out) printf "\n### %s\n%s", title[order[i]], out[order[i]]
    }
'