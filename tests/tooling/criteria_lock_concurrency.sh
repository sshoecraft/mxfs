#!/bin/bash
# criteria_lock_concurrency.sh — do concurrent board writers lose each other's cells?
#
# Rig groups run several run.sh at once, each writing its own configuration's
# column into the one board file.  The board is rewritten whole, so without
# criteria.py's lock two writers read the same snapshot and the later save drops
# the earlier one's cells.  This runs one `pending` writer per configuration, all
# at once, against a COPY of the board, then checks that every writer's markers
# landed, and that `finalize --at` heals only the column it names.
#
# Never touches data/criteria.json: MXFS_CRIT points criteria.py at the copy.
#
# --control runs the same writers with the lock disabled, to show the check can
# see a lost update at all; it exits 0 iff at least one writer's cells were lost.
#
# Usage: tests/tooling/criteria_lock_concurrency.sh [--control]
# Exit 0 iff every check passes.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
cp "$REPO/data/criteria.json" "$W/criteria.json"
export MXFS_CRIT="$W/criteria.json"
CRITPY="$REPO/tools/criteria.py"
CONTROL=0
[ "${1:-}" = --control ] && CONTROL=1
writer() {  # criteria.py, or with --control the same code with its lock disabled
    if [ "$CONTROL" = 1 ]; then
        python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import criteria
criteria.take_lock = lambda: None
sys.argv = ["criteria.py"] + sys.argv[2:]
sys.exit(criteria.main())' "$REPO/tools" "$@"
    else
        "$CRITPY" "$@"
    fi
}

mapfile -t IDS < <("$CRITPY" rows | cut -f3 | head -12)
mapfile -t CFGS < <(python3 "$REPO/tools/configuration.py" list | head -12)
[ "${#IDS[@]}" -ge 2 ] && [ "${#CFGS[@]}" -ge 2 ] || { echo "FAIL: no ids or configurations to write"; exit 1; }
echo "writers=${#CFGS[@]} ids_each=${#IDS[@]}"

pids=()
for c in "${CFGS[@]}"; do
    writer pending "${IDS[@]}" --at "$c" --run-id "lockcheck-$c" > "$W/out.$(echo "$c" | tr / -)" 2>&1 &
    pids+=($!)
done
crashed=0
for p in "${pids[@]}"; do wait "$p" || crashed=$((crashed + 1)); done
if [ "$CONTROL" = 1 ] && [ "$crashed" -gt 0 ]; then
    # Unlocked writers share one temp file, so most die in os.replace before
    # anything is lost quietly -- their cells are lost all the same.
    echo "CONTROL OK: with the lock disabled, $crashed of ${#CFGS[@]} writers failed to save"
    grep -ho 'FileNotFoundError.*' "$W"/out.* | sort | uniq -c | head -3
    exit 0
fi
[ "$crashed" = 0 ] || { echo "FAIL: $crashed writer(s) exited non-zero"; cat "$W"/out.*; exit 1; }

count() {  # <configuration> <reason> -> cells in that column with that reason
    python3 - "$MXFS_CRIT" "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(sum(1 for e in d["criteria"]
          if ((e.get("per_config") or {}).get(sys.argv[2]) or {}).get("reason") == sys.argv[3]))
PY
}

fail=0
for c in "${CFGS[@]}"; do
    n=$(count "$c" "running lockcheck-$c")
    [ "$n" = "${#IDS[@]}" ] || { echo "FAIL: $c has $n of ${#IDS[@]} markers"; fail=1; }
done
if [ "$CONTROL" = 1 ]; then
    [ "$fail" = 1 ] && { echo "CONTROL OK: with the lock disabled, concurrent writers lost cells"; exit 0; }
    echo "CONTROL INCONCLUSIVE: no cells lost even without the lock"; exit 1
fi
[ "$fail" = 0 ] && echo "PASS: every concurrent writer's ${#IDS[@]} markers landed in all ${#CFGS[@]} columns"

"$CRITPY" finalize --at "${CFGS[0]}" >/dev/null
n0=$(count "${CFGS[0]}" "running lockcheck-${CFGS[0]}")
n1=$(count "${CFGS[1]}" "running lockcheck-${CFGS[1]}")
if [ "$n0" = 0 ] && [ "$n1" = "${#IDS[@]}" ]; then
    echo "PASS: finalize --at ${CFGS[0]} healed its column only (${CFGS[1]} still has $n1 markers)"
else
    echo "FAIL: after finalize --at ${CFGS[0]}: its markers=$n0 (want 0), ${CFGS[1]} markers=$n1 (want ${#IDS[@]})"
    fail=1
fi
exit $fail
