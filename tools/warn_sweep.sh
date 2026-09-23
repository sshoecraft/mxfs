#!/bin/bash
# tools/warn_sweep.sh — ask the compiler, for every object in the module, which
# branches it can prove unreachable, WITHOUT touching the build tree.
#
# WHY IT EXISTS.  Two of 0.89.59's defects were branches gcc deleted because the
# comparison guarding them could not come out the way the author meant:
#
#   * a uint8_t strike counter tested `>= 280` — the only strand escape TCP has,
#     absent from the module entirely;
#   * an exhausted-budget sentinel of -1 returned through an unsigned
#     conditional, so `if (budget_ms < 0)` was provably dead and an expired
#     deadline became the largest possible SCSI timeout.
#
# Neither is visible in any amount of source reading, and neither produces a
# warning at the project's normal warning level.  `-Wtype-limits` names the
# first class ("comparison is always false due to limited range of data type")
# and `-Wunused-function` / `-Wunused-variable` name a whole function or object
# the compiler dropped.
#
# WHY IT DOES NOT JUST BUILD WITH -Wextra.  Changing KCFLAGS changes every
# recorded compile command, so `make modules KCFLAGS=-Wextra` rebuilds all 129
# objects and RELINKS mxfs.ko.  A relink while a lap queue is running deploys a
# different module to the remaining laps and splits the sweep across two
# srcversions.  This script replays each object's OWN recorded compile command
# from its .cmd file with the extra warning flags added and the output sent to
# /dev/null, so the tree's objects, mxfs.ko and the dependency files are all
# left exactly as they were.  It is safe to run against a live rig.
#
# Usage:
#   tools/warn_sweep.sh [outfile]          all 129 objects, default
#                                          tests/evidence/warnsweep_<utc>.log
#   WARN_FLAGS="-Wtype-limits" tools/warn_sweep.sh   narrow the sweep
#   WARN_JOBS=8 tools/warn_sweep.sh                  parallelism (default: nproc)
#
# It prints a per-class tally at the end and exits 1 if any "always false"/
# "always true" comparison was reported, because that class is the one that has
# already produced two shipped defects.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KDIR=/lib/modules/$(uname -r)/build
OUT=${1:-$ROOT/tests/evidence/warnsweep_$(date -u +%Y%m%dT%H%M%SZ).log}
FLAGS=${WARN_FLAGS:--Wtype-limits -Wunused-function -Wunused-variable -Wunused-but-set-variable}
JOBS=${WARN_JOBS:-$(nproc)}

[ -d "$KDIR" ] || { echo "no kernel build dir: $KDIR" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

# Collect every recorded compile command for an object of this module.  The
# file name pattern kbuild uses is `.<name>.o.cmd` beside `<name>.o`.
mapfile -t CMDS < <(cd "$ROOT" && ls -1 \
    ./.[a-zA-Z0-9_]*.o.cmd \
    ./*/.[a-zA-Z0-9_]*.o.cmd \
    ./*/*/.[a-zA-Z0-9_]*.o.cmd 2>/dev/null | sort -u)

[ "${#CMDS[@]}" -gt 0 ] || { echo "no .o.cmd files under $ROOT — build first" >&2; exit 2; }

# WARN_ONLY="dlm/v5_mount.o xfs/xfs_mxfs_dlm.o": replay only those objects —
# the compile check for a file edited while a lap queue is deploying the
# module, which a `make modules` would split across two builds.  A replayed
# command that fails is a compile error in that file; a warning is a warning.
if [ -n "${WARN_ONLY:-}" ]; then
    KEEP=()
    for c in "${CMDS[@]}"; do
        obj=$(dirname "${c#./}")/$(basename "$c" | sed 's/^\.//; s/\.cmd$//')
        for want in $WARN_ONLY; do
            [ "$obj" = "$want" ] && KEEP+=("$c")
        done
    done
    CMDS=("${KEEP[@]}")
    [ "${#CMDS[@]}" -gt 0 ] || { echo "WARN_ONLY named no built object: [$WARN_ONLY]" >&2; exit 2; }
fi

echo "WARN SWEEP start objects=${#CMDS[@]} flags=[$FLAGS] jobs=$JOBS $(date -u +%FT%TZ)" > "$OUT"
echo "WARN SWEEP kdir=$KDIR tree=$ROOT version=$(cat "$ROOT/VERSION" 2>/dev/null)" >> "$OUT"

# One object per worker.  Each replays its own recorded command with:
#   - the dependency-file write stripped  (-Wp,-MMD,<path>), so nothing in the
#     tree is rewritten;
#   - `-o <obj>` rewritten to `-o /dev/null`, so no object is replaced;
#   - the warning flags appended, which is enough to override anything the
#     recorded command turned off earlier on the same line.
sweep_one() {
    local cmdfile=$1 flags=$2 tmp=$3
    local line obj src
    line=$(sed -n '1s/^savedcmd_[^ ]* := //p' "$cmdfile")
    [ -n "$line" ] || return 0
    obj=${cmdfile%.cmd}; obj=$(dirname "$obj")/$(basename "$obj" | sed 's/^\.//')
    # A recorded command is a COMPOUND: the gcc invocation, then `; objtool ...`
    # (and sometimes a record-mcount pass) over the object that was just
    # written.  Only the first clause is the compile, and the rest cannot run
    # against /dev/null — objtool exits 129 on it, which would make every
    # object's replay look like a failure.  Keep the compile and drop the rest.
    line=${line%%;*}
    # drop the -Wp,-MMD,<file> argument wherever it sits
    line=$(printf '%s\n' "$line" | sed 's#-Wp,-MMD,[^ ]* ##')
    # send the object to /dev/null
    line=${line//-o $obj/-o /dev/null}
    src=${line##* }
    printf '=== OBJECT %s (src %s)\n' "$obj" "$src" > "$tmp"
    ( cd "$KDIR" && eval "$line $flags" ) >> "$tmp" 2>&1
    printf '=== RC %s %s\n' "$?" "$obj" >> "$tmp"
}
export -f sweep_one

i=0
for c in "${CMDS[@]}"; do
    i=$((i + 1))
    sweep_one "$ROOT/${c#./}" "$FLAGS" "$TMP/$i.out" &
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
done
wait

for n in $(seq 1 "$i"); do [ -f "$TMP/$n.out" ] && cat "$TMP/$n.out" >> "$OUT"; done

alwaysfalse=$(grep -c 'comparison is always' "$OUT")
unusedfn=$(grep -c 'defined but not used' "$OUT")
unusedset=$(grep -c 'set but not used' "$OUT")
failed=$(grep -c '^=== RC [^0]' "$OUT")

{
    echo
    echo "WARN SWEEP DONE objects=${#CMDS[@]} $(date -u +%FT%TZ)"
    echo "  comparison is always true/false : $alwaysfalse   <- the class that deleted two shipped branches"
    echo "  defined but not used            : $unusedfn"
    echo "  set but not used                : $unusedset"
    echo "  objects whose replay failed     : $failed"
} | tee -a "$OUT"

echo "log: $OUT"

if [ "$alwaysfalse" -gt 0 ]; then
    echo
    echo "--- every 'comparison is always' site ---"
    grep -B1 'comparison is always' "$OUT" | grep -E '^[^ ]+\.[ch]:[0-9]+|comparison is always'
    exit 1
fi
exit 0
