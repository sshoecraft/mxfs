#!/bin/bash
# demoter_punt_ab.sh — same-build A/B for the demoter-claim strand.
# (ccloop c7ee71c6 sess29, D-MOUNT-DEGRADES-WITH-USE.)
#
# WHAT IS UNDER TEST
#   A demoter claim (i_dlm_demoter / i_dlm_demoter2) that is never cleared makes
#   mxfs_foreign_demoter() true for the life of the in-core inode, so EVERY
#   reload of that inode pays mxfs.reload_demote_wait_ms and then abandons the
#   reload with i_dlm_stale still set.  sess28 measured 224-354 such bails on a
#   single inode on 32-node sustained_load stragglers while healthy nodes showed
#   one, and the criterion failed its whole 180 s budget with 3 nodes unable to
#   finish a 20-op loop the other 29 finished in ~2.5 s.
#
#   mxfs.demoter_punt_reclaim releases a claim that mxfs_trans_drain_inode_
#   unlocks' P152 punt retained past the transaction, once the window it covers
#   has provably closed (the retaining task no longer owns ILOCK-EXCL and the
#   claim is older than mxfs.demoter_punt_grace_ms).
#     1 = fix, 0 = the pre-fix behaviour (the negative control)
#
# THE EXPOSURE COUNTER IS KNOB-INDEPENDENT
#   P152-TRANSDRAIN-PUNT is emitted by the punt itself and is NOT gated on the
#   knob, so `punt` proves the control arm entered the same state the fix arm
#   repairs.  An arm with punt=0 proved NOTHING and must be re-run with more
#   aging -- exactly the trap sess28's creator_baseline arm fell into.
#
# RULE 0
#   sustained_load's budget is 180 s (tests/suite/manifest) and run.sh enforces
#   it.  Measured healthy wall on this build is 6-8 s; measured run.sh wrapper
#   overhead at 32 nodes is ~25-30 s.  Per-iteration timeout is therefore
#   budget + 40, and a timeout is a FAILURE, not a retry signal.
#
# USAGE
#   tests/demoter_punt_ab.sh <nodes> <arm 0|1> <iters>
#
# The mount must already be AGED (run the board first); a fresh prep passes in
# both arms and proves nothing.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

N="${1:?usage: demoter_punt_ab.sh <nodes> <arm 0|1> <iters>}"
ARM="${2:?arm: 0 = control, 1 = fix}"
ITERS="${3:-4}"
BUDGET=180
OVERHEAD=40

nodes() { local i; for ((i = 1; i <= N; i++)); do echo "test$i"; done; }

# Set the knob everywhere and READ IT BACK.  A module reload resets it to the
# built-in default, so an arm that silently ran at the default would be
# indistinguishable from a fix that did nothing.
# MXFS_EXTRA_KNOBS is a comma-separated k=v list applied alongside the arm axis
# (e.g. MXFS_EXTRA_KNOBS=demoter_strand_ms=2000 to name a claim sooner).  Every
# knob is read back; a module reload resets them all to their built-in defaults,
# so this must run after every prep.
set_arm() {
    local h kv k v got bad=0
    local spec="demoter_punt_reclaim=$ARM${MXFS_EXTRA_KNOBS:+,$MXFS_EXTRA_KNOBS}"
    for h in $(nodes); do
        for kv in ${spec//,/ }; do
            k="${kv%%=*}"; v="${kv#*=}"
            tools/mxfs_sshpass.sh "$h" \
                "echo $v > /sys/module/mxfs/parameters/$k" >/dev/null 2>&1
            got=$(tools/mxfs_sshpass.sh "$h" \
                  "cat /sys/module/mxfs/parameters/$k" \
                  2>/dev/null | tr -d '\r' | tail -1)
            [ "$got" = "$v" ] || { echo "  !! $h: $k=$got (wanted $v)"; bad=1; }
        done
    done
    [ "$bad" = 0 ] || { echo "ABORT: knob not applied on every node"; exit 3; }
    echo "--- $spec confirmed on all $N node(s) ---"
}

set_arm
# Scope the census to THIS arm.  Without it dmesg is cumulative and both arms
# report identical totals — measured, and it silently proves nothing.
timeout 60 tests/demoter_strand_census.sh "$N" mark

# EXPOSURE FIRST.  sustained_load alone punts ~0 times per run; the punts (and
# the strand) come from heavy shared-directory churn.  dir_reuse_coherency and
# dirent_durability are the two board tests measured to produce them, so each
# arm runs the identical pair before the criterion under test.  Their budgets
# are the manifest's (120 s and 240 s); a timeout is a FAILURE.
echo "=== ARM $ARM — exposure workload (dir_reuse_coherency dirent_durability) ==="
timeout $((120 + 240 + OVERHEAD)) ./run.sh "$N" caw \
    dir_reuse_coherency dirent_durability 2>&1 |
    grep -E "^\s+(PASS|FAIL)\s" | sed 's/^/  /'

echo "=== ARM $ARM — $ITERS x sustained_load @ $N/caw (budget ${BUDGET}s each) ==="
pass=0; fail=0
for ((k = 1; k <= ITERS; k++)); do
    line=$(timeout $((BUDGET + OVERHEAD)) ./run.sh "$N" caw sustained_load 2>&1 |
           grep -E "^\s+(PASS|FAIL)\s+sustained_load" | tail -1)
    if [ -z "$line" ]; then
        echo "  iter $k: NO RESULT LINE (timed out past $((BUDGET + OVERHEAD))s) — FAILURE"
        fail=$((fail + 1))
        continue
    fi
    case "$line" in
        *PASS*) pass=$((pass + 1)) ;;
        *)      fail=$((fail + 1)) ;;
    esac
    echo "  iter $k:${line#*sustained_load}"
done
echo "=== ARM $ARM RESULT: PASS=$pass FAIL=$fail of $ITERS ==="
echo
timeout 120 tests/demoter_strand_census.sh "$N" full 2>/dev/null
