#!/bin/bash
# demoter_claim_fix_verify.sh — exercise the causes of the claim-slot defects on
# the build under test, not just a clean board.
#
# WHAT IT FORCES
#   1. The slot races (D-DEMOTER-SLOT-PUBLISHED-BEFORE-ITS-TASK-REFERENCE,
#      D-DEMOTER-SLOT-REMOVER-ZEROES-DEPTH-AFTER-THE-SLOT-IS-ALREADY-REUSABLE):
#      mxfs.demoter_slot_selftest races claimants, the punt sweep, dead-claim
#      retirement and threads that exit holding a claim, on detached inodes,
#      first as built and then with mxfs.demoter_test_window_us stalling inside
#      the windows the races lived in.  gen_reject > 0 says the sweep met a
#      later claim of a slot it was aimed at, which is the first race's
#      precondition; dead_reap > 0 says retirement ran against live claimants.
#   2. The unclaimed drain (D-PINNED-RELEASE-RUNS-BAST-PROCESS-WITH-NO-DEMOTER-
#      CLAIM): mxfs.demoter_claim_fail_inject=N makes every Nth claim wait report
#      no slot, at every inline-drain site, during a contended board workload.
#      drain_deferred > 0 says the defer path ran; the workload rows must pass,
#      and no node may log a hung task, a WARN/BUG, a refcount error, an inode
#      wedge or a synchronous claim still waiting.
#
# Usage: tests/demoter_claim_fix_verify.sh <configuration> <group> <node,node,...>
#   INJECT     (default 2)   claim-fail injection period
#   SELFTEST_S (default 20)  seconds per self-test arm
#   WINDOW_US  (default 200) stall for the second self-test arm
#
# Budget: prep 72-137 s measured; self-test 2 x SELFTEST_S; the rows are
# graded against their own manifest budgets by run.sh, which flips an overrun
# to FAIL.  Nothing here widens a budget.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO" || exit 1

CONFIG="${1:?usage: demoter_claim_fix_verify.sh <configuration> <group> <nodes>}"
GROUP="${2:?group}"
IFS=, read -r -a NODES <<<"${3:?nodes}"
INJECT="${INJECT:-2}"
SELFTEST_S="${SELFTEST_S:-20}"
WINDOW_US="${WINDOW_US:-200}"
SSH=tools/mxfs_sshpass.sh
ROWS="dir_reuse_coherency dirent_durability sustained_load posix_multi cache_coherency alloc_witness chk_clean"
WANT=$(modinfo -F srcversion mxfs.ko)
T0=$(date '+%Y-%m-%d %H:%M:%S')
fail=0

say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

say "prep $CONFIG on $GROUP (${NODES[*]}), tree srcversion $WANT"
MXFS_FORCE_PREP=1 ./run.sh "$CONFIG" --group "$GROUP" prep_cluster 2>&1 | tail -3

for h in "${NODES[@]}"; do
    got=$(timeout 20 "$SSH" "$h" "cat /sys/module/mxfs/srcversion" 2>/dev/null | tr -d '\r' | tail -1)
    [ "$got" = "$WANT" ] || { say "ABORT: $h runs srcversion '$got', not $WANT"; exit 3; }
done
say "srcversion $WANT on all ${#NODES[@]} nodes"

h0=${NODES[0]}
for w in 0 "$WINDOW_US"; do
    timeout 10 "$SSH" "$h0" "echo $w > /sys/module/mxfs/parameters/demoter_test_window_us" >/dev/null 2>&1
    timeout $((SELFTEST_S + 30)) "$SSH" "$h0" \
        "echo $SELFTEST_S > /sys/module/mxfs/parameters/demoter_slot_selftest" >/dev/null 2>&1
    rc=$?
    line=$(timeout 20 "$SSH" "$h0" "journalctl -k --no-pager --since '$T0' | grep -o 'P-DEMOTER-SLOT-SELFTEST.*' | tail -1" 2>/dev/null | tr -d '\r')
    say "selftest window_us=$w rc=$rc: ${line:-NO LINE}"
    case "$line" in *verdict=PASS*) ;; *) fail=1 ;; esac
done
timeout 10 "$SSH" "$h0" "echo 0 > /sys/module/mxfs/parameters/demoter_test_window_us" >/dev/null 2>&1

for h in "${NODES[@]}"; do
    timeout 10 "$SSH" "$h" "echo $INJECT > /sys/module/mxfs/parameters/demoter_claim_fail_inject" >/dev/null 2>&1
    got=$(timeout 10 "$SSH" "$h" "cat /sys/module/mxfs/parameters/demoter_claim_fail_inject" 2>/dev/null | tr -d '\r' | tail -1)
    [ "$got" = "$INJECT" ] || { say "ABORT: $h demoter_claim_fail_inject=$got"; exit 3; }
done
say "demoter_claim_fail_inject=$INJECT on all nodes; rows: $ROWS"

./run.sh "$CONFIG" --group "$GROUP" $ROWS 2>&1 | grep -E '^\s+(PASS|FAIL|SKIP|FLAKY)\s' | sed 's/^/  /' | tee -a /dev/stderr | grep -qE '^\s+FAIL\s' && fail=1

for h in "${NODES[@]}"; do
    out=$(timeout 150 "$SSH" "$h" "echo 1 > /sys/module/mxfs/parameters/demoter_dump 2>/dev/null
        echo 0 > /sys/module/mxfs/parameters/demoter_claim_fail_inject
        k=\$(journalctl -k --no-pager --since '$T0')
        echo \"\$k\" | grep -o 'P75-DEMOTER-DRAIN.*' | tail -1
        echo bad=\$(echo \"\$k\" | grep -cE 'WARNING: CPU|BUG:|refcount_t|P-DEMOTER-CLAIM-SYNC-WAIT|P-INODE-WEDGE|blocked for more than|Oops')
        echo deferred_lines=\$(echo \"\$k\" | grep -c 'P-DEMOTER-DRAIN-DEFER')" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
    say "$h: $out"
    case "$out" in *bad=0*) ;; *) fail=1 ;; esac
    case "$out" in *drain_deferred=0\ *|"") fail=1 ;; esac
done
say "VERDICT $([ $fail = 0 ] && echo PASS || echo FAIL) $CONFIG $GROUP srcversion=$WANT"
exit $fail
