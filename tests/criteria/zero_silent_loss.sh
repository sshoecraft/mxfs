#!/bin/bash
# Criterion: Zero silent data/dirent loss under any workload.  Verifier:
# wrap scripts/sess88_workload_a_modeN_baseline.sh — the workload-A
# shared-directory mkdir storm — and assert 0 silent dirent loss across
# every iter.  Threshold: fs_silent across all iters = 0.
#
# Usage: zero_silent_loss.sh [--iters I] [--dpn D] [--mode M] [--nodes N]
#   Defaults: iters=3 dpn=100 mode=1 nodes=16
#
# Background: mode=1 = skip_merge enabled (v0.20.5 default).  See
# memory[sess89_v0205_skip_merge_default_flip].

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "zero_silent_loss"
# RULE 0 budget (tests/criteria/TIMEOUT_BUDGETS.md): 3 iters × ~120 s
# measured wall (incl. full remount, sess15 run14d) + one mount_cluster
# retry (~60 s) + harness overhead = 480 s.  A run that needs more than
# this is itself a FAIL — do not widen.
set_script_timeout 480

ITERS=3; DPN=100; MODE=1
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --iters) ITERS="$2"; shift 2 ;;
        --dpn)   DPN="$2"; shift 2 ;;
        --mode)  MODE="$2"; shift 2 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
parse_common_args "${ARGS[@]+"${ARGS[@]}"}"

# sess88 script enumerates test17..test32 internally; we just invoke it
LOG=$(mktemp -t zero_silent_loss.XXXXXX.log)
"$MXFS_REPO/scripts/sess88_workload_a_modeN_baseline.sh" "$MXFS_MODULE" "$DPN" "$ITERS" "$MODE" \
    > "$LOG" 2>&1
# Parse summary line
total_silent=$(grep -oE 'fs_silent=[0-9]+' "$LOG" | tail -1 | cut -d= -f2)
total_silent=${total_silent:-999999}
iters_with_loss=$(grep -oE 'iters_with_fs_silent_loss=[0-9]+/[0-9]+' "$LOG" | tail -1 | cut -d= -f2)
iters_with_loss=${iters_with_loss:-unknown}
completed=$(grep -oE 'iters_completed=[0-9]+/[0-9]+' "$LOG" | tail -1 | cut -d= -f2 | cut -d/ -f1)
completed=${completed:-0}

measured="iters=$ITERS dpn=$DPN mode=$MODE total_fs_silent=$total_silent iters_with_loss=$iters_with_loss completed=$completed/$ITERS"
threshold="total_fs_silent=0 completed=$ITERS/$ITERS"

[ "$total_silent" = "0" ] \
    || result_fail "$measured" "$threshold" "silent dirent loss detected (see $LOG)"
[ "$completed" = "$ITERS" ] \
    || result_fail "$measured" "$threshold" "infra: only $completed/$ITERS iterations produced data (see $LOG)"
result_pass "$measured" "$threshold"
