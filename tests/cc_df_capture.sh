#!/bin/bash
# cc_df_capture.sh — run the full 2/tcp suite with dirwr=1 (always-on dir
# coherency detectors), clean-rebooting before each iter, and on ANY failure of
# the shared-dir-churn family (crash_consistency / dlm_fairness / tcp_dlm_scaling)
# dump the dir detectors from BOTH nodes' dmesg so the exact stale-base / reload
# mechanism is captured (RULE 4).  Loops until a capture is taken or ITERS done.
#
# Usage: cc_df_capture.sh [iters]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/..
cd "$REPO"
ITERS="${1:-6}"
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
LOG="$REPO/tests/cc_df_capture.log"
DET='P58-STALE-BASE|P-SFDIR-REVERT|P91-RELOAD-PROTECT|P34D|P62-RELOAD-FORK|P104-CONSUMER|P-SFDIR-FASTEX|P-DIRFASTEX|P-RDDIAG|P9-SFREFRESH|mxfs-cc-DISCRIM|mxfs-cc-FAIL|RELOAD-TYPEFLIP|P-NONE-HELD'
CHURN_FAILS=0
echo "=== cc_df_capture start $(date -u) iters=$ITERS ===" | tee -a "$LOG"
for i in $(seq 1 "$ITERS"); do
    echo "----- ITER $i/$ITERS $(date -u +%T) -----" | tee -a "$LOG"
    bash "$REPO/tests/reboot_cluster.sh" 2 >/dev/null 2>&1
    for n in test1 test2; do timeout 8 "$SSH" "$n" "$PF" 'dmesg --clear' >/dev/null 2>&1; done
    out=$(MXFS_EXTRA_MODARGS='dirwr=1' timeout 1400 ./run.sh 2 tcp 2>&1)
    fails=$(echo "$out" | grep -E '  FAIL ' )
    echo "$out" | grep -E '  (PASS|FAIL) ' | tee -a "$LOG"
    # P-SFMERGE engagement count (confirms the merge actually ran)
    for n in test1 test2; do
        m=$(timeout 10 "$SSH" "$n" "$PF" "dmesg | grep -ac 'P-SFMERGE'" 2>/dev/null | tr -dc '0-9')
        echo "    $n P-SFMERGE fires: ${m:-0}" | tee -a "$LOG"
    done
    if echo "$fails" | grep -qE 'crash_consistency|dlm_fairness|tcp_dlm_scaling'; then
        CHURN_FAILS=$((CHURN_FAILS+1))
        echo "  >>> CHURN-FAMILY FAIL (#$CHURN_FAILS) — capturing detectors $(date -u +%T)" | tee -a "$LOG"
        for n in test1 test2; do
            echo "  ===== $n dmesg detectors =====" | tee -a "$LOG"
            timeout 15 "$SSH" "$n" "$PF" "dmesg | grep -aE '$DET' | tail -40" 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"
        done
    fi
done
echo "=== DONE: $CHURN_FAILS churn-family fail(s) in $ITERS iters ===" | tee -a "$LOG"
