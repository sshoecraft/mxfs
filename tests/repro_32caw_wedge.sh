#!/bin/bash
# repro_32caw_wedge.sh — looped reproducer for the 32/caw spurious-shutdown
# wedge family (ccloop c7ee71c6 sess12-D: folio-wedge >150s → AG AIL-STALL
# stuck_ino ilocked+in_ail → P-NOINO-RELFENCE-WEDGE shutdown at
# xfs_mxfs_dlm.c:15884).  One spontaneous hit 2026-07-26 ~11:11 on the mpath
# rig; fresh-cluster single runs pass — the wedge needs aged state + load.
#
# Each lap: re-arm tests/stallcap_watch.sh on every node (captures live
# stacks at first AG-AIL-STALL/NOINO print), then run the churn chain that
# preceded the original hit.  Stops on: any row FAIL, any stallcap capture,
# or any node logging the wedge signature — leaving the evidence in place.
#
# Usage:  MXFS_PASS=<passfile> tests/repro_32caw_wedge.sh <laps>
# Precondition: rig.sh mpath 32 up + cluster prepped 32/caw (marker matches).

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile)}"
LAPS="${1:-5}"
SIG='P-NOINO-RELFENCE-WEDGE|Shutting down filesystem|blocked for more than'

arm() {
    for i in $(seq 1 32); do
        (timeout 12 "$SSH" "test$i" "$PASS" \
            'pkill -f stallcap_watch 2>/dev/null; rm -rf /root/stallcap;
             cat > /root/stallcap_watch.sh && chmod +x /root/stallcap_watch.sh;
             nohup /root/stallcap_watch.sh 900 /root/stallcap >/root/stallcap.log 2>&1 &' \
            < "$REPO/tests/stallcap_watch.sh" >/dev/null 2>&1) &
    done
    wait
}

harvest() {   # -> 0 if evidence found (stop looping)
    local found=0
    for i in $(seq 1 32); do
        # sess12: fail-CLOSED — an unreachable node is itself suspicious
        # during a wedge hunt (a wedged node's sshd stalls); never let a
        # silent ssh error count as "clean".
        r=$(timeout 8 "$SSH" "test$i" "$PASS" \
            "c=\$(ls /root/stallcap/round1 2>/dev/null | wc -l); \
             s=\$(dmesg | grep -cE '$SIG'); echo PROBE \$c \$s" 2>/dev/null </dev/null)
        case "$r" in
        *PROBE*)
            set -- $r
            if [ "${2:-0}" != 0 ] || [ "${3:-0}" != 0 ]; then
                echo "EVIDENCE on test$i: stallcap_files=${2:-0} wedge_sigs=${3:-0}"
                found=1
            fi ;;
        *)
            echo "UNREACHABLE test$i during harvest — treating as evidence"
            found=1 ;;
        esac
    done
    return $(( found == 0 ))
}

for lap in $(seq 1 "$LAPS"); do
    echo "=== lap $lap/$LAPS $(date -u +%H:%M:%S) ==="
    arm
    out=$("$REPO/run.sh" 32 caw dlm_scaling cache_coherency dir_reuse_coherency \
          fence_during_write 2>&1 | grep -E '  (PASS|FAIL)')
    echo "$out"
    # sess13(c7ee71c6): row FAILs with an EMPTY harvest have twice proven to
    # be slope/interference (aged-state or load), not the wedge — and the
    # slope-degraded state is exactly the aged precondition the wedge wants.
    # Only REAL evidence (stallcap capture, wedge signature, unreachable
    # node) stops the hunt now; a bare row FAIL is logged and the loop
    # continues so state keeps aging.
    if harvest; then
        if echo "$out" | grep -q FAIL; then
            echo "=== WEDGE EVIDENCE on lap $lap (rows also FAILed) — inspect /root/stallcap ==="
        else
            echo "=== WEDGE EVIDENCE on lap $lap (rows green) — inspect /root/stallcap ==="
        fi
        exit 3
    fi
    if echo "$out" | grep -q FAIL; then
        echo "--- lap $lap row FAIL, harvest EMPTY (slope/interference) — continuing, state ages ---"
    fi
done
echo "=== $LAPS laps done — no wedge evidence ==="
exit 0
