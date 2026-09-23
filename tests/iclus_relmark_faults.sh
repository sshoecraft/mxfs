#!/bin/bash
# iclus_relmark_faults.sh — fault-injection matrix for the ICLUS clean-release
# certificate (0.55.0, sess448; design-consult ruling ccmemory
# docs/rulings/iclus-relmark-certificate-and-sequencing.md,
# evidence 6.3).  Requires a LAB build (modinfo mxfs_iclus_relmark_lab=1) and a
# fleet prepped with MXFS_EXTRA_MODARGS=icluster_dlm=1; the caller does both.
# Each arm drives tests/tmpfile_churn_kill.sh (regular-file churn = routed
# inodes; victims virsh-destroyed mid-churn) with mxfs.relgate_fault_* armed
# on the fleet so the armed stage fires in whichever node's
# mxfs_iclus_disk_release reaches it first (oneshot); the P282-RELGATE-FAULT
# line names the node.  Expectations are evaluated from the survivors'
# replay-side evidence (the victim's own journal is volatile — trap sess433):
#
#   premark_crash   stage 19 delay 60 s (proof passed, before stamp+marker):
#                   the victim killed inside the window died HOLDING the
#                   cluster grant with no marker -> its tuple must classify
#                   APPLY (manifest held) or refuse, NEVER REDUNDANT_CLEAN.
#                   expect VERDICT PASS, redundant_skip may be >0 only from
#                   OTHER (cleanly released) tenures; P282 stage=19 seen.
#   publish_fail    stage 20 force (marker publish fails, release proceeds
#                   UNMARKED): a later death must find that tenure's images
#                   refused or applied, never falsely clean.  expect P282
#                   stage=20 seen; replay-side no false REDUNDANT for an
#                   unmarked tenure (the sweep's relmarks= count excludes it).
#   postmark_crash  stage 21 delay 60 s (marker durable, before the unlock
#                   CAS): victim killed holding the grant WITH a marker ->
#                   manifest-held precedence => APPLY (images are home, so the
#                   outcome is safe either way).  expect VERDICT PASS.
#   cas_fail        stage 21 force (transport-failed CAS after the marker):
#                   no crash; the deferred-release episode must retry and
#                   succeed with the tuple still marked, admission never
#                   reopened on the failure.  expect VERDICT PASS, P282
#                   stage=21 seen, P-ICLUS-WEDGE absent, iclus_reinst_ref 0.
#
# budget: each arm bounded like rman_matrix arms (measured 188-325 s on
# 0.41.2; 300 s wrap + the fault delay for the crash arms).  the unkillable-wedge rule: every
# remote call bounded, per-node rc files.  the source-tree rule: lives in tests/.
#
# Usage: tests/iclus_relmark_faults.sh <outdir> [arm ...]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
OUT=${1:?evidence dir}; shift
mkdir -p "$OUT"
ARMS=("$@"); [ ${#ARMS[@]} -eq 0 ] && ARMS=(premark_crash publish_fail postmark_crash cas_fail)
SSH=tools/mxfs_sshpass.sh

if [ "$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)" -ne 1 ]; then
    echo "iclus_relmark_faults: FAIL tree mxfs.ko is not a LAB build (modinfo mxfs_iclus_relmark_lab absent)" | tee -a "$OUT/matrix.txt"
    exit 2
fi

sweep_fleet() { # $1 pattern -> per-node counts since 20 min, and the sum
    local d; d=$(mktemp -d); local i s=0
    for i in $(seq 1 32); do ( timeout 20 $SSH test$i "journalctl -k --since -20min --no-pager 2>/dev/null | grep -ac '$1'" 2>/dev/null | tr -dc '0-9' > "$d/$i"; echo $? > "$d/rc$i" ) & done; wait
    for i in $(seq 1 32); do local c; c=$(cat "$d/$i"); [ -n "$c" ] && s=$((s + c)); printf 't%s=%s ' "$i" "${c:-?}"; done; echo " sum=$s"
}

# sess461: how many times the marker block in mxfs_iclus_disk_release ran on
# each SURVIVOR since its prep (debugfs relmark counters: iclus_marked +
# iclus_failed + iclus_unmarked).  A stage can only fire inside that block,
# so a fleet total of 0 says the workload never reached it — the matrix is
# then vacuous by construction, not by evidence loss.
sweep_relmark() {
    local d; d=$(mktemp -d); local i
    for i in $(seq 1 32); do ( timeout 20 $SSH test$i "grep -a -A11 '^relmark' /sys/kernel/debug/mxfs/*/inode_authority 2>/dev/null | grep -a 'iclus_marked\|iclus_failed\|iclus_unmarked' | awk '{printf \"%s=%s \", \$1, \$2}'" 2>/dev/null | grep -av '^Unauthorized access\|^Warning: Permanently\|^If you are not' > "$d/$i" ) & done; wait
    for i in $(seq 1 32); do printf 't%s:%s ' "$i" "$(grep -oE 'iclus_marked=[0-9]+' "$d/$i" | cut -d= -f2)"; done
    echo
    echo "relmark fleet: iclus_marked=$(cat "$d"/* | grep -oE 'iclus_marked=[0-9]+' | cut -d= -f2 | paste -sd+ | bc) iclus_failed=$(cat "$d"/* | grep -oE 'iclus_failed=[0-9]+' | cut -d= -f2 | paste -sd+ | bc) iclus_unmarked=$(cat "$d"/* | grep -oE 'iclus_unmarked=[0-9]+' | cut -d= -f2 | paste -sd+ | bc) nodes_reporting=$(grep -l iclus_marked "$d"/* | wc -l)"
}

run_arm() {
    local arm=$1 params=$2 extra_env=$3 wrap=${4:-360}
    local log=$OUT/$arm.log t0=$(date +%s) rc
    echo "=== arm=$arm params='$params' wrap=${wrap}s $(date -u +%FT%TZ)" | tee -a "$OUT/matrix.txt"
    # sess459: TCK_VICTIMS overrides the victim class (default auto:shared);
    # auto:slots:25,26 targets the AG-0/AG-1 sharers for the D-0517 veto shape.
    ( [ -n "$extra_env" ] && eval "export $extra_env"; TCK_PARAMS="$params" TCK_OUT="$OUT/$arm" timeout "$wrap" tests/tmpfile_churn_kill.sh "$arm" "${TCK_VICTIMS:-auto:shared}" 0 2000 32 ) > "$log" 2>&1
    rc=$?
    {
        echo "rc=$rc wall=$(( $(date +%s) - t0 ))s"
        grep -E '^victims|^knobs|^PREKILL|^KILL|^WAIT|^gate|^afterkill|^chk|^FAIL|^VERDICT' "$log" | cut -c1-300
        # sess461: the stage fires on the RELEASING node = the victim under a
        # kill arm; its journal dies with the VM, so the pre-kill probe
        # (tmpfile_churn_kill.sh TCK_PREKILL_GREP, auto-armed by the
        # relgate_fault_stage param) is the stage-hit evidence.
        for pk in "$OUT/$arm"/prekill_test*.txt; do [ -f "$pk" ] && echo "prekill $(basename "$pk" .txt): $(grep -a 'P282-RELGATE-FAULT' "$pk" | tail -2 | cut -c1-200 | tr '\n' '|')"; done
        grep -E 'P273-SHADOW-EVAL' "$OUT/$arm/sweep.txt" 2>/dev/null | grep -oE 'victim_slot=[0-9]+ capable=[0-9].*' | grep -oE 'victim_slot=[0-9]+|WOULD_APPLY=[0-9]+|ENFORCEABLE_WOULD_APPLY=[0-9]+|REDUNDANT_CLEAN=[0-9]+|redundant_skipped=[0-9]+|relmarks=[0-9]+|not_?held=[0-9]+' | tr '\n' ' '; echo
        echo "P282 stage hits (fleet): $(sweep_fleet 'P282-RELGATE-FAULT stage=')"
        echo "relmark iclus_marked per survivor: $(sweep_relmark)"
        echo "ICLUS-UNMARKED (fleet): $(sweep_fleet 'P-RELMARK-ICLUS-UNMARKED')"
        echo "ICLUS-REINSTALL-REFUSED (fleet): $(sweep_fleet 'P-RELMARK-ICLUS-REINSTALL-REFUSED')"
        echo "ICLUS-WEDGE (fleet): $(sweep_fleet 'P-ICLUS-WEDGE')"
        echo "FR-REDUNDANT-SKIP (fleet): $(sweep_fleet 'P227-FR-REDUNDANT-SKIP')"
    } | tee -a "$OUT/matrix.txt"
    echo | tee -a "$OUT/matrix.txt"
    # disarm on the fleet whatever the arm left behind
    tests/fleet_set_params.sh relgate_fault_stage=0 32 "$OUT/$arm.disarm.txt" >/dev/null 2>&1
    tests/fleet_set_params.sh relgate_fault_force=0 32 "$OUT/$arm.disarm2.txt" >/dev/null 2>&1
}

for arm in "${ARMS[@]}"; do
    case $arm in
    premark_crash)  run_arm premark_crash  "relgate_fault_res=0 relgate_fault_oneshot=1 relgate_fault_force=0 relgate_fault_delay_ms=60000 relgate_fault_stage=19" "TCK_KILL_AFTER=20 TCK_RECOV_BOUND=160 TCK_EXTRA_RECOV=60" 420 ;;
    publish_fail)   run_arm publish_fail   "relgate_fault_res=0 relgate_fault_oneshot=0 relgate_fault_force=1 relgate_fault_delay_ms=0 relgate_fault_stage=20" "TCK_KILL_AFTER=20" 360 ;;
    postmark_crash) run_arm postmark_crash "relgate_fault_res=0 relgate_fault_oneshot=1 relgate_fault_force=0 relgate_fault_delay_ms=60000 relgate_fault_stage=21" "TCK_KILL_AFTER=20 TCK_RECOV_BOUND=160 TCK_EXTRA_RECOV=60" 420 ;;
    cas_fail)       run_arm cas_fail       "relgate_fault_res=0 relgate_fault_oneshot=1 relgate_fault_force=1 relgate_fault_delay_ms=0 relgate_fault_stage=21" "TCK_KILL_AFTER=20" 360 ;;
    *) echo "unknown arm $arm" | tee -a "$OUT/matrix.txt" ;;
    esac
done
echo "=== matrix done $(date -u +%FT%TZ) ===" | tee -a "$OUT/matrix.txt"
