#!/bin/bash
# dlm_scaling_diag.sh — measure WHERE dlm_scaling@N spends its time (RULE 4).
#
# dlm_scaling has each node drive 2000×(create+stat+unlink) in its OWN private
# subdir.  At 16 it fails the 50 ops/sec/node floor (~20ms/op vs native µs).
# The root was INFERRED as shared-LUN FUA saturation but never MEASURED.  This
# harness runs the test standalone and captures, per node, the op-rate AND the
# iSCSI block device's iostat (%util, r/s, w/s, r_await, w_await) DURING the run
# so we can attribute the stall to read-IOPS (FUA), write-IOPS (log/destage), or
# neither (CPU/lock).  Optional MXFS_EXTRA_MODARGS passthrough for A/B (e.g.
# publish_dirs=0, fua_skip_owned_inode=1, caw_unlock_backoff=1).
#
# Usage: scripts/dlm_scaling_diag.sh <N> [extra_modargs]
#   e.g. scripts/dlm_scaling_diag.sh 16
#        scripts/dlm_scaling_diag.sh 16 "publish_dirs=0"
# Requires: caw_preflight already run (clean cluster).  Runs on mpatha.
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd); cd "$REPO"
SSH="$REPO/tools/mxfs_sshpass.sh"; PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
N="${1:?usage: dlm_scaling_diag.sh <N> [extra_modargs]}"; EXTRA="${2:-}"
[ -s "$PASS" ] || cp /home/steve/.mxfs/pass "$PASS" 2>/dev/null
sq(){ timeout "${2:-20}" "$SSH" "$1" "$PASS" "$3" 2>/dev/null | grep -vE '^Warning:|^Unauthorized|^If you'; }
NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

# The dm-multipath device's underlying sd* paths are what actually do IO; iostat
# on dm-0/mpatha aggregates them.  Sample every node's mpatha for the run window.
echo "=== dlm_scaling_diag N=$N extra='$EXTRA' $(date -u +%H:%M:%SZ) ==="
for n in "${NODES[@]}"; do
    ( sq "$n" 90 "nohup iostat -x -d 5 24 /dev/mapper/mpatha >/tmp/dsdiag_iostat.txt 2>&1 & echo started" ) >/dev/null &
done
wait
echo "--- iostat armed on all nodes; launching dlm_scaling@$N/caw/mpatha ---"

LOG=/tmp/dsdiag_run_${N}.log
MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="$EXTRA" \
    timeout 700 ./run.sh "$N" caw dlm_scaling >"$LOG" 2>&1
echo "--- run.sh done rc=$? ---"; tail -6 "$LOG"

echo "=== per-node op-rate (from run.sh aggregation) ==="
jq -r '.categories[].tests[]|select(.name=="dlm_scaling")|.runs["'"$N"'/caw"]|"status=\(.status) measured=\(.measured) reason=\(.reason)"' criteria.json 2>/dev/null

echo "=== per-node iSCSI %util / await during run (peak lines) ==="
for n in "${NODES[@]}"; do
    line=$(sq "$n" 15 "awk '/mpatha/{u=\$NF; if(u+0>mu){mu=u+0; ml=\$0}} END{print ml}' /tmp/dsdiag_iostat.txt 2>/dev/null")
    echo "  $n peak: ${line:-<none>}"
done
echo "=== DONE dlm_scaling_diag ==="
