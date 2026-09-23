#!/bin/bash
# rman_prover_kill.sh — the prover-death takeover arm of the recovery-manifest
# matrix (docs/recovery-manifest.md step 6: "prover death between certify and
# seal -> SNAPSHOTTING takeover").  Runs ON CLYDE as the kill harness's
# TCK_AFTER_KILL_CMD hook, once the victims' heartbeats have expired and the
# prover has proved exclusion but — with mxfs.rman_inject=1 armed fleet-wide —
# failed the manifest write (P-RMAN-INJECT mode=1 / P-RMAN-SNAPSHOT-PENDING on
# the prover, descriptor parked at SNAPSHOTTING).  It then:
#   1. finds the prover: the first live node whose dmesg carries
#      'P-RMAN-INJECT ... mode=1' (two victims may have two provers; the first
#      by node number is killed, the other seals normally once the knob clears),
#   2. virsh-destroys it and records it in $OUT/extra_victims.txt so the kill
#      harness treats it as a third victim (survivor counting, replay count),
#   3. clears rman_inject on the rest of the fleet so the takeover (and the
#      other prover's retry) can seal.
# Expected on the survivors afterwards: P-RMAN-SNAPSHOT-TAKEOVER >= 1 (the
# parked victim re-scanned and sealed under a new attempt lease by a node that
# saw the prover dead AND fenced), P-RMAN-SEALED >= 3, all three slices
# replayed, no P-RMAN-INVALID/POSTSEAL/ABORT, chk clean.
#
# budget: every ssh bounded (20 s), fleet sweep in parallel; virsh bounded.
# the unkillable-wedge rule: per-node rc files, no pgrep/ps.  the source-tree rule: lives in tests/.
#
# Usage: tests/rman_prover_kill.sh [outdir=$TCK_OUT] [nodes=32]
#        (as a TCK_AFTER_KILL_CMD hook the harness's TCK_OUT is inherited)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
OUT=${1:-${TCK_OUT:?outdir or TCK_OUT}}; NODES=${2:-32}
SSH=tools/mxfs_sshpass.sh
mkdir -p "$OUT"
D=$(mktemp -d)
echo "prover_kill: sweep for P-RMAN-INJECT mode=1 at $(date -u +%FT%T.%3NZ)"
for i in $(seq 1 "$NODES"); do
    ( timeout 20 $SSH test$i "dmesg | grep -a 'P-RMAN-INJECT' | grep -a 'mode=1' | head -2 | cut -c1-200" > "$D/p$i" 2>/dev/null; echo $? > "$D/rc$i" ) &
done; wait
prover=""
for i in $(seq 1 "$NODES"); do
    if grep -aq 'P-RMAN-INJECT' "$D/p$i"; then
        echo "test$i: $(grep -av '^Unauthorized\|^Warning:\|^If you' "$D/p$i" | tr '\n' ' ')"
        [ -z "$prover" ] && prover=test$i
    fi
done
if [ -z "$prover" ]; then
    echo "prover_kill: FAIL no node logged P-RMAN-INJECT mode=1 (rcs: $(for i in $(seq 1 "$NODES"); do printf 't%s=%s ' $i "$(cat $D/rc$i)"; done))"
    # still clear the knob so the run can finish and be diagnosed
    tests/fleet_set_params.sh rman_inject=0 "$NODES" "$OUT/prover_kill_clear.txt"
    exit 2
fi
echo "prover_kill: KILL prover $prover at $(date -u +%FT%T.%3NZ)"
timeout 60 sudo virsh -c qemu:///system destroy "$prover" 2>&1 | tr '\n' ' '; echo " virsh rc=${PIPESTATUS[0]}"
echo "$prover" >> "$OUT/extra_victims.txt"
sleep 8
echo "prover_kill: clearing rman_inject on the fleet"
tests/fleet_set_params.sh rman_inject=0 "$NODES" "$OUT/prover_kill_clear.txt"
echo "prover_kill: clear rc=$? $(grep -c 'rman_inject=0' "$OUT/prover_kill_clear.txt" 2>/dev/null)/$NODES report 0"
exit 0
