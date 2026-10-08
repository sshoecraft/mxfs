#!/bin/bash
# pve_demoter_strand.sh — does shared-directory churn on a Proxmox pair leave a
# demoter claim behind that nothing clears, and does the next walk over a
# reused inode number then fail?
#
# Observed on nested pair A (0.90.104, 2026-10-08): during
# tests/pve_churn_fairness.sh a release kworker took a demoter claim on a
# regular file (set in mxfs_inode_dlm_defer_bast) and held it for 326 s, until
# the worker thread exited and P-DEMOTER-DEAD-REAP retired it.  Meanwhile the
# file was removed by the churn and its number reused by the peer for a new
# directory; every lookup of that directory on the claim's host then waited
# 201 rounds and failed ESTALE (find: Stale file handle, 48.6 s per walk),
# because the in-core shell of the dead file could be neither evicted nor
# reloaded while a foreign claim stood (P34J-RELOAD-DEMOTE-BAIL).
#
# Each lap: tests/pve_churn_fairness.sh (both hosts churn one shared
# directory), then tests/pve_peer_delete.sh (participant 0 creates FILES files
# in a new directory, reusing the numbers the churn freed; participant 1 walks
# them).  The demoter probes are on for the whole run, both kernel logs are
# marked at its start, and after the last lap each host's counters are dumped.
#
# Per host, over the run: P214-DEMOTER-STRANDED (a claim older than
# demoter_strand_ms met by a reload; it names the claim's site and replays the
# claim ring), P-DEMOTER-DEAD-REAP (a claim retired only because its owner
# exited), P34J-RELOAD-DEMOTE-BAIL, P201-TYPEFLIP-UNRESOLVED-FAIL, and the
# P215-DEFER / P213-PUNT balances.
#
# Verdict: FAIL when any lap's walk is not clean (an error, or not every file
# found), or when either host logs a strand, a dead-reap or an unresolved type
# flip.
#
# Usage: tests/pve_demoter_strand.sh [label]
# Env:
#   PVE_PAIR   "<addr> <addr>" (default nested pair A "192.168.120.137
#              192.168.120.192"); participant 0 is the lower address
#   LAPS       churn + walk laps (default 4)
#   CHURN      loops per host in the churn (default 8)
#   WORK_S     seconds of churn per lap (default 40)
#   STRAND_MS  demoter_strand_ms for the run (default 5000, the module's)
#
# Budget per lap: the churn's ARM_S 20 + WORK_S + ~30 s of collection, the
# walk's create + stat + remove (~15 s healthy on this pair), so ~110 s at the
# defaults; the run's own timeout is LAPS x 150 s + 60 s.
#
# Evidence: tests/evidence/pve_demoter_strand/<UTC stamp>[-label]/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_demoter_strand: PVE_PAIR must name two hosts"; exit 2; }
LAPS=${LAPS:-4}
CHURN=${CHURN:-8}
WORK_S=${WORK_S:-40}
STRAND_MS=${STRAND_MS:-5000}
LABEL=${1:-}
EVID="$REPO/tests/evidence/pve_demoter_strand/$(date -u +%Y%m%dT%H%M%SZ)${LABEL:+-$LABEL}"
mkdir -p "$EVID" || exit 2
MARK="mxfs-test: pve_demoter_strand $(basename "$EVID") start"

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
H=("${PAIR[@]}")

PROBES="P214-DEMOTER-STRANDED P214-DEMEV P34J-RELOAD-DEMOTE-BAIL P152-TRANSDRAIN-PUNT P213-PUNT P215-DEFER P215-DRAIN-RESIDUE P216-CLAIM-RECYCLE P75-DEMOTER-CLAIM P201-TYPEFLIP-UNRESOLVED-FAIL P201-RELOOKUP P95B-TYPEFLIP-WAIT P207-COHERENT-TRUTH"
probes() {  # <host> <+p|-p>
    local cmd="" f
    for f in $PROBES; do
        cmd+="echo 'module mxfs format \"$f\" $2' > /proc/dynamic_debug/control; "
    done
    on "$1" "$cmd echo PROBES_DONE" 30 | grep -q PROBES_DONE
}

for h in "${H[@]}"; do
    b=$(on "$h" "cat /sys/module/mxfs/srcversion; awk '\$2 == \"/mnt/shared\" && \$3 == \"mxfs\"' /proc/mounts | wc -l" 20 | tr '\n' ' ')
    say "$h build+mounted: $b"
    probes "$h" +p || say "$h: could not turn the probes on"
    on "$h" "echo $STRAND_MS > /sys/module/mxfs/parameters/demoter_strand_ms; echo '<5>$MARK' > /dev/kmsg; echo OK" 20 | grep -q OK \
        || say "$h: could not set demoter_strand_ms or mark the log"
done

fail=0
for lap in $(seq 1 "$LAPS"); do
    PVE_PAIR="${H[*]}" CHURN=$CHURN WORK_S=$WORK_S timeout 200 "$REPO/tests/pve_churn_fairness.sh" > "$EVID/churn-$lap.log" 2>&1
    crc=$?
    say "lap $lap churn rc=$crc $(grep -a 'slower host' "$EVID/churn-$lap.log" | cut -c1-120)"
    PVE_PAIR="${H[*]}" timeout 400 "$REPO/tests/pve_peer_delete.sh" "strand$lap" > "$EVID/walk-$lap.log" 2>&1
    wrc=$?
    w=$(grep -a 'peer-stat' "$EVID/walk-$lap.log" | cut -c1-200)
    say "lap $lap walk rc=$wrc $w"
    case "$w" in
        *"rc=0"*" 400") ;;
        *) fail=1 ;;
    esac
    [ "$wrc" = 0 ] || fail=1
done

for h in "${H[@]}"; do
    on "$h" "echo 1 > /sys/module/mxfs/parameters/demoter_dump; sleep 1; journalctl -k --no-pager -o short-monotonic | awk -v m='$MARK' 'index(\$0, m) {p=1} p' | sed 's/^.*kernel: //' | grep -a 'mxfs'" 90 > "$EVID/klog-$h"
    n_strand=$(grep -ac 'P214-DEMOTER-STRANDED' "$EVID/klog-$h")
    n_reap=$(grep -ac 'P-DEMOTER-DEAD-REAP' "$EVID/klog-$h")
    n_bail=$(grep -ac 'P34J-RELOAD-DEMOTE-BAIL' "$EVID/klog-$h")
    n_p201=$(grep -ac 'P201-TYPEFLIP-UNRESOLVED-FAIL' "$EVID/klog-$h")
    say "$h strand=$n_strand dead_reap=$n_reap demote_bail=$n_bail typeflip_fail=$n_p201"
    grep -aE 'P215-DEFER|P213-PUNT |P216-CLAIM|P75-DEMOTER-DRAIN' "$EVID/klog-$h" | tail -4 | sed "s/^/  $h: /" | tee -a "$EVID/log"
    grep -aE 'P214-DEMOTER-STRANDED|P-DEMOTER-DEAD-REAP' "$EVID/klog-$h" | head -6 | cut -c1-300 | sed "s/^/  $h: /" | tee -a "$EVID/log"
    [ $((n_strand + n_reap + n_p201)) = 0 ] || fail=1
    probes "$h" -p || say "$h: could not turn the probes off"
done

say "evidence $EVID"
if [ "$fail" = 0 ]; then say "RESULT PASS"; exit 0; fi
say "RESULT FAIL"
exit 1
