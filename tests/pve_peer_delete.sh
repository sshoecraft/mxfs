#!/bin/bash
# pve_peer_delete.sh — what an unlink storm costs on a Proxmox pair when the
# OTHER host holds read grants on every file being removed: participant 0
# creates FILES small files in a directory of its own, participant 1 stats
# every one of them (a read grant on each, cached), then participant 0 removes
# the directory with rm -rf.  Each phase is timed; afterwards both hosts must
# agree the directory is gone.
#
# This is the workload the dir_ex_bast_sweep heuristic was written for: the
# remover's exclusive acquire of the directory makes the reader drop its idle
# read grants all at once, instead of one revocation per child as the remover
# reaches it (D-TCP-REMOTE-DELETE-OF-PEER-CREATED-FILES-16-PER-SECOND; the
# sweep's cost on walks is in D-DRBD-PAIR-NEW-FILES-COST-...).
#
# Usage: tests/pve_peer_delete.sh [label]
# Env:
#   PVE_PAIR     "<addr> <addr>" (default the physical pair); participant 0 first
#   FILES        files created (400)
#   PHASE_BUDGET seconds any one phase may take (120)
# Output: one line per phase with its wall; exit 0 when every phase finished
# and both hosts see the directory gone (a phase over budget is reported, not
# hidden: the exit is 1).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:-run}
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
MNT=/mnt/shared
FILES=${FILES:-400}
BUDGET=${PHASE_BUDGET:-120}
D=$MNT/peerdel/$(date -u +%H%M%S)-$LABEL
bad=0

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
phase() {  # <name> <host> <cmd>
    local t0 rc out
    t0=$(date +%s%N)
    out=$(on "$2" "$3" "$BUDGET"); rc=$?
    echo "$1 host=$2 rc=$rc wall_ms=$(( ($(date +%s%N) - t0) / 1000000 )) $out"
    [ "$rc" = 0 ] || bad=1
}

echo "label=$LABEL dir=$D files=$FILES"
phase create "${H[0]}" "mkdir -p $D && cd $D && for i in \$(seq 1 $FILES); do echo \$i > f\$i; done && sync && echo created=\$(ls -f | grep -c '^f')"
# %s needs each file's size, so every file is stat'ed (a read grant each);
# -printf . alone answers from the directory entries' types and stats nothing
phase peer-stat "${H[1]}" "find $D -type f -printf '%s\n' | wc -l"
phase remove "${H[0]}" "rm -rf $D && sync && echo removed"
for h in "${H[@]}"; do
    phase check "$h" "[ ! -e $D ] && echo gone"
done
[ "$bad" = 0 ] && echo "RESULT PASS" || echo "RESULT FAIL"
exit "$bad"
