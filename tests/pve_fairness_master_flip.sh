#!/bin/bash
# pve_fairness_master_flip.sh — does the shared-directory churn's winner follow
# the directory lock's master?
#
# For D-DRBD-PAIR-SHARED-DIR-CHURN-STARVES-PARTICIPANT-1.  A lock's master is
# active_nodes[seeded page hash % 2], with the active nodes sorted by node id,
# and a mount's node id is random, so remounting participant 0 reshuffles
# which host masters a given lock.  This remounts participant 0 until a
# tests/pve_churn_fairness.sh PROBES=1 run names participant 1 as the shared
# directory's master (tools/tenure_report.py: the host that fires P7S), and
# prints every run's iterations and master, so the two cases sit side by side.
#
# Usage: tests/pve_fairness_master_flip.sh
# Env:
#   PVE_PAIR   "<participant 0> <participant 1>" (default the nested pair
#              "192.168.120.137 192.168.120.192")
#   TRIES      remounts to try (default 5)
#   CHURN, WORK_S  passed to the fairness run (default 4, 40)
#   JOIN_BUDGET    seconds for the pair to be whole after a remount (default
#              300: a remount's heartbeat scan and join took 12-170 s here)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
PAIR_S=${PVE_PAIR:-192.168.120.137 192.168.120.192}
read -r -a PAIR <<<"$PAIR_S"
P0=${PAIR[0]}; P1=${PAIR[1]}
TRIES=${TRIES:-5}
JOIN_BUDGET=${JOIN_BUDGET:-300}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/fairflip.XXXXXX") || exit 1

on() {
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
whole() {
    local h s
    for h in "$P0" "$P1"; do
        s=$(on "$h" "grep ' cs:' /proc/drbd; grep -c ' /mnt/shared mxfs ' /proc/mounts" 15)
        case "$s" in *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*) ;; *) return 1 ;; esac
        [ "$(tail -1 <<<"$s")" = 1 ] || return 1
    done
}
fair_run() {  # <label>: one probed fairness run, one summary line
    local log="$OUT/$1.out" master it
    env PVE_PAIR="$PAIR_S" PROBES=1 CHURN="${CHURN:-4}" WORK_S="${WORK_S:-40}" timeout 300 \
        "$REPO/tests/pve_churn_fairness.sh" > "$log" 2>&1
    it=$(grep -a '^iterations' "$log" | head -1)
    master=$(grep -aB30 'this host masters the directory lock' "$log" | grep -aoE '^  [0-9.]+:' | tail -1 | tr -d ' :')
    echo "$1: master=${master:-unknown} $it evidence=$(grep -ao "$REPO/tests/evidence/pve_churn_fairness/[^ ]*" "$log" | tail -1)"
    [ "$master" = "$P1" ]
}

for t in $(seq 1 "$TRIES"); do
    if fair_run "try$t"; then
        echo "participant 1 masters the directory in try $t"
        exit 0
    fi
    on "$P0" "systemctl restart mxfs-drbd@mxfs" 180 >/dev/null
    t0=$(date +%s)
    until whole; do
        if [ $(( $(date +%s) - t0 )) -ge "$JOIN_BUDGET" ]; then
            echo "ABORT: the pair was not whole ${JOIN_BUDGET}s after remounting $P0"
            exit 1
        fi
        sleep 10
    done
    on "$P0" "cat /sys/module/mxfs/parameters/cluster_passenger_skip" 15 | sed "s/^/$P0 remounted after $(( $(date +%s) - t0 ))s, passenger knob /"
done
echo "participant 1 never mastered the directory in $TRIES tries"
exit 2
