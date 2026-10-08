#!/bin/bash
# pve_write_authority_laps.sh — run tests/pve_cluster_write_authority.sh lap
# after lap on a DRBD pair and print one line per lap: the DRBD conflicts each
# host logged, whether a host restarted, each host's churn iterations, and the
# slot record's census (slots written, unlogged "passenger" slots written,
# passengers of a poisoned shell).
#
# For D-DRBD-BOTH-HOSTS-WRITE-ONE-DINODE-AT-ONCE-AND-DRBD-DROPS-THE-LINK: the
# arm with mxfs.cluster_passenger_skip=7 must show no conflict and no passenger
# in any lap; the arm at 3 (the behaviour before bit2) is the control, on the
# same build.
#
# Usage: tests/pve_write_authority_laps.sh <laps> [knob]
#   knob  set mxfs.cluster_passenger_skip to this on both hosts before every
#         lap; a host that restarted comes back at the build's default, so it
#         is set again each lap.  Omitted: whatever the hosts have.
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.120.137 192.168.120.192", the
#              nested pair)
#   CHURN, WORK_S, PROFILE  passed to the harness
#   LAP_BUDGET seconds a lap may take (default 420: the harness's profiler
#              window 130 s, the churn, the reads of both hosts and a
#              restarted host's return, as the single runs measured 3-4 min)
#   JOIN_BUDGET seconds to wait before a lap for both hosts to be mounted,
#              Connected, Primary/Primary, UpToDate (default 300: a restarted
#              participant 1 rejoins in ~150 s)
#
# Each lap's evidence is the harness's own directory, named on its line.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LAPS=${1:?usage: tests/pve_write_authority_laps.sh <laps> [knob]}
KNOB=${2:-}
PAIR_S=${PVE_PAIR:-192.168.120.137 192.168.120.192}
read -r -a PAIR <<<"$PAIR_S"
LAP_BUDGET=${LAP_BUDGET:-420}
JOIN_BUDGET=${JOIN_BUDGET:-300}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/pve_wal.XXXXXX") || exit 1

on() {  # <host> <cmd> [timeout]
    timeout "${3:-30}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
whole() {  # both hosts mounted, Connected, Primary/Primary, UpToDate/UpToDate
    local h s
    for h in "${PAIR[@]}"; do
        s=$(on "$h" "grep ' cs:' /proc/drbd; grep -c ' /mnt/shared mxfs ' /proc/mounts" 15)
        case "$s" in *"cs:Connected ro:Primary/Primary ds:UpToDate/UpToDate"*) ;; *) return 1 ;; esac
        [ "$(tail -1 <<<"$s")" = 1 ] || return 1
    done
}

for lap in $(seq 1 "$LAPS"); do
    t0=$(date +%s)
    until whole; do
        if [ $(( $(date +%s) - t0 )) -ge "$JOIN_BUDGET" ]; then
            echo "lap $lap: ABORT: the pair was not whole within ${JOIN_BUDGET}s"
            exit 1
        fi
        sleep 10
    done
    if [ -n "$KNOB" ]; then
        for h in "${PAIR[@]}"; do
            on "$h" "echo $KNOB > /sys/module/mxfs/parameters/cluster_passenger_skip && cat /sys/module/mxfs/parameters/cluster_passenger_skip" 15 | grep -qx "$KNOB" \
                || { echo "lap $lap: ABORT: could not set cluster_passenger_skip=$KNOB on $h"; exit 1; }
        done
    fi
    knobs=$(for h in "${PAIR[@]}"; do on "$h" "cat /sys/module/mxfs/parameters/cluster_passenger_skip" 15; done | tr '\n' '/')
    log="$OUT/lap$lap.out"
    env PVE_PAIR="$PAIR_S" timeout "$LAP_BUDGET" "$REPO/tests/pve_cluster_write_authority.sh" > "$log" 2>&1
    rc=$?
    evid=$(grep -o -E "$REPO/tests/evidence/pve_cluster_write_authority/[0-9TZ]+" "$log" | tail -1)
    iters=$(sed -n 's/.*churn rc=[0-9]* (iterations \([^:]*\):.*/\1/p' "$log" | head -1)
    restarted=$(grep -c 'RESTARTED in the window' "$log")
    conflicts=$(sed -n 's/^conflicts: \([0-9]*\)$/\1/p' "$log" | tail -1)
    census=$(grep -E '^[0-9.]+ census:' "$log" | sed -E 's/^([0-9.]+) census: ([0-9]+) slots written.*passengers (\{[^}]*\}).*/\1 written=\2 \3/' | tr '\n' ';')
    echo "lap $lap: rc=$rc knob=${knobs%/} conflicts=${conflicts:-?} restarted=$restarted iterations=[$iters] $census evidence=${evid:-none} ($(( $(date +%s) - t0 ))s)"
done
