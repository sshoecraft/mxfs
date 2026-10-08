#!/bin/bash
# pve_freespace_drift.sh — does each host of a pair count the other's frees?
#
# Each host's free-space admission counter (the one a reservation is taken
# from before any block is allocated, and what fallocate and delayed
# allocation are refused ENOSPC by) is set from the superblock at mount and
# then moved by that host's own transactions.  If a block the peer frees never
# reaches it, a host whose files the peer deletes loses that space for good:
# participant 0 allocates FRAC percent of the free space, participant 1
# removes the file, and the round repeats.  With the frees counted, every
# round succeeds; without, participant 0 is refused ENOSPC by the second
# round on a filesystem that is almost empty.  Both hosts' df is printed
# after each round, so a statfs that disagrees between the hosts shows too.
#
# Usage: tests/pve_freespace_drift.sh [label]
# Env:
#   PVE_PAIR     "<addr> <addr>" (default nested pair A); participant 0 first
#   FRAC         percent of the free space each round allocates (55)
#   ROUNDS       rounds (3)
#   PHASE_BUDGET seconds any one step may take (60: a fallocate of unwritten
#                extents and an unlink of one file are each well under a
#                second on native XFS)
#   DF_EACH_ROUND 1 prints both hosts' df after every round (statfs refreshes
#                the counters, so 0 leaves the ENOSPC retry as the only path
#                that brings the peer's frees in before the next round)
#   CONVERGE_S   seconds both hosts' df may take to agree after the cleanup (45)
# Exit 0 when every round's allocation and removal succeeded, both hosts' df
# agree within 100 MiB inside CONVERGE_S, and each is back within 100 MiB of
# where it started.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:-run}
read -r -a H <<<"${PVE_PAIR:-192.168.120.137 192.168.120.192}"
MNT=/mnt/shared
FRAC=${FRAC:-55}
ROUNDS=${ROUNDS:-3}
DF_EACH_ROUND=${DF_EACH_ROUND:-1}
BUDGET=${PHASE_BUDGET:-60}
D=$MNT/fsdrift
bad=0

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
step() {  # <name> <host> <cmd>
    local t0 rc out
    t0=$(date +%s%N)
    out=$(on "$2" "$3" "$BUDGET"); rc=$?
    echo "$1 host=$2 rc=$rc wall_ms=$(( ($(date +%s%N) - t0) / 1000000 )) $out"
    return "$rc"
}
used_kib() {  # <host>
    on "$1" "df -k --output=used $MNT | tail -1" 30 | tr -d ' '
}
dfboth() {  # <tag>
    local u0 u1
    u0=$(used_kib "${H[0]}"); u1=$(used_kib "${H[1]}")
    echo "$1 df_used_kib ${H[0]}=$u0 ${H[1]}=$u1"
    LAST_U0=$u0; LAST_U1=$u1
}

echo "label=$LABEL pair=${H[*]} frac=$FRAC rounds=$ROUNDS"
for h in "${H[@]}"; do
    on "$h" "echo \$(uname -n) build=\$(cat /sys/module/mxfs/srcversion) \$(df -k --output=size,used,avail $MNT | tail -1)" 30
done
step setup "${H[0]}" "mkdir -p $D && sync && echo ok" || bad=1
dfboth start
START_U0=$LAST_U0; START_U1=$LAST_U1
avail=$(on "${H[0]}" "df -k --output=avail $MNT | tail -1" 30 | tr -d ' ')
size_mib=$(( avail * FRAC / 100 / 1024 ))
echo "each round allocates ${size_mib} MiB of ${avail} KiB available"

for r in $(seq 1 "$ROUNDS"); do
    f=$D/r$r-$LABEL
    step "alloc-$r" "${H[0]}" "fallocate -l ${size_mib}M $f && sync && echo ok" || bad=1
    step "remove-$r" "${H[1]}" "rm -f $f && sync && echo ok" || bad=1
    [ "$DF_EACH_ROUND" = 1 ] && dfboth "after-$r"
done
step cleanup "${H[0]}" "rm -rf $D && sync && echo ok" || bad=1
# A host reads the AGs it does not hold from the medium, so a free the peer
# made reaches its df when the peer's log pushes the AG header home: the log
# worker pushes every 30 s.  Both hosts must agree, and be back where they
# started, within CONVERGE_S.
CONVERGE_S=${CONVERGE_S:-45}
t0=$(date +%s); agree=0
while :; do
    dfboth end
    diff=$(( LAST_U0 > LAST_U1 ? LAST_U0 - LAST_U1 : LAST_U1 - LAST_U0 ))
    if [ "$diff" -le 102400 ]; then agree=1; break; fi
    [ $(( $(date +%s) - t0 )) -ge "$CONVERGE_S" ] && break
    sleep 5
done
if [ "$agree" = 1 ]; then
    echo "df agrees between the hosts after $(( $(date +%s) - t0 )) s"
else
    echo "df disagrees between the hosts by ${diff} KiB after ${CONVERGE_S} s"
    bad=1
fi
for i in 0 1; do
    s=$([ "$i" = 0 ] && echo "$START_U0" || echo "$START_U1")
    e=$([ "$i" = 0 ] && echo "$LAST_U0" || echo "$LAST_U1")
    d=$(( e > s ? e - s : s - e ))
    if [ "$d" -gt 102400 ]; then
        echo "${H[$i]} df used ended ${d} KiB from where it started"
        bad=1
    fi
done
[ "$bad" = 0 ] && echo "RESULT PASS" || echo "RESULT FAIL"
exit "$bad"
