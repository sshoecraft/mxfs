#!/bin/bash
# rig_depart_wall.sh — how long a clean unmount of one node takes while its
# peer stays mounted, on a prepared 2-node shared-LUN rig (2/net/mesh/direct:
# `./run.sh 2/net/mesh/direct prep_cluster` first), and what it costs the
# survivor.  The rig twin of tests/pve_depart_wall.sh.
#
# On this rig (0.85.1, 2026-09-13) such an unmount took 35-80 s, handing ~6700
# ledger pages to the survivor one at a time, while the survivor's lock
# requests to the departing master went unanswered (its superblock-cover
# worker retried an EX acquire for 32 s).  Since 0.90.111 a departure hands
# pages for at most tauth_depart_budget_ms (default 2000) and the survivor
# takes over the rest on GOODBYE.
#
# Setup (once): with both nodes mounted, node A creates NFILES files so that
# it serves ledger pages (each create records a grant at the page's master).
# Each lap: the survivor runs a create+stat loop; the departing node is
# unmounted (`umount`, timed to its return: on this rig the unmount runs the
# whole teardown before it returns); both kernel logs are read for the window;
# the departed node mounts again.  Departures alternate between the nodes.
# A lap FAILS on an unmount over UMOUNT_BUDGET or with an error, a survivor
# lock request given up on, a survivor takeover refused or missing when pages
# were left, a survivor workload error, or a survivor operation over
# SURVIVOR_OP_BUDGET_MS.
#
# Usage: tests/rig_depart_wall.sh
# Env:
#   MXFS_NODE_LIST  "A,B" (default test1,test2); A departs first
#   LAPS            departures (default 4)
#   NFILES          files A creates in the setup (default 3000, ~375 pages; 0 = skip)
#   UMOUNT_BUDGET   seconds for one unmount (default 60: native XFS unmounts
#                   in about a second; the hand-off is bounded at 2 s and the
#                   teardown measured 3-16 s on the DRBD pairs)
#   SURVIVOR_OP_BUDGET_MS  slowest survivor create+stat allowed (default 15000)
#   BUDGET_MS       set tauth_depart_budget_ms on both nodes first (unset: the
#                   module's own); a small one leaves pages for the survivor's
#                   takeover, which a rig departure otherwise finishes in 2 s
#   GOODBYE_DELAY_MS  arm dbg_goodbye_rx_delay_ms on the survivor before each
#                   departure, so the retire worker's settle of the departing
#                   record lands before the GOODBYE is processed
#   SETTLED_GONE    set tauth_settled_gone on both nodes (0 = the control arm:
#                   a settled record's slot still counts in the election)
# Evidence: tests/evidence/rig_depart_wall/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
NL=${MXFS_NODE_LIST:-test1,test2}
A=${NL%%,*}
B=${NL##*,}
LAPS=${LAPS:-4}
NFILES=${NFILES:-3000}
UMOUNT_BUDGET=${UMOUNT_BUDGET:-60}
SURVIVOR_OP_BUDGET_MS=${SURVIVOR_OP_BUDGET_MS:-15000}
MNT=/mnt/shared
EVID="$REPO/tests/evidence/rig_depart_wall/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
bad=0

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
mounted() { on "$1" "grep -c ' $MNT mxfs ' /proc/mounts" 20; }

for h in "$A" "$B"; do
    [ "$(mounted "$h")" = 1 ] || { say "FAIL: $h has no mxfs mount on $MNT; prepare the rig first"; exit 1; }
done
DEV=$(on "$A" "awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" { print \$1 }' /proc/mounts" 20)
[ -n "$DEV" ] || { say "FAIL: cannot read the mounted device"; exit 1; }
if [ -n "${BUDGET_MS:-}" ]; then
    for h in "$A" "$B"; do
        on "$h" "echo $BUDGET_MS > /sys/module/mxfs/parameters/tauth_depart_budget_ms" 20 >/dev/null
    done
fi
if [ -n "${SETTLED_GONE:-}" ]; then
    for h in "$A" "$B"; do
        on "$h" "echo $SETTLED_GONE > /sys/module/mxfs/parameters/tauth_settled_gone" 20 >/dev/null
    done
fi
say "nodes A=$A B=$B dev=$DEV builds: $(on "$A" 'cat /sys/module/mxfs/srcversion' 20) $(on "$B" 'cat /sys/module/mxfs/srcversion' 20) budget_ms: $(on "$A" 'cat /sys/module/mxfs/parameters/tauth_depart_budget_ms' 20)"

if [ "$NFILES" -gt 0 ]; then
    t=$(date +%s)
    on "$A" "mkdir -p $MNT/rdw-seed && cd $MNT/rdw-seed && for i in \$(seq 1 $NFILES); do echo x > s\$i || exit 1; done; echo SEED_OK" 900 | grep -q SEED_OK || { say "FAIL: the seed did not complete"; exit 1; }
    say "seed: $NFILES files on $A in $(( $(date +%s) - t ))s"
fi

dep=$A
for lap in $(seq 1 "$LAPS"); do
    [ "$dep" = "$A" ] && sur=$B || sur=$A
    tag="lap$lap-$dep"
    on "$sur" "rm -f /root/rdw.stop /root/rdw.log; mkdir -p $MNT/rdw-wl-$lap; nohup setsid bash -c 'd=$MNT/rdw-wl-$lap; i=0; while [ ! -e /root/rdw.stop ]; do t0=\$(date +%s%N); echo x > \$d/f\$i; stat \$d/f\$((i / 2)) > /dev/null; echo \$(( (\$(date +%s%N) - t0) / 1000000 )) \$((t0 / 1000000)); i=\$((i + 1)); done > /root/rdw.log 2>&1' > /dev/null 2>&1 < /dev/null & echo WL_STARTED" 20 | grep -q WL_STARTED || say "$tag: survivor workload did not start"
    sleep 3
    [ -n "${GOODBYE_DELAY_MS:-}" ] && on "$sur" "echo $GOODBYE_DELAY_MS > /sys/module/mxfs/parameters/dbg_goodbye_rx_delay_ms" 20 >/dev/null
    t_start=$(on "$dep" "date +%s" 20)
    out=$(on "$dep" "T0=\$(date +%s%N); timeout $UMOUNT_BUDGET umount $MNT; echo UMOUNT_RC=\$?; echo UMOUNT_MS=\$(( (\$(date +%s%N) - T0) / 1000000 ))" $((UMOUNT_BUDGET + 30)))
    urc=$(grep -ao 'UMOUNT_RC=[0-9]*' <<<"$out" | cut -d= -f2)
    ums=$(grep -ao 'UMOUNT_MS=[0-9]*' <<<"$out" | cut -d= -f2)
    # the survivor takes over what the departure left: wait until 3 s pass
    # with no new page made its own (at most 120 s)
    n_prev=-1 t2=$(date +%s)
    while [ $(( $(date +%s) - t2 )) -lt 120 ]; do
        n_now=$(on "$sur" "journalctl -k --since @$t_start --no-pager -o cat | grep -acE 'P-TAUTH-PAGE-MINE page=.*via=(frozen-msg|takeover|orphan-sweep)'" 30)
        [ "$n_now" = "$n_prev" ] && break
        n_prev=$n_now
        sleep 3
    done
    wl=$(on "$sur" "touch /root/rdw.stop; sleep 2; cp /root/rdw.log /root/rdw-$tag.log; awk -v ts=$t_start '/^[0-9]+ [0-9]+\$/ { n++; if (\$1 > m) { m = \$1; ms = \$2 / 1000 - ts } if (\$1 > 1000) { s++; slow = slow sprintf(\" %d@%+.1f\", \$1, \$2 / 1000 - ts) } } !/^[0-9]+ [0-9]+\$/ { e++ } END { printf \"ops=%d slowest_ms=%d at=%+.1fs over_1s=%d [%s ] errors=%d\", n, m, ms, s, slow, e }' /root/rdw.log; rm -rf $MNT/rdw-wl-$lap" 300)
    on "$dep" "journalctl -k --since @$t_start --no-pager -o short-unix" 60 > "$EVID/kmsg-$tag.txt"
    on "$sur" "journalctl -k --since @$t_start --no-pager -o short-unix" 60 > "$EVID/kmsg-$tag-survivor.txt"
    depart=$(grep -a 'P-TAUTH-DEPART node=' "$EVID/kmsg-$tag.txt" | tail -1 | grep -aoE 'pages_left=[0-9]+ workers=[0-9]+ ms=[0-9]+ pages=[0-9]+')
    left_n=$(grep -aoE '^pages_left=[0-9]+' <<<"${depart:-}" | cut -d= -f2)
    tkline=$(grep -a 'P-TAUTH-TAKEOVER departed=' "$EVID/kmsg-$tag-survivor.txt" | tail -1 | grep -aoE 'pages_prepared=[0-9]+|total_ms=[0-9]+' | tr '\n' ' ')
    notboot=$(grep -ac 'P-TAUTH-TAKEOVER-NOTBOOT' "$EVID/kmsg-$tag-survivor.txt")
    lockfail=$(grep -acE 'lock request failed after [0-9]+ retries|P-ACQ-LADDER-END' "$EVID/kmsg-$tag-survivor.txt")
    p36=$(grep -ac 'P36-RETRY' "$EVID/kmsg-$tag-survivor.txt")
    served=$(grep -a 'P-GOODBYE-SENT' "$EVID/kmsg-$tag.txt" | tail -1 | grep -aoE 'teardown_freeze_served=[0-9]+')
    drops=$(grep -ac 'P-TEARDOWN-MSG-DROP' "$EVID/kmsg-$tag.txt")
    slow=$(grep -aoE 'slowest_ms=[0-9]+' <<<"$wl" | cut -d= -f2)
    verdict=PASS
    [ "${urc:-1}" = 0 ] && [ "${ums:-0}" -le $((UMOUNT_BUDGET * 1000)) ] || { verdict=FAIL; bad=1; }
    [ "$lockfail" = 0 ] && [ "$notboot" = 0 ] || { verdict=FAIL; bad=1; }
    [ "${left_n:-0}" -gt 0 ] && [ -z "$tkline" ] && { verdict=FAIL; bad=1; }
    grep -q 'errors=0' <<<"$wl" || { verdict=FAIL; bad=1; }
    [ "${slow:-0}" -le "$SURVIVOR_OP_BUDGET_MS" ] || { verdict=FAIL; bad=1; }
    say "$tag umount_rc=${urc:-?} umount_ms=${ums:-?} ${depart:-no P-TAUTH-DEPART line} survivor_takeover=[${tkline:-none}] notboot=$notboot survivor_lock_failures=$lockfail survivor_p36_retries=$p36 ${served:-teardown_freeze_served=n/a} teardown_drops=$drops survivor_workload: $wl -> $verdict"
    t1=$(date +%s)
    on "$dep" "mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?" 300 | grep -q 'MOUNT_RC=0' || { say "FAIL: $dep did not mount again"; bad=1; break; }
    say "$tag $dep mounted again after $(( $(date +%s) - t1 ))s"
    [ "$dep" = "$A" ] && dep=$B || dep=$A
done
[ "$NFILES" -gt 0 ] && on "$A" "rm -rf $MNT/rdw-seed" 900 >/dev/null
[ "$bad" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
exit "$bad"
