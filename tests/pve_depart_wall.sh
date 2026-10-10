#!/bin/bash
# pve_depart_wall.sh — how long a clean unmount of one host takes while its
# peer stays mounted, on an MXFS-on-DRBD Proxmox pair, and where it goes: the
# departing host hands every ledger page it is the authority of to the
# survivor before it can leave (dlm/dlm.c mxfs_dlm_handoff_depart).
#
# On the physical pair (2026-10-08) participant 1's unmount, with participant
# 0 mounted, took 36-113 s and then 184 s, past the boot program's 170 s
# umount bound: the unit failed with DRBD left Primary under the unmount.
#
# Each lap, per arm: the knobs are set on both hosts, the dlm probes are
# turned on on the departing host, its unit is stopped and the departure timed
# to the unit's stop (the mount leaves /proc/mounts long before its teardown
# ends); then P-TAUTH-DEPART (pages left, workers, ms)
# and the count of P-TAUTH-HANDOFF why=depart lines are read from its log, the
# probes are turned off and the unit is started again until the pair is
# mounted Primary/Primary, Connected, UpToDate.  Arms alternate LAPS times.
#
# Usage: tests/pve_depart_wall.sh
# Env:
#   PVE_PAIR      "<addr> <addr>" (default the physical pair)
#   DEPART        participant that departs first, 0 (lower address) or 1
#                 (default 0: participant 0 mounts first on a pair start, so
#                 it serves the ledger pages)
#   ALTERNATE     1 (default): each later departure is the previous survivor's,
#                 which then serves every page; 0: always the same host.  A host
#                 that has just rejoined serves no page, so departing it twice
#                 measures nothing (0.7 s, no P-TAUTH-DEPART line, 2026-10-08).
#   KNOB          the module parameter the arms set on both hosts (default
#                 tauth_group_commit; tauth_depart_budget_ms A/Bs how long
#                 a departure hands pages before leaving the rest to the
#                 survivor's takeover; drbd_span_waves A/Bs the DRBD swap's
#                 waves)
#   ARMS          "<KNOB value>..." (default "0 1")
#   LAPS          (default 2)
#   UMOUNT_BUDGET seconds for the unmount (default 170: the boot program's own
#                 bound, past which a clean departure becomes a loss)
#   MOUNT_BUDGET  seconds for the unit's start to the pair whole (default 300,
#                 as scripts/pve_pair_update.sh)
#   WORKLOAD      1: the survivor creates a file and stats an earlier one, in a
#                 loop, from before the departure until the survivor wait
#                 ends; each new inode lands on a page the departing host may
#                 have served, so a survivor stall behind the departure shows
#                 as slow operations (reported: ops, slowest ms, ops > 1 s)
#   SURVIVOR_WAIT seconds the survivor is given to make the departed pages its
#                 own (handed, or taken over on GOODBYE) before the departed
#                 host is started again (default 120)
# A lap also FAILS on any survivor takeover that did not finish a page
# (P-TAUTH-TAKEOVER-NOTACTIVE/-INTERRUPTED/-DECERTIFIED/-SCAN-FAIL/-NOINC,
# P-TAUTH-FROZEN-NOT-CONSUMED, P-TAUTH-FREEZE-DRAIN-TIMEOUT), on a survivor
# takeover refused as not the bootstrap node (P-TAUTH-TAKEOVER-NOTBOOT), and
# when the departure left pages but the survivor logged no P-TAUTH-TAKEOVER,
# and on any lock request the survivor gave up on (an error to a file
# operation).
# Evidence: tests/evidence/pve_depart_wall/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_depart_wall: PVE_PAIR must name two hosts"; exit 2; }
if python3 -I -c 'import ipaddress, sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) < ipaddress.ip_address(sys.argv[2]) else 1)' "${PAIR[0]}" "${PAIR[1]}"; then
    P0=${PAIR[0]}; P1=${PAIR[1]}
else
    P0=${PAIR[1]}; P1=${PAIR[0]}
fi
KNOB=${KNOB:-tauth_group_commit}
ARMS=${ARMS:-0 1}
LAPS=${LAPS:-2}
case "${DEPART:-0}" in
    0) DEPART_FIRST=$P0 ;;
    1) DEPART_FIRST=$P1 ;;
    *) echo "pve_depart_wall: DEPART must be 0 or 1"; exit 2 ;;
esac
ALTERNATE=${ALTERNATE:-1}
UMOUNT_BUDGET=${UMOUNT_BUDGET:-170}
MOUNT_BUDGET=${MOUNT_BUDGET:-300}
SURVIVOR_WAIT=${SURVIVOR_WAIT:-120}
MNT=/mnt/shared
P=/sys/module/mxfs/parameters
EVID="$REPO/tests/evidence/pve_depart_wall/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
bad=0

on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
whole() {  # <host>: mounted Primary/Primary Connected UpToDate/UpToDate
    on "$1" "grep -q ' $MNT mxfs ' /proc/mounts && [ \"\$(drbdadm role mxfs)\" = Primary/Primary ] && [ \"\$(drbdadm cstate mxfs)\" = Connected ] && [ \"\$(drbdadm dstate mxfs)\" = UpToDate/UpToDate ] && echo WHOLE" 20 | grep -q WHOLE
}

orig=$(on "$P0" "cat $P/$KNOB" 20)
say "first departing host $DEPART_FIRST (alternate=$ALTERNATE) of $P0 $P1; $KNOB before: $orig; arms [$ARMS] x $LAPS laps"
for h in "$P0" "$P1"; do
    whole "$h" || { say "FAIL: $h is not mounted Primary/Primary, Connected, UpToDate; not starting"; exit 1; }
done

dep=$DEPART_FIRST
for lap in $(seq 1 "$LAPS"); do
    # with ALTERNATE the departing host alternates every arm, so the same
    # order each lap would tie each arm to one host: even laps run the arms
    # in reverse, and over two laps every arm departs from both hosts
    arms_now=$ARMS
    [ $((lap % 2)) = 0 ] && arms_now=$(echo "$ARMS" | tr ' ' '\n' | tac | tr '\n' ' ')
    for arm in $arms_now; do
        tag="lap$lap-$KNOB$arm-$dep"
        for h in "$P0" "$P1"; do
            on "$h" "echo $arm > $P/$KNOB" 20 >/dev/null
        done
        [ "$dep" = "$P0" ] && sur=$P1 || sur=$P0
        # the dlm probes print through one format; the DRBD swap's lock
        # statistics are a pr_debug of their own.  On both hosts: the
        # survivor's activations of the pages it is handed are half the cost.
        for h in "$dep" "$sur"; do
            on "$h" "echo 'module mxfs format \"%s%pV\" +p' > /proc/dynamic_debug/control; echo 'module mxfs format \"P-DRBD-CAS-STATS\" +p' > /proc/dynamic_debug/control" 20 >/dev/null
        done
        if [ "${WORKLOAD:-0}" = 1 ]; then
            on "$sur" "rm -f /root/depart-wl.stop /root/depart-wl.log; mkdir -p $MNT/depart-wl-$lap-$arm; nohup setsid bash -c 'd=$MNT/depart-wl-$lap-$arm; i=0; while [ ! -e /root/depart-wl.stop ]; do t0=\$(date +%s%N); echo x > \$d/f\$i; stat \$d/f\$((i / 2)) > /dev/null; echo \$(( (\$(date +%s%N) - t0) / 1000000 )) \$((t0 / 1000000)); i=\$((i + 1)); done > /root/depart-wl.log 2>&1' > /dev/null 2>&1 < /dev/null & echo WL_STARTED" 20 | grep -q WL_STARTED || say "$tag: survivor workload did not start"
            sleep 3
        fi
        # the window is read on the departing host's own clock
        t_start=$(on "$dep" "date +%s" 20)
        t0=$(date +%s%N)
        on "$dep" "systemctl stop --no-block mxfs-drbd@mxfs" 30 >/dev/null
        # The mount leaves /proc/mounts as soon as umount(2) detaches it; the
        # filesystem's teardown (put_super, where the handoff runs) goes on
        # after that, so the departure ends when the unit has stopped, not
        # when the mount is gone (measured 2026-10-08: gone at 0.8 s, the DLM
        # shut down 31 s later, every handoff probe after 0.8 s lost).
        gone_ms=0 ms=0
        while [ $(( ($(date +%s%N) - t0) / 1000000000 )) -lt $((UMOUNT_BUDGET + 60)) ]; do
            st=$(on "$dep" "grep -q ' $MNT mxfs ' /proc/mounts && echo MOUNTED; systemctl is-active mxfs-drbd@mxfs" 20)
            if [ "$gone_ms" = 0 ] && ! grep -q MOUNTED <<<"$st"; then
                gone_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
            fi
            if ! grep -qE '^(active|deactivating|activating)$' <<<"$st"; then
                ms=$(( ($(date +%s%N) - t0) / 1000000 ))
                break
            fi
            sleep 1
        done
        unit=$(on "$dep" "systemctl is-active mxfs-drbd@mxfs" 20)
        # the survivor may still be activating what it was handed, or taking
        # over what the departure left (tauth_depart_budget_ms): wait until
        # 3 s pass with no new page made its own (at most SURVIVOR_WAIT s)
        n_prev=-1 t2=$(date +%s)
        while [ $(( $(date +%s) - t2 )) -lt "$SURVIVOR_WAIT" ]; do
            n_now=$(on "$sur" "journalctl -k --since @$t_start --no-pager -o cat | grep -acE 'P-TAUTH-PAGE-MINE page=.*via=(frozen-msg|takeover|orphan-sweep)'" 30)
            [ "$n_now" = "$n_prev" ] && break
            n_prev=$n_now
            sleep 3
        done
        for h in "$dep" "$sur"; do
            on "$h" "echo 'module mxfs format \"%s%pV\" -p' > /proc/dynamic_debug/control; echo 'module mxfs format \"P-DRBD-CAS-STATS\" -p' > /proc/dynamic_debug/control" 20 >/dev/null
        done
        wl=
        if [ "${WORKLOAD:-0}" = 1 ]; then
            # stop the loop, let its last operation finish, summarise, clean up
            # each line: duration ms, start epoch ms; the slow ones are kept
            # with their start as seconds after the departure began
            wl=$(on "$sur" "touch /root/depart-wl.stop; sleep 2; cp /root/depart-wl.log /root/depart-wl-$tag.log; awk -v ts=$t_start '/^[0-9]+ [0-9]+\$/ { n++; if (\$1 > m) { m = \$1; ms = \$2 / 1000 - ts } if (\$1 > 1000) { s++; slow = slow sprintf(\" %d@%+.1f\", \$1, \$2 / 1000 - ts) } } !/^[0-9]+ [0-9]+\$/ { e++ } END { printf \"ops=%d slowest_ms=%d at=%+.1fs over_1s=%d [%s ] errors=%d\", n, m, ms, s, slow, e }' /root/depart-wl.log; rm -rf $MNT/depart-wl-$lap-$arm" 120)
            grep -q 'errors=0' <<<"$wl" || { verdict_wl=FAIL; }
        fi
        # epoch-stamped (both hosts' clocks are chrony-synced; the survivor's
        # lag below compares them)
        on "$dep" "journalctl -k --since @$t_start --no-pager -o short-unix" 60 > "$EVID/kmsg-$tag.txt"
        on "$sur" "journalctl -k --since @$t_start --no-pager -o short-unix" 60 > "$EVID/kmsg-$tag-survivor.txt"
        depart=$(grep -a 'P-TAUTH-DEPART node=' "$EVID/kmsg-$tag.txt" | tail -1 | grep -ao 'pages_left=.*')
        handed=$(grep -ac 'P-TAUTH-HANDOFF page=.*why=depart' "$EVID/kmsg-$tag.txt")
        t_handed=$(grep -a 'P-TAUTH-HANDOFF page=.*why=depart' "$EVID/kmsg-$tag.txt" | tail -1 | awk '{print $1}')
        activated=$(grep -ac 'P-TAUTH-PAGE-MINE page=.*via=frozen-msg' "$EVID/kmsg-$tag-survivor.txt")
        t_act=$(grep -a 'P-TAUTH-PAGE-MINE page=.*via=frozen-msg' "$EVID/kmsg-$tag-survivor.txt" | tail -1 | awk '{print $1}')
        lag=$(awk -v a="${t_act:-0}" -v h="${t_handed:-0}" 'BEGIN { if (a > 0 && h > 0) printf "%.1f", a - h; else print "n/a" }')
        # what the departure left: the survivor's takeover of it, the pages a
        # request needed first, and any page the takeover could not finish
        took=$(grep -acE 'P-TAUTH-PAGE-MINE page=.*via=(takeover|orphan-sweep)' "$EVID/kmsg-$tag-survivor.txt")
        ondemand=$(grep -ac 'P-TAUTH-TAKEOVER-ONDEMAND' "$EVID/kmsg-$tag-survivor.txt")
        tkline=$(grep -a 'P-TAUTH-TAKEOVER departed=' "$EVID/kmsg-$tag-survivor.txt" | tail -1 | grep -aoE 'pages_prepared=[0-9]+ skipped=[0-9]+|total_ms=[0-9]+' | tr '\n' ' ')
        tkbad=$(grep -acE 'P-TAUTH-TAKEOVER-(NOTACTIVE|INTERRUPTED|DECERTIFIED|SCAN-FAIL|NOINC)|P-TAUTH-FROZEN-NOT-CONSUMED|P-TAUTH-FREEZE-DRAIN-TIMEOUT' "$EVID/kmsg-$tag-survivor.txt")
        # the teardown's phases, as seconds after "DLM shutting down"
        phases=$(awk '
            { s = $1 + 0 }
            /mxfs: DLM shutting down/       { t0 = s }
            /P-RELALL-WALL/ && t0           { printf "relall=+%.1f ", s - t0 }
            /P-TAUTH-DEPART node=/ && t0    { printf "depart=+%.1f ", s - t0 }
            /mxfs: DLM shutdown complete/ && t0 { printf "dlm_down=+%.1f", s - t0 }
        ' "$EVID/kmsg-$tag.txt")
        # pages the departure left must be taken over by the survivor on
        # GOODBYE: a refused takeover (not bootstrap while the departer's
        # slot still read live) left them under the departed authority, and
        # a stale record on one stalled the survivor 14.5 s at the next
        # departure (0.90.110)
        left_n=$(grep -aoE '^pages_left=[0-9]+' <<<"${depart:-}" | cut -d= -f2)
        notboot=$(grep -ac 'P-TAUTH-TAKEOVER-NOTBOOT' "$EVID/kmsg-$tag-survivor.txt")
        tk_unrun=0
        [ "${left_n:-0}" -gt 0 ] && [ -z "$tkline" ] && tk_unrun=1
        # a lock request the survivor gave up on returns an error to whatever
        # file operation made it, whether or not the workload loop was the one
        # (0.90.111 physical lap 2: two such, none of them the loop's)
        lockfail=$(grep -acE 'lock request failed after [0-9]+ retries|P-ACQ-LADDER-END' "$EVID/kmsg-$tag-survivor.txt")
        verdict=PASS
        [ "$ms" -gt 0 ] && [ "$unit" = inactive ] && [ "$ms" -le $((UMOUNT_BUDGET * 1000)) ] || { verdict=FAIL; bad=1; }
        [ "$tkbad" = 0 ] || { verdict=FAIL; bad=1; }
        [ "$notboot" = 0 ] && [ "$tk_unrun" = 0 ] || { verdict=FAIL; bad=1; }
        [ "$lockfail" = 0 ] || { verdict=FAIL; bad=1; }
        teardown_served=$(grep -a 'P-GOODBYE-SENT' "$EVID/kmsg-$tag.txt" | tail -1 | grep -aoE 'teardown_freeze_served=[0-9]+')
        handoff_drops=$(grep -ac 'P-TEARDOWN-MSG-DROP type=17' "$EVID/kmsg-$tag.txt")
        [ "${verdict_wl:-}" = FAIL ] && { verdict=FAIL; bad=1; }
        verdict_wl=
        say "$tag departing=$dep mount_gone_ms=$gone_ms stopped_ms=$ms unit=$unit handed=$handed [$phases] ${depart:-no P-TAUTH-DEPART line} survivor_activated=$activated last_activation_after_last_handoff_s=$lag survivor_took_over=$took ondemand=$ondemand [${tkline:-no P-TAUTH-TAKEOVER line}] takeover_faults=$tkbad notboot=$notboot takeover_unrun=$tk_unrun survivor_lock_failures=$lockfail ${teardown_served:-teardown_freeze_served=n/a} teardown_handoff_drops=$handoff_drops${wl:+ survivor_workload: $wl} -> $verdict"
        # back to a whole pair: a failed unit leaves DRBD up, often Primary
        if on "$dep" "if ! grep -q ' $MNT mxfs ' /proc/mounts && [ -n \"\$(drbdadm role mxfs 2>/dev/null)\" ] && [ \"\$(systemctl is-active mxfs-drbd@mxfs)\" != active ]; then echo DRBD_UP; fi" 20 | grep -q DRBD_UP; then
            on "$dep" "drbdadm secondary mxfs; drbdadm down mxfs" 60 >/dev/null
        fi
        on "$dep" "systemctl reset-failed mxfs-drbd@mxfs 2>/dev/null; systemctl start --no-block mxfs-drbd@mxfs" 30 >/dev/null
        t1=$(date +%s)
        until whole "$dep"; do
            [ $(( $(date +%s) - t1 )) -lt "$MOUNT_BUDGET" ] || { say "FAIL: $dep not whole again within ${MOUNT_BUDGET}s; stopping"; bad=1; break 3; }
            sleep 5
        done
        say "$tag $dep whole again after $(( $(date +%s) - t1 ))s"
        # the survivor now serves every page the departed host handed it, and
        # the rejoined host serves none: the next departure is the survivor's
        [ "$ALTERNATE" = 1 ] && { [ "$dep" = "$P0" ] && dep=$P1 || dep=$P0; }
    done
done
for h in "$P0" "$P1"; do
    on "$h" "echo ${orig:-0} > $P/$KNOB" 20 >/dev/null
done
say "$KNOB restored to ${orig:-0}"
[ "$bad" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
exit "$bad"
