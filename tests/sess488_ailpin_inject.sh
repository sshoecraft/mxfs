#!/bin/bash
# sess488: D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-PIN-0487 — the pin, produced
# on demand, and the push's terminal behaviour measured against it.
#
# THE DEFECT.  xfsaild's grant guard refuses to write a committed AG-metadata
# image for an allocation group this node no longer holds (writing it would
# revert the holder's newer image).  The refusal stales the buffer and reports
# the push as a success, and nothing removes the buf log item from the AIL, so
# the item is re-refused every cycle forever: the log tail cannot move past it
# and xfs_ail_push_all_sync (unmount, quiesce, freeze) never returns.  Lap 3 of
# the unmount campaign measured it — one node's AGI/inobt/finobt of one AG at
# one LSN at the head of its AIL for the whole 240 s budget (P128-AILSTUCK),
# the same three blocks the P126 skip lines named — and the holder kept the
# cluster-wide SB summary lock the whole time, so 26 peers waited behind it.
#
# THE VEHICLE.  The only producers of such an item are defects (D-0483's
# unmount ordering, fixed in 0.69.3), so the pin cannot be reproduced on the
# fixed tree by workload.  0.69.6 adds a per-mount debugfs injector,
# inject_unheld_agmeta_dirty: for an AG the node does NOT hold it reads the AGI
# through the ordinary transactional read, logs it unchanged, commits and
# forces the log — a committed AGI image whose grant the node never held, in
# its AIL, with nothing racing.  Only the DLM authorization is bypassed.
#
# LEGS, one per module build:
#   A  0.69.6 — REPORT ONLY (identity-carrying P126-XFSAILD-REFUSE lines, the
#      P126-AIL-PINNED alert after the grace period, P126-AIL-PINNED-MOUNT from
#      the work item; the push still stales-and-skips).  Expected: the alert
#      within grace + one xfsaild retry, NO shutdown, umount on the victim
#      HANGS (P128-AILSTUCK names the injected AGI), peers unaffected.  This is
#      the measured reproduction the fix is then held against.
#   B  the fix build — refuse without staling, XFS_ITEM_LOCKED, and after the
#      grace period a named fail-stop.  Expected: the same refusal lines and
#      alert, then a shutdown naming the item, umount RETURNS within budget,
#      peers unaffected, and the victim's remount replays its slice with the
#      injected image REFUSED by the authority gate (it was captured with no
#      grant epoch).
#
# derived time budgets, derived: prep 300 (measured 106-138 s this session); the
# injection is one ssh (30); the wait is grace (10 s default) + 6 s for the
# next xfsaild retry and the work item; the peer workload is the chain-140
# round shape (200 creates + sync, measured 3-5 s) -> 30; umount 50 inside a
# 60 s ssh (a clean umount is ~1 s, a shutdown umount the same — 50 s is the
# assertion that it returned at all, and lets one 30 s P128 dump land on the
# hang leg); hang capture 90; power-cycle + SSH 180 (measured 60-120);
# remount 60.  ~9 min per leg after the prep.
#
# Usage:  GATE=<log> setsid nohup bash tests/sess488_ailpin_inject.sh s488d &
#         LEGS="A B" KO_B=<frozen fix ko> GATE=<log> setsid nohup bash tests/sess488_ailpin_inject.sh s488e &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s488d}
GATE=${GATE:-tests/evidence/sess487_chain139_persig_ab_s488c.log}
LEGS=${LEGS:-A}
KO_A=${KO_A:-tests/evidence/sess488_frozen_0696/mxfs.ko}
KO_B=${KO_B:-}
V=${V:-test1}
PEERS=${PEERS:-test2 test3}
AGS=${AGS:-7 11 15 19 23 27 3 30 5 9}
GRACE_MS=${GRACE_MS:-10000}
MNT=/mnt/shared
LOG=tests/evidence/sess488_ailpin_inject_$LABEL.log
O=tests/evidence/sess488_ailpin_inject_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"

wait_ssh() { # <node> <bound_s>
    local dl=$(( $(date +%s) + $2 ))
    while [ "$(date +%s)" -lt "$dl" ]; do
        [ "$(timeout 8 $SSH "$1" 'echo SSH_UP' 2>/dev/null | grep -c SSH_UP)" = 1 ] && return 0
        sleep 5
    done
    return 1
}

install_ko() { # <ko> <name>
    [ -f "$1" ] || { echo "  ABORT LEG $2: missing $1"; return 1; }
    cp "$1" mxfs.ko || return 1
    echo "  STAGE install_ko $2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') marker_refuse=$(strings -a mxfs.ko | grep -ac 'P126-XFSAILD-REFUSE ') marker_pinned=$(strings -a mxfs.ko | grep -ac 'P126-AIL-PINNED ') injector=$(strings -a mxfs.ko | grep -ac 'inject_unheld_agmeta_dirty')"
}

leg() { # <name> <ko>
    local name=$1 ko=$2 t0 rc since d injected="" tried="" out ag
    local D="$O/$name"
    mkdir -p "$D"
    echo "--- leg=$name ko=$ko ---"
    install_ko "$ko" "$name" || return 1
    t0=$(date +%s)
    timeout 300 ./run.sh 32 caw prep_cluster > "$D/prep.out" 2>&1; rc=$?
    echo "  STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s build=$(grep -ao 'build [0-9A-F]*' "$D/prep.out" | tail -1)"
    [ "$rc" = 0 ] || { echo "  LEG $name NOT RUN: prep rc=$rc"; return 1; }

    since=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    d=$(timeout 30 $SSH "$V" "ls -d /sys/kernel/debug/mxfs/*/ 2>/dev/null | head -1" 2>/dev/null | tr -d '[:space:]')
    [ -n "$d" ] || { echo "  LEG $name NOT RUN: no /sys/kernel/debug/mxfs/<dev>/ on $V"; return 1; }
    for ag in $AGS; do
        out=$(timeout 30 $SSH "$V" "if echo $ag > ${d}inject_unheld_agmeta_dirty 2>/dev/null; then echo INJ_OK=$ag; else echo INJ_RC=\$?; fi" 2>/dev/null)
        tried="$tried $ag:$(echo "$out" | grep -ao 'INJ_[A-Z]*=[0-9]*' | head -1)"
        case "$out" in *INJ_OK*) injected=$ag; break;; esac
    done
    echo "  STAGE inject victim=$V debugfs=$d ag=${injected:-NONE} tried=$tried wall=$(( $(date +%s) - t0 ))s"
    [ -n "$injected" ] || { echo "  LEG $name NOT RUN: no unheld AG accepted the injection (every try refused = the node holds them all, or the file is missing)"; return 1; }

    # the grace period, then one more xfsaild retry and the work item
    sleep $(( GRACE_MS / 1000 + 6 ))

    # peers, while the victim's item is refused: the chain-140 round shape
    local p
    for p in $PEERS; do
        ( timeout 30 $SSH "$p" "mkdir -p $MNT/ailpin_${name}_$p && cd $MNT/ailpin_${name}_$p && n=0; for i in \$(seq 1 200); do echo x > f\$i && n=\$((n+1)); done; sync; echo PEER_MADE=\$n" > "$D/peer_$p.txt" 2>&1; echo "PEER_RC=$?" >> "$D/peer_$p.txt" ) &
    done
    wait
    local pok=0
    for p in $PEERS; do
        grep -q 'PEER_MADE=200' "$D/peer_$p.txt" && grep -q 'PEER_RC=0' "$D/peer_$p.txt" && pok=$((pok + 1))
        echo "  PEER $p: $(tr '\n' ' ' < "$D/peer_$p.txt" | cut -c1-120)"
    done

    # the victim's own view before umount: the refusal identity, the alert, any shutdown
    timeout 60 $SSH "$V" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P-INJECT|P126-|P128-AILSTUCK|P60-|P-LWEDGE|shut ?down|Shutdown|SHUTDOWN|Corruption|P131|P243'" > "$D/victim_pre_umount.txt" 2>/dev/null
    echo "  VICTIM pre-umount: inject=$(grep -ac 'P-INJECT-UNHELD-AGMETA agno' "$D/victim_pre_umount.txt") skip=$(grep -ac 'P126-XFSAILD-SKIP-AGMETA' "$D/victim_pre_umount.txt") refuse=$(grep -ac 'P126-XFSAILD-REFUSE ' "$D/victim_pre_umount.txt") relog=$(grep -ac 'P126-XFSAILD-REFUSE-RELOG' "$D/victim_pre_umount.txt") pinned=$(grep -ac 'P126-AIL-PINNED ' "$D/victim_pre_umount.txt") pinned_mount=$(grep -ac 'P126-AIL-PINNED-MOUNT' "$D/victim_pre_umount.txt") shutdown=$(grep -aciE 'shut ?down' "$D/victim_pre_umount.txt")"
    grep -a -m1 'P-INJECT-UNHELD-AGMETA agno' "$D/victim_pre_umount.txt" | cut -c1-260 | sed 's/^/    /'
    grep -a -m1 'P126-XFSAILD-REFUSE ' "$D/victim_pre_umount.txt" | cut -c1-300 | sed 's/^/    /'
    grep -a -m1 'P126-AIL-PINNED ' "$D/victim_pre_umount.txt" | cut -c1-300 | sed 's/^/    /'
    grep -aiE -m2 'shut ?down' "$D/victim_pre_umount.txt" | cut -c1-200 | sed 's/^/    /'

    # umount on the victim, bounded: the assertion is that it RETURNS
    local dev ures urc ums
    dev=$(timeout 20 $SSH "$V" "awk '\$2==\"$MNT\"{print \$1}' /proc/mounts" 2>/dev/null | tr -d '[:space:]')
    t0=$(date +%s)
    ures=$(timeout 60 $SSH "$V" "t=\$(date +%s%3N); timeout 50 umount $MNT; rc=\$?; echo UMOUNT_RC=\$rc UMOUNT_MS=\$(( \$(date +%s%3N) - t ))" 2>/dev/null | grep -a UMOUNT_RC)
    urc=$(echo "$ures" | grep -ao 'UMOUNT_RC=[0-9]*' | cut -d= -f2); ums=$(echo "$ures" | grep -ao 'UMOUNT_MS=[0-9]*' | cut -d= -f2)
    echo "  STAGE umount victim=$V dev=$dev rc=${urc:-NONE} ms=${ums:-?} wall=$(( $(date +%s) - t0 ))s budget=50s"

    if [ "${urc:-124}" != 0 ]; then
        # hang capture BEFORE the power cycle: journald on the nodes is volatile
        timeout 90 $SSH "$V" \
            "echo '### umount task ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null) || continue; [ \"\$c\" = umount ] || continue; echo \"pid=\${t#/proc/} state=\$(awk '{print \$3}' \$t/stat 2>/dev/null) wchan=\$(cat \$t/wchan 2>/dev/null)\"; cat \$t/stack 2>/dev/null; done; echo '### D-state and fs/dlm tasks ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null) || continue; st=\$(awk '{print \$3}' \$t/stat 2>/dev/null); case \"\$st:\$c\" in D:*|*:umount|*:xfsaild*) echo \"--- pid=\${t#/proc/} comm=\$c state=\$st wchan=\$(cat \$t/wchan 2>/dev/null)\"; cat \$t/stack 2>/dev/null;; esac; done; echo '### mounts ###'; grep -a mxfs /proc/mounts" \
            > "$D/hang_$V.txt" 2>&1
        echo "  HANG umount task: $(grep -a -m1 'pid=' "$D/hang_$V.txt" | cut -c1-120)"
        grep -a -A8 '### umount task ###' "$D/hang_$V.txt" | grep -aE '^\[<|[a-z_0-9]+\+0x' | head -6 | sed 's/^/    /'
    fi

    # the victim's journal, whole and filtered, before any power cycle
    timeout 90 $SSH "$V" "journalctl -k --no-pager --since '$since' 2>/dev/null" > "$D/kjournal_$V.txt" 2>/dev/null
    grep -aE 'P-INJECT|P126-|P128-AILSTUCK|P60-|P-LWEDGE|shut ?down|Shutdown|SHUTDOWN|Corruption|P131|P243|replay|REPLAY|REFUS|taint|TAINT' "$D/kjournal_$V.txt" > "$D/victim_probes.txt"
    echo "  VICTIM total: skip=$(grep -ac 'P126-XFSAILD-SKIP-AGMETA' "$D/victim_probes.txt") refuse=$(grep -ac 'P126-XFSAILD-REFUSE ' "$D/victim_probes.txt") pinned=$(grep -ac 'P126-AIL-PINNED ' "$D/victim_probes.txt") pinned_mount=$(grep -ac 'P126-AIL-PINNED-MOUNT' "$D/victim_probes.txt") ailstuck_dumps=$(grep -ac 'P128-AILSTUCK iter' "$D/victim_probes.txt") ailstuck_injected_daddr=$(grep -a 'P128-AILSTUCK  \[' "$D/victim_probes.txt" | grep -ac "daddr=0x$(printf '%x' "$(grep -a -m1 'P-INJECT-UNHELD-AGMETA agno' "$D/victim_probes.txt" | grep -ao 'daddr=[0-9]*' | cut -d= -f2 || echo 0)")") shutdown=$(grep -aciE 'shut ?down' "$D/victim_probes.txt") journal_lines=$(wc -l < "$D/kjournal_$V.txt")"
    grep -a 'P128-AILSTUCK  \[' "$D/victim_probes.txt" | head -3 | cut -c1-200 | sed 's/^/    /'

    if [ "${urc:-124}" != 0 ]; then
        t0=$(date +%s)
        timeout 60 sudo virsh -c qemu:///system destroy "$V" > /dev/null 2>&1; local krc=$?
        sleep 2
        timeout 60 sudo virsh -c qemu:///system start "$V" > /dev/null 2>&1
        wait_ssh "$V" 180 && local back=up || local back=DOWN
        echo "  STAGE power_cycle victim=$V destroy_rc=$krc back=$back wall=$(( $(date +%s) - t0 ))s budget=240s"
    else
        # the fix leg: remount and watch the slice replay decide on the injected image
        local msince mres
        msince=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
        mres=$(timeout 60 $SSH "$V" "mount -t mxfs $dev $MNT; echo MOUNT_RC=\$?" 2>/dev/null | grep -a MOUNT_RC)
        echo "  STAGE remount victim=$V $mres wall=$(( $(date +%s) - t0 ))s budget=60s"
        timeout 60 $SSH "$V" "journalctl -k --no-pager --since '$msince' 2>/dev/null | grep -aiE 'replay|refus|taint|authority|recover|P126|shut ?down'" > "$D/victim_remount.txt" 2>/dev/null
        echo "  REMOUNT replay lines: $(wc -l < "$D/victim_remount.txt")"
        head -8 "$D/victim_remount.txt" | cut -c1-240 | sed 's/^/    /'
    fi

    # peers' loss-class probes over the leg
    for p in $PEERS; do
        echo "  PEER $p probes: $(timeout 30 $SSH "$p" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -acE 'P-DIRSTALE|P17-CLOBBER|DURABLE-FAIL|P190-MODIFY-BASE-BEHIND|P61-ADOPT-DISK|P126-|shut down'" 2>/dev/null | tr -dc '0-9')"
    done
    echo "  LEG $name SUMMARY: injected_ag=$injected peers_ok=$pok/$(echo $PEERS | wc -w) umount_rc=${urc:-NONE} umount_ms=${ums:-?}"
}

{
  echo "=== sess488 ailpin_inject START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) LEGS='$LEGS' KO_A=$KO_A KO_B=${KO_B:-none} V=$V GRACE_MS=$GRACE_MS ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  for l in $LEGS; do
      case "$l" in
          A) leg A "$KO_A" ;;
          B) [ -n "$KO_B" ] || { echo "--- leg=B SKIPPED: KO_B not given ---"; continue; }; leg B "$KO_B" ;;
          *) echo "ABORT: unknown leg $l" ;;
      esac
  done
  echo "--- VERDICT ---"
  echo "  A (report only) reproduces the pin if: refuse>=1 with the injected daddr, pinned=1 within grace+retry, shutdown=0, umount rc!=0 (hang) and P128-AILSTUCK names the injected daddr, peers_ok=all."
  echo "  B (the fix) is verified if: refuse>=1, pinned=1, a shutdown naming the item, umount rc=0 within 50 s, peers_ok=all, and the remount's replay refuses the injected image."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
