#!/bin/bash
# sess488: D-SB-SUMMARY-LOCK-HELD-ACROSS-UNBOUNDED-LOG-QUIESCE-FLEET-CONVOY-0487
# — does one node with a pinned AIL stall the other 31 unmounts?
#
# THE SHAPE.  Lap 3 of the unmount campaign: one node's AIL could not drain
# (a committed AG-metadata image for a grant it no longer held, refused by
# xfsaild), it took the cluster-wide SB summary EX lock in put_super and sat
# in xfs_log_quiesce under it, and 26 peers parked in the CAW acquire poll for
# that lock (P-SB-SUMMARY-BAST refused) for the whole 240 s budget.
#
# This chain produces the pinned node on demand (the 0.69.6 injector,
# tests/sess488_ailpin_inject.sh) and then unmounts ALL 32 nodes at once,
# timing each.  Two module builds, same workload:
#   0.70.0  fail-stop only: the pinned node takes the lock, its quiesce ends
#           when the fail-stop shuts it down after the grace period (10 s),
#           the lock is released — peers are expected to stall for up to
#           ~grace, then complete.  P-SB-SUMMARY-BAST lines on peers = the
#           convoy, bounded.
#   0.70.1  the pre-lock push: the pinned node stalls and shuts down BEFORE
#           taking the lock; peers are expected to unmount at their normal
#           ~1 s with zero P-SB-SUMMARY-BAST refusals.
# The number that decides: per-node umount_ms on the 31 peers (p50/max) and
# the count of P-SB-SUMMARY-BAST lines fleet-wide; the victim's own umount
# returns in both builds (a shutdown unmount).
#
# derived time budgets, derived: prep 300 (measured 106-146 s); inject 30; the mass
# unmount of a freshly prepped fleet is ~1-2 s per node in parallel, the victim
# needs grace (10 s) + one xfsaild retry + the shutdown -> per-node ssh 90 with
# `timeout 60 umount`; sweep 60 per node in parallel.  ~5 min per leg after prep.
#
# Usage:  LEGS="X Y" KO_X=<0.70.0 ko> KO_Y=<0.70.1 ko> GATE=<log> setsid nohup bash tests/sess488_ailpin_fleet_umount.sh s488f &
#
# sess493 (0.70.10 fix: the SB summary key is classified out of closure for
# AG-scoped refusals): leg Z now also counts the strips that free the dead
# holder's lock (publisher P299-CLOSURE-STRIP, survivor P299-SCRUB-STRIP, the
# classifier's own P487-SBSUM-OUT-OF-CLOSURE), the peers' dirty-departure
# lines (P277/P302), the successors' P-SB-SEALED epochs against the victim's,
# and then REMOUNTS one peer to see which slots that mount fences/recovers
# (the bar: only the victim's).  Leg S is leg Z prepped with
# closure_skip_publisher_purge=1 so the survivor demand scrub is the only
# repair path.  Remount budget: fence + one refused-slice recovery, measured
# 20-40 s on this rig -> timeout 120.
# Usage:  LEGS="Z S" KO_Z=<0.70.10 ko> GATE=<log> setsid nohup bash tests/sess488_ailpin_fleet_umount.sh s493z &
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s488f}
GATE=${GATE:-tests/evidence/sess488_ailpin_inject_s488e.log}
LEGS=${LEGS:-X Y}
KO_X=${KO_X:-tests/evidence/sess488_frozen_0700/mxfs.ko}
KO_Y=${KO_Y:-tests/evidence/sess488_frozen_0701/mxfs.ko}
KO_Z=${KO_Z:-tests/evidence/sess492_frozen_0706/mxfs.ko}
V=${V:-test1}
AGS=${AGS:-7 11 15 19 23 27 3 30 5 9}
GRACE_MS=${GRACE_MS:-10000}
MNT=/mnt/shared
LOG=tests/evidence/sess488_ailpin_fleet_umount_$LABEL.log
O=tests/evidence/sess488_ailpin_fleet_umount_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"

nodes() { seq 1 32 | sed 's/^/test/'; }

install_ko() { # <ko> <name>
    [ -f "$1" ] || { echo "  ABORT LEG $2: missing $1"; return 1; }
    cp "$1" mxfs.ko || return 1
    echo "  STAGE install_ko $2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') refuse=$(strings -a mxfs.ko | grep -ac 'P126-XFSAILD-REFUSE ') transient=$(strings -a mxfs.ko | grep -ac 'P126-XFSAILD-REFUSE-TRANSIENT') injector=$(strings -a mxfs.ko | grep -ac 'inject_unheld_agmeta_dirty')"
}

leg() { # <name> <ko>
    local name=$1 ko=$2 t0 rc since d injected="" tried="" out ag n
    local D="$O/$name"
    mkdir -p "$D"
    echo "--- leg=$name ko=$ko ---"
    install_ko "$ko" "$name" || return 1
    t0=$(date +%s)
    local modargs=""
    [ "$name" = S ] && modargs="closure_skip_publisher_purge=1"
    MXFS_EXTRA_MODARGS="$modargs" timeout 300 ./run.sh 32 caw prep_cluster > "$D/prep.out" 2>&1; rc=$?
    echo "  STAGE prep rc=$rc wall=$(( $(date +%s) - t0 ))s budget=300s modargs='$modargs' build=$(grep -ao 'build [0-9A-F]*' "$D/prep.out" | tail -1)"
    [ "$rc" = 0 ] || { echo "  LEG $name NOT RUN: prep rc=$rc"; return 1; }
    if [ "$name" = S ]; then
        out=$(timeout 30 $SSH test2 "cat /sys/module/mxfs/parameters/closure_skip_publisher_purge 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
        echo "  STAGE readback closure_skip_publisher_purge(test2)=${out:-?}"
        [ "$out" = 1 ] || { echo "  LEG $name NOT RUN: fault injection not armed on the fleet"; return 1; }
    fi

    since=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
    if [ "$name" = Z ] || [ "$name" = S ]; then
        # sess492: leg Z pins the victim UNDER the lock.  Nothing is injected
        # now; the one-shot module parameter arms mxfs_sb_summary_final_sync
        # to commit the unheld-AG image after it has taken the SB summary lock
        # and before its quiesce (P487-INJECT-UNDER-LOCK).  The pre-unmount
        # injector of legs X/Y is always caught before the lock by the
        # fail-stop, so it cannot measure the under-lock bound; this can.
        local first_ag; first_ag=$(echo $AGS | awk '{print $1}')
        out=$(timeout 30 $SSH "$V" "if echo $first_ag > /sys/module/mxfs/parameters/dbg_sb_inject_unheld_agno 2>/dev/null; then echo ARM_OK=\$(cat /sys/module/mxfs/parameters/dbg_sb_inject_unheld_agno); else echo ARM_RC=\$?; fi" 2>/dev/null)
        echo "  STAGE arm_under_lock victim=$V agno_from=$first_ag $(echo "$out" | grep -ao 'ARM_[A-Z]*=[0-9-]*' | head -1) wall=$(( $(date +%s) - t0 ))s"
        case "$out" in *ARM_OK=$first_ag*) injected="under-lock>=$first_ag";; *) echo "  LEG $name NOT RUN: could not arm dbg_sb_inject_unheld_agno on $V"; return 1;; esac
    else
    d=$(timeout 30 $SSH "$V" "ls -d /sys/kernel/debug/mxfs/*/ 2>/dev/null | head -1" 2>/dev/null | tr -d '[:space:]')
    [ -n "$d" ] || { echo "  LEG $name NOT RUN: no /sys/kernel/debug/mxfs/<dev>/ on $V"; return 1; }
    for ag in $AGS; do
        out=$(timeout 30 $SSH "$V" "if echo $ag > ${d}inject_unheld_agmeta_dirty 2>/dev/null; then echo INJ_OK=$ag; else echo INJ_RC=\$?; fi" 2>/dev/null)
        tried="$tried $ag:$(echo "$out" | grep -ao 'INJ_[A-Z]*=[0-9]*' | head -1)"
        case "$out" in *INJ_OK*) injected=$ag; break;; esac
    done
    echo "  STAGE inject victim=$V ag=${injected:-NONE} tried=$tried wall=$(( $(date +%s) - t0 ))s"
    [ -n "$injected" ] || { echo "  LEG $name NOT RUN: no unheld AG accepted the injection"; return 1; }
    # let xfsaild refuse it at least once before the fleet moves (one push cycle)
    sleep 2
    fi

    # the mass unmount, every node at once, each timed on the node itself
    t0=$(date +%s)
    for n in $(nodes); do
        ( timeout 90 $SSH "$n" "t=\$(date +%s%3N); timeout 60 umount $MNT; rc=\$?; echo UMOUNT_RC=\$rc UMOUNT_MS=\$(( \$(date +%s%3N) - t ))" > "$D/umount_$n.txt" 2>&1 ) &
    done
    # sess490: WHERE does the victim's umount wait?  s490c showed the pinned
    # node parked ~8 s before the SB summary lock on BOTH builds (it never
    # took the lock), so the wait site is what separates X from Y.  Sample
    # the umount task's kernel stack twice while it is parked (pgrep -x
    # matches comm only: safe).
    ( sleep 3; for s in 1 2; do timeout 20 $SSH "$V" "for p in \$(pgrep -x umount); do echo \"STACK t=\$(date +%T) pid=\$p\"; cat /proc/\$p/stack 2>/dev/null; done" 2>/dev/null; sleep 3; done > "$D/victim_umount_stack.txt" ) &
    # sess492: the umount task waits in flush_workqueue(m_mxfs_inode_bast_wq)
    # (s490i, both builds) — name the work it waits on.  Kernel-thread stacks
    # only, chosen by comm (/proc/<pid>/comm and /proc/<pid>/stack are safe to
    # read on a wedged task; cmdline is not), kept if they mention mxfs/xfs.
    ( sleep 4; for s in 1 2; do timeout 25 $SSH "$V" "for c in /proc/[0-9]*/comm; do p=\${c#/proc/}; p=\${p%/comm}; case \$(cat \$c 2>/dev/null) in kworker*|xfsaild*|mxfs*) st=\$(cat /proc/\$p/stack 2>/dev/null); case \$st in *mxfs*|*xfs_*) echo \"KSTACK t=\$(date +%T) pid=\$p comm=\$(cat \$c)\"; echo \"\$st\";; esac;; esac; done" 2>/dev/null; sleep 3; done > "$D/victim_kworker_stacks.txt" ) &
    # sess492 leg Z: 7 of 31 PEERS never returned from their umount within
    # the 90 s ssh budget after the victim had released the lock at ~grace,
    # and nothing named where they waited.  Sample every peer's umount task
    # stack at +15/+30/+50 s (pgrep -x = comm match, safe) so a stalled peer
    # is caught while it is stalled.
    ( for s in 15 15 20; do sleep $s; for n in $(nodes); do [ "$n" = "$V" ] && continue; ( timeout 15 $SSH "$n" "for p in \$(pgrep -x umount); do echo \"PSTACK node=$n t=\$(date +%T) pid=\$p\"; cat /proc/\$p/stack 2>/dev/null; done" 2>/dev/null ) & done; wait; done > "$D/peer_umount_stacks.txt" ) &
    wait
    echo "  PEER umount stack samples: $(grep -ac '^PSTACK' "$D/peer_umount_stacks.txt") nodes_seen=$(grep -a '^PSTACK' "$D/peer_umount_stacks.txt" | grep -ao 'node=[a-z0-9]*' | sort -u | wc -l) top_frames: $(grep -a -A1 '^PSTACK' "$D/peer_umount_stacks.txt" | grep -a '^\[' | awk '{print $2}' | sort | uniq -c | sort -rn | head -4 | awk '{printf "%s x%s ", $2, $1}')"
    local wall=$(( $(date +%s) - t0 ))
    echo "  VICTIM umount stack samples: $(grep -ac '^STACK' "$D/victim_umount_stack.txt") frames=$(grep -avc '^STACK' "$D/victim_umount_stack.txt") top=$(grep -av '^STACK' "$D/victim_umount_stack.txt" | grep -a 'mxfs\|xfs' | head -4 | awk '{print $2}' | tr '\n' ' ')"
    echo "  VICTIM kernel-thread stacks with mxfs frames: $(grep -ac '^KSTACK' "$D/victim_kworker_stacks.txt") ($(grep -a '^KSTACK' "$D/victim_kworker_stacks.txt" | grep -ao 'comm=[^ ]*' | sort | uniq -c | sort -rn | head -4 | awk '{printf "%s x%s ", $2, $1}'))"
    grep -a -A3 '^KSTACK' "$D/victim_kworker_stacks.txt" | grep -a 'mxfs\|xfs_' | awk '{print $2}' | sort | uniq -c | sort -rn | head -6 | sed 's/^/    KFRAME: /'
    echo "  STAGE mass_umount wall=${wall}s budget=90s"
    # per-node table and the peer distribution
    : > "$D/umount_ms.txt"
    for n in $(nodes); do
        rc=$(grep -ao 'UMOUNT_RC=[0-9]*' "$D/umount_$n.txt" | cut -d= -f2); local ms; ms=$(grep -ao 'UMOUNT_MS=[0-9]*' "$D/umount_$n.txt" | cut -d= -f2)
        echo "$n rc=${rc:-NONE} ms=${ms:-?}" >> "$D/umount_ms.txt"
    done
    echo "  VICTIM $V: $(grep "^$V " "$D/umount_ms.txt")"
    grep -v "^$V " "$D/umount_ms.txt" | awk '{split($2,a,"="); split($3,b,"="); if (a[2]=="0") ok++; else bad++; if (b[2] ~ /^[0-9]+$/) v[++k]=b[2]} END{n=asort(v); printf "  PEERS: rc0=%d not_rc0=%d umount_ms n=%d min=%d p50=%d p90=%d max=%d\n", ok+0, bad+0, n, v[1], v[int((n+1)/2)], v[int(n*0.9)], v[n]}'
    grep -v "^$V " "$D/umount_ms.txt" | awk '{split($2,a,"="); if (a[2]!="0") print "    NOT-CLEAN: " $0}' | head -6

    # sweep: the lock/convoy and pin lines, per node, in parallel
    for n in $(nodes); do
        ( timeout 60 $SSH "$n" "journalctl -k --no-pager --since '$since' 2>/dev/null | grep -aE 'P-SB-SUMMARY-|P126-|P128-AILSTUCK|P-INJECT|P487-|P482-UMOUNT-AGREL|P483-AGFREE-WINDOW|P-SB-SEAL|P304-RETIRE|P302-PR-KEY|P277-|P299-|P240-QUAR|domain=|shut down|Shutdown|SHUTDOWN|P-LWEDGE|replay|elected|FENCE|recover|dead-slice|WITHDRAW|FROZEN|hung task|blocked for more|Unmounting|caw_wait|P-LOCKWAIT|P12-'" > "$D/probes_$n.txt" 2>/dev/null ) &
    done
    wait
    local bast=0 lockok=0 refuse=0 pinned=0 shut=0
    for n in $(nodes); do
        bast=$(( bast + $(grep -ac 'P-SB-SUMMARY-BAST' "$D/probes_$n.txt") ))
        lockok=$(( lockok + $(grep -ac 'P-SB-SUMMARY-LOCK .*rc=0' "$D/probes_$n.txt") ))
    done
    refuse=$(grep -ac 'P126-XFSAILD-REFUSE ' "$D/probes_$V.txt"); pinned=$(grep -ac 'P126-AIL-PINNED ' "$D/probes_$V.txt"); shut=$(grep -aciE 'shut ?down' "$D/probes_$V.txt")
    echo "  FLEET: sb_lock_rc0=$lockok/32 sb_bast_refused_total=$bast ; VICTIM: refuse=$refuse pinned=$pinned shutdown_lines=$shut skip=$(grep -ac 'P126-XFSAILD-SKIP-AGMETA' "$D/probes_$V.txt") ailstuck=$(grep -ac 'P128-AILSTUCK iter' "$D/probes_$V.txt")"
    grep -a -m1 'P126-AIL-PINNED ' "$D/probes_$V.txt" | cut -c1-260 | sed 's/^/    /'
    grep -aiE -m1 'shut ?down' "$D/probes_$V.txt" | cut -c1-200 | sed 's/^/    /'
    # the victim's order of events: lock taken before or after the pin?
    grep -aE 'P-SB-SUMMARY-LOCK|P-SB-SUMMARY-UNLOCK|P487-INJECT|P126-AIL-PINNED |P-SB-SEALED|P482-UMOUNT-AGREL' "$D/probes_$V.txt" | cut -c1-140 | sed 's/^/    V: /' | head -8
    echo "  LEG $name SUMMARY: injected_ag=$injected mass_umount_wall=${wall}s sb_bast_refused=$bast victim_lock=$(grep -ac 'P-SB-SUMMARY-LOCK .*rc=0' "$D/probes_$V.txt") victim_unlock=$(grep -ac 'P-SB-SUMMARY-UNLOCK' "$D/probes_$V.txt") under_lock_inject=$(grep -ac 'P487-INJECT-UNDER-LOCK' "$D/probes_$V.txt")"
    if [ "$name" = Z ] || [ "$name" = S ]; then
        # sess493: the D-0487 bar.  Who freed the dead holder's SB summary
        # lock, did every peer depart clean, and did a successor seal with a
        # newer epoch than the victim's grant?
        local cstrip=0 sstrip=0 ooc=0 p277=0 p302=0 sealed=0 quar=0 ptry=0
        for n in $(nodes); do
            cstrip=$(( cstrip + $(grep -ac 'P299-CLOSURE-STRIP' "$D/probes_$n.txt") ))
            sstrip=$(( sstrip + $(grep -ac 'P299-SCRUB-STRIP' "$D/probes_$n.txt") ))
            ooc=$(( ooc + $(grep -ac 'P487-SBSUM-OUT-OF-CLOSURE' "$D/probes_$n.txt") ))
            ptry=$(( ptry + $(grep -ac 'P299-SCRUB-TRY' "$D/probes_$n.txt") ))
            quar=$(( quar + $(grep -ac 'P240-QUAR-IMPORT' "$D/probes_$n.txt") ))
            [ "$n" = "$V" ] && continue
            p277=$(( p277 + $(grep -ac 'P277-' "$D/probes_$n.txt") ))
            p302=$(( p302 + $(grep -ac 'P302-PR-KEY' "$D/probes_$n.txt") ))
            sealed=$(( sealed + $(grep -ac 'P-SB-SEALED' "$D/probes_$n.txt") ))
        done
        local vepoch pmax
        vepoch=$(grep -a 'P-SB-SUMMARY-LOCK .*rc=0' "$D/probes_$V.txt" | grep -ao 'epoch=[0-9]*' | head -1 | cut -d= -f2)
        pmax=$(cat "$D"/probes_test*.txt | grep -v "^$V" | grep -a 'P-SB-SEALED' | grep -ao 'epoch=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
        echo "  LEG $name D0487-BAR: closure_strip=$cstrip scrub_strip=$sstrip sbsum_out_of_closure=$ooc scrub_try=$ptry quar_import=$quar peer_p277=$p277 peer_p302=$p302 peer_sealed=$sealed victim_grant_epoch=${vepoch:-?} peer_seal_epoch_max=${pmax:-?}"
        grep -ah 'P299-CLOSURE-STRIP\|P299-SCRUB-STRIP\|P487-SBSUM-OUT-OF-CLOSURE\|domain=' "$D"/probes_test*.txt | cut -c1-200 | sort | uniq -c | sort -rn | head -8 | sed 's/^/    STRIP: /'
        grep -ah 'P277-\|P302-PR-KEY' "$D"/probes_test*.txt | grep -v "slot=0 " | cut -c1-160 | head -6 | sed 's/^/    PEER-DIRTY: /'
        # sess493 (D-0493): before anyone remounts, record what the LUN holds —
        # every heartbeat record with its identity binding (the frozen
        # checker next to the leg's ko) and the registered PR keys — so the
        # bootstrap's classification can be checked against the platter.
        local CHK=/src/mxfs/tools/chk_mxfs     # the tree build: it reports which flag binding a re-flagged identity validates against
        [ -x "$CHK" ] || CHK="$(dirname "$ko")/tools/chk_mxfs"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
        timeout 90 $SSH test2 "$CHK -v $MXFS_DEV 2>&1 | grep -a 'disklock HB slot\|identity\|GUARD\|RETIRE_PENDING'; echo ===KEYS; (sg_persist --in -k -d $MXFS_DEV 2>&1 || mpathpersist --in -k $MXFS_DEV 2>&1) | head -12; echo ===RECOV; /src/mxfs/tools/recov_forge $MXFS_DEV dump 0 2>&1 | head -12" > "$D/platter_before_remount.txt" 2>/dev/null
        echo "  PLATTER before remount: guard_slots=$(grep -ac 'RECOVERY GUARD' "$D/platter_before_remount.txt") retire_pending=$(grep -ac 'RETIRE_PENDING' "$D/platter_before_remount.txt") identities=$(grep -ac 'identity' "$D/platter_before_remount.txt") keys=$(sed -n '/===KEYS/,/===RECOV/p' "$D/platter_before_remount.txt" | grep -aci '0x')"
        grep -a 'slot 0:\|slot 0 \|GUARD\|ident.*slot 0' "$D/platter_before_remount.txt" | cut -c1-200 | head -4 | sed 's/^/    P: /'
        sed -n '/===KEYS/,/===RECOV/p' "$D/platter_before_remount.txt" | cut -c1-160 | head -6 | sed 's/^/    K: /'
        # remount ONE peer: which slots does that mount fence / recover?
        local R=test2 rsince rwall
        rsince=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
        out=$(timeout 150 $SSH "$R" "timeout 120 mount -t mxfs $MXFS_DEV $MNT && echo MOUNT_OK || echo MOUNT_RC=\$?; timeout 60 umount $MNT; echo UMOUNT_RC=\$?" 2>/dev/null | tr '\n' ' ')
        rwall=$(( $(date +%s) - t0 ))
        timeout 60 $SSH "$R" "journalctl -k --no-pager --since '$rsince' 2>/dev/null | grep -aE 'FENCE|fence|recover|elected|replay|dead-slice|P240-QUAR|domain=|P302-PR-KEY|P277-|P-BOOT-|ADMITTED with AG mask|claimed heartbeat slot|P-PR-DEPARTURE-UNHELD'" > "$D/remount_$R.txt" 2>/dev/null
        echo "  STAGE remount $R $out wall=${rwall}s budget=150s fence_lines=$(grep -aci 'fence' "$D/remount_$R.txt") recover_lines=$(grep -aci 'recover' "$D/remount_$R.txt") slots=$(grep -aoE '(victim|dead|fenc[a-z]*|recover[a-z]*)[ _=-]*slot[= ]*[0-9]+' "$D/remount_$R.txt" | grep -oE '[0-9]+$' | sort -n | uniq | tr '\n' ',')"
        grep -aiE 'fence|recover|elected|replay' "$D/remount_$R.txt" | cut -c1-180 | head -10 | sed 's/^/    REMOUNT: /'
        # sess494 (D-0493 bar): the scan must classify the terminal guard, not
        # refuse on it; the quarantine must be imported BEFORE admission (journal
        # order: P240-QUAR-IMPORT precedes 'mount ADMITTED with AG mask'); the
        # mount must claim a slot other than the guard's, and fence/replay/zero
        # nothing on slot 0.
        local il al
        il=$(grep -an 'P240-QUAR-IMPORT' "$D/remount_$R.txt" | head -1 | cut -d: -f1)
        al=$(grep -an 'ADMITTED with AG mask' "$D/remount_$R.txt" | head -1 | cut -d: -f1)
        echo "  D0493-BAR $R: scan_terminal=$(grep -ac 'P-BOOT-SCAN-TERMINAL' "$D/remount_$R.txt") scan_frozen=$(grep -ac 'P-BOOT-SCAN-FROZEN' "$D/remount_$R.txt") unclassified=$(grep -ac 'P-BOOT-KEY-UNCLASSIFIED' "$D/remount_$R.txt") quar_import=$(grep -ac 'P240-QUAR-IMPORT' "$D/remount_$R.txt") admitted_mask=$(grep -ac 'ADMITTED with AG mask' "$D/remount_$R.txt") import_before_admit=$( [ -n "$il" ] && [ -n "$al" ] && [ "$il" -lt "$al" ] && echo 1 || echo 0 ) claimed_slot=$(grep -ao 'claimed heartbeat slot [0-9]*' "$D/remount_$R.txt" | head -1 | grep -o '[0-9]*$') slot0_fence_or_replay=$(grep -aE 'P238-FENCE-DONE|P-BOOT-REG-FENCE|PREEMPT|elected \(slot|replay of slot [0-9]+ complete|P-BOOT-SEALED' "$D/remount_$R.txt" | grep -ac 'slot[= ]0\b\|slot 0 \|dead node') slot0_death_pipeline=$(grep -ac 'P163-FENCED-SEEN slot=0 \|P-PRKEY-FENCE-REFUSED slot=0 ' "$D/remount_$R.txt") departure_unheld=$(grep -ac 'P-PR-DEPARTURE-UNHELD' "$D/remount_$R.txt")"
        grep -a 'P-BOOT-SCAN\|P240-QUAR-IMPORT\|ADMITTED with AG mask\|claimed heartbeat slot' "$D/remount_$R.txt" | cut -c1-220 | head -6 | sed 's/^/    BOOT: /'
        # then every node: each must mount, import the same AG mask before its
        # admission, and claim a slot other than the guard's.  Per-node output,
        # per-node rc, inner timeout (fleet sweep rule).  Budget: the survivor
        # scan waits one dead window (~62 s) when the table is frozen; the first
        # claim moves it and the rest take the ordinary path -> 150 s inner.
        local fsince fw=0 fm=0 fi=0 fa=0 fo=0 fs0=0 fu=0
        fsince=$(date -u +'%Y-%m-%d %H:%M:%S'); t0=$(date +%s)
        for n in $(nodes); do
            ( timeout 200 $SSH "$n" "echo D0493-FLEET-$LABEL > /dev/kmsg; timeout 150 mount -t mxfs $MXFS_DEV $MNT && echo MOUNT_OK || echo MOUNT_RC=\$?; journalctl -k --no-pager --since '$fsince' 2>/dev/null | grep -aE 'P240-QUAR-IMPORT|ADMITTED with AG mask|P-BOOT-SCAN|P-BOOT-KEY-UNCLASSIFIED|claimed heartbeat slot|elected|replay of slot|FENCE'" > "$D/fleet_remount_$n.txt" 2>&1 ) &
        done
        wait
        fw=$(( $(date +%s) - t0 ))
        for n in $(nodes); do
            grep -aq 'MOUNT_OK' "$D/fleet_remount_$n.txt" && fm=$((fm + 1))
            grep -aq 'P240-QUAR-IMPORT' "$D/fleet_remount_$n.txt" && fi=$((fi + 1))
            grep -aq 'ADMITTED with AG mask' "$D/fleet_remount_$n.txt" && fa=$((fa + 1))
            il=$(grep -an 'P240-QUAR-IMPORT' "$D/fleet_remount_$n.txt" | head -1 | cut -d: -f1)
            al=$(grep -an 'ADMITTED with AG mask' "$D/fleet_remount_$n.txt" | head -1 | cut -d: -f1)
            [ -n "$il" ] && [ -n "$al" ] && [ "$il" -lt "$al" ] && fo=$((fo + 1))
            grep -ao 'claimed heartbeat slot [0-9]*' "$D/fleet_remount_$n.txt" | grep -q 'slot 0$' && fs0=$((fs0 + 1))
            grep -aq 'P-BOOT-KEY-UNCLASSIFIED' "$D/fleet_remount_$n.txt" && fu=$((fu + 1))
        done
        echo "  STAGE fleet_remount wall=${fw}s budget=200s mounted=$fm/32 quar_import=$fi/32 admitted_mask=$fa/32 import_before_admit=$fo/32 slot0_claimed=$fs0 unclassified=$fu ag_masks=$(grep -aho 'ag_mask=0x[0-9a-f]*' "$D"/fleet_remount_test*.txt | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
        grep -aL 'MOUNT_OK' "$D"/fleet_remount_test*.txt | head -5 | sed 's/^/    NOT-MOUNTED: /'
        for n in $(nodes); do
            ( timeout 90 $SSH "$n" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?" > "$D/fleet_umount_$n.txt" 2>&1 ) &
        done
        wait
        echo "  STAGE fleet_umount rc0=$(grep -al 'UMOUNT_RC=0' "$D"/fleet_umount_test*.txt | wc -l)/32"
    fi
}

{
  echo "=== sess488 ailpin_fleet_umount START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) LEGS='$LEGS' KO_X=$KO_X KO_Y=$KO_Y V=$V GRACE_MS=$GRACE_MS ==="
  gate_dl=$(( $(date +%s) + 21600 ))
  while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
      [ "$(date +%s)" -ge "$gate_dl" ] && { echo "ABORT: gate $GATE never reached DONE within 6 h"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
      sleep 30
  done
  echo "STAGE gate cleared: $GATE"
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  for l in $LEGS; do
      case "$l" in
          X) leg X "$KO_X" ;;
          Y) leg Y "$KO_Y" ;;
          Z) leg Z "$KO_Z" ;;
          S) leg S "$KO_Z" ;;
          *) echo "ABORT: unknown leg $l" ;;
      esac
  done
  echo "--- VERDICT ---"
  echo "  X (0.70.0, fail-stop only): peers expected to stall up to ~grace behind the victim's lock (sb_bast_refused>0, peer p50 near ${GRACE_MS} ms), all 32 umounts return."
  echo "  Y (0.70.1, pre-lock push): sb_bast_refused=0 and peer umount_ms at the normal ~1 s while the victim alone shuts down; the victim's P126-AIL-PINNED must precede its P-SB-SUMMARY-LOCK line or that line must be absent."
  echo "  Z (under-lock pin, 0.70.6+): the victim takes the lock (victim_lock=1), P487-INJECT-UNDER-LOCK rc=0, then P126-AIL-PINNED at ~grace, the shutdown, and P-SB-SUMMARY-UNLOCK (victim_unlock=1) — the lock is held for at most ~grace + one push cycle; peers all return (rc0=31) with umount_ms max <= ~grace + 2 s. A victim that never unlocks, or a peer umount that exceeds the 60 s inner timeout, is the defect unbounded."
  echo "  Z/S on 0.70.10 (D-0487 bar): the victim shuts down at grace with no seal; closure_strip (Z) or scrub_strip (S) >= 1 and sbsum_out_of_closure >= 1; PEERS rc0=31 with umount_ms max bounded by grace + fence + verdict; peer_p277=0 peer_p302=0; peer_sealed >= 1 with peer_seal_epoch_max > victim_grant_epoch; quar_import >= 1; the remount fences/recovers slot 0 only."
  echo "  Z on 0.70.12 (D-0493 bar): remount MOUNT_OK with scan_terminal>=1 unclassified=0 quar_import>=1 admitted_mask=1 import_before_admit=1 claimed_slot!=0 slot0_fence_or_replay=0 (slot0_death_pipeline>0 is the monitor declaring the certified death and REFUSING to fence with no key — expected); fleet_remount mounted=31/32: a 32-slice volume with one slot under a terminal verdict has 31 usable members (the 32nd refuses P300-CLAIM-EXHAUSTED / P300-CLAIM-QUARANTINE, by design until operator repair), import_before_admit=31/32 slot0_claimed=0 unclassified=0; fleet_umount rc0=31/32."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
