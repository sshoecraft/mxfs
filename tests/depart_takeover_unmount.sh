#!/bin/bash
# depart_takeover_unmount.sh — a node unmounts while its departure worker is
# still taking over a dead authority's ledger pages.  Does it leave cleanly,
# or die?  (D-0953)
#
# THE SHAPE (DEATH=ghost, default — the one the crash was captured in).  A
# node's ledger pages stay under its own authority when it unmounts as the
# LAST member (nobody to hand them to).  When it mounts again, alone, its
# previous incarnation is a dead authority holding every page it served, and
# the settle's takeover-only pass takes them over on the departure worker
# (P-SETTLED-INCARNATION then P-TAUTH-PAGE-MINE via=takeover; the orphan
# sweep queued after it takes whatever else is dead): one durable prepare and
# one durable activate per page, ~15-30 ms each.  While that pass is in
# flight the node is unmounted.  This is the s574xm shape: the sole
# survivor's across-mount remount, then its unmount, with the worker at page
# 9569 of its ghost's pages when the teardown freed the array under it.
#
# THE AUTHORITY IS BUILT UNDER GRANTS, WITH BOTH NODES MOUNTED.  The ledger
# records grants; a lone mount modifies everything at NL with no grant and
# writes no record.  The s588 laps got their ~15k-page pass from an aged
# ledger's residue, not from the creates: on a freshly prepared filesystem
# the original ordering (B leaves, THEN A creates) left the pass 10 pages
# (s67l, 0.89.4: P-TAUTH-TAKEOVER cand=10, done in 2.7 s, the unmount could
# not be issued inside it).  So A creates while B is still a member (each
# create takes its inode's grant at whichever node masters it, ~14 ms), B's
# clean departure hands B's pages to A, and A's last-member unmount keeps
# them all: measured ~NFILES/8 pages (s67m, join_during_takeover: 496 pages
# from 4000 files), a pass of ~30 ms a page.
#
# DEATH=destroy is the other shape a takeover has: a peer virsh-destroyed mid
# authority.  MEASURED s588a (0.84.3, 16000 files): that takeover runs INSIDE
# the peer's recovery, and put_super waits for the recovery to complete before
# the DLM teardown begins, so the unmount takes the whole pass (105 s) and the
# interruption path is never reached.  The arm is kept as the regression
# check of that ordering; it cannot exercise the fix.
#
# What happened before the fix (netconsole, s574xm, 0.75.128): the teardown
# joined the worker for 30 s, printed P-DEPART-WORKER-STUCK ("quarantined,
# nothing it can reach is freed"), then destroyed the engine, closed the
# ledger and freed the context anyway; the worker's next page_state store
# faulted on the freed array (RIP dlm_page_now_mine, page 9569) and the node
# panicked and rebooted.  A store that lands inside another allocation instead
# of on an unmapped page is the same bug without the panic.
#
# After the fix (0.84.3): the engine's shutting_down flag stops the pass
# BETWEEN pages (P-TAUTH-ORPHAN-SWEEP-INTERRUPTED / P-TAUTH-TAKEOVER-INTERRUPTED
# naming the page reached and the candidates remaining), the worker refuses
# new work, and the unmount joins it without bound; nothing the worker reaches
# is freed before it returns.  The pages not reached stay under the dead
# authority until the next bootstrap node's orphan sweep, which the re-form at
# the end of this lap exercises: A mounts first and must log
# P-TAUTH-ORPHAN-SWEEP taking them, and both nodes must then read the
# directory that was built, within a bound.
#
# THE FALSE PASSES THIS LAP GUARDS AGAINST: an unmount that starts after the
# pass has finished measures nothing, so the lap requires the pass to be in
# flight (per-page activations still arriving) when the unmount is issued and,
# on the fixed build, requires the interruption line to report pages
# remaining.  A node that "did not panic" because the freed memory happened to
# stay mapped is caught by the same line: the old build never prints it.
#
# the budget rule (derived), ghost arm: creates NFILES x 14 ms measured under
# two members (bound NFILES/25 + 60 s) + B's unmount handing ~NFILES/16 pages
# to A (9.3 s for 4000 files, s67m; bound 120 s) + A's last-node unmount
# (pages stay, ~10 s, bound 180 s) + A's lone mount (bound 180 s) + the pass's
# settle wait (<= 60 s) and in-flight detection (bound 240 s from the mount)
# + unmount (fixed: one page + one scan, bound 150 s; old build: 30 s join then
# panic) + A reboot (old build, bound 180 s) + re-form
# (scripts/module_swap_deploy.sh, its own bounds, <= 480 s) + directory reads
# (bound 90 s each).  Destroy arm: as before — creates + death detection ~62 s +
# fence/replay ~25 s + in-flight wait (240 s from the destroy) + unmount + B
# boot (bound 180 s) + re-form + reads.
#
# Usage: tests/depart_takeover_unmount.sh <label> [A=test1] [B=test2]
# Env:   NFILES (default 16000: ~2000 pages, a pass of ~1 min; the in-flight
#        detection needs >= 50 activations across two 5 s samples and the
#        unmount must land with pages remaining, so NFILES >= 8000), MXFS_MNT
#        (default /mnt/shared), DEATH=ghost|destroy (default ghost),
#        EXPECT=observe|panic|clean (default observe).  "panic" asserts the
#        defect as measured on the old build; "clean" asserts the fix.
# Leaves both nodes mounted (re-formed in place, filesystem untouched).
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
A=${2:-test1}; B=${3:-test2}
NFILES=${NFILES:-16000}
EXPECT=${EXPECT:-observe}
DEATH=${DEATH:-ghost}
case "$EXPECT" in observe|panic|clean) ;; *) echo "ABORT: EXPECT must be observe, panic or clean"; exit 2;; esac
case "$DEATH" in ghost|destroy) ;; *) echo "ABORT: DEATH must be ghost or destroy"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
VIRSH="sudo virsh -c qemu:///system"
NCLOG=tests/evidence/netconsole.log
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_departtk_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
# The device the cluster was formed on, for the lone remount of the ghost arm.
DEV=${MXFS_DEV:-$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("dev",""))
except Exception:
    print("")' .cluster_marker.json 2>/dev/null)}
[ -n "$DEV" ] || { echo "ABORT: no device: set MXFS_DEV or form the cluster first (.cluster_marker.json has no dev)"; exit 2; }

echo "=== depart_takeover_unmount label=$LABEL A=$A B=$B nfiles=$NFILES death=$DEATH expect=$EXPECT out=$OUT $(date -u +%FT%TZ) ==="
# The fleet must be on ONE build.  The clean arm must be on the tree's build;
# the panic arm measures the build the fleet is running (the tree may already
# hold the fix), so it only records which.  The re-form at the end deploys the
# tree's build either way.
SVA=""; SVB=""
for n in "$A" "$B"; do
    info=$(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) m=\$(grep -c ' mxfs ' /proc/mounts) boot=\$(cat /proc/sys/kernel/random/boot_id)")
    echo "  INFO $n $info (tree sv=$TREESV)"
    [[ "$info" == *"m=1"* ]]        || { echo "ABORT: $n not mounted ($info)"; exit 2; }
    sv=$(echo "$info" | grep -ao 'sv=[0-9A-F]*' | cut -d= -f2)
    [ "$n" = "$A" ] && SVA=$sv || SVB=$sv
done
[ "$SVA" = "$SVB" ] || { echo "ABORT: $A and $B run different builds ($SVA vs $SVB)"; exit 2; }
if [ "$EXPECT" = "clean" ] && [ "$SVA" != "$TREESV" ]; then
    echo "ABORT: EXPECT=clean needs the fleet on the tree's build ($SVA != $TREESV)"; exit 2
fi
echo "  INFO fleet build under test: $SVA"
BOOT_A=$(rs 15 "$A" "cat /proc/sys/kernel/random/boot_id")
tools/netconsole_listen.sh status 2>&1 | grep -q running || { echo "ABORT: the netconsole listener is not running (tools/netconsole_listen.sh start)"; exit 2; }
NC_BEFORE=$(wc -l < "$NCLOG")
MARK="DEPARTTK-$LABEL-$$"
rs 15 "$A" "echo '$MARK' > /dev/kmsg" >/dev/null
# A's kernel log is followed into a file from the marker on: the pass prints
# one line per page and the ring alone would roll the marker and the recovery
# lines away.
rs 20 "$A" "rm -f /tmp/departtk_dmesg.txt; nohup sh -c 'dmesg --follow' > /tmp/departtk_dmesg.txt 2>&1 & echo started" >/dev/null
DMA="awk '/$MARK/{f=1} f' /tmp/departtk_dmesg.txt"
D=$MNT/.departtk_$LABEL
cb=$(( NFILES / 25 + 60 ))

if [ "$DEATH" = "ghost" ]; then
    # 1g. The authority: NFILES creates in one directory on A while BOTH
    #     nodes are members, so every create takes its inode's grant and the
    #     ledger records it (a lone mount records nothing — see the header).
    rs "$cb" "$A" "mkdir -p '$D' && i=0; s=\$(date +%s%N); while [ \$i -lt $NFILES ]; do : > '$D/f'\$i || break; i=\$((i+1)); done; sync; e=\$(date +%s%N); echo CREATED=\$i ms=\$(( (e-s)/1000000 ))" > "$OUT/create.txt"
    created=$(grep -ao 'CREATED=[0-9]*' "$OUT/create.txt" | cut -d= -f2)
    echo "  INFO A created ${created:-0}/$NFILES files under two members: $(tr '\n' ' ' < "$OUT/create.txt") at +$(el)s"
    [ "${created:-0}" = "$NFILES" ] || { echo "ABORT: A created ${created:-0}/$NFILES inside $cb s"; exit 2; }
    # 2g. B leaves, cleanly, so A is the last member: B's departure hands the
    #     pages B masters to A (P-TAUTH-HANDOFF, ~NFILES/16 pages), and what A
    #     serves stays A's when A unmounts.
    bu=$(rs 120 "$B" "s=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo B_UMOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "  INFO B unmounted after the creates: ${bu:-no result} at +$(el)s"
    [[ "$bu" == *"B_UMOUNT_RC=0"* ]] || { echo "ABORT: B's unmount did not return 0 ($bu)"; exit 2; }
    handed=$(rs 20 "$A" "$DMA | grep -a 'P-TAUTH-PAGE-MINE' | grep -ao 'via=[a-z-]*' | sort | uniq -c | tr '\n' ' '")
    echo "  INFO A's page activations since the marker (B's departure hand-off among them): [${handed:-none}] at +$(el)s"
    # 3g. A unmounts as the last member: its pages stay under its authority
    #     (mxfs_dlm_handoff_depart: "last node: the pages stay ours").
    au=$(rs 180 "$A" "s=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo A_UMOUNT1_RC=\$rc ms=\$(( (e-s)/1000000 )); grep -c ' mxfs ' /proc/mounts")
    echo "  INFO A's last-member unmount: $(echo "$au" | tr '\n' ' ') at +$(el)s"
    [[ "$au" == *"A_UMOUNT1_RC=0"* ]] || { echo "ABORT: A's first unmount did not return 0 ($au)"; exit 2; }
    left=$(rs 20 "$A" "$DMA | grep -a 'P-TAUTH-DEPART node' | tail -1")
    echo "  INFO A's departure line at that unmount: [${left:-none}] (absent = last node, pages kept)"
    # The followed log on A survives the unmount (no module reload), so the
    # settle and takeover-only lines of the remount land in the same file.
    # 4g. A mounts again, alone: its previous incarnation is now a dead
    #     authority holding every page, and the bootstrap orphan sweep on the
    #     departure worker takes them over, page by page.
    am=$(rs 180 "$A" "s=\$(date +%s%N); mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%N); echo A_MOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "  INFO A's lone remount: ${am:-no result} at +$(el)s"
    [[ "$am" == *"A_MOUNT_RC=0"* ]] || { echo "ABORT: A's lone remount did not return 0 ($am)"; exit 2; }
    tdie=$(date +%s)
    # The remount settles its own predecessor's heartbeat record and queues
    # a takeover-only named takeover of that incarnation's pages on the
    # worker (v5_settled_incarnation: P-SETTLED-INCARNATION then
    # P-DEPART-TAKEOVER-ONLY, activations via=takeover — the s574xm stack,
    # v5_depart_run -> v5_handoff_takeover); the orphan sweep queued after
    # it takes whatever else is dead.  Whichever is in flight at the unmount
    # is the pass under test.
    VIA='\(takeover\|orphan-sweep\)'
    INTR_PAT='P-TAUTH-TAKEOVER-INTERRUPTED\|P-TAUTH-ORPHAN-SWEEP-INTERRUPTED'
else
    # 1. B builds its authority: NFILES creates in one directory.
    rs "$cb" "$B" "mkdir -p '$D' && i=0; s=\$(date +%s%N); while [ \$i -lt $NFILES ]; do : > '$D/f'\$i || break; i=\$((i+1)); done; sync; e=\$(date +%s%N); echo CREATED=\$i ms=\$(( (e-s)/1000000 ))" > "$OUT/create.txt"
    created=$(grep -ao 'CREATED=[0-9]*' "$OUT/create.txt" | cut -d= -f2)
    echo "  INFO B created ${created:-0}/$NFILES files: $(tr '\n' ' ' < "$OUT/create.txt") at +$(el)s"
    [ "${created:-0}" = "$NFILES" ] || { echo "ABORT: B created ${created:-0}/$NFILES inside $cb s"; exit 2; }
    # 2. B dies.
    $VIRSH destroy "$B" > "$OUT/virsh_destroy.txt" 2>&1; echo "  INFO virsh destroy $B rc=$? at +$(el)s"
    tdie=$(date +%s)
    VIA=takeover
    INTR_PAT='P-TAUTH-TAKEOVER-INTERRUPTED'
fi

# 3. The pass.  Destroy arm: A recovers B and the takeover runs INSIDE the
#    recovery (s587a: 3776 pages in 62 s, finished before P163-RECOVERY-COMPLETE
#    was printed), so it is watched for from the destroy onward.  Ghost arm:
#    the orphan sweep is queued at the mount's settle (<= 60 s) and its
#    activations say via=orphan-sweep.  "In flight" means the per-page
#    activation count GREW between two samples five seconds apart and is
#    already past a floor: one sample proves only that a pass happened, not
#    that it is still running.
abort_restart_b() {
    echo "ABORT: $1"
    if [ "$DEATH" = "destroy" ]; then
        $VIRSH start "$B" > "$OUT/virsh_start_abort.txt" 2>&1
        echo "  INFO $B restarted after the abort (rc=$?); re-form the cluster before the next lap"
    else
        echo "  INFO re-form the cluster before the next lap (scripts/module_swap_deploy.sh 2 tcp)"
    fi
    exit 2
}
mine0=0; mine1=0; inflight=0
for i in $(seq 1 48); do
    sleep 5
    c=$(rs 20 "$A" "$DMA | grep -ac 'P-TAUTH-PAGE-MINE page=[0-9]* via=$VIA'")
    c=${c:-0}
    if [ "$c" -ge 50 ] && [ "$mine0" -ge 1 ] && [ "$c" -gt "$mine0" ]; then mine1=$c; inflight=1; break; fi
    mine0=$c
done
measure "$A" 20 "$OUT/rv_recov_1.txt" '^READ_RC=[0-9]+$' "recov on $A" "$DMA | grep -a 'P163-RECOVERY-COMPLETE' | head -1; printf '\nREAD_RC=%s\n' \$?"; recov=$(grep -av '^READ_RC=' "$OUT/rv_recov_1.txt")
echo "  INFO $VIA pass: activations_so_far=$mine1 (previous sample $mine0) in_flight=$inflight ($(( $(date +%s) - tdie )) s after the $DEATH) at +$(el)s"
[ "$DEATH" = "destroy" ] && echo "  INFO recovery-complete line at that moment: [${recov:-not yet}]"
if [ "$inflight" != "1" ]; then
    done_line=$(rs 20 "$A" "$DMA | grep -a 'P-TAUTH-TAKEOVER departed\|P-TAUTH-ORPHAN-SWEEP by' | tail -1")
    abort_restart_b "the $VIA pass was not seen in flight (activations=$mine0; ${done_line:-no summary line}) — the unmount would measure nothing"
fi

# 4. A unmounts INSIDE the pass.  Detached with a done marker: on the old
#    build the node reboots under it and the ssh session dies.
rs 20 "$A" "rm -f /tmp/departtk_um.done; nohup sh -c 's=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo rc=\$rc ms=\$(( (e-s)/1000000 )) > /tmp/departtk_um.done' >/dev/null 2>&1 &" >/dev/null
tum=$(date +%s)
um=""; rebooted=0; live_stuck=0; live_intr=""
for i in $(seq 1 30); do
    sleep 5
    # Sampled while A is alive: on the old build the STUCK line is printed
    # 30 s into the unmount and the panic follows ~15 s later, taking the
    # followed log with it; the netconsole carries only emergency-level
    # lines, and this one is not.
    s=$(rs 15 "$A" "echo stuck=\$($DMA | grep -ac 'P-DEPART-WORKER-STUCK'); $DMA | grep -a '$INTR_PAT' | head -1")
    n=$(echo "$s" | grep -ao 'stuck=[0-9]*' | cut -d= -f2); [ "${n:-0}" -gt "$live_stuck" ] && live_stuck=$n
    l=$(echo "$s" | grep -a 'INTERRUPTED'); [ -n "$l" ] && live_intr=$l
    measure "$A" 15 "$OUT/rv_um_2.txt" '^READ_RC=[0-9]+$' "um on $A" "cat /tmp/departtk_um.done 2>/dev/null; printf '\nREAD_RC=%s\n' \$?"; um=$(grep -av '^READ_RC=' "$OUT/rv_um_2.txt")
    [ -n "$um" ] && break
    b=$(rs 15 "$A" "cat /proc/sys/kernel/random/boot_id")
    if [ -n "$b" ] && [ "$b" != "$BOOT_A" ]; then rebooted=1; break; fi
done
# A store that lands after the teardown returns would panic AFTER the
# unmount reported success; look again before believing the marker.
if [ "$rebooted" = "0" ]; then
    sleep 15
    b=$(rs 15 "$A" "cat /proc/sys/kernel/random/boot_id")
    [ -n "$b" ] && [ "$b" != "$BOOT_A" ] && rebooted=1
fi
um_wall=$(( $(date +%s) - tum ))
echo "  INFO unmount of $A: ${um:-no result} rebooted=$rebooted poll_wall=${um_wall}s at +$(el)s"
um_rc=$(echo "$um" | grep -ao 'rc=[0-9]*' | cut -d= -f2)
um_ms=$(echo "$um" | grep -ao 'ms=[0-9]*' | cut -d= -f2)

# 5. Evidence.  A's followed log (if A is alive) and the host's netconsole
#    capture (new lines only).
if [ "$rebooted" = "0" ]; then
    rs 30 "$A" "$DMA" > "$OUT/dmesg_A_followed.txt"
    rs 30 "$A" "dmesg" > "$OUT/dmesg_A_ring.txt"
fi
tail -n +$(( NC_BEFORE + 1 )) "$NCLOG" > "$OUT/netconsole_new.txt"
stuck=$(grep -ac 'P-DEPART-WORKER-STUCK' "$OUT/dmesg_A_followed.txt" "$OUT/netconsole_new.txt" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
[ "$live_stuck" -gt "$stuck" ] && stuck=$live_stuck
slow=$(grep -ac 'P-DEPART-WORKER-SLOW' "$OUT/dmesg_A_followed.txt" 2>/dev/null); slow=${slow:-0}
intr=$(grep -a "$INTR_PAT" "$OUT/dmesg_A_followed.txt" 2>/dev/null | head -1)
[ -z "$intr" ] && intr=$live_intr
intr_remaining=$(echo "$intr" | grep -ao 'remaining=[0-9]*' | cut -d= -f2)
intr_page=$(echo "$intr" | grep -ao 'at_page=[0-9]*' | cut -d= -f2)
intr_done=$(echo "$intr" | grep -ao 'prepared=[0-9]*' | head -1 | cut -d= -f2)
refused=$(grep -ac 'P-DEPART-WORK-REFUSED' "$OUT/dmesg_A_followed.txt" 2>/dev/null); refused=${refused:-0}
complete=$(grep -ac 'DLM shutdown complete' "$OUT/dmesg_A_followed.txt" 2>/dev/null); complete=${complete:-0}
bug=$(grep -ac 'BUG: unable to handle\|Oops:\|RIP: 0010:dlm_page_now_mine\|Kernel panic' "$OUT/netconsole_new.txt")
mine_total=$(grep -ac "P-TAUTH-PAGE-MINE page=[0-9]* via=$VIA" "$OUT/dmesg_A_followed.txt" 2>/dev/null); mine_total=${mine_total:-0}
depart_work=$(grep -a 'P-DEPART-WORK node\|P-DEPART-WORK-ORPHAN-SWEEP' "$OUT/dmesg_A_followed.txt" 2>/dev/null | tail -1 | cut -c1-200)
echo "  INFO A: stuck=$stuck slow=$slow refused=$refused shutdown_complete=$complete activations_total=$mine_total"
echo "  INFO A interrupted: [${intr:-none}]"
echo "  INFO A depart-work: [${depart_work:-none}]"
echo "  INFO netconsole new lines=$(wc -l < "$OUT/netconsole_new.txt") crash_lines=$bug"

# 6. If A rebooted, wait for it to come back.
if [ "$rebooted" = "1" ]; then
    back=0
    for i in $(seq 1 36); do
        sleep 5
        b=$(rs 15 "$A" "cat /proc/sys/kernel/random/boot_id")
        [ -n "$b" ] && [ "$b" != "$BOOT_A" ] && { back=1; break; }
    done
    echo "  INFO $A back after the reboot: $back at +$(el)s"
fi

# 7. Recovery: the cluster is re-formed in place (A mounts first, as the
#    bootstrap node, and its orphan sweep must take the pages the interrupted
#    pass left), then both nodes read the directory that was built.
if [ "$DEATH" = "destroy" ]; then
    $VIRSH start "$B" > "$OUT/virsh_start.txt" 2>&1; echo "  INFO virsh start $B rc=$? at +$(el)s"
    bup=0
    for i in $(seq 1 36); do
        sleep 5
        u=$(rs 15 "$B" "uptime -s 2>/dev/null | head -1")
        [ -n "$u" ] && { bup=1; break; }
    done
    echo "  INFO $B ssh back: $bup at +$(el)s"
    sleep 20    # pam nologin lifts a few seconds after ssh answers
fi
MARK2="DEPARTTK2-$LABEL-$$"
rs 15 "$A" "echo '$MARK2' > /dev/kmsg" >/dev/null
# B joins only after A's sweep has taken the pages the interrupted pass left:
# a joiner that mounts INSIDE that sweep exhausts its root-inode lock retries
# on remaster, shuts its filesystem down and withdraws (s588c) — a defect of
# its own, recorded in the queue, and not the one this lap measures.  Bound:
# the settle's own takeover (<= the pages the pass activated) + settle wait
# + the sweep of the remainder: ~10 ms a page on an aged ledger (14978 pages
# = 157 s, s588c), ~30 ms a page under grants (s68a, 0.89.5: 9329 pages,
# the 320 s bound of NFILES/40+120 expired before the summary and B joined
# inside the sweep) — so NFILES/20 + 120 s.
MXFS_JOIN_WAIT_PATTERN='P-TAUTH-ORPHAN-SWEEP by' MXFS_JOIN_WAIT_S=$(( NFILES / 20 + 120 )) \
    scripts/module_swap_deploy.sh 2 tcp > "$OUT/reform.txt" 2>&1; reform_rc=$?
echo "  INFO $(grep -a 'join wait' "$OUT/reform.txt" | head -1)"
echo "  INFO re-form rc=$reform_rc: $(grep -a 'SWAP_OK\|FAIL\|bad nodes' "$OUT/reform.txt" | head -2 | tr '\n' ' ') at +$(el)s"
# The sweep runs on the worker after the settle's own takeover of the
# previous incarnation's pages (up to the pages that pass activated, ~16 ms
# each) and the settle wait (<= 60 s): bound 300 s before its summary.
sweep=""
for i in $(seq 1 60); do
    sweep=$(rs 20 "$A" "dmesg | awk '/$MARK2/{f=1} f' | grep -a 'P-TAUTH-ORPHAN-SWEEP by'")
    [ -n "$sweep" ] && break
    sleep 5
done
# Every departure queues a sweep, so the first (full) sweep is followed by an
# empty one two seconds later (s588d: prepared=14995 then prepared=0); the
# pages taken are the SUM over the sweeps of this re-form, never the last
# line.  The settle's own takeover of the interrupted incarnation's pages
# (P-TAUTH-TAKEOVER pages_prepared=) is reported beside it.
sweep_prepared=$(echo "$sweep" | grep -ao ' prepared=[0-9]*' | cut -d= -f2 | awk '{s+=$1} END{print s+0}')
sweep_dead=$(echo "$sweep" | grep -ao 'dead=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
settle_tk=$(rs 20 "$A" "dmesg | awk '/$MARK2/{f=1} f' | grep -a 'P-TAUTH-TAKEOVER departed' | grep -ao 'pages_prepared=[0-9]*' | cut -d= -f2 | tail -1")
echo "  INFO A orphan sweeps after the re-form (prepared summed=$sweep_prepared, settle takeover pages_prepared=${settle_tk:-0}): [$(echo "$sweep" | cut -c1-200 | tr '\n' '|')] at +$(el)s"
ra=$(rs 90 "$A" "s=\$(date +%s%N); n=\$(ls -f '$D' | grep -c '^f'); e=\$(date +%s%N); echo n=\$n ms=\$(( (e-s)/1000000 ))")
rb=$(rs 90 "$B" "s=\$(date +%s%N); n=\$(ls -f '$D' | grep -c '^f'); md5sum '$D/f1' '$D/f$((NFILES/2))' '$D/f$((NFILES-1))' > /dev/null; e=\$(date +%s%N); echo n=\$n ms=\$(( (e-s)/1000000 ))")
echo "  INFO directory reads after the re-form: A=[${ra:-none}] B=[${rb:-none}] at +$(el)s"
ra_n=$(echo "$ra" | grep -ao 'n=[0-9]*' | cut -d= -f2); rb_n=$(echo "$rb" | grep -ao 'n=[0-9]*' | cut -d= -f2)
rs 30 "$A" "dmesg | awk '/$MARK2/{f=1} f'" > "$OUT/dmesg_A_reform.txt"
rs 30 "$B" "dmesg | tail -400" > "$OUT/dmesg_B_reform.txt"
rs 15 "$A" "rm -f /tmp/departtk_dmesg.txt /tmp/departtk_um.done" >/dev/null

echo "--- verdict ---"
ck "the authority was built ($NFILES creates)" "$created" "$NFILES"
[ "$DEATH" = "destroy" ] && ck "A recovered B (P163-RECOVERY-COMPLETE)" "$([ -n "$recov" ] && echo 1 || echo 0)" "1"
ck "the $VIA pass was IN FLIGHT when the unmount was issued (activations still arriving)" "$inflight" "1"
ck "the cluster re-formed in place afterwards" "$reform_rc" "0"
ck "both nodes read the directory that was built after the re-form" "$([ "${ra_n:-0}" = "$NFILES" ] && [ "${rb_n:-0}" = "$NFILES" ] && echo 1 || echo 0)" "1"
case "$EXPECT" in
panic)
    ck "A rebooted under the unmount (the defect)" "$rebooted" "1"
    ck "the teardown gave up on the worker (P-DEPART-WORKER-STUCK on netconsole)" "$([ "$stuck" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the panic was captured (BUG/Oops/dlm_page_now_mine on netconsole)" "$([ "$bug" -ge 1 ] && echo 1 || echo 0)" "1"
    ;;
clean)
    ck "A did not reboot" "$rebooted" "0"
    ck "the unmount returned rc=0" "${um_rc:-none}" "0"
    ck "the unmount returned inside the bound (150 s)" "$([ -n "$um" ] && echo 1 || echo 0)" "1"
    ck "the teardown never gave up on the worker (no P-DEPART-WORKER-STUCK)" "$stuck" "0"
    ck "the pass was stopped between pages ($INTR_PAT)" "$([ -n "$intr" ] && echo 1 || echo 0)" "1"
    ck "the interrupted pass had pages remaining (not a pass that had finished)" "$([ "${intr_remaining:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the teardown completed (DLM shutdown complete)" "$([ "$complete" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "nothing crashed (no BUG/Oops on netconsole)" "$bug" "0"
    ck "the next bootstrap's orphan sweep took the pages the pass left (prepared >= 1)" "$([ "${sweep_prepared:-0}" -ge 1 ] && echo 1 || echo 0)" "1"
    echo "  INFO clean-arm figures: unmount ms=${um_ms:-?} interrupted at_page=${intr_page:-?} prepared=${intr_done:-?} remaining=${intr_remaining:-?} sweep_prepared=${sweep_prepared:-?} sweep_dead=${sweep_dead:-?} slow_lines=$slow refused=$refused"
    ;;
esac
echo "=== depart_takeover_unmount $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
