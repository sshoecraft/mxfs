#!/bin/bash
# join_during_takeover.sh — a node joins while the bootstrap node is taking
# over a dead authority's ledger pages.  Does the join succeed, or does the
# joiner die?  (D-0960)
#
# THE SHAPE.  A node that unmounts as the LAST member keeps every ledger page
# it served under its own authority.  When it mounts again, alone, it settles
# its previous incarnation's heartbeat record and its departure worker runs
# the takeover-only pass over that incarnation's pages (~10 ms a page).  A
# node that joins INSIDE that pass makes its first cluster acquire — the root
# inode's EX at mount — on a page the pass has not reached.
#
# TWO SHAPES, ONE COIN.  Which node masters the root inode's page is a hash of
# the per-incarnation node ids, so every re-form is a coin flip:
#   A-mastered — the joiner's request reaches the bootstrap, whose own
#       prepare must serve the page.  THIS is the shape measured in s588b,
#       s588c and the plain deploy: before 0.84.5 the bootstrap's on-demand
#       branch asked its id-keyed purged list, which never names its OWN
#       previous incarnation, so it answered REMASTER until the pass reached
#       the page; the joiner exhausted 60 retries in 18 s, its acquire
#       classifier shut its filesystem down at mount ('DLM inode lock
#       unrecoverable'), the mount withdrew (P-WITHDRAW, PR key retired), the
#       peer fenced and replayed it, and the mount failed.
#   B-mastered — the joiner is the master; its own prepare parks and asks the
#       bootstrap by FREEZE_REQ, whose handler already served a settled
#       predecessor on demand (0.75.69).  The old build survives this shape
#       (s590c: mount in 3.1 s, three takeover-request services).
# The lap therefore names the shape it measured (LOCALITY=A|B|none, from
# which node logged the root request meeting the transition) and repeats the
# sequence, up to ITER_MAX times, until WANT= is met.  A lap whose request
# met no transition at all (the page was already taken over) measures nothing.
#
# After the fix (0.84.5), three defences, each measurable alone (ARM=):
#   ondemand (default) — the bootstrap takes the requested page over ahead of
#       the pass (P960-ONDEMAND-SERVED ino=128 on A); the join completes in
#       seconds with no REMASTER answers.
#   nodemand — with mxfs.dl_no_ondemand_takeover=1 on A the request is
#       answered AUTH_TRANSITION carrying A's page-takeover count (A-mastered:
#       LOCK_DENY grant_gen; B-mastered: NOT_OWNER prepared_seq); B waits on
#       that count instead of its retry budget (P960-AUTH-TRANSITION-WAIT) and
#       the join completes when the pass reaches the page — never a shutdown.
#   stall — additionally mxfs.dl_takeover_pause_ms=45000 on A holds the pass
#       between pages once it is in flight, so the count B watches stops
#       advancing; after 30 s of no progress B's root acquire fails THIS
#       OPERATION (P960-AUTH-TRANSITION-STALLED, P960-AUTH-TRANSITION-FAIL,
#       'Failed to lock root inode'), the mount is refused with EAGAIN and
#       unwinds cleanly — no shutdown, no withdraw, no fence on A — and once
#       the knobs are cleared and the pass has finished, the same mount
#       succeeds.
#
# THE FALSE PASSES THIS LAP GUARDS AGAINST: a join issued after the pass has
# finished measures nothing, so the lap requires the pass to be in flight
# (activations still arriving) when the mount is issued and the request to
# have met the transition by name; on the fixed build it requires the defence
# under test to have fired by name.
#
# the budget rule (derived), per iteration: the authority, taken under
# grants with both nodes mounted (creates NFILES x 0.25 ms measured alone;
# a stat of every entry when the directory already holds NFILES; bound
# NFILES/25+60 s either way) + B's clean unmount (bound 120 s, measured 40 s
# when B hands ~15k pages back) + A's last-member unmount (bound 180 s,
# measured <1 s) + A's lone mount (bound 180 s, ~2 s) + in-flight detection
# (<= 240 s from the mount, ~11 s) + B's mount (ondemand: 90 s; nodemand: the
# pass, NFILES/50+60 s; stall: 45 s pause + 30 s watchdog + mount overhead,
# 120 s; death: 90 s) + stall recovery (pass remainder NFILES/50+120 s, then
# a 90 s mount) + captures ~20 s.  Then directory reads (90 s each) and the
# death re-form (scripts/module_swap_deploy.sh, <= 480 s).
#
# Usage: tests/join_during_takeover.sh <label> [A=test1] [B=test2]
# Env:   NFILES (default 32000), MXFS_MNT (default /mnt/shared),
#        EXPECT=observe|death|clean (default observe): "death" asserts the
#        defect as measured on the old build; "clean" asserts the fix.
#        ARM=ondemand|nodemand|stall (default ondemand; clean only).
#        WANT=A|B|any (default A: the measured defect shape), ITER_MAX
#        (default 6: a coin flip six times).
# Leaves both nodes mounted.  Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
A=${2:-test1}; B=${3:-test2}
NFILES=${NFILES:-32000}
EXPECT=${EXPECT:-observe}
ARM=${ARM:-ondemand}
WANT=${WANT:-A}
ITER_MAX=${ITER_MAX:-6}
case "$EXPECT" in observe|death|clean) ;; *) echo "ABORT: EXPECT must be observe, death or clean"; exit 2;; esac
case "$ARM" in ondemand|nodemand|stall) ;; *) echo "ABORT: ARM must be ondemand, nodemand or stall"; exit 2;; esac
case "$WANT" in A|B|any) ;; *) echo "ABORT: WANT must be A, B or any"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
NCLOG=tests/evidence/netconsole.log
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_jointk_$LABEL
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
DEV=${MXFS_DEV:-$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("dev",""))
except Exception:
    print("")' .cluster_marker.json 2>/dev/null)}
[ -n "$DEV" ] || { echo "ABORT: no device: set MXFS_DEV or form the cluster first (.cluster_marker.json has no dev)"; exit 2; }

echo "=== join_during_takeover label=$LABEL A=$A B=$B nfiles=$NFILES expect=$EXPECT arm=$ARM want=$WANT iter_max=$ITER_MAX out=$OUT $(date -u +%FT%TZ) ==="
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
BOOT_B=$(rs 15 "$B" "cat /proc/sys/kernel/random/boot_id")
tools/netconsole_listen.sh status 2>&1 | grep -q running || { echo "ABORT: the netconsole listener is not running (tools/netconsole_listen.sh start)"; exit 2; }
NC_BEFORE=$(wc -l < "$NCLOG")
D=$MNT/.jointk
# The knobs are read live; both start clear on A (a module reload also
# clears them).  A knob the arm sets is cleared again before the lap ends.
knobs() { rs 15 "$A" "echo ${1:-0} > $P/dl_no_ondemand_takeover; echo ${2:-0} > $P/dl_takeover_pause_ms; echo knobs=\$(cat $P/dl_no_ondemand_takeover)/\$(cat $P/dl_takeover_pause_ms)"; }
if [ "$EXPECT" = "clean" ]; then
    kn=$(knobs 0 0); echo "  INFO A knobs cleared: ${kn:-no result}"
    [[ "$kn" == *"knobs=0/0"* ]] || { echo "ABORT: A does not expose the test knobs ($kn) — is the fleet on 0.84.5+?"; exit 2; }
fi
abort_reform() {
    echo "ABORT: $1"
    knobs 0 0 >/dev/null
    echo "  INFO re-form the cluster before the next lap (scripts/module_swap_deploy.sh 2 tcp)"
    exit 2
}
cnt() { local n; n=$(grep -ac "$2" "$1" 2>/dev/null); echo "${n:-0}"; }
case "$EXPECT:$ARM" in
    clean:ondemand) MB=90 ;;
    clean:nodemand) MB=$(( NFILES / 50 + 60 )) ;;
    # stall on 0.84.8: the joiner is held at the settle gate (the incumbent's
    # install waits on the paused pass, so its beacon never carries the
    # two-node view); each of the untrusted iget's 5 budgets is a 60 s gate
    # refusal of the non-blocking probe plus another of the blocking acquire
    # (derived: 5 x 120 s = 600 s), then 'Failed to read root inode'.
    clean:stall)    MB=660 ;;
    *)              MB=90 ;;
esac

# One iteration: B leaves, A holds the authority alone, A unmounts last and
# remounts alone, B mounts inside the pass, evidence is captured, and the
# shape is classified.  Sets the globals the verdict reads.
iteration() {
    local it=$1 MARK MARKA DMA bu have cb au am tmount mine0 mine1 c i kn bm pb summ bm2
    MARK="JOINTK-$LABEL-$$-$it"
    for n in "$A" "$B"; do
        rs 15 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null
        # Both kernel logs are followed into a file from the marker on: the
        # pass prints one line per page and the ring alone would roll the
        # marker away.
        rs 20 "$n" "rm -f /tmp/jointk_dmesg.txt; nohup sh -c 'dmesg --follow' > /tmp/jointk_dmesg.txt 2>&1 & echo started" >/dev/null
    done
    DM="awk '/$MARK/{f=1} f' /tmp/jointk_dmesg.txt"
    echo "--- iteration $it ---"
    # 1. The authority: NFILES entries in one directory, taken under grants
    #    while BOTH nodes are members.  The ledger records grants; a lone
    #    mount modifies everything at NL with no grant and writes no record,
    #    so a directory created after B has left leaves the pass nothing to
    #    take over (s591d, s592a: cand=4 on a fresh filesystem, the pass
    #    done in 2.3 s, the join could not be issued inside it).  A creates
    #    the entries (fresh), or stats every one of them (a directory left
    #    by an earlier lap): each takes its inode's grant at whichever node
    #    masters it, and B's clean departure below hands B's pages to A.
    have=$(rs 90 "$A" "ls -f '$D' 2>/dev/null | grep -c '^f'")
    have=${have:-0}
    cb=$(( NFILES / 25 + 60 ))
    if [ "$have" -ge "$NFILES" ]; then
        created=$NFILES
        rs "$cb" "$A" "s=\$(date +%s%N); n=\$(ls -l '$D' | grep -c '^-'); e=\$(date +%s%N); echo STATTED=\$n ms=\$(( (e-s)/1000000 ))" > "$OUT/create_$it.txt"
        echo "  INFO A already holds $have entries in $D (reused; grants taken: $(tr '\n' ' ' < "$OUT/create_$it.txt")) at +$(el)s"
        grep -q "STATTED=$NFILES" "$OUT/create_$it.txt" || { echo "ABORT: A statted $(tr '\n' ' ' < "$OUT/create_$it.txt") of $NFILES inside $cb s"; exit 2; }
    else
        rs "$cb" "$A" "mkdir -p '$D' && i=0; s=\$(date +%s%N); while [ \$i -lt $NFILES ]; do : > '$D/f'\$i || break; i=\$((i+1)); done; sync; e=\$(date +%s%N); echo CREATED=\$i ms=\$(( (e-s)/1000000 ))" > "$OUT/create_$it.txt"
        created=$(grep -ao 'CREATED=[0-9]*' "$OUT/create_$it.txt" | cut -d= -f2)
        echo "  INFO A created ${created:-0}/$NFILES files: $(tr '\n' ' ' < "$OUT/create_$it.txt") at +$(el)s"
        [ "${created:-0}" = "$NFILES" ] || { echo "ABORT: A created ${created:-0}/$NFILES inside $cb s"; exit 2; }
    fi
    # 2. B leaves, cleanly, so A is the last member: B's pages are handed to
    #    A at the departure and what A serves stays A's when A unmounts.
    bu=$(rs 120 "$B" "s=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo B_UMOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "  INFO B unmounted first: ${bu:-no result} at +$(el)s"
    [[ "$bu" == *"B_UMOUNT_RC=0"* ]] || { echo "ABORT: B's unmount did not return 0 ($bu)"; exit 2; }
    # 3. A unmounts as the last member: its pages stay under its authority.
    au=$(rs 180 "$A" "s=\$(date +%s%N); umount $MNT; rc=\$?; e=\$(date +%s%N); echo A_UMOUNT_RC=\$rc ms=\$(( (e-s)/1000000 )); grep -c ' mxfs ' /proc/mounts")
    echo "  INFO A's last-member unmount: $(echo "$au" | tr '\n' ' ') at +$(el)s"
    [[ "$au" == *"A_UMOUNT_RC=0"* ]] || { echo "ABORT: A's unmount did not return 0 ($au)"; exit 2; }
    # 4. A mounts again, alone: its previous incarnation is a dead authority
    #    holding every page, and the takeover-only pass runs on the worker.
    #    nodemand: the on-demand defence is switched off before any request
    #    can meet it.
    [ "$ARM" = "nodemand" ] && [ "$EXPECT" = "clean" ] && { kn=$(knobs 1 0); echo "  INFO A knobs for the arm: ${kn:-no result}"; }
    # A second marker on A, written just before the remount: everything the
    # lap counts on A from here on — the pass in flight, the activations at
    # issue and return, the pass summary, the on-demand services — belongs
    # to THIS incarnation's pass.  Measured s592e: the previous lap's pass
    # (A's takeover of the lap before) was still running during step 1, so
    # the first marker's window counted ~7000 of its activations and the
    # summary line the verdict quoted was that pass's, not this one's.
    MARKA="$MARK-A2"
    rs 15 "$A" "echo '$MARKA' > /dev/kmsg" >/dev/null
    DMA="awk '/$MARKA/{f=1} f' /tmp/jointk_dmesg.txt"
    am=$(rs 180 "$A" "s=\$(date +%s%N); mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%N); echo A_MOUNT_RC=\$rc ms=\$(( (e-s)/1000000 ))")
    echo "  INFO A's lone remount: ${am:-no result} at +$(el)s"
    [[ "$am" == *"A_MOUNT_RC=0"* ]] || { echo "ABORT: A's lone remount did not return 0 ($am)"; exit 2; }
    tmount=$(date +%s)
    # 5. The pass, seen IN FLIGHT: the per-page activation count grew between
    #    two samples five seconds apart and is past a floor.
    mine0=0; mine1=0; inflight=0
    for i in $(seq 1 48); do
        sleep 5
        c=$(rs 20 "$A" "$DMA | grep -ac 'P-TAUTH-PAGE-MINE page=[0-9]* via=takeover'")
        c=${c:-0}
        if [ "$c" -ge 50 ] && [ "$mine0" -ge 1 ] && [ "$c" -gt "$mine0" ]; then mine1=$c; inflight=1; break; fi
        mine0=$c
    done
    echo "  INFO takeover pass: activations_so_far=$mine1 (previous sample $mine0) in_flight=$inflight ($(( $(date +%s) - tmount )) s after the mount) at +$(el)s"
    if [ "$inflight" != "1" ]; then
        local done_line
        done_line=$(rs 20 "$A" "$DMA | grep -a 'P-TAUTH-TAKEOVER departed\|P-TAUTH-ORPHAN-SWEEP by' | tail -1")
        abort_reform "the takeover pass was not seen in flight (activations=$mine0; ${done_line:-no summary line}) — the join would measure nothing"
    fi
    # stall: hold the pass between pages from here on; the count B watches
    # stops advancing.
    if [ "$ARM" = "stall" ] && [ "$EXPECT" = "clean" ]; then
        kn=$(knobs 1 45000); echo "  INFO A knobs for the arm: ${kn:-no result} at +$(el)s"
        sleep 2
    fi
    # 6. B mounts INSIDE the pass.
    #    stall: the mount is issued detached, because two things are timed
    #    separately — how long until the refusal is logged (the 45 s pause
    #    plus the 30 s watchdog, bound MB) and how long the refused mount's
    #    unwind then takes to return (bound 30 s: it must take no cluster
    #    acquire; measured before 0.84.5's no-cover unwind it parked on the
    #    SB summary lock until the knobs were cleared, s590j).
    value_now_into mine_at_issue "$A" 20 "$OUT/rv_mine_at_issue_1.txt" '^[0-9]+$' "mine_at_issue on $A" "$DMA | grep -ac 'P-TAUTH-PAGE-MINE page=[0-9]* via=takeover' || [ \$? = 1 ]"
    refused_s=""; unwind_s=""
    if [ "$ARM" = "stall" ] && [ "$EXPECT" = "clean" ]; then
        local ti tr rf
        rs 20 "$B" "rm -f /tmp/jointk_mount.txt; nohup sh -c 's=\$(date +%s%N); mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%N); { echo B_MOUNT_RC=\$rc ms=\$(( (e-s)/1000000 )); grep -c \" mxfs \" /proc/mounts; } > /tmp/jointk_mount.txt.tmp; mv /tmp/jointk_mount.txt.tmp /tmp/jointk_mount.txt' >/dev/null 2>&1 & echo issued" >/dev/null
        ti=$(date +%s); tr=""; bm=""
        for i in $(seq 1 $(( MB / 3 ))); do
            sleep 3
            rf=$(rs 20 "$B" "$DM | grep -ac 'Failed to read root inode'")
            if [ "${rf:-0}" -ge 1 ]; then tr=$(date +%s); break; fi
            bm=$(rs 15 "$B" "cat /tmp/jointk_mount.txt 2>/dev/null")
            [ -n "$bm" ] && { tr=$(date +%s); break; }
        done
        [ -n "$tr" ] && refused_s=$(( tr - ti ))
        echo "  INFO B's refusal logged: ${refused_s:-not inside ${MB}s}s after the mount was issued at +$(el)s"
        # the command had already returned inside the same 3 s poll
        [ -n "$bm" ] && unwind_s=0
        if [ -n "$tr" ] && [ -z "$bm" ]; then
            for i in $(seq 1 30); do
                bm=$(rs 15 "$B" "cat /tmp/jointk_mount.txt 2>/dev/null")
                [ -n "$bm" ] && break
                sleep 2
            done
            [ -n "$bm" ] && unwind_s=$(( $(date +%s) - tr ))
        fi
        [ -n "$bm" ] || echo "  INFO B's refused mount did not return inside 60 s of the refusal (a timeout is a failure)"
        echo "  INFO B's refused mount returned: $(echo "$bm" | tr '\n' ' ') unwind=${unwind_s:-not inside 60s}s at +$(el)s"
    else
        bm=$(rs "$MB" "$B" "s=\$(date +%s%N); mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%N); echo B_MOUNT_RC=\$rc ms=\$(( (e-s)/1000000 )); grep -c ' mxfs ' /proc/mounts")
    fi
    mine_at_return=$(rs 20 "$A" "$DMA | grep -ac 'P-TAUTH-PAGE-MINE page=[0-9]* via=takeover'")
    echo "  INFO B's mount inside the pass: $(echo "$bm" | tr '\n' ' ') (activations at issue=$mine_at_issue at return=$mine_at_return, bound ${MB}s) at +$(el)s"
    bm_rc=$(echo "$bm" | grep -ao 'B_MOUNT_RC=[0-9]*' | cut -d= -f2)
    bm_ms=$(echo "$bm" | grep -ao 'ms=[0-9]*' | cut -d= -f2)
    bm_mounted=$(echo "$bm" | tail -1 | grep -ao '^[0-9]*')
    [ -n "$bm" ] || echo "  INFO B's mount did not return inside ${MB}s (a timeout is a failure)"
    # 7. stall: clear the knobs, let the pass finish, mount B for real.
    bm2_rc=""; bm2_ms=""; summ=""
    if [ "$ARM" = "stall" ] && [ "$EXPECT" = "clean" ]; then
        kn=$(knobs 0 0); echo "  INFO A knobs cleared: ${kn:-no result} at +$(el)s"
        pb=$(( NFILES / 50 + 120 ))
        # the MAIN pass's summary (hundreds of pages), not the 50-page
        # takeover of the refused mount's own departed incarnation, which
        # A logs first (s591a)
        for i in $(seq 1 $(( pb / 5 ))); do
            summ=$(rs 20 "$A" "$DMA | grep -a 'P-TAUTH-TAKEOVER departed=.*pages_prepared=[0-9][0-9][0-9]' | tail -1")
            [ -n "$summ" ] && break
            sleep 5
        done
        echo "  INFO pass summary after the stall: [${summ:-not seen inside ${pb}s}] at +$(el)s"
        bm2=$(rs 90 "$B" "grep -q ' mxfs ' /proc/mounts && echo ALREADY; s=\$(date +%s%N); mount -t mxfs $DEV $MNT; rc=\$?; e=\$(date +%s%N); echo B_MOUNT2_RC=\$rc ms=\$(( (e-s)/1000000 )); grep -c ' mxfs ' /proc/mounts")
        echo "  INFO B's mount after the pass: $(echo "$bm2" | tr '\n' ' ') at +$(el)s"
        bm2_rc=$(echo "$bm2" | grep -ao 'B_MOUNT2_RC=[0-9]*' | cut -d= -f2)
        bm2_ms=$(echo "$bm2" | grep -ao 'ms=[0-9]*' | cut -d= -f2)
    fi
    stall_summary=$summ
    # 8. Evidence.
    sleep 5
    FA=$OUT/dmesg_A_followed_$it.txt; FB=$OUT/dmesg_B_followed_$it.txt
    rs 30 "$A" "$DMA" > "$FA"
    rs 30 "$B" "$DM" > "$FB"
    rs 30 "$B" "dmesg | tail -300" > "$OUT/dmesg_B_ring_$it.txt"
    unrec=$(cnt "$FB" 'DLM inode lock unrecoverable')
    withdraw=$(cnt "$FB" 'P-WITHDRAW\b\|P163-WITHDRAW-STAMP')
    poison=$(cnt "$FB" 'P-SESSION-POISON')
    corrupt=$(cnt "$FB" 'Corruption of in-memory data')
    budget=$(cnt "$FB" 'lock request failed after')
    remaster_rx=$(cnt "$FB" 'P-TAUTH-REMASTER-RX')
    parked=$(cnt "$FB" 'P-TAUTH-PAGE-PARKED')
    # the three silent parks a budget can be spent on (instrumented after
    # s592e: nine 60-retry budgets of 'prepare' answers with the PARKED
    # probe capped out)
    park_nt=$(cnt "$FB" 'P960-PARK-NOT-TRANSITION')
    park_no=$(cnt "$FB" 'P960-PARK-NOT-OWNER')
    park_is=$(cnt "$FB" 'P960-PARK-IMPORT-STALE')
    park_nt_first=$(grep -a 'P960-PARK-NOT-TRANSITION' "$FB" | head -1 | cut -c1-260)
    # The settle gate at B's first acquire: on 0.84.7 it opened unconfirmed
    # at the 20 s window because the incumbent's zero-view beacon was never
    # recorded (s592e, s593a), and every acquire issued before the
    # incumbent installed the two-node view was deferred by it.
    gate_first=$(grep -a 'P-D7-SETTLEGATE' "$FB" | head -1 | sed 's/.*P-D7-SETTLEGATE //' | cut -c1-200)
    gate_n=$(cnt "$FB" 'P-D7-SETTLEGATE')
    gate_refused=$(cnt "$FB" 'P-D7-SETTLEGATE.*REFUSED')
    # 0.84.8: the gate holds B's first acquire while the incumbent beacons
    # no multi-node view (pending_live=1) and opens on the incumbent's
    # installed view (confirmed=1).  A refusal at the 60 s backstop is
    # retried by the mount's untrusted iget; the join then completes once
    # the incumbent has installed, so B's first requests may meet no
    # transition at all (the shape 'gate').
    gate_pending=$(cnt "$FB" 'P-D7-SETTLEGATE.*pending_live=1')
    gate_confirmed=$(cnt "$FB" 'P-D7-SETTLEGATE.*confirmed=1')
    rootfail_any=$(cnt "$FB" 'Failed to read root inode')
    # the progress-aware wait measured on the incumbent's own worker (its
    # join prepare's SB summary lock lands on a page the pass has not
    # reached while on-demand service is off)
    a_worker_wait=$(cnt "$FA" 'P960-AUTH-TRANSITION-WAIT.*comm=mxfs-worker')
    a_worker_stalled=$(cnt "$FA" 'P960-AUTH-TRANSITION-STALLED.*comm=mxfs-worker')
    trans_rx=$(cnt "$FB" 'P960-AUTH-TRANSITION-RX')
    trans_wait=$(cnt "$FB" 'P960-AUTH-TRANSITION-WAIT')
    trans_stalled=$(cnt "$FB" 'P960-AUTH-TRANSITION-STALLED')
    trans_fail=$(cnt "$FB" 'P960-AUTH-TRANSITION-FAIL')
    trans_park=$(cnt "$FB" 'P960-AUTH-TRANSITION-PARK')
    rootfail=$(cnt "$FB" 'Failed to read root inode.*refused')
    noqueue=$(cnt "$FB" 'P960-AUTH-TRANSITION-NOQUEUE')
    nocover=$(cnt "$FB" 'P960-REFUSED-MOUNT-NOCOVER')
    sumlock_q=$(cnt "$FB" 'P-SB-SUMMARY-LOCK .*at=quiesce')
    ondemand=$(cnt "$FA" 'P-TAUTH-TAKEOVER-ONDEMAND')
    # The mount's first cluster acquires are AG 0's lock (the untrusted
    # iget) and then the root inode's; either can be the request that meets
    # the transition, so both are counted on A.
    ROOTREQ='type=1 ino=128 \|type=3 ino=0 ag=0 '
    served_root=$(cnt "$FA" "P960-ONDEMAND-SERVED \($ROOTREQ\)")
    parked_root=$(cnt "$FA" "P-TAUTH-REMASTER-PARKED \($ROOTREQ\)")
    trans_tx_root=$(cnt "$FA" "P960-AUTH-TRANSITION-TX \($ROOTREQ\)")
    trans_tx=$(cnt "$FA" 'P960-AUTH-TRANSITION-TX')
    decline=$(cnt "$FA" 'P960-AUTH-TRANSITION-DECLINE\|via=takeover-request')
    defer=$(cnt "$FA" 'P-TAUTH-HANDOFF-DEFER')
    recov_a=$(cnt "$FA" 'P163-RECOVERY-COMPLETE\|P163-FENCE')
    summary=$(grep -a 'P-TAUTH-TAKEOVER departed=.*pages_prepared=[0-9][0-9][0-9]' "$FA" | tail -1 | cut -c1-200)
    retired=$(cnt "$FA" 'P961-JOIN-SIGHTING-RETIRED')
    stale_view=$(cnt "$FA" 'MXFS-MEMBERSHIP local=[0-9]* active_count=[3-9]')
    mine_total=$(cnt "$FA" 'P-TAUTH-PAGE-MINE page=[0-9]* via=takeover')
    # The shape: A-mastered if A logged the mount's request meeting the
    # transition at its own prepare (served, parked or answered
    # AUTH_TRANSITION there); B-mastered if the ask came to A by FREEZE_REQ
    # (A deferred it, declined it or served a takeover-request) or B parked
    # the page itself; none if the request met no transition (measures
    # nothing).  B's own WAIT line is printed in both shapes and decides
    # nothing.
    if [ $(( served_root + parked_root + trans_tx_root )) -ge 1 ]; then locality=A
    elif [ $(( decline + defer + parked )) -ge 1 ]; then locality=B
    elif [ "$gate_pending" -ge 1 ]; then locality=gate
    else locality=none; fi
    echo "  INFO B: unrecoverable=$unrec withdraw=$withdraw poison=$poison corrupt=$corrupt budget_exhausted=$budget remaster_rx=$remaster_rx parked=$parked"
    echo "  INFO B parks: not_transition=$park_nt not_owner=$park_no import_stale=$park_is first=[${park_nt_first:-none}]"
    echo "  INFO B settle gate: lines=$gate_n refused=$gate_refused pending_live=$gate_pending confirmed=$gate_confirmed first=[${gate_first:-none}]"
    echo "  INFO A worker: transition_wait=$a_worker_wait stalled=$a_worker_stalled"
    echo "  INFO B: transition rx=$trans_rx wait=$trans_wait noqueue=$noqueue stalled=$trans_stalled fail=$trans_fail park=$trans_park root_refused=$rootfail nocover=$nocover summary_lock_at_quiesce=$sumlock_q rebooted=$([ "$(rs 15 "$B" "cat /proc/sys/kernel/random/boot_id")" = "$BOOT_B" ] && echo 0 || echo 1)"
    echo "  INFO A: ondemand=$ondemand served_root=$served_root parked_root=$parked_root transition_tx=$trans_tx (root/AG0 $trans_tx_root) decline/takeover-request=$decline defer=$defer recovery_of_peer=$recov_a activations_total=$mine_total"
    echo "  INFO A pass summary: [${summary:-none yet}]"
    echo "  INFO LOCALITY=$locality (want $WANT)"
    grep -a 'P960\|P-TAUTH-TAKEOVER-ONDEMAND\|unrecoverable\|P-WITHDRAW\|Failed to .* root inode\|lock request failed\|REMASTER' "$FB" "$FA" | cut -c1-240 > "$OUT/key_lines_$it.txt"
    for n in "$A" "$B"; do rs 15 "$n" "rm -f /tmp/jointk_dmesg.txt" >/dev/null; done
}

matched=0; iters=0
for it in $(seq 1 "$ITER_MAX"); do
    iters=$it
    iteration "$it"
    if [ "$WANT" = "any" ] && [ "$locality" != "none" ]; then matched=1; break; fi
    [ "$locality" = "$WANT" ] && { matched=1; break; }
    # Not the shape wanted.  B must be mounted again to repeat; a mount that
    # failed (a death, or a refused stall mount whose second mount failed)
    # ends the lap here.
    if [ "$ARM" = "stall" ] && [ "$EXPECT" = "clean" ]; then
        [ "${bm2_rc:-1}" = "0" ] || { echo "  INFO B is not mounted after iteration $it; stopping"; break; }
    else
        [ "${bm_rc:-1}" = "0" ] || { echo "  INFO B's mount failed in an unwanted shape ($locality) at iteration $it; stopping"; break; }
    fi
done
echo "  INFO iterations=$iters matched=$matched locality=$locality"

tail -n +$(( NC_BEFORE + 1 )) "$NCLOG" > "$OUT/netconsole_new.txt"
bug=$(grep -ac 'BUG: unable to handle\|Oops:\|Kernel panic' "$OUT/netconsole_new.txt")
echo "  INFO netconsole new lines=$(wc -l < "$OUT/netconsole_new.txt") crash_lines=$bug"

# 9. Death arm: B is shut down and withdrawn; the fleet is re-formed in place
#    so the next lap starts from two mounted nodes.
reform_rc=""
if [ "$EXPECT" = "death" ] || { [ "$EXPECT" = "observe" ] && [ "${bm_rc:-1}" != "0" ]; }; then
    MXFS_JOIN_WAIT_S=$(( NFILES / 40 + 120 )) scripts/module_swap_deploy.sh 2 tcp > "$OUT/reform.txt" 2>&1; reform_rc=$?
    echo "  INFO re-form rc=$reform_rc: $(grep -a 'SWAP_OK\|FAIL\|bad nodes\|join wait' "$OUT/reform.txt" | head -2 | tr '\n' ' ') at +$(el)s"
fi

# 10. Both nodes read the directory.
ra=$(rs 90 "$A" "s=\$(date +%s%N); n=\$(ls -f '$D' | grep -c '^f'); e=\$(date +%s%N); echo n=\$n ms=\$(( (e-s)/1000000 ))")
rb=$(rs 90 "$B" "s=\$(date +%s%N); n=\$(ls -f '$D' | grep -c '^f'); md5sum '$D/f1' '$D/f$((NFILES/2))' '$D/f$((NFILES-1))' > /dev/null; e=\$(date +%s%N); echo n=\$n ms=\$(( (e-s)/1000000 ))")
echo "  INFO directory reads: A=[${ra:-none}] B=[${rb:-none}] at +$(el)s"
ra_n=$(echo "$ra" | grep -ao 'n=[0-9]*' | cut -d= -f2); rb_n=$(echo "$rb" | grep -ao 'n=[0-9]*' | cut -d= -f2)
[ "$EXPECT" = "clean" ] && knobs 0 0 >/dev/null

echo "--- verdict (iteration $iters, locality $locality) ---"
ck "the authority exists ($NFILES entries)" "$created" "$NFILES"
ck "the takeover pass was IN FLIGHT when B's mount was issued (activations still arriving)" "$inflight" "1"
ck "the pass was still in flight at B's mount (activations at issue < total)" "$([ "${mine_at_issue:-0}" -lt "${mine_total:-0}" ] && echo 1 || echo 0)" "1"
ck "the root request met the transition in the wanted shape (LOCALITY=$WANT)" "$matched" "1"
ck "nothing crashed (no BUG/Oops on netconsole)" "$bug" "0"
ck "both nodes read the directory afterwards" "$([ "${ra_n:-0}" = "$NFILES" ] && [ "${rb_n:-0}" = "$NFILES" ] && echo 1 || echo 0)" "1"
case "$EXPECT" in
death)
    ck "B's mount failed (the defect)" "$([ "${bm_rc:-1}" != "0" ] && echo 1 || echo 0)" "1"
    ck "B exhausted its retry budget on remaster ('lock request failed after')" "$([ "$budget" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "B shut its own filesystem down at mount (DLM inode lock unrecoverable)" "$([ "$unrec" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "B withdrew (P-WITHDRAW / P163-WITHDRAW-STAMP)" "$([ "$withdraw" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "the cluster re-formed afterwards" "$reform_rc" "0"
    ;;
clean)
    ck "B did not shut its filesystem down (no DLM inode lock unrecoverable)" "$unrec" "0"
    ck "B did not withdraw" "$withdraw" "0"
    ck "B's session was not poisoned" "$poison" "0"
    ck "no in-memory corruption shutdown on B" "$corrupt" "0"
    ck "B never exhausted a retry budget (no 'lock request failed after')" "$budget" "0"
    ck "A never fenced or recovered B" "$recov_a" "0"
    case "$ARM" in
    ondemand)
        ck "B's mount inside the pass returned rc=0" "${bm_rc:-none}" "0"
        ck "B's mount returned inside 90 s" "$([ -n "$bm_ms" ] && [ "$bm_ms" -le 90000 ] && echo 1 || echo 0)" "1"
        ck "A served the page on demand (P-TAUTH-TAKEOVER-ONDEMAND >= 1)" "$([ "$ondemand" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "B's root request was never answered REMASTER" "$remaster_rx" "0"
        ;;
    nodemand)
        ck "B's mount inside the pass returned rc=0" "${bm_rc:-none}" "0"
        ck "B's mount returned inside the pass bound (${MB}s)" "$([ -n "$bm_ms" ] && [ "$bm_ms" -le $(( MB * 1000 )) ] && echo 1 || echo 0)" "1"
        ck "A took nothing over on demand (the knob held)" "$ondemand" "0"
        # 0.84.8: the joiner is admitted only once the incumbent's beacon
        # carries the two-node view (the gate held it, pending_live=1, and
        # opened on confirmation); its first requests may then meet the
        # pass by name, or nothing at all if the pass has moved past them
        ck "the gate held B's first acquire on the incumbent's zero view (P-D7-SETTLEGATE pending_live=1 >= 1)" "$([ "$gate_pending" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the gate opened on the incumbent's installed view (P-D7-SETTLEGATE confirmed=1 >= 1)" "$([ "$gate_confirmed" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "B spent no retry budget on the incumbent's DEFER window (no P-TAUTH-HANDOFF-DEFER on A)" "$defer" "0"
        ck "the progress-aware wait fired by name (A's worker or B: P960-AUTH-TRANSITION-WAIT/-RX >= 1)" "$([ $(( trans_rx + trans_wait + a_worker_wait )) -ge 1 ] && echo 1 || echo 0)" "1"
        ck "B's root request was never answered REMASTER" "$remaster_rx" "0"
        ck "no wait stalled on either node (no P960-AUTH-TRANSITION-STALLED)" "$(( trans_stalled + a_worker_stalled ))" "0"
        ;;
    stall)
        ck "B's mount inside the stalled pass was REFUSED (rc != 0)" "$([ "${bm_rc:-0}" != "0" ] && echo 1 || echo 0)" "1"
        ck "the refusal was logged inside ${MB} s of the mount being issued" "$([ -n "$refused_s" ] && [ "$refused_s" -le "$MB" ] && echo 1 || echo 0)" "1"
        ck "the refused mount's command returned inside 30 s of the refusal (its unwind took no cluster acquire)" "$([ -n "$unwind_s" ] && [ "$unwind_s" -le 30 ] && echo 1 || echo 0)" "1"
        ck "the refused mount's quiesce wrote no SB summary (P960-REFUSED-MOUNT-NOCOVER >= 1)" "$([ "$nocover" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the refused mount took no SB summary lock at quiesce" "$sumlock_q" "0"
        ck "B left the mount unmounted (nothing half-mounted)" "${bm_mounted:-none}" "0"
        # 0.84.8: the joiner never reaches the stalled transition — the gate
        # holds it while the incumbent (whose own install waits on the
        # paused pass) beacons no two-node view — so the refusal comes from
        # the gate's backstop; the watchdog fires on the incumbent's worker
        ck "the refusal came from the settle gate's backstop or the no-progress watchdog (REFUSED >= 1 or STALLED >= 1)" "$([ $(( gate_refused + trans_stalled )) -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the incumbent's own wait on the paused pass was named and never failed it (A's worker STALLED >= 1, no shutdown)" "$([ "$a_worker_stalled" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the mount was refused at the root lookup, not shut down ('Failed to read root inode')" "$([ "$rootfail_any" -ge 1 ] && echo 1 || echo 0)" "1"
        ck "the pass finished once the knobs were cleared" "$([ -n "$stall_summary" ] && echo 1 || echo 0)" "1"
        ck "A installed no view with a third member (the refused mount's departed identity, D-0961)" "$stale_view" "0"
        ck "B's mount after the pass returned rc=0" "${bm2_rc:-none}" "0"
        echo "  INFO A: retired sightings (P961-JOIN-SIGHTING-RETIRED)=$retired"
        ;;
    esac
    ;;
esac
echo "  INFO figures: iterations=$iters locality=$locality B mount rc=${bm_rc:-?} ms=${bm_ms:-?} refused_s=${refused_s:-n/a} unwind_s=${unwind_s:-n/a} (second: rc=${bm2_rc:-n/a} ms=${bm2_ms:-n/a}) pass activations at issue=$mine_at_issue return=$mine_at_return total=$mine_total ondemand=$ondemand served_root=$served_root transition tx=$trans_tx rx=$trans_rx wait=$trans_wait stalled=$trans_stalled fail=$trans_fail park=$trans_park remaster_rx=$remaster_rx parked=$parked"
echo "=== join_during_takeover $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
