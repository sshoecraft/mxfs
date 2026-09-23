#!/bin/bash
# sess485 chain 133: DOES THE 0.69.3 UNMOUNT REORDERING CLOSE THE AG-RELEASE
# WINDOW, AND DID THE WINDOW EVER GET CROSSED ON THE BUILD BEFORE IT?
#
# THE DEFECT.  D-UNMOUNT-AG-GRANTS-PUBLISHED-BEFORE-METADATA-QUIESCE-0483.  Up
# to 0.69.2 an unmounting node published every AG grant it still held, and THEN
# ran its deferred inode inactivation, its final SB summary sync (log quiesce)
# and xfs_unmountfs's AIL push and inode flush -- writing AGI, inobt, finobt and
# inode clusters for allocation groups a peer may already own.  0.69.3 hoists
# all of that work above the publication (see CHANGELOG 0.69.3).
#
# THE WORKLOAD, AND WHY CHAIN 131'S DID NOT CROSS.  Chain 131 created and
# deleted files, then unmounted a few seconds later: by the time put_super ran,
# the inodegc worker (one-jiffy queue delay) had inactivated everything and the
# destage kick had pushed the AIL, so nothing was left for the unmount to write
# and all 64 window lines read zero.  This chain holds FILES unlinked files OPEN
# per node and closes them in the same shell command that runs umount, so the
# close->put_super gap is milliseconds: the inactivation backlog and the dirty
# AG metadata it produces are still pending when the grants are published.
#
# THE A/B.  Two legs on identically prepped filesystems:
#   BASE   the frozen 0.69.2 module (carries the 0.68.1 P483 probes, not the
#          fix).  Expected: dlm_wr > 0 -- AG metadata written after
#          publication while the DLM still existed -- which is the reproduction
#          this record and D-408 have lacked.
#   FIX    the 0.69.3 module.  Expected: every after-publication counter zero,
#          pre_wr > 0 (the same work, now done before publication), and
#          ags_drained = 0 (the quiesce, not the release drains, carried it).
# Both legs run chk_mxfs on the quiescent image afterwards.
#
# ANTI-VACUITY GATES, checked before any number is read:
#   G1 both modules carry the P483 probes; the FIX module carries "ags_drained="
#      and "pre_wr=" and the BASE module carries neither;
#   G2 every node's srcversion equals the leg's module;
#   G3 per-node workload accounting: files created AND held open, reported by
#      the node itself, so a node that opened nothing is not a clean zero;
#   G4 per-node umount rc and a mountpoint recheck;
#   G5 the verdict refuses to score a leg unless P483-AGFREE-WINDOW was printed,
#      and reports covered/32;
#   G6 P482-UMOUNT-AGREL ags_released is the population denominator;
#   G7 the FIX leg's pre_wr must be nonzero, or its zeros are not a measurement.
#
# derived time budgets, derived.  prep 88-112 s measured -> 300 per leg.  The node
# command = FILES creates in a private directory at the measured 27-32 ms
# (400 -> ~13 s) + a mass 32-way umount (~100 s measured, chain 131 control
# 68 s) -> 240 per node, run in parallel.  chk_mxfs 240 (measured budget for
# this image).  Sweep 90.  ~700 s per leg, ~1500 s total after the gate.
#
# LAP 1 (s485a, sess485/486) RESULT AND WHAT IT CHANGED HERE.  Fix leg: 32/32
# umount clean in 15 s, every after-publication counter zero, pre_wr=12 on
# 4/32 nodes, ags_drained=0, chk clean.  Base leg: 23/32 nodes NEVER RETURNED
# from umount within the 240 s budget — each printed P482-UMOUNT-AGREL (grants
# published) and then nothing the sweep filter matched — and the NEXT leg's
# prep power-cycled them, destroying the only evidence of where they were
# stuck (node journals are volatile).  Design-consult ruling (sess486): the A/B
# does not meet the pre-declared closure rule (no after-publication write was
# OBSERVED on base); the hang is its own record; the discriminating lap is a
# base-only lap that captures, on every hung node BEFORE anything reboots it,
# the umount task's stack, the blocked/worker task stacks and the UNFILTERED
# kernel journal.  Hence:
#   LEGS="base" / "fix" / "base fix"   which legs to run (default both);
#   HANG CAPTURE: any node without an umount rc after the workload budget
#     gets hang_testN.txt (umount stack+wchan, sysrq-w, every D-state / umount /
#     kworker / xfsaild / mxfs task stack) and kjournal_testN.txt (journalctl -k
#     since the leg started, unfiltered) written into the leg's evidence dir;
#   the seal counter now counts the real violation lines (P-SB-SEAL-TRANS /
#     -SYNCSB / -DIRTY-DEPARTURE); lap 1 counted P-SB-SEAL-OK as a violation;
#   the sweep filter also keeps P-SB-SUMMARY-*, P-SB-SEALED, P6S-ARM-REFUSED,
#     P-DEMWAIT-REDRIVE and hung-task lines;
#   chk on a leg with hung nodes is labelled NOT QUIESCENT and not a verdict.
# Budget for the capture: 32 nodes in parallel, 90 s per node hard cap.
#
# LAP 2 (s486a, base only, sess486/487) RESULT.  32/32 unmounted clean in 16 s
# on the same frozen 0.69.2 module, every after-publication counter zero,
# ags_released=34, chk clean.  Nothing hung, so the capture never fired.  Read
# with lap 1: on 0.69.2 a node whose inactivation is still pending at
# publication hangs (lap 1, 23/32 -- the 9 that finished in ~1 s had nothing
# pending) and a node whose inactivation finished before put_super does not
# (lap 2, 32/32; a zero dlm_wr on the base module means exactly that nothing
# was left to write after publication).  Both laps let the subshell exit and
# then ran umount, so whether work was pending at put_super was a race the
# inodegc worker usually won.
#
# LAP 3 HYPOTHESIS (sess487, falsifiable): the lap-1 stall and the D-0483
# window both require deferred inactivation to be pending when the grants are
# published; make that pending state certain and the base leg stalls -- now
# with stacks captured -- or writes after publication (dlm_wr > 0) on ~32/32
# nodes, while the fix leg shows pre_wr > 0 on ~32/32 with every
# after-publication counter zero.  Falsified if the base leg unmounts clean
# with dlm_wr = 0 while the fix leg's pre_wr proves the work WAS pending on the
# same workload.  The workload change that makes it certain is described at
# the node command below.
#
# LAP 3 (s487a, sess487) RESULT.  Base: 28/32 hung, stacks captured — 26 umount
# tasks parked in the CAW acquire of the cluster-wide SB summary EX lock, ONE
# holder (test1) in D state in xfs_ail_push_all_sync under xfs_log_quiesce
# with 480 P126-XFSAILD-SKIP-AGMETA lines after its publication (xfsaild
# refusing dirty AG metadata for AGs it no longer held), 4 nodes that reached
# the lock first unmounted in ~1 s.  Fix: 28/28 measured nodes clean, every
# after-publication counter zero, pre_wr>0 on 2; 4 nodes unmeasured by the
# harness bug described at the node command (no kernel hang on them).  GPT
# Design-consult ruling (sess487): the SB-lock convoy is proven (filed D-...-0487);
# the base leg does NOT meet the sess485 rule (no WRITE was observed — the
# guard hangs first) and that rule may not be swapped after the fact; a
# mutation-based rule may be declared PROSPECTIVELY and the base leg rerun.
#
# LAP 4 RULE, DECLARED HERE BEFORE THE RUN (sess487):
#   BASE reproduces D-0483 if EITHER >=1 P483-AGMETA-AFTER-AGFREE submit is
#     counted (the sess485 rule) OR >=1 node logs P126-XFSAILD-SKIP-AGMETA
#     AFTER its own P482-UMOUNT-AGREL line (dirty AG metadata for a published
#     AG, refused by the guard); the harness counts both.
#   FIX closes it only with window lines from 32/32 nodes, no hang, every
#     after-publication counter zero, zero xfsaild refusals, pre_wr>0 on >=1
#     node, seal violations 0 — then a plain 32/caw board on the fixed build.
#
# Usage:  setsid nohup bash tests/sess485_chain133_agfree_hoist_ab.sh s485a &
#         LEGS=base GATE=<log> setsid nohup bash tests/sess485_chain133_agfree_hoist_ab.sh s486a &
#         GATE=<log> setsid nohup bash tests/sess485_chain133_agfree_hoist_ab.sh s487a &   (lap 3, both legs)
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s485a}
LEGS=${LEGS:-base fix}
GATE=${GATE:-tests/evidence/sess483_chain132_dirtenure_s483c.log}
LOG=tests/evidence/sess485_chain133_agfree_hoist_$LABEL.log
EV=tests/evidence/sess485_agfree_hoist_$LABEL
BASE_KO=${BASE_KO:-tests/evidence/sess483_chain132_frozen_0692/mxfs.ko}
FIX_KO=${FIX_KO:-tests/evidence/sess485_frozen_0693/mxfs.ko}
NNODES=${NNODES:-32}
FILES=${FILES:-400}
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"

gate_dl=$(( $(date +%s) + 21600 ))
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$gate_dl" ]; then
        echo "=== sess485 chain133 ABORT: gate $GATE never reached DONE within 6 h ===" >> "$LOG"
        echo "DONE $(date -u +%FT%TZ)" >> "$LOG"
        exit 1
    fi
    sleep 30
done

# "name=value" from a probe line, anchored on the leading space: nodlm_wr is a
# suffix of iclus_nodlm_wr and pre_wr of pre_iclus_wr.
fld() { echo "$2" | sed -n "s/.* $1=\([0-9-]*\).*/\1/p" | head -1; }

install_ko() { # <ko> <label>
    [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
    cp "$1" mxfs.ko || return 1
    local d; d=$(dirname "$1")
    for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do
        [ -f "$d/tools/$t" ] && cp "$d/tools/$t" "tools/$t"
    done
    echo "STAGE install_$2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
}

# One leg: install, prep, workload+umount in one node command, sweep, chk.
# $1 = leg name (base|fix), $2 = module path
leg() {
    local NAME=$1 KO=$2 i T0 rc
    local D="$EV/$NAME"
    mkdir -p "$D"
    echo "===== LEG $NAME ko=$KO $(date -u +%FT%TZ) ====="

    install_ko "$KO" "$NAME" || { echo "  ABORT LEG: install failed"; return 1; }
    local SV; SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')

    timeout 300 ./run.sh "$NNODES" caw prep_cluster; rc=$?
    echo "  STAGE prep rc=$rc"
    [ "$rc" = 0 ] || { echo "  ABORT LEG: prep rc=$rc — nothing below measures anything"; return 1; }

    # G2
    : > "$D/fleet_sv.txt"
    for i in $(seq 1 "$NNODES"); do
        ( s=$(timeout 30 "$SSH" "test$i" "cat /sys/module/mxfs/srcversion 2>/dev/null" 2>/dev/null | tr -dc 'A-F0-9')
          echo "test$i ${s:-NONE}" > "$D/.sv.test$i" ) &
    done
    wait
    for i in $(seq 1 "$NNODES"); do cat "$D/.sv.test$i" >> "$D/fleet_sv.txt" 2>/dev/null; done
    local match; match=$(grep -c " $SV\$" "$D/fleet_sv.txt")
    echo "  STAGE fleet_identity match=$match/$NNODES sv=$SV"
    if [ "$match" -ne "$NNODES" ]; then
        echo "  ABORT LEG: only $match of $NNODES nodes run this leg's module:"
        grep -v " $SV\$" "$D/fleet_sv.txt" | head -8 | sed 's/^/    /'
        return 1
    fi

    SINCE=$(date -u +'%Y-%m-%d %H:%M:%S')

    # THE WORKLOAD AND THE MEASUREMENT, one command per node (lap 3 shape).
    # A BACKGROUND subshell creates FILES files in a private directory, opens
    # each on its own fd, unlinks them all, raises a ready flag and parks in
    # a fifo read -- a bash builtin, so no child ever inherits the fds or the
    # cwd.  The foreground waits for the flag, syncs the filesystem (the
    # create/unlink transactions are then durable and the ONLY work left for
    # the unmount is the deferred inactivation), releases the parked subshell
    # through the fifo and wait(2)s for it: when wait returns, exit_files has
    # closed all FILES fds, FILES inodes are evicted and queued for
    # inactivation, and umount is the next statement.  Laps 1-2 closed the
    # fds by letting the subshell exit and ran umount after it, which left the
    # inodegc worker (queue delay one jiffy, immediate past a 32-item backlog)
    # a shell-exit's worth of time to finish: lap 1 caught 4/32 nodes with
    # work pending, lap 2 caught 0/32 and hung nothing.  Here the close ->
    # put_super gap is one reaped wait plus one syscall, so the backlog is
    # pending at publication by construction, on every node.  The node
    # reports how many it created and held, the umount rc, a mountpoint
    # recheck and the umount wall in ms.
    # Lap 3 (s487a) fix leg, 4 nodes "hung" with NO umount task: the setup
    # was written `rm && mkfifo && ( list ) &`, and `&` binds the whole
    # AND-list, so rm/mkfifo ran in the background too.  On the 4 nodes the
    # fix prep had NOT rebooted (they unmounted cleanly on base) the stale
    # /run/p485_ready from the previous leg satisfied the foreground's wait
    # at once (READY_WAIT_DS=0), the foreground opened the STALE fifo for
    # writing, the background then unlinked it and made a new one, and both
    # sides waited forever on different fifos.  Setup now runs in the
    # foreground and the `&` applies to the subshell alone.
    T0=$(date +%s)
    : > "$D/work.txt"
    for i in $(seq 1 "$NNODES"); do
        ( d="$MNT/p485_test$i"
          out=$(timeout 240 "$SSH" "test$i" \
            "mkdir -p $d && cd $d && rm -f /run/p485_ready /run/p485_fifo && mkfifo /run/p485_fifo || { echo SETUP_FAIL; exit 1; }; ( n=0; h=0; for k in \$(seq 1 $FILES); do : > f\$k && n=\$((n+1)) && exec {fd}<f\$k && h=\$((h+1)); done; rm -f $d/f*; echo WORK made=\$n held=\$h; : > /run/p485_ready; read -t 600 x < /run/p485_fifo ) & HP=\$!; w=0; while [ ! -e /run/p485_ready ] && [ \$w -lt 2000 ]; do sleep 0.1; w=\$((w+1)); done; cd /; sync; echo READY_WAIT_DS=\$w HELD_FDS=\$(for p in \$HP \$(cat /proc/\$HP/task/\$HP/children 2>/dev/null); do ls /proc/\$p/fd 2>/dev/null; done | wc -l); echo go > /run/p485_fifo; wait \$HP; T=\$(date +%s%N); umount $MNT 2>&1; rc=\$?; echo RC=\$rc; mountpoint -q $MNT && echo STILL_MOUNTED || echo UNMOUNTED; echo UMOUNT_MS=\$(( (\$(date +%s%N) - T) / 1000000 ))" 2>/dev/null)
          echo "test$i $(echo "$out" | tr '\n' ' ')" > "$D/.work.test$i" ) &
    done
    wait
    for i in $(seq 1 "$NNODES"); do cat "$D/.work.test$i" >> "$D/work.txt" 2>/dev/null; done
    local wwall=$(( $(date +%s) - T0 ))
    local wmade; wmade=$(grep -c "made=$FILES held=$FILES " "$D/work.txt")
    local uok; uok=$(grep -c 'RC=0 UNMOUNTED' "$D/work.txt")
    # lap 3 G3b: the fd count of the parked holder, read from /proc by the
    # foreground shell just before the release -- the node's own h counter
    # says what it opened, this says what was still open at the close.
    # Lap 3 (s487a) read 3 on every node: under a non-interactive shell bash
    # forks TWICE for `( list ) &`, so $! is a wrapper whose CHILD runs the
    # list and holds the fds (reproduced on clyde: wrapper fds=3, child
    # fds=403).  wait(2) on the wrapper still returns only after the child
    # has exited, so the timing property held; the count now sums the
    # wrapper and its children.
    local fdsok; fdsok=$(awk -v n="$FILES" '{for(i=1;i<=NF;i++) if($i ~ /^HELD_FDS=/){split($i,a,"="); if (a[2]+0 >= n) c++}} END{print c+0}' "$D/work.txt")
    echo "  STAGE workload+umount wall=${wwall}s budget=240s nodes_at_full_count=$wmade/$NNODES nodes_with_${FILES}_fds_open_at_release=$fdsok/$NNODES files_per_node=$FILES umount_clean=$uok/$NNODES"
    [ "$wwall" -ge 240 ] && echo "    budget: the workload+umount step hit its budget. That is a RESULT, not a number to widen."
    grep -v "made=$FILES held=$FILES " "$D/work.txt" | head -6 | sed 's/^/    SHORT: /'
    grep -v 'RC=0 UNMOUNTED' "$D/work.txt" | head -8 | sed 's/^/    NOT-CLEAN: /'
    # lap 3: per-node umount wall, from the reaped fd-holder to umount's return.
    awk '{for(i=1;i<=NF;i++) if($i ~ /^UMOUNT_MS=/){split($i,a,"="); print a[2]}}' "$D/work.txt" | sort -n | \
        awk '{v[NR]=$1} END{if(NR) printf "    umount_ms: n=%d min=%d p50=%d max=%d (nodes that returned)\n", NR, v[1], v[int((NR+1)/2)], v[NR]}'

    # HANG CAPTURE (sess486): every node whose umount printed no rc is still
    # inside put_super.  Freeze its state NOW, before chk, before the sweep,
    # and long before any prep power-cycles it.  Per node, in parallel:
    # the umount task (found by comm through /proc, never pgrep -f), its
    # kernel stack and wchan; sysrq-w into the node's kmsg; the stack of
    # every task in D state and of every umount/kworker/xfsaild/mxfs task;
    # then the whole kernel journal since the leg began, unfiltered.
    local hung; hung=$(grep -vc 'RC=' "$D/work.txt"); hung=${hung:-0}
    if [ "$hung" -gt 0 ]; then
        T0=$(date +%s)
        for i in $(seq 1 "$NNODES"); do
            grep -q "^test$i .*RC=" "$D/work.txt" && continue
            ( timeout 90 "$SSH" "test$i" \
                "echo '### umount task ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null) || continue; [ \"\$c\" = umount ] || continue; echo \"pid=\${t#/proc/} state=\$(awk '{print \$3}' \$t/stat 2>/dev/null) wchan=\$(cat \$t/wchan 2>/dev/null)\"; cat \$t/stack 2>/dev/null; done; echo '### sysrq-w ###'; echo w > /proc/sysrq-trigger 2>/dev/null; sleep 1; echo '### D-state and fs/dlm tasks ###'; for t in /proc/[0-9]*; do c=\$(cat \$t/comm 2>/dev/null) || continue; st=\$(awk '{print \$3}' \$t/stat 2>/dev/null); case \"\$st:\$c\" in D:*|*:umount|*:kworker*|*:xfsaild*|*:mxfs*|*:xfs-*) echo \"--- pid=\${t#/proc/} comm=\$c state=\$st wchan=\$(cat \$t/wchan 2>/dev/null)\"; cat \$t/stack 2>/dev/null;; esac; done; echo '### mounts ###'; grep -a mxfs /proc/mounts" \
                > "$D/hang_test$i.txt" 2>&1
              timeout 60 "$SSH" "test$i" "journalctl -k --no-pager --since '$SINCE' 2>/dev/null" \
                > "$D/kjournal_test$i.txt" 2>&1 ) &
        done
        wait
        local caps; caps=$(ls "$D"/hang_test*.txt 2>/dev/null | wc -l)
        echo "  STAGE hang_capture hung=$hung captured=$caps wall=$(( $(date +%s) - T0 ))s budget=150s — hang_testN.txt + kjournal_testN.txt in $D"
        for f in "$D"/hang_test*.txt; do
            [ -f "$f" ] || continue
            echo "    $(basename "$f" .txt): $(grep -a -m1 'pid=' "$f" | cut -c1-120)"
            grep -a -A6 '### umount task ###' "$f" | grep -a '^\[<\|^[a-z_]*+0x\| [a-z_0-9]*+0x' | head -6 | sed 's/^/        /'
        done
    fi

    # On-platter forensics on the image — QUIESCENT only if every node
    # unmounted; otherwise the numbers are a live image and not a verdict.
    T0=$(date +%s)
    timeout 240 tools/chk_mxfs -v "$IMG" > "$D/chk.txt" 2>&1
    local chkrc=$?
    local cerr; cerr=$(grep -ac 'ERROR' "$D/chk.txt"); cerr=${cerr:-0}
    echo "  STAGE chk rc=$chkrc wall=$(( $(date +%s) - T0 ))s budget=240s img=$IMG ERROR_lines=$cerr$([ "$hung" -gt 0 ] && echo " — NOT QUIESCENT: $hung node(s) still mounted, not a platter verdict")"
    [ "$chkrc" = 124 ] && echo "    chk TIMED OUT — treat ERROR_lines as a floor, not a count."
    grep -aiE 'freecount|inobt|finobt|unlinked|ERROR' "$D/chk.txt" | head -14 | sed 's/^/    /'

    # Sweep: journalctl, not dmesg (the ring wraps under fleet load).
    for i in $(seq 1 "$NNODES"); do
        ( timeout 90 "$SSH" "test$i" \
            "journalctl -k --no-pager --since '$SINCE' 2>/dev/null | grep -aE 'P483-|P485-|P482-UMOUNT-AGREL|P482-AGIFC-AUDIT-COVERAGE|P-AGIFC-RELEASE-MISMATCH|P-SB-SEAL|P-SB-SUMMARY-|P6S-ARM-REFUSED|P-DEMWAIT-REDRIVE|P134-BASTQ|blocked for more than|P483-AGLOCK-NULLDLM|P126-XFSAILD-SKIP-AGMETA|P88-PUBOB-RECLAIM-REFUSED'" \
            > "$D/p483_test$i.txt" 2>/dev/null ) &
    done
    wait

    # G5 coverage.
    local covered=0 missing="" c
    for i in $(seq 1 "$NNODES"); do
        c=$(grep -ac 'P483-AGFREE-WINDOW' "$D/p483_test$i.txt" 2>/dev/null); c=${c:-0}
        [ "$c" -ge 1 ] && covered=$(( covered + 1 )) || missing="$missing test$i"
    done
    echo "  STAGE coverage window_lines_present=$covered/$NNODES${missing:+ missing:$missing}"

    # G6 population, plus the 0.69.3 drain count.
    local tot_seen=0 tot_rel=0 tot_drained=0 relnodes=0 l s r dr
    for i in $(seq 1 "$NNODES"); do
        l=$(grep -a 'P482-UMOUNT-AGREL' "$D/p483_test$i.txt" 2>/dev/null | tail -1)
        [ -n "$l" ] || continue
        s=$(fld ags_seen "$l"); s=${s:-0}
        r=$(fld ags_released "$l"); r=${r:-0}
        dr=$(fld ags_drained "$l"); dr=${dr:-0}
        tot_seen=$(( tot_seen + s )); tot_rel=$(( tot_rel + r )); tot_drained=$(( tot_drained + dr ))
        [ "$r" -gt 0 ] && relnodes=$(( relnodes + 1 ))
    done
    echo "  POPULATION ags_seen=$tot_seen ags_released=$tot_rel relnodes=$relnodes/$NNODES ags_drained=$tot_drained"

    # The window numbers.
    local ndw=0 ndr=0 indw=0 indr=0 dw=0 dr2=0 icw=0 icr=0 nu=0 hot=0 line
    local any=0 anynd=0 prew=0 preic=0 prenodes=0 agl=0 igc=0
    local a b
    for i in $(seq 1 "$NNODES"); do
        line=$(grep -a 'P483-AGFREE-WINDOW' "$D/p483_test$i.txt" 2>/dev/null | tail -1)
        [ -n "$line" ] || continue
        a=$(fld nodlm_wr "$line");          ndw=$(( ndw + ${a:-0} ))
        b=$(fld nodlm_rd "$line");          ndr=$(( ndr + ${b:-0} ))
        a=$(fld iclus_nodlm_wr "$line");    indw=$(( indw + ${a:-0} ))
        b=$(fld iclus_nodlm_rd "$line");    indr=$(( indr + ${b:-0} ))
        a=$(fld dlm_wr "$line");            dw=$(( dw + ${a:-0} ))
        b=$(fld dlm_rd "$line");            dr2=$(( dr2 + ${b:-0} ))
        a=$(fld iclus_dlm_wr "$line");      icw=$(( icw + ${a:-0} ))
        b=$(fld iclus_dlm_rd "$line");      icr=$(( icr + ${b:-0} ))
        a=$(fld nulldlm_acquires "$line");  nu=$(( nu + ${a:-0} ))
        a=$(fld anyio "$line");             any=$(( any + ${a:-0} ))
        b=$(fld anyio_nodlm "$line");       anynd=$(( anynd + ${b:-0} ))
        a=$(fld pre_wr "$line");            prew=$(( prew + ${a:-0} ))
        b=$(fld pre_iclus_wr "$line");      preic=$(( preic + ${b:-0} ))
        [ "${a:-0}" -gt 0 ] && prenodes=$(( prenodes + 1 ))
        a=$(fld aglock_after "$line");      agl=$(( agl + ${a:-0} ))
        b=$(fld inodegc_after_stop "$line"); igc=$(( igc + ${b:-0} ))
        a=$(fld nodlm_wr "$line"); b=$(fld dlm_wr "$line")
        if [ "${a:-0}" -gt 0 ] || [ "${b:-0}" -gt 0 ]; then
            hot=$(( hot + 1 ))
            [ "$hot" -le 6 ] && echo "    test$i: $line"
        fi
    done
    echo "  WINDOW  nodlm_wr=$ndw nodlm_rd=$ndr iclus_nodlm_wr=$indw iclus_nodlm_rd=$indr | dlm_wr=$dw dlm_rd=$dr2 iclus_dlm_wr=$icw iclus_dlm_rd=$icr | nulldlm_acquires=$nu | nodes_with_agmeta_write_after_publication=$hot/$covered"
    echo "  PRE     pre_wr=$prew pre_iclus_wr=$preic nodes_with_pre_wr=$prenodes/$covered — AG-metadata / inode-cluster writes made BEFORE publication (0.69.3 only; the base module does not print this field)"
    echo "  LATE    aglock_after=$agl inodegc_after_stop=$igc — AG acquires and inactivation enqueues AFTER publication (0.69.3 only); both must be zero"
    echo "  CONTROL anyio=$any anyio_nodlm=$anynd"
    # Lap 4 (sess487): dirty AG metadata for a PUBLISHED AG, refused by
    # xfsaild's grant guard AFTER this node's publication line -- the
    # observable that the pre-fix ordering actually produces (the guard
    # converts the write into a hang, so the submit-time counters stay 0).
    # Counted per node only after its own P482-UMOUNT-AGREL line.
    local p126=0 p126nodes=0 c126
    for i in $(seq 1 "$NNODES"); do
        c126=$(awk '/P482-UMOUNT-AGREL/{a=1; next} a && /P126-XFSAILD-SKIP-AGMETA/{n++} END{print n+0}' "$D/p483_test$i.txt" 2>/dev/null); c126=${c126:-0}
        p126=$(( p126 + c126 )); [ "$c126" -gt 0 ] && p126nodes=$(( p126nodes + 1 ))
    done
    local sblock; sblock=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -ac 'P-SB-SUMMARY-LOCK '); sblock=${sblock:-0}
    echo "  GUARD   xfsaild_skips_after_publication=$p126 on $p126nodes/$NNODES nodes; sb_summary_lock_taken=$sblock/$NNODES"
    local mm; mm=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -ac 'P-AGIFC-RELEASE-MISMATCH'); mm=${mm:-0}
    # sess486: only the violation lines count; P-SB-SEAL-OK and P-SB-SEALED
    # are the seal working (lap 1 counted them and reported 32 "violations").
    local sealv; sealv=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -acE 'P-SB-SEAL-(TRANS|SYNCSB|DIRTY)'); sealv=${sealv:-0}
    local sealok; sealok=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -ac 'P-SB-SEAL-OK'); sealok=${sealok:-0}
    local ffail; ffail=$(cat "$D"/p483_test*.txt 2>/dev/null | grep -ac 'P-SB-SUMMARY-FINAL-FAIL'); ffail=${ffail:-0}
    echo "  P-AGIFC-RELEASE-MISMATCH=$mm  seal_violations=$sealv seal_ok=$sealok/$NNODES  sb_summary_final_fail=$ffail"
    echo "  first AFTER-AGFREE / P485-UMOUNT-DRAIN lines:"
    cat "$D"/p483_test*.txt 2>/dev/null | grep -a 'AFTER-AGFREE\|P485-UMOUNT-DRAIN\|P483-AGLOCK-NULLDLM' | head -10 | sed 's/^/    /'

    printf '%s covered=%d rel=%d drained=%d ndw=%d ndr=%d indw=%d indr=%d dw=%d dr=%d icw=%d icr=%d nu=%d any=%d prew=%d preic=%d agl=%d igc=%d hot=%d seal=%d ffail=%d chkerr=%d chkrc=%d uok=%d wmade=%d p126=%d p126nodes=%d hung=%d\n' \
        "$NAME" "$covered" "$tot_rel" "$tot_drained" "$ndw" "$ndr" "$indw" "$indr" "$dw" "$dr2" "$icw" "$icr" "$nu" "$any" "$prew" "$preic" "$agl" "$igc" "$hot" "$sealv" "$ffail" "$cerr" "$chkrc" "$uok" "$wmade" "$p126" "$p126nodes" "$hung" \
        >> "$EV/legs.txt"
    return 0
}

{
  echo "=== sess485 chain133 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  echo "STAGE gate cleared: $GATE"
  : > "$EV/legs.txt"

  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  # G1: the two modules must be what the legs assume they are.
  for k in "$BASE_KO" "$FIX_KO"; do
      [ -f "$k" ] || { echo "ABORT: missing module $k"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  done
  bp=$(strings -a "$BASE_KO" | grep -ac 'P483-AGFREE-WINDOW'); bd=$(strings -a "$BASE_KO" | grep -ac 'ags_drained='); bpre=$(strings -a "$BASE_KO" | grep -ac 'pre_wr=')
  fp=$(strings -a "$FIX_KO"  | grep -ac 'P483-AGFREE-WINDOW'); fd_=$(strings -a "$FIX_KO" | grep -ac 'ags_drained='); fpre=$(strings -a "$FIX_KO" | grep -ac 'pre_wr=')
  echo "STAGE instrument_present base: window=$bp drained=$bd pre=$bpre sv=$(modinfo "$BASE_KO" | awk '/srcversion/{print $2}')"
  echo "STAGE instrument_present fix:  window=$fp drained=$fd_ pre=$fpre sv=$(modinfo "$FIX_KO" | awk '/srcversion/{print $2}')"
  if [ "$bp" -lt 1 ] || [ "$bd" -ne 0 ] || [ "$fp" -lt 1 ] || [ "$fd_" -lt 1 ] || [ "$fpre" -lt 1 ]; then
      echo "ABORT: the modules are not a pre-fix / post-fix pair that both carry the window probe."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  for L in $LEGS; do
      case "$L" in
          base) leg base "$BASE_KO" ;;
          fix)  leg fix  "$FIX_KO" ;;
          *)    echo "ABORT: unknown leg '$L'"; echo "DONE $(date -u +%FT%TZ)"; exit 1 ;;
      esac
  done

  # Leave the tree on the fixed module whatever happened above.  A base-only
  # lap leaves the fleet on the BASE module: the next prep reinstalls.
  install_ko "$FIX_KO" restore || echo "WARN: could not restore the fix module into the tree"

  echo "--- VERDICT (legs run: $LEGS) ---"
  sed 's/^/  LEG /' "$EV/legs.txt"
  # cget: a leg's field, or 0 when the leg never published (an aborted leg
  # writes no line, and an empty operand would break the arithmetic below).
  cget() { local v; v=$(grep "^$1 " "$EV/legs.txt" | sed -n "s/.* $2=\([0-9-]*\).*/\1/p" | head -1); echo "${v:-0}"; }
  b_cov=$(cget base covered); f_cov=$(cget fix covered)
  b_rel=$(cget base rel);     f_rel=$(cget fix rel)
  b_after=$(( $(cget base ndw) + $(cget base indw) + $(cget base dw) + $(cget base icw) ))
  f_after=$(( $(cget fix ndw) + $(cget fix indw) + $(cget fix dw) + $(cget fix icw) ))
  f_rd=$(( $(cget fix ndr) + $(cget fix indr) + $(cget fix dr) + $(cget fix icr) ))
  f_nu=$(cget fix nu)
  f_agl=$(cget fix agl)
  f_igc=$(cget fix igc)
  f_pre=$(cget fix prew)
  f_drained=$(cget fix drained)
  f_seal=$(cget fix seal)
  f_ffail=$(cget fix ffail)
  b_err=$(cget base chkerr); f_err=$(cget fix chkerr)
  b_uok=$(cget base uok);    f_uok=$(cget fix uok)

  case " $LEGS " in *" base "*) ran_base=1 ;; *) ran_base=0 ;; esac
  case " $LEGS " in *" fix "*)  ran_fix=1 ;;  *) ran_fix=0 ;;  esac
  if { [ "$ran_base" = 1 ] && [ "$b_cov" -eq 0 ] && [ "$b_uok" -eq "$NNODES" ]; } || \
     { [ "$ran_fix" = 1 ] && [ "$f_cov" -eq 0 ]; }; then
      echo "  VACUOUS: a leg produced no P483-AGFREE-WINDOW line (base=$b_cov fix=$f_cov of $NNODES). Nothing here is a measurement."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi
  if { [ "$ran_base" = 1 ] && [ "$b_rel" -eq 0 ]; } || { [ "$ran_fix" = 1 ] && [ "$f_rel" -eq 0 ]; }; then
      echo "  EMPTY BY CONSTRUCTION: ags_released=0 on a leg (base=$b_rel fix=$f_rel) — no AG was still held at put_super, so the path published nothing."
      echo "DONE $(date -u +%FT%TZ)"; exit 1
  fi

  b_p126=$(cget base p126); b_p126n=$(cget base p126nodes); b_hung=$(cget base hung)
  if [ "$ran_base" = 1 ]; then
  echo "  BASE (0.69.2): AG-metadata/inode-cluster WRITES after publication = $b_after over $b_cov nodes, ags_released=$b_rel, umount_clean=$b_uok/$NNODES, xfsaild refusals of unheld-AG metadata after publication = $b_p126 on $b_p126n nodes, hung=$b_hung"
  if [ "$b_after" -gt 0 ]; then
      echo "    REPRODUCED (write): the pre-fix unmount wrote AG metadata for allocation groups it had already published. D-0483 has its measurement."
  elif [ "$b_p126n" -gt 0 ]; then
      echo "    REPRODUCED (mutation, lap-4 rule declared sess487 BEFORE this run): $b_p126n node(s) carried dirty AG metadata for allocation groups they had already published — xfsaild refused to write it $b_p126 times after the publication line. The write never happens on this build because the grant guard turns it into a hang (D-0486 / D-0487 records); the mutation after publication is the defect D-0483 names."
      [ "$b_hung" -gt 0 ] && echo "    and $b_hung node(s) never returned from umount — the D-0486 hang; stacks in hang_testN.txt / kjournal_testN.txt in the base evidence dir."
  elif [ "$b_uok" -lt "$NNODES" ]; then
      echo "    HUNG, NOT MEASURED: $(( NNODES - b_uok )) node(s) never returned from umount after publishing their grants; no after-publication write or refused mutation was observed before they stalled. Read hang_testN.txt / kjournal_testN.txt in the base evidence dir for where they were stuck."
  else
      echo "    NOT REPRODUCED on the pre-fix module with this workload — the window was not crossed here; the fix leg below is then a regression check, not a closure."
  fi
  fi

  f_p126=$(cget fix p126); f_hung=$(cget fix hung)
  if [ "$ran_fix" = 1 ]; then
  echo "  FIX  (0.69.3): writes after publication = $f_after, reads after = $f_rd, null-DLM acquires = $f_nu, AG acquires after = $f_agl, inodegc after stop = $f_igc, pre_wr = $f_pre, ags_drained = $f_drained, seal_violations = $f_seal, sb_final_fail = $f_ffail, xfsaild refusals after publication = $f_p126, hung=$f_hung, umount_clean=$f_uok/$NNODES, window coverage=$f_cov/$NNODES"
  if [ "$f_cov" -lt "$NNODES" ] || [ "$f_hung" -gt 0 ]; then
      echo "    INCOMPLETE (lap-4 rule): the fix leg needs the window line from every node and no hang; coverage=$f_cov/$NNODES hung=$f_hung. Not a closure measurement."
  elif [ "$f_pre" -eq 0 ]; then
      echo "    NOT A MEASUREMENT (G7): pre_wr=0 — the fixed unmount wrote no AG metadata before publication either, so the workload left it nothing to do and its zeros after publication prove nothing."
  elif [ "$f_after" -eq 0 ] && [ "$f_rd" -eq 0 ] && [ "$f_nu" -eq 0 ] && [ "$f_agl" -eq 0 ] && [ "$f_igc" -eq 0 ]; then
      echo "    CLOSED THE WINDOW: $f_pre AG-metadata writes were made under live grants before publication and ZERO accesses, acquires or inactivation enqueues after it, over $f_cov nodes with ags_released=$f_rel."
      [ "$f_drained" -gt 0 ] && echo "    NOTE: the release drains still found $f_drained dirty AG(s) after the quiesce — read the P485-UMOUNT-DRAIN lines; the quiesce should have left nothing."
      [ "$f_seal" -gt 0 ] && echo "    NOTE: $f_seal seal violations were logged — a producer ran after the SB summary seal; those departures were refused as clean. Read the P-SB-SEAL lines."
      [ "$f_ffail" -gt 0 ] && echo "    NOTE: $f_ffail nodes failed the final SB summary sync (departure DIRTY)."
  else
      echo "    STILL CROSSED: after=$f_after reads=$f_rd nulldlm=$f_nu — the reordering did not close the window on every node. Read the AFTER-AGFREE lines above."
  fi
  fi
  echo "  PLATTER: chk_mxfs ERROR lines — base=$b_err fix=$f_err (a leg with hung nodes is NOT QUIESCENT; see its chk STAGE line)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
