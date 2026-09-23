#!/bin/bash
# tests/post_closure_renewal_at_peer.sh — what a PEER does with membership lease
# renewals that keep arriving from a node whose local authority has CLOSED.
# (ledger D-POST-CLOSURE-MEMBERSHIP-RENEWAL-HAS-NO-DEFINED-MEANING-AT-THE-PEER)
#
# WHY IT EXISTS.  The sender side is settled by reading: mxfs_lease_renew_fn
# (dlm/lease.c:47-114) loops on `while (ctx->running)` and consults no
# withdrawal flag, no authority state and no shutdown flag, so a withdrawn
# mount that is still LOADED keeps renewing.  The receiver side is settled to
# the same depth: mxfs_lease_process_renewal (dlm/lease.c:651-689) stamps
# liveness, zeroes missed_renewals, and promotes JOINING or SUSPECT to ACTIVE
# unconditionally, with an epoch argument that is the literal 0 on every UDP
# packet because the wire message has no epoch field.  What NO lap has observed
# is what the two do to each other on a live cluster, and that is the whole of
# what is left in this record:
#
#   (b) with the withdrawn node still renewing, does the peer still fence and
#       replay its dirty slice on the ordinary schedule — and WHICH detector
#       fired?  Reading says the lease path alone could never get there (a node
#       that keeps renewing resets missed_renewals to 0 on every packet and so
#       never reaches SUSPECT->DEAD, which is the only route into
#       lease_expire_cb).  Reading also says a SECOND detector gets there
#       first: the WITHDRAWN stamp in the on-disk heartbeat slot, which
#       disklock_hb_fn classifies on sight and takes straight to fire_dead.
#       Both are predictions.  This lap records which one actually fired.
#
#   (a') is the withdrawn node's membership entry at the peer RESURRECTED?  The
#       renewal cannot do it alone — mxfs_lease_process_renewal takes the
#       -ENOENT branch and creates nothing when recovery has removed the entry
#       — but mxfs_lease_register_node has three call sites on this transport
#       and two of them are the UDP DISCOVERY ANNOUNCE handler and the TCP
#       peer-connect callback.  Whether the withdrawn node's announce thread
#       keeps running is the named, unmeasured precondition.  The kernel log
#       discriminates the two paths exactly: a promotion that says "(was
#       JOINING)" means something RE-REGISTERED a node the peer had already
#       recovered; "(was SUSPECT)" means the entry was never removed and the
#       renewal alone promoted it.  Both are resurrection; they are different
#       bugs and this lap does not conflate them.
#
#   (c) with the peer possibly holding the withdrawn node as a live member,
#       does a request for a resource that node still MASTERS complete, or does
#       it park?  That is the property the freeze is actually for, and a peer
#       that forwards a grant to a corpse is a hang — which the release bar
#       refuses on its own terms, independently of any data question.
#
# WHAT IS BEING HELD STILL.  The node that withdraws is NOT unmounted, NOT
# rebooted and NOT rmmod'd.  Its module stays loaded for the whole lap, because
# `while (ctx->running)` is the entire precondition of the record and unloading
# the module is precisely what clears it.  A lap that tore the node down would
# measure a clean departure and report it as this record's answer.
#
# THE OBSERVABLE SURFACE IS THE KERNEL LOG AND NOTHING ELSE.  There is no
# procfs, sysfs, debugfs, module parameter or ioctl anywhere in the tree that
# exposes the in-memory mxfs_node_lease table (established s125 over 4
# proc_create, 16 debugfs_create_file, 0 DEVICE_ATTR, 1 sysfs_create_file and
# 645 module_param sites).  tools/chk_mxfs reads the ON-DISK disklock slot
# table, a different structure.  So every membership verdict here is taken from
# four lines, all at levels that reach dmesg by default:
#   "lease: node %u transitioned to ACTIVE (was %s)"           INFO  lease.c:680
#   "mxfs: heartbeat received from unknown node %u"            WARN  lease.c:667
#   "mxfs: node %u may be unreachable (missed %d heartbeats"   WARN  lease.c:253
#   "mxfs: node %u has left the cluster (no heartbeat for"     WARN  lease.c:280
# The registration line itself is DEBUG and will not appear, which is why the
# re-registration is inferred from "(was JOINING)" rather than looked for.
#
# THE DIRTY SLICE IS THE POINT.  The hazard this record states is that a peer
# reading a renewal as membership defers or skips the recovery of a slice that
# is dirty, which is silent loss.  So the withdrawal is injected MID-rm, with
# committed-but-unreplayed unlink work in the withdrawing node's journal slice
# — the same shape tests/withdraw_recovery_test.sh reproduces — and the oracle
# is read back from the peer afterwards.  A withdrawal with a clean slice would
# leave the peer nothing to defer and the lap would measure nothing.
#
# WHAT IS ASSERTED
#   - the withdrawing node stamped WITHDRAWN and its module is still loaded;
#   - the peer's detector was the WITHDRAWN stamp (P163-WITHDRAW-SEEN), and
#     which of the lease-path lines also appeared is recorded either way;
#   - the peer replayed the dirty slice to completion (P163-RECOVERY-COMPLETE)
#     while the renewals were still arriving;
#   - after that recovery, the peer does NOT promote the withdrawn node's
#     membership entry back to ACTIVE — asserted separately for "(was SUSPECT)"
#     (the renewal alone) and "(was JOINING)" (something re-registered it);
#   - a workload on the peer that must take resources the withdrawn node
#     mastered COMPLETES inside its derived bound;
#   - every file the withdrawing node fsynced before the withdrawal is present
#     and byte-identical read from the peer, and the namespace it was tearing
#     down carries no dangling dirent;
#   - no shutdown, BUG or Oops on the peer, and the peer is still mounted.
#
# THE BUDGET (derived; a timeout is a failure and never a safety net):
#   prep 300 (measured 233) + identities and baseline 25 + the 64-file oracle
#   and the doomed tree 30 + the injection 15 + the peer seeing the stamp 60
#   (measured 8 ms behind the stamp, so this is nearly all slack) + the slice
#   replayed to completion 120 (the COMPLETE banner waits on the
#   disklock_purge_node zeroing pass: ~4 s on the VM/SCST rig, 31 s measured on
#   the QNAP physrig) + 30 s of renewal observation (the renew thread runs
#   every ~500 ms, so 30 s is 60 renewals) + the resurrection window 30 + the
#   conflicting-grant workload, whose bound is DERIVED INSIDE THE LAP from the
#   wall its own build took (that build made NFILES+DOOMED files on a healthy
#   two-node cluster; the workload makes DOOMED of them with the peer gone, so
#   the same wall plus 30 s is a bound the lap has already earned) — budget it
#   here at the 60 s floor + the oracle read and the namespace walk 60 + final
#   captures and cleanup 60  =  790.
#   Caller bound 800 s, plus up to 150 s of boot when the domains start
#   powered off — caller bound 950 s.
#
# THE SUSPECT-FIRST ARM (SUSPECT_FIRST=1, 0.89.66).  s133z answered (b) and
# (c) and showed why 2(a) could not be measured on that schedule: the peer's
# WITHDRAWN detector unregisters the entry within seconds of the stamp, so the
# entry passes from ACTIVE to removed without ever being SUSPECT, and the one
# promotion the code reading identified (SUSPECT -> ACTIVE, dlm/lease.c:678-685)
# has nothing to act on.  This arm makes the entry SUSPECT FIRST: before the
# withdrawal the peer is made to stop HEARING the withdrawing node's renewals —
# an inbound drop of UDP port 7603 on the peer; the TCP DLM, the disklock
# heartbeat and every other packet are untouched, so nothing declares the node
# dead — until the lease monitor logs "node %u may be unreachable" (the 60 s
# duration window plus MXFS_LEASE_SUSPECT_MISSES=150 misses at the 2 s monitor
# interval = 360 s, a constant of the module and not patience).  The authority
# is then closed while the entry is SUSPECT and the drop is removed the instant
# the injection returns, so the renewals that resume are POST-closure renewals
# landing on a SUSPECT entry.  Whether they promote it is READ from the peer's
# ring between the stamp and the recovery; whether such a promotion DEFERS the
# replay of the dirty slice is what section 5's recovery bound GRADES, and the
# post-recovery assertions are unchanged.  The drop is removed on every exit.
# Budget for the arm: the ordinary lap + 400 s for the SUSPECT wait = 1200 s;
# caller bound 1300 s with the boot allowance.
#
# Usage: tests/post_closure_renewal_at_peer.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2 — the FIRST is the peer that
#        observes, the SECOND is the node that withdraws), NFILES (64),
#        DOOMED (256, the files in the tree the withdrawing node is tearing
#        down when it is shut down), OBSERVE_S (30), SUSPECT_FIRST (0; 1 runs
#        the SUSPECT-first arm above).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
P=${MXFS_NODE_LIST%%,*}          # the PEER: observes, survives, replays
W=${MXFS_NODE_LIST##*,}          # the node whose authority CLOSES
[ "$P" = "$W" ] && { echo "ABORT: this lap needs two distinct nodes (MXFS_NODE_LIST=$MXFS_NODE_LIST)"; exit 2; }
NFILES=${NFILES:-64}
DOOMED=${DOOMED:-256}
OBSERVE_S=${OBSERVE_S:-30}
SUSPECT_FIRST=${SUSPECT_FIRST:-0}
MNT=/mnt/shared
DUMP=/src/mxfs/tools/disklock_hb_dump.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_pcren_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="PCREN-MARK-$LABEL"
ODIR=$MNT/pcren_${LABEL}_oracle
DDIR=$MNT/pcren_${LABEL}_doomed
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# A withdrawal through the cluster-fence entry is what the authority machinery
# is for and is not bad news.  Every other shutdown on the PEER is.
bad_lines() { echo $(( $(grep -a 'hutting down filesystem' "$1" 2>/dev/null | grep -avc 'mxfs_dlm_fence_notify') + $(cnt "$1" 'BUG:\|Oops') )); }

# ---- 0. the fleet on the tree build
if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== post_closure_renewal_at_peer label=$LABEL peer=$P withdrawing=$W nfiles=$NFILES doomed=$DOOMED sv=$SV $(date -u +%FT%TZ) ==="
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
waitboot "$P" "$W"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$P" "$W"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$P"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# THE INJECTOR MUST EXIST BEFORE ANYTHING IS BUILT.  dbg_dialloc_shutdown makes
# the next create on the withdrawing node fire a DIRTY trans_cancel ->
# EFSCORRUPTED -> force shutdown, mid-transaction, which is the only supported
# way to leave committed-but-unreplayed work in that node's slice.  A lap that
# discovered its absence after the tree was populated would heal the rig and
# report nothing; arming is checked here, where it costs one ssh.
value_now_into inj "$W" 30 "$OUT/injector.txt" '^INJECTOR=(present|absent)$' \
    "the dirty-cancel injector on $W" \
    "test -w /sys/module/mxfs/parameters/dbg_dialloc_shutdown && echo INJECTOR=present || echo INJECTOR=absent"
if [ "$inj" != "INJECTOR=present" ]; then
    echo "ABORT: /sys/module/mxfs/parameters/dbg_dialloc_shutdown is not writable on $W, so this lap cannot leave a DIRTY slice behind; a clean withdrawal gives the peer nothing to defer and would measure nothing"
    echo "RESULT: ABORT label=$LABEL stage=injector evidence=$OUT"; exit 2
fi

# ---- 1. identities.  The membership verdicts below all read "node %u", so the
#         withdrawing node's MXFS node id must be known, and it is read off the
#         on-disk slot table rather than assumed from the hostname.
for n in "$P" "$W"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "PSLOT=\$slot_$P; WSLOT=\$slot_$W"
dump_into() { measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"; }
slot_of()  { grep -aE "^slot +$2 " "$1" | head -1; }
dump_into "$P" "$OUT/hb_0.txt" "the disklock table before the withdrawal"
PNODE=$(slot_of "$OUT/hb_0.txt" "$PSLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
WNODE=$(slot_of "$OUT/hb_0.txt" "$WSLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
if [ -z "$PNODE" ] || [ -z "$WNODE" ] || [ "$PSLOT" = "$WSLOT" ] || [ "$PNODE" = "$WNODE" ]; then
    echo "ABORT: the table did not yield two distinct live records for $P and $W (peer slot=$PSLOT node=$PNODE, withdrawing slot=$WSLOT node=$WNODE)"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2
fi
echo "STAGE identities: peer $P = node $PNODE slot $PSLOT; withdrawing $W = node $WNODE slot $WSLOT"

# ---- 2. the mark, in BOTH rings, before anything is built
for n in "$P" "$W"; do rs 20 "$n" "echo $MARK > /dev/kmsg" >/dev/null 2>&1; done

# ---- 3. the oracle and the doomed tree, both created by the node that will
#         withdraw.  The oracle is fsynced so its bytes are owed; the doomed
#         tree is what it will be tearing down when the authority closes, so
#         its unlink transactions are the dirty work the peer must replay.
T_BUILD0=$(date +%s)
measure "$W" 90 "$OUT/W_build.txt" '^BUILD_END$' "the oracle and the doomed tree on $W" \
    "set -e; mkdir -p $ODIR $DDIR; \
     for i in \$(seq 1 $NFILES); do printf 'PCREN %s %04d\n' $LABEL \$i > $ODIR/f\$i; done; \
     for i in \$(seq 1 $DOOMED); do printf 'DOOMED %04d\n' \$i > $DDIR/d\$i; done; \
     sync; \
     cd $ODIR && sha256sum f* | sort; \
     echo ORACLE_N=\$(ls $ODIR | wc -l); echo DOOMED_N=\$(ls $DDIR | wc -l); echo BUILD_END"
grep -a '^[0-9a-f]\{64\}  f' "$OUT/W_build.txt" | LC_ALL=C sort > "$OUT/W_oracle_sha.txt"
on=$(grep -ao 'ORACLE_N=[0-9]*' "$OUT/W_build.txt" | head -1 | cut -d= -f2)
dn=$(grep -ao 'DOOMED_N=[0-9]*' "$OUT/W_build.txt" | head -1 | cut -d= -f2)
ck "the oracle was built on $W" "$on" "$NFILES"
ck "the doomed tree was built on $W" "$dn" "$DOOMED"
ck "the oracle's digests were captured before the withdrawal" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/W_oracle_sha.txt")" "$NFILES"
# the peer must be able to see them too, or the "read it back from the peer"
# verdict below would be about a namespace it never had
value_now_into pv "$P" 60 "$OUT/P_baseline.txt" '^ORACLE_SEEN=[0-9]+$' "the peer's cold read of the oracle" \
    "echo ORACLE_SEEN=\$(ls $ODIR 2>/dev/null | wc -l)"
ck "the peer $P sees the oracle before the withdrawal" "$pv" "ORACLE_SEEN=$NFILES"
# THE POST-RECOVERY WORKLOAD'S BOUND IS DERIVED FROM THIS LAP'S OWN CLOCK, not
# from a round number.  This build made $(( NFILES + DOOMED )) files and synced
# them on a healthy two-node cluster; the workload in section 7 makes $DOOMED
# of them on ONE node with the peer gone, which has strictly less coordination
# to do.  So the same wall plus 30 s of slack is a bound the lap has already
# earned, and an overrun of it is a park, not a slow disk.  A floor of 60 s
# keeps an unrepresentatively fast build from manufacturing a failure.
BUILD_WALL=$(( $(date +%s) - T_BUILD0 ))
AFTER_BOUND=$(( BUILD_WALL + 30 ))
[ "$AFTER_BOUND" -lt 60 ] && AFTER_BOUND=60
echo "STAGE built: $NFILES fsynced oracle files and $DOOMED doomed files in ${BUILD_WALL}s, both visible from $P, at +$(el)s (the post-recovery workload's bound is therefore ${AFTER_BOUND}s)"

# ---- 3b. SUSPECT FIRST: the peer stops hearing $W's renewals until its lease
#          monitor marks $W SUSPECT.  The drop is the only thing this arm changes
#          outside the filesystem and it is undone on every path out, including
#          an abort, so a lap that dies half way cannot leave the peer deaf.
DROPPED=0
udp_undrop() {
    [ "$DROPPED" = 1 ] || return 0
    DROPPED=0
    rs 20 "$P" "while iptables -D INPUT -p udp --dport 7603 -j DROP 2>/dev/null; do :; done; iptables -S INPUT | grep -c 'dport 7603' || true" > "$OUT/P_undrop.txt" 2>/dev/null
    echo "STAGE the inbound UDP 7603 drop on $P was removed at +$(el)s (rules left naming the port: $(tail -1 "$OUT/P_undrop.txt" 2>/dev/null || echo unreadable))"
}
trap udp_undrop EXIT
if [ "$SUSPECT_FIRST" = 1 ]; then
    measure "$P" 30 "$OUT/P_drop.txt" '^DROPPED$' "the inbound UDP 7603 drop on $P" \
        "iptables -I INPUT -p udp --dport 7603 -j DROP && echo DROPPED"
    DROPPED=1
    echo "STAGE $P now drops inbound UDP 7603 (lease renewals only) at +$(el)s; the module's SUSPECT threshold is 60 s + 150 x 2 s = 360 s"
    wait_for_into wsus "$P" 400 "$MARK" "node $WNODE may be unreachable"
    if [ "$wsus" = timeout ]; then
        udp_undrop
        echo "VACUOUS: $P never marked node $WNODE SUSPECT within 400 s of dropping its renewals (module constant 360 s) — the arm did not produce its subject"
        echo "RESULT: VACUOUS label=$LABEL arm=suspect-first stage=suspect wall=$(el)s evidence=$OUT"; exit 3
    fi
    echo "STAGE $P marked node $WNODE SUSPECT ${wsus}s after the drop at +$(el)s — the entry the resumed post-closure renewals will land on"
fi

# ---- 4. close the authority on $W, MID-TEAR-DOWN, and leave the module loaded
# The rm runs first and the injector fires under it, so the force shutdown lands
# with committed-but-unreplayed unlink transactions in $W's journal slice.
# Nothing here unmounts, rmmods or reboots $W: mxfs_lease_renew_fn's only exit
# is ctx->running, and clearing it is exactly the condition this record is
# about.
measure "$W" 60 "$OUT/W_inject.txt" '^INJECTED$' "the authority closure on $W" \
    "nohup sh -c 'rm -rf $DDIR' >/dev/null 2>&1 & \
     sleep 0.4; echo 1 > /sys/module/mxfs/parameters/dbg_dialloc_shutdown; \
     timeout 10 touch $MNT/.pcren_trigger >/dev/null 2>&1; \
     echo INJECTED"
T_INJ=$(date +%s)
echo "STAGE authority closed on $W mid-rm at +$(el)s"
# the resumed renewals must be POST-closure ones: the drop comes off now, before
# the peer's next 2 s monitor scan can see the stamp and unregister the entry
[ "$SUSPECT_FIRST" = 1 ] && udp_undrop

# THE MODULE MUST STILL BE LOADED, or the renew thread is gone and this lap has
# measured a clean departure instead of a post-closure renewal.
value_now_into ld "$W" 30 "$OUT/W_loaded.txt" '^MODULE=(loaded|gone)$' \
    "whether mxfs is still loaded on $W" \
    "test -d /sys/module/mxfs && echo MODULE=loaded || echo MODULE=gone"
if [ "$ld" != "MODULE=loaded" ]; then
    echo "VACUOUS: mxfs is no longer loaded on $W, so its lease renew thread has exited and no post-closure renewal was ever sent — this lap's whole premise is absent"
    echo "RESULT: VACUOUS label=$LABEL stage=module-gone wall=$(el)s evidence=$OUT"; exit 3
fi
window_into "$OUT/W_withdraw.txt" "$W" 40 "$MARK"
ckge "$W stamped WITHDRAWN (its own final record)" "$(cnt "$OUT/W_withdraw.txt" 'P163-WITHDRAW-STAMP\|WITHDRAW-STAMP\|EXPIRED-WITHDRAWN')" 1

# ---- 5. WHICH DETECTOR FIRED, and did the replay happen at all
wait_for_into seen "$P" 60 "$MARK" "P163-WITHDRAW-SEEN"
wait_for_into recov "$P" 120 "$MARK" "P163-RECOVERY-COMPLETE"
window_into "$OUT/P_recov.txt" "$P" 40 "$MARK"
count_file_into d_stamp "$OUT/P_recov.txt" 'P163-WITHDRAW-SEEN'
count_file_into d_left  "$OUT/P_recov.txt" "node $WNODE has left the cluster"
count_file_into d_susp  "$OUT/P_recov.txt" "node $WNODE may be unreachable"
count_file_into rc_done "$OUT/P_recov.txt" 'P163-RECOVERY-COMPLETE'
echo "STAGE detectors on $P: WITHDRAW-SEEN=$d_stamp lease-SUSPECT=$d_susp lease-DEAD=$d_left; recovery-complete=$rc_done (waits seen=${seen}s recov=${recov}s, injection at +$(( T_INJ - s0 ))s) at +$(el)s"
# WHICH detector fired is recorded, not graded: the reading predicts the
# WITHDRAWN stamp gets there in milliseconds and the lease path never does
# (renewals reset missed_renewals on every packet), and a lease-DEAD line would
# falsify that prediction rather than prove a defect.  What IS graded is that
# the recovery happened and happened inside its bound.
if [ "$d_left" != 0 ]; then
    echo "  INFO the lease path ALSO declared node $WNODE dead ($d_left line(s)) — the code reading predicted it could not, so the renewals stopped or were lost"
fi
if [ "$SUSPECT_FIRST" = 1 ]; then
    # what the resumed post-closure renewals did to the SUSPECT entry BEFORE the
    # recovery removed it: read, and reported by name; the deferral question it
    # exists to answer is graded by the recovery bound just below
    count_file_into pre_susp "$OUT/P_recov.txt" "node $WNODE transitioned to ACTIVE (was SUSPECT)"
    ckge "the arm produced its subject: the peer held node $WNODE SUSPECT before the closure" "$d_susp" 1
    echo "STAGE suspect-first: post-closure renewals promoted the SUSPECT entry back to ACTIVE $pre_susp time(s) before the recovery removed it (WITHDRAW-SEEN ${seen}s, RECOVERY-COMPLETE ${recov}s after the mark)"
    grep -a "node $WNODE transitioned to ACTIVE\|node $WNODE may be unreachable\|P163-WITHDRAW-SEEN\|P163-RECOVERY-COMPLETE\|P-LEASE-WITHDRAWN-RENEWAL\|P-LEASE-INCARNATION" "$OUT/P_recov.txt" | tail -8 | cut -c1-200 | sed 's/^/    /'
    # 0.89.68: the renewal carries the sender's authority state, and the
    # receiver takes nothing but mastership retention from a WITHDRAWN one.
    # On a build that carries that receiver the promotion is graded, not
    # reported: s146c (0.89.66) measured it happening once, which is the
    # defect the state word exists to remove.
    if [ "$(strings -a mxfs.ko | grep -c 'P-LEASE-WITHDRAWN-RENEWAL')" != 0 ]; then
        count_file_into wd_ren "$OUT/P_recov.txt" "P-LEASE-WITHDRAWN-RENEWAL node $WNODE"
        ckge "the peer read the post-closure renewals as WITHDRAWN (the sender's state word)" "$wd_ren" 1
        ck "a post-closure renewal did not promote the SUSPECT entry back to ACTIVE before the recovery" "$pre_susp" 0
    fi
fi
ckge "the peer saw the WITHDRAWN stamp, which is the detector that authorises the replay" "$d_stamp" 1
ckge "the peer replayed the withdrawn node's DIRTY slice to completion while its renewals were still arriving" "$rc_done" 1
if [ "$recov" = timeout ]; then
    echo "  FAIL the slice replay did not complete inside its 120 s bound (a timeout is a failure, not a slow pass)"
    fails=$((fails+1))
fi

# ---- 6. the renewals: are they still arriving, and do they resurrect anything
# The recovery is the boundary.  A promotion BEFORE it says nothing (the entry
# was live and the node had not withdrawn yet); a promotion AFTER it is the
# resurrection this record is about.  So the window is re-marked here, and
# every membership count below is taken from the new mark forward.
MARK2="PCREN-MARK2-$LABEL"
rs 20 "$P" "echo $MARK2 > /dev/kmsg" >/dev/null 2>&1
sleep "$OBSERVE_S"
window_into "$OUT/P_membership.txt" "$P" 40 "$MARK2"
count_file_into inert "$OUT/P_membership.txt" "heartbeat received from unknown node $WNODE"
count_file_into act_join "$OUT/P_membership.txt" "node $WNODE transitioned to ACTIVE (was JOINING)"
count_file_into act_susp "$OUT/P_membership.txt" "node $WNODE transitioned to ACTIVE (was SUSPECT)"
count_file_into act_any  "$OUT/P_membership.txt" "node $WNODE transitioned to ACTIVE"
echo "STAGE $OBSERVE_S s of post-recovery observation on $P: inert renewals (unknown node $WNODE)=$inert; promotions to ACTIVE total=$act_any was-JOINING=$act_join was-SUSPECT=$act_susp at +$(el)s"
if [ "$inert" = 0 ] && [ "$act_any" = 0 ]; then
    # Nothing arrived at all.  Either the withdrawal stops the renew thread
    # after all, or the packets are being dropped.  Both make every membership
    # verdict below vacuous, and saying so is the result — an absence counted
    # as "no resurrection" is the laundering this record keeps being bitten by.
    echo "  INFO the peer logged NO renewal traffic from node $WNODE in $OBSERVE_S s — neither an inert-renewal warning nor a promotion."
    echo "       The renew thread is ratelimited (pr_warn_ratelimited), so a single suppressed burst can read as zero;"
    echo "       what this says is that nothing RESURRECTED the entry, not that nothing was sent."
fi
ck "a post-closure renewal did not promote the withdrawn node back to ACTIVE (was SUSPECT)" "$act_susp" 0
ck "nothing RE-REGISTERED the withdrawn node after the peer recovered it (was JOINING)" "$act_join" 0

# ---- 7. the conflicting grant: work on the peer that must take resources the
#         withdrawn node mastered.  The peer holding a corpse as a live member
#         is only a defect if it then parks on it, and that is a hang whichever
#         way the membership question came out — so it is measured either way.
# The bound was derived above from this lap's own build wall.  An overrun is a
# FAIL, never a reason to look again with a bigger number.
W_START=$(date +%s)
rsx "$AFTER_BOUND" "$P" "set -e; mkdir -p $MNT/pcren_${LABEL}_after; \
     for i in \$(seq 1 $DOOMED); do printf 'AFTER %04d\n' \$i > $MNT/pcren_${LABEL}_after/a\$i; done; \
     sync; \
     ls -d $DDIR >/dev/null 2>&1 && ls $DDIR | wc -l || echo DOOMED_GONE; \
     echo AFTER_N=\$(ls $MNT/pcren_${LABEL}_after | wc -l); echo AFTER_END" > "$OUT/P_after.txt"
arc=$?
W_WALL=$(( $(date +%s) - W_START ))
echo "STAGE the peer's post-recovery workload: rc=$arc wall=${W_WALL}s (bound ${AFTER_BOUND}s, derived from this lap's ${BUILD_WALL}s build) at +$(el)s"
if [ "$arc" = 124 ]; then
    echo "  FAIL the peer's workload did not complete inside its ${AFTER_BOUND}s bound — a request for a resource the withdrawn node mastered parked"
    fails=$((fails+1))
else
    capture_require "$OUT/P_after.txt" '^AFTER_END$' "the peer's post-recovery workload"
    count_file_into an "$OUT/P_after.txt" "^AFTER_N=$DOOMED\$"
    ck "the peer completed a workload over resources the withdrawn node mastered" "$an" 1
fi

# ---- 8. the oracle and the namespace, read from the peer
measure "$P" 90 "$OUT/P_files.txt" '^FILES_END$' "the oracle read back from $P" \
    "cd $ODIR 2>/dev/null && sha256sum f* 2>/dev/null | sort; echo FILES_END"
grep -a '^[0-9a-f]\{64\}  f' "$OUT/P_files.txt" | LC_ALL=C sort > "$OUT/P_oracle_sha.txt"
same=$(LC_ALL=C comm -12 "$OUT/W_oracle_sha.txt" "$OUT/P_oracle_sha.txt" | grep -ac '^[0-9a-f]\{64\}  f')
ck "every file $W fsynced before the withdrawal is present and byte-identical from $P" "$same" "$NFILES"
# A dangling dirent is the tear this shape produced historically: a name readdir
# lists that no lookup can resolve, left by unlink work that was replayed only
# half way.  It is read from the peer because the withdrawn node has no mount.
measure "$P" 90 "$OUT/P_dangle.txt" '^DANGLE_END$' "the namespace walk on $P" \
    "d=0; n=0; if [ -d $DDIR ]; then for f in \$(ls $DDIR 2>/dev/null); do n=\$((n+1)); [ -e $DDIR/\$f ] || d=\$((d+1)); done; fi; \
     echo WALK_N=\$n; echo DANGLING=\$d; echo DANGLE_END"
count_file_into dang "$OUT/P_dangle.txt" '^DANGLING=0$'
wn=$(grep -ao '^WALK_N=[0-9]*' "$OUT/P_dangle.txt" | head -1 | cut -d= -f2)
echo "STAGE namespace walk on $P: ${wn:-?} names left of the doomed tree, dangling=$(grep -ao '^DANGLING=[0-9]*' "$OUT/P_dangle.txt" | head -1 | cut -d= -f2) at +$(el)s"
if [ "${wn:-0}" = 0 ]; then
    echo "  INFO the doomed tree was gone entirely, so this walk had no name to resolve: it says the replay left nothing dangling only in the trivial sense"
fi
ck "no dangling dirent in the tree the withdrawn node was tearing down" "$dang" 1

# ---- 9. nothing crashed on the peer
window_into "$OUT/P_final.txt" "$P" 40 "$MARK"
ck "no shutdown, BUG or Oops on the peer ($P)" "$(bad_lines "$OUT/P_final.txt")" 0
value_now_into pm "$P" 30 "$OUT/P_mounted.txt" '^MOUNTED=[01]$' "the peer's mount state" \
    "mountpoint -q $MNT && echo MOUNTED=1 || echo MOUNTED=0"
ck "the peer ($P) is still mounted" "$pm" "MOUNTED=1"
# the withdrawn node is left exactly as the lap made it; the next lap's own
# prep_cluster reloads and remounts it, and tearing it down here would destroy
# the state a follow-up read might want
echo "STAGE $W is left withdrawn with its module loaded; the next lap's prep restores it"

if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"; exit 1
