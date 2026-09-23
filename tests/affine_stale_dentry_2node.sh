#!/bin/bash
# affine_stale_dentry_2node.sh — D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED
# on the two-node TCP rig.
#
# The vector: mxfs_drevalidate's affine exit (pal/linux/xfs_super.c) blesses
# a POSITIVE regular-file dentry whose inode lives in this node's own affine
# AG with no coordinated lookup and no parent hold-epoch check.  In
# multi-node mode every file a node creates lands in its own affine AG
# (xfs/libxfs/xfs_ialloc.c), so every file A creates and then names again
# is in that population.  A peer unlinking the name takes the parent's EX,
# which drops A to NL and bumps A's epoch — the epoch fast path correctly
# declines — and the affine exit blesses the destroyed binding anyway until
# the asynchronous stale-flag ring reaches the child inode.
#
# Three legs, A = creator, B = peer:
#   1. SERVED-STALE.  A caches f1; B unlinks it; A immediately stats f1.  A
#      fixed build answers ENOENT.  A's tight stat loop also measures how
#      long the stale binding is served after B's unlink returned (clock
#      offsets estimated per node).
#   2. WRITE THROUGH THE STALE NAME, INSIDE THE WINDOW.  A caches f2 and
#      runs a tight loop of `echo > f2` (open O_CREAT|O_TRUNC|O_WRONLY +
#      write), recording per iteration the inode the name resolved to and
#      the time; B unlinks f2 one second in.  A fixed build never resolves
#      f2 to the freed inode after B's unlink returned; the defect hands A
#      the freed inode for the length of the stale window — every write in
#      that span returns success and lands in an inode that has no name
#      (a lost create).  s522c's single write 435 ms after the unlink
#      could not see a 58 ms window; the loop can.
#   3. THE DENOMINATOR.  With mxfs.affine_audit_pct=100 on A the leg-1
#      stat loop is repeated on f3: P165-AFFINE-AUDIT-MISS kind=GONE naming
#      f3 proves the affine exit is the path these lookups take (s522c's
#      one stat, 400 ms late, found the dentry already evicted and reached
#      no exit at all), and the interlock's refusal must shrink the window.
#
# the budget rule (derived): prep 50 s measured (2/tcp QNAP) + three legs ~5 s each
# + loop 8 s + capture 10 s = ~85 s; chain bound 300 (prep manifest) + 120.
#
# Usage: tests/affine_stale_dentry_2node.sh <label>
# Env:   MXFS_DEV (default: the device of A's live mxfs mount after prep,
#        resolved by mxfs_dev_resolve — no rig's device path is assumed),
#        MXFS_NODE_LIST (default test1,test2; A = first, B = second),
#        AGSHIFT (inode -> AG shift; 23 on the QNAP LUN), NOPREP=1 to reuse
#        the current mount.
#
# Every capture a verdict is counted from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted: a
# failed acquisition is an ABORT, never a count of zero.  A loop that hits
# its bound (status 124) is reported by the loop's own line, not an ABORT.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
AGSHIFT=${AGSHIFT:-23}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
P=/sys/module/mxfs/parameters
D=$MNT/affine_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_affine_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckne() { if [ "$2" != "$3" ]; then echo "  PASS $1 ($2 != $3)"; else echo "  FAIL $1 got=$2 must_differ_from=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
PAT='P165-AFFINE-AUDIT\|P-DREVAL-STALEFLAG\|P-DREVAL-AFFINE-FAST\|P-DREVAL-EPOCH-FAST\|P-EVICT-RESULT\|P91-CAW-FALSEPOS-CLEAR\|P-VNLOOKUP\|Corruption\|shutting down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-DREVAL-TYPEMISS'
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-DREVAL-TYPEMISS\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
# clock offset of a node vs this host, in ms (remote - local, ssh latency halved)
offset_ms() {
    local t0 tr t1
    t0=$(date +%s%N); tr=$(rs 15 "$1" "date +%s%N" | tr -dc 0-9); t1=$(date +%s%N)
    python3 -c "print(int(($tr - ($t0 + $t1) / 2) / 1e6))"
}

echo "=== affine_stale_dentry_2node label=$LABEL A=$A B=$B agshift=$AGSHIFT sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -z "${NOPREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat $P/force_transport) audit_pct=\$(cat $P/affine_audit_pct) hbslot=\$(dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1 | awk '{print \$NF}')" | tr -d '\n')"
done
for n in $A $B; do
    measure "$n" 20 "$OUT/${n}_mounted.txt" '^[0-9]+$' "the mount count on $n" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes mounted on the tree's build" "$(cat "$OUT/${A}_mounted.txt" "$OUT/${B}_mounted.txt" | tr -d '\n')" "11"
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
offA=$(offset_ms "$A"); offB=$(offset_ms "$B")
echo "  INFO clock offsets vs host (ms): $A=$offA $B=$offB"
MK="AFFINE-$LABEL"
for n in $A $B; do rs 15 "$n" "echo 0 > $P/affine_audit_pct; echo '$MK' > /dev/kmsg" >/dev/null; done
# the test directory, and the revalidate trace (0.75.37) on A for every
# dentry under it: which exit each lookup takes is the measurement.
value_now_into dino "$A" 30 "$OUT/rv_dino_1.txt" '^[0-9]+$' "dino on $A" "mkdir -p $D && stat -c %i $D && echo \$(stat -c %i $D) > $P/dbg_dreval_trace_ino"
echo "  INFO dir $D ino=$dino trace=$(rs 15 "$A" "cat $P/dbg_dreval_trace_ino" | tr -d '\n') stats_before='$(rs 15 "$A" "cat $P/affine_audit_stats" | tr -d '\n')'"
ckge "A: test dir created and traced" "$dino" 1

# ---------------------------------------------------------------- leg 1
value_now_into ino1 "$A" 30 "$OUT/rv_ino1_2.txt" '^[0-9]+$' "ino1 on $A" "echo payload-1 > $D/f1 && stat -c %i $D/f1 >/dev/null && stat -c %i $D/f1"
echo "  INFO leg1 A f1 ino=$ino1 ag=$(( ${ino1:-0} >> AGSHIFT )) dir_ag=$(( $(rs 20 "$A" "stat -c %i $D" | tr -dc 0-9) >> AGSHIFT ))"
ckge "leg1: A created f1" "$ino1" 1
( rsx 40 "$A" "t0=\$(date +%s%N); ok=0; i=0; ft=; while [ \$i -lt 4000 ]; do i=\$((i+1)); if stat -c %i $D/f1 >/dev/null 2>&1; then ok=\$((ok+1)); else ft=\$(date +%s%N); break; fi; sleep 0.002; done; echo A_LOOP start=\$t0 first_enoent=\${ft:-none} ok=\$ok iters=\$i" > "$OUT/loop1_$A.txt"; echo $? > "$OUT/loop1_$A.rc" ) &
LPID=$!
sleep 1
value_now_into brm "$B" 30 "$OUT/rv_brm_3.txt" '^B_RM ' "brm on $B" "rm $D/f1; echo B_RM rc=\$? end=\$(date +%s%N)"
echo "  INFO leg1 $brm"
value_now_into post "$A" 20 "$OUT/rv_post_4.txt" '^A_POST ' "post on $A" "stat -c %i $D/f1 2>/dev/null; echo A_POST rc=\$? at=\$(date +%s%N)"
echo "  INFO leg1 A post-unlink stat: $post"
wait $LPID
loop_require "$(cat "$OUT/loop1_$A.rc")" "$OUT/loop1_$A.txt" '^A_LOOP start=' "A's leg-1 stat loop"
echo "  INFO leg1 $(cat "$OUT/loop1_$A.txt")"
ck "leg1: B unlinked f1 rc=0" "$(echo "$brm" | grep -ac 'B_RM rc=0')" "1"
ck "D-AFFINE leg1: A's stat of f1 after the peer's unlink is ENOENT (rc=1)" "$(echo "$post" | grep -ao 'A_POST rc=[0-9]*' | cut -d= -f2)" "1"
rm_end=$(echo "$brm" | grep -ao 'end=[0-9]*' | cut -d= -f2)
fe=$(grep -ao 'first_enoent=[0-9]*' "$OUT/loop1_$A.txt" | cut -d= -f2)
lok=$(grep -ao 'ok=[0-9]*' "$OUT/loop1_$A.txt" | cut -d= -f2)
post_at=$(echo "$post" | grep -ao 'at=[0-9]*' | cut -d= -f2)
if [ -n "${fe:-}" ] && [ -n "${rm_end:-}" ]; then
    win=$(python3 -c "print(int(($fe - $offA*1e6) / 1e6 - ($rm_end - $offB*1e6) / 1e6))")
else
    win=none
fi
post_ms=$(python3 -c "print(int(($post_at - $offA*1e6) / 1e6 - ($rm_end - $offB*1e6) / 1e6))" 2>/dev/null)
echo "  D-AFFINE-MEASURE $LABEL leg1 stale_window_ms=${win} post_stat_after_unlink_ms=${post_ms:-?} post_rc=$(echo "$post" | grep -ao 'A_POST rc=[0-9]*' | cut -d= -f2) loop_ok=${lok:-?} loop_first_enoent=${fe:-none}"

# ---------------------------------------------------------------- leg 2
key2=$(rs 30 "$A" "echo payload-2 > $D/f2 && stat -c %i $D/f2 >/dev/null && stat -c '%i %.9W' $D/f2" | tail -1 | tr -d '\n')
ino2=${key2%% *}; bt2=${key2##* }
echo "  INFO leg2 A f2 ino=$ino2 btime=$bt2 ag=$(( ${ino2:-0} >> AGSHIFT ))"
ckge "leg2: A created f2" "$ino2" 1
# A's loop: 1500 create-writes through the name, each recorded as
# "<iter> <ino> <birth time> <ns> <write rc>" on the node, fetched afterwards.
# The (ino, birth time) pair is the incarnation: a recycled inode NUMBER
# (s522d: the new f2 was 134 again) carries a new birth time.
# Paced at 10 ms per iteration: s522e's unpaced loop held the child's EX so
# continuously that B's unlink waited until the loop ENDED (leg 2b measures
# that on purpose); the pacing lets B's unlink land mid-loop so the window
# after it is sampled.
( rsx 60 "$A" "i=0; : > /tmp/affine_loop2.txt; while [ \$i -lt 400 ]; do i=\$((i+1)); echo X\$i > $D/f2; w=\$?; echo \$i \$(stat -c '%i %.9W' $D/f2 2>/dev/null || echo 0 0) \$(date +%s%N) \$w >> /tmp/affine_loop2.txt; sleep 0.01; done; echo A_LOOP2 done iters=\$i" > "$OUT/loop2_$A.txt"; echo $? > "$OUT/loop2_$A.rc" ) &
LPID=$!
sleep 1
value_now_into brm2 "$B" 30 "$OUT/rv_brm2_5.txt" '^B_RM ' "brm2 on $B" "s=\$(date +%s%N); rm $D/f2; rc=\$?; e=\$(date +%s%N); echo B_RM rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) end=\$e"
echo "  INFO leg2 $brm2"
wait $LPID
loop_require "$(cat "$OUT/loop2_$A.rc")" "$OUT/loop2_$A.txt" '^A_LOOP2 done ' "A's leg-2 create loop"
echo "  INFO leg2 $(cat "$OUT/loop2_$A.txt")"
# the rows are the stale-create measurement: the file ends in a sentinel so
# an empty row set from a loop that never ran is told from a failed fetch
measure "$A" 30 "$OUT/loop2_rows_$A.txt" '^ROWS_END$' "the leg-2 row log on $A" "cat /tmp/affine_loop2.txt; echo ROWS_END"
rm_end2=$(echo "$brm2" | grep -ao 'end=[0-9]*' | cut -d= -f2)
ck "leg2: B unlinked f2 rc=0" "$(echo "$brm2" | grep -ac 'B_RM rc=0')" "1"
ck "leg2: A's loop completed 400 iterations" "$(grep -ac 'A_LOOP2 done iters=400' "$OUT/loop2_$A.txt")" "1"
# rows after B's unlink returned (clock-corrected) that still resolved f2 to
# the freed inode: each is a successful write into an inode with no name.
read -r stale_creates first_new last_stale_ms new_key first_gap_ms <<< "$(python3 - "$OUT/loop2_rows_$A.txt" "${rm_end2:-0}" "$offA" "$offB" "$ino2" "${bt2:-0}" <<'PY'
import sys
rows=[l.split() for l in open(sys.argv[1]) if len(l.split())>=5]
rm_end=int(sys.argv[2]); offA=int(sys.argv[3]); offB=int(sys.argv[4]); old=(sys.argv[5], sys.argv[6])
rm_host=rm_end-offB*1000000
stale=0; first_new=None; last_stale=None; new_key='none'; prev=None; first_gap=None
for i,ino,bt,t,w in rows:
    th=int(t)-offA*1000000
    if th<=rm_host:
        prev=th; continue
    if first_gap is None and prev is not None:
        first_gap=int((th-prev)/1e6)
    if (ino,bt)==old and int(w)==0:
        stale+=1; last_stale=th
    elif (ino,bt)!=old and ino!='0' and first_new is None:
        first_new=int(i); new_key=ino+'@'+bt
    prev=th
print(stale, first_new if first_new is not None else 'none', int((last_stale-rm_host)/1e6) if last_stale else 0, new_key, first_gap if first_gap is not None else 'none')
PY
)"
value_now_into bsee "$B" 30 "$OUT/rv_bsee_6.txt" '^B_SEES ' "bsee on $B" "sleep 1; echo B_SEES key=\$(stat -c '%i@%.9W' $D/f2 2>/dev/null) content=\$(cat $D/f2 2>/dev/null)"
echo "  INFO leg2 $bsee"
echo "  D-AFFINE-MEASURE $LABEL leg2 stale_creates_after_unlink=${stale_creates} last_stale_write_ms=${last_stale_ms} first_iter_after_unlink_gap_ms=${first_gap_ms} first_new_iter=${first_new} old_key=$ino2@$bt2 new_key=${new_key} b_sees='$bsee'"
ck "D-AFFINE leg2: ZERO successful writes through the freed incarnation after B's unlink returned (lost creates)" "${stale_creates:-?}" "0"
ck "leg2: A eventually created a NEW incarnation for f2" "$( [ "${new_key:-none}" != none ] && echo 1 || echo 0)" "1"
ck "leg2: B sees A's final f2 content (X400)" "$(echo "$bsee" | grep -ac 'content=X400')" "1"

# (The peer-unlink-under-a-hot-writer measurement that ran here as leg 2b in
# s522f-h — B's rm waiting 2.5-3 s until A's loop ended — is its own defect
# and lives in tests/hot_inode_peer_unlink_2node.sh.)

# ---------------------------------------------------------------- leg 3
ino3=$(rs 30 "$A" "echo payload-3 > $D/f3 && stat -c %i $D/f3 >/dev/null && stat -c %i $D/f3 && echo 100 > $P/affine_audit_pct" | tail -1 | tr -d '\n')
echo "  INFO leg3 A f3 ino=$ino3 audit_pct=$(rs 15 "$A" "cat $P/affine_audit_pct" | tr -d '\n')"
( rsx 40 "$A" "t0=\$(date +%s%N); ok=0; i=0; ft=; while [ \$i -lt 4000 ]; do i=\$((i+1)); if stat -c %i $D/f3 >/dev/null 2>&1; then ok=\$((ok+1)); else ft=\$(date +%s%N); break; fi; sleep 0.002; done; echo A_LOOP3 start=\$t0 first_enoent=\${ft:-none} ok=\$ok iters=\$i" > "$OUT/loop3_$A.txt"; echo $? > "$OUT/loop3_$A.rc" ) &
LPID=$!
sleep 1
value_now_into brm3 "$B" 30 "$OUT/rv_brm3_7.txt" '^B_RM ' "brm3 on $B" "rm $D/f3; echo B_RM rc=\$? end=\$(date +%s%N)"
wait $LPID
loop_require "$(cat "$OUT/loop3_$A.rc")" "$OUT/loop3_$A.txt" '^A_LOOP3 start=' "A's leg-3 audited stat loop"
measure "$A" 15 "$OUT/rv_stats3.txt" '^READ_RC=[0-9]+$' "the affine audit stats on $A" "cat $P/affine_audit_stats; printf '\nREAD_RC=%s\n' \$?; echo 0 > $P/affine_audit_pct"; stats3=$(grep -av '^READ_RC=' "$OUT/rv_stats3.txt" | tr -d '\n')
echo "  INFO leg3 $brm3 | $(cat "$OUT/loop3_$A.txt") | stats_after='$stats3'"
ck "leg3: B unlinked f3 rc=0" "$(echo "$brm3" | grep -ac 'B_RM rc=0')" "1"
rm_end3=$(echo "$brm3" | grep -ao 'end=[0-9]*' | cut -d= -f2)
fe3=$(grep -ao 'first_enoent=[0-9]*' "$OUT/loop3_$A.txt" | cut -d= -f2)
if [ -n "${fe3:-}" ] && [ -n "${rm_end3:-}" ]; then
    win3=$(python3 -c "print(int(($fe3 - $offA*1e6) / 1e6 - ($rm_end3 - $offB*1e6) / 1e6))")
else
    win3=none
fi
echo "  D-AFFINE-MEASURE $LABEL leg3 audited_stale_window_ms=${win3} loop_ok=$(grep -ao 'ok=[0-9]*' "$OUT/loop3_$A.txt" | cut -d= -f2)"
ck "leg3: A's loop reached ENOENT for f3" "$(grep -ac 'first_enoent=[0-9]' "$OUT/loop3_$A.txt")" "1"

# ---------------------------------------------------------------- leg 4
# THE RELEASED-GRANT SHAPE, the default configuration.  close_release=1
# releases a clean regular file's PR grant at its last read-only close, so a
# name A has read and closed carries NO grant on the child.  B's unlink then
# BASTs nobody on A and nothing flags A's cached child stale; the epoch fast
# path declines (dp lost its grant) and the affine exit is the only thing
# left to answer — with a dentry whose binding is dead.
# Preparation that leaves A with a cached positive dentry and NO grant on
# the child (s522f's first form re-stat'd the name, which re-took a PR the
# unlink then BASTed — stale_src=5 — and measured the held-grant shape
# again): A writes f4 (EX), B reads it (BASTs A's EX away, src 5 on A), A
# reads it (the coordinated lookup clears the flag; the read takes PR; the
# read-only close releases it under close_release=1), and A touches nothing
# else.  B's unlink then requests nothing from A.
value_now_into ino4 "$A" 30 "$OUT/rv_ino4_8.txt" '^[0-9]+$' "ino4 on $A" "echo payload-4 > $D/f4 && sync -f $MNT && stat -c %i $D/f4"
measure "$B" 20 "$OUT/rv_bread4_1.txt" '^READ_RC=[0-9]+$' "bread4 on $B" "cat $D/f4; printf '\nREAD_RC=%s\n' \$?"; bread4=$(grep -av '^READ_RC=' "$OUT/rv_bread4_1.txt" | tail -1)
measure "$A" 20 "$OUT/rv_aread4_1.txt" '^READ_RC=[0-9]+$' "aread4 on $A" "cat $D/f4; printf '\nREAD_RC=%s\n' \$?"; aread4=$(grep -av '^READ_RC=' "$OUT/rv_aread4_1.txt" | tail -1)
sleep 0.5
echo "  INFO leg4 A f4 ino=$ino4 ag=$(( ${ino4:-0} >> AGSHIFT )) B_read='$bread4' A_read='$aread4' (A's last touch: read-only close)"
ckge "leg4: A created f4" "$ino4" 1
ck "leg4: B then A read f4" "$bread4/$aread4" "payload-4/payload-4"
value_now_into brm4 "$B" 30 "$OUT/rv_brm4_9.txt" '^B_RM ' "brm4 on $B" "s=\$(date +%s%N); rm $D/f4; rc=\$?; e=\$(date +%s%N); echo B_RM rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))"
measure "$A" 20 "$OUT/rv_post4_10.txt" '^A_POST2 ' "post4 on $A" "sleep 0.5; stat -c %i $D/f4 2>&1; echo A_POST rc=\$?; stat -c %i $D/f4 2>&1; echo A_POST2 rc=\$?"; post4=$(cat "$OUT/rv_post4_10.txt" | tr '\n' ' ')
echo "  INFO leg4 $brm4 | $post4"
ck "leg4: B unlinked f4 rc=0 (no grant on A to strip)" "$(echo "$brm4" | grep -ac 'B_RM rc=0')" "1"
ck "D-AFFINE leg4: A's stat of the read-and-closed name 500 ms after the peer's unlink is ENOENT (rc=1)" "$(echo "$post4" | grep -ao 'A_POST rc=[0-9]*' | cut -d= -f2)" "1"
ck "D-AFFINE leg4: and still ENOENT on the second stat" "$(echo "$post4" | grep -ao 'A_POST2 rc=[0-9]*' | cut -d= -f2)" "1"

# ---------------------------------------------------------------- leg 5
# THE CITED INCIDENT's precondition: a stale positive dentry for a name
# whose inode NUMBER has been recycled by a new file on the same node.  A's
# cached f5 (same preparation as f4), B unlinks it, A creates files until
# one lands on f5's number, then A writes through the stale name.
# MEASURED s522g/h/i: the recycle does not happen on this rig — only A
# allocates in AG 0 (node-affine allocation) and A's cached dentry pins the
# in-core inode, so A's allocator never hands the number out while the
# dentry lives; eight creates all took other numbers.  That is the
# construction that keeps the incident unreachable, and the leg asserts it
# (a recycle WITH a live stale dentry would be the hazard), then asserts the
# write through the stale name still creates f5 anew.
value_now_into ino5 "$A" 30 "$OUT/rv_ino5_11.txt" '^[0-9]+$' "ino5 on $A" "echo payload-5 > $D/f5 && sync -f $MNT && stat -c %i $D/f5"
measure "$B" 20 "$OUT/rv_bread5_2.txt" '^READ_RC=[0-9]+$' "bread5 on $B" "cat $D/f5; printf '\nREAD_RC=%s\n' \$?"; bread5=$(grep -av '^READ_RC=' "$OUT/rv_bread5_2.txt" | tail -1)
measure "$A" 20 "$OUT/rv_aread5_2.txt" '^READ_RC=[0-9]+$' "aread5 on $A" "cat $D/f5; printf '\nREAD_RC=%s\n' \$?"; aread5=$(grep -av '^READ_RC=' "$OUT/rv_aread5_2.txt" | tail -1)
sleep 0.5
ckge "leg5: A created f5" "$ino5" 1
ck "leg5: B then A read f5" "$bread5/$aread5" "payload-5/payload-5"
value_now_into brm5 "$B" 30 "$OUT/rv_brm5_12.txt" '^B_RM ' "brm5 on $B" "rm $D/f5; echo B_RM rc=\$?"
ck "leg5: B unlinked f5 rc=0" "$(echo "$brm5" | grep -ac 'B_RM rc=0')" "1"
# recycle: A creates g files until one lands on f5's number (freed numbers
# below it in the same AG are taken first)
measure "$A" 40 "$OUT/rv_gk_13.txt" '^END$' "the guard creates on $A" "for k in 1 2 3 4 5 6 7 8; do echo GUARD-\$k > $D/g\$k && sync -f $MNT; key=\$(stat -c '%i@%.9W' $D/g\$k); case \$key in $ino5@*) echo RECYCLED g\$k \$key; break;; esac; done; echo END"; gk=$(grep -a 'RECYCLED' "$OUT/rv_gk_13.txt")
gname=$(echo "$gk" | awk '{print $2}'); gkey=$(echo "$gk" | awk '{print $3}')
gkeys=$(rs 30 "$A" "stat -c '%n=%i' $D/g1 $D/g2 $D/g3 $D/g4 $D/g5 $D/g6 $D/g7 $D/g8 2>/dev/null | sed 's|.*/||' | tr '\n' ' '")
echo "  INFO leg5 A f5 ino=$ino5 recycle='${gk:-none}' g_inos='$gkeys'"
echo "  D-AFFINE-MEASURE $LABEL leg5 f5_old_ino=$ino5 recycled_while_dentry_live=$(echo "$gk" | grep -ac 'RECYCLED') g_inos='$gkeys'"
ck "D-AFFINE leg5 (construction): A never recycled f5's number while its stale dentry pinned the in-core inode (8 creates)" "$(echo "$gk" | grep -ac 'RECYCLED')" "0"
value_now_into wr5 "$A" 30 "$OUT/rv_wr5_14.txt" '^A_WRITE ' "wr5 on $A" "echo CLOBBER > $D/f5; w=\$?; echo A_WRITE rc=\$w f5_key=\$(stat -c '%i@%.9W' $D/f5 2>/dev/null) g1=\$(cat $D/g1 2>/dev/null)"
value_now_into bsee5 "$B" 30 "$OUT/rv_bsee5_15.txt" '^B_SEES ' "bsee5 on $B" "sleep 0.5; echo B_SEES f5_key=\$(stat -c '%i@%.9W' $D/f5 2>/dev/null) f5_content=\$(cat $D/f5 2>/dev/null) g1=\$(cat $D/g1 2>/dev/null)"
echo "  INFO leg5 $wr5 | $bsee5"
ck "leg5: A's open(O_CREAT) of f5 through the stale name succeeded" "$(echo "$wr5" | grep -ac 'A_WRITE rc=0')" "1"
ckne "D-AFFINE leg5: the recreated f5 is a new inode, not the freed one" "$(echo "$wr5" | grep -ao 'f5_key=[0-9]*' | cut -d= -f2)" "$ino5"
ck "D-AFFINE leg5: B sees the recreated f5 with A's content (no lost create)" "$(echo "$bsee5" | grep -ac 'f5_content=CLOBBER')" "1"
ck "D-AFFINE leg5: the other files keep their content on both nodes" "$(echo "$wr5" | grep -ac 'g1=GUARD-1')/$(echo "$bsee5" | grep -ac 'g1=GUARD-1')" "1/1"

# ---------------------------------------------------------------- leg 6
# THE LOCK-FREE LOOKUP SHAPE.  A stat ends holding a PR grant on the child
# (getattr takes the ilock), so the peer's unlink must BAST it and the
# release flags the child.  An access(2) check re-establishes the dentry
# through a coordinated lookup that clears the flag and re-igets the child
# but takes no ilock afterwards, so the child carries NO grant and NO flag
# until the eviction ring reports the peer's free.  Inside that window the
# affine exit is the only thing answering for the name.
value_now_into ino6 "$A" 30 "$OUT/rv_ino6_16.txt" '^[0-9]+$' "ino6 on $A" "echo payload-6 > $D/f6 && sync -f $MNT && stat -c %i $D/f6"
measure "$B" 20 "$OUT/rv_bread6_3.txt" '^READ_RC=[0-9]+$' "bread6 on $B" "cat $D/f6; printf '\nREAD_RC=%s\n' \$?"; bread6=$(grep -av '^READ_RC=' "$OUT/rv_bread6_3.txt" | tail -1)
value_now_into acc6 "$A" 20 "$OUT/rv_acc6_17.txt" '^ACCESS1 ' "acc6 on $A" "sleep 0.3; test -r $D/f6; echo ACCESS1 rc=\$?"
sleep 0.3
echo "  INFO leg6 A f6 ino=$ino6 B_read='$bread6' $acc6"
ckge "leg6: A created f6" "$ino6" 1
ck "leg6: B read f6, then A's access check found it (rc=0)" "$bread6/$(echo "$acc6" | grep -ao 'rc=[0-9]*')" "payload-6/rc=0"
value_now_into brm6 "$B" 30 "$OUT/rv_brm6_18.txt" '^B_RM ' "brm6 on $B" "rm $D/f6; echo B_RM rc=\$?"
value_now_into post6 "$A" 30 "$OUT/rv_post6_19.txt" '^ACCESS2 ' "post6 on $A" "sleep 0.2; test -r $D/f6; a=\$?; echo CLOBBER > $D/f6; w=\$?; echo ACCESS2 rc=\$a WRITE rc=\$w f6_key=\$(stat -c '%i@%.9W' $D/f6 2>&1 | tr ' ' '_')"
value_now_into bsee6 "$B" 30 "$OUT/rv_bsee6_20.txt" '^B_SEES ' "bsee6 on $B" "sleep 0.5; echo B_SEES f6_key=\$(stat -c '%i@%.9W' $D/f6 2>/dev/null) f6_content=\$(cat $D/f6 2>/dev/null)"
echo "  INFO leg6 $brm6 | $post6 | $bsee6"
echo "  D-AFFINE-MEASURE $LABEL leg6 f6_old_ino=$ino6 a='$post6' b='$bsee6'"
ck "leg6: B unlinked f6 rc=0" "$(echo "$brm6" | grep -ac 'B_RM rc=0')" "1"
ck "D-AFFINE leg6: A's access check 200 ms after the peer's unlink says the name is gone (rc=1)" "$(echo "$post6" | grep -ao 'ACCESS2 rc=[0-9]*' | cut -d= -f2)" "1"
ck "D-AFFINE leg6: A's open(O_CREAT) through the name succeeds (rc=0) — not a spurious create failure" "$(echo "$post6" | grep -ao 'WRITE rc=[0-9]*' | cut -d= -f2)" "0"
ckne "D-AFFINE leg6: the recreated f6 is a new inode" "$(echo "$post6" | grep -ao 'f6_key=[0-9]*' | cut -d= -f2)" "$ino6"
ck "D-AFFINE leg6: B sees the recreated f6 with A's content (no lost create)" "$(echo "$bsee6" | grep -ac 'f6_content=CLOBBER')" "1"

# ---------------------------------------------------------------- capture
rs 15 "$A" "sync -f $MNT; echo 0 > $P/dbg_dreval_trace_ino" >/dev/null
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
    grep -a "$PAT\|^DMESG_END\$" "$OUT/dmesg_full_$n.txt" > "$OUT/dmesg_$n.txt"
done
# the same captures by name, so the per-node verdicts below read from a
# path the boundary was crossed for
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
capture_require "$OUT/dmesg_$A.txt" '^DMESG_END$' "the filtered kernel log on $A"
echo "  INFO A audit lines: $(grep -a 'P165-AFFINE-AUDIT' "$OUT/dmesg_$A.txt" | sed 's/^\[[^]]*\] mxfs: //' | cut -c1-120 | tr '\n' ';')"
for nm in f1 f2 f3 f4 f5 f6; do
    echo "  D-AFFINE-MEASURE $LABEL trace $nm: affine_blessed=$(grep -a 'P-DREVAL-AFFINE-FAST' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm .*audited=0") blessed_while_dp_NL=$(grep -a 'P-DREVAL-AFFINE-FAST' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm .*dp_mode=0 audited=0") affine_audited=$(grep -a 'P-DREVAL-AFFINE-FAST' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm .*audited=1") epoch_fast=$(grep -a 'P-DREVAL-EPOCH-FAST' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm ") staleflag=$(grep -a 'P-DREVAL-STALEFLAG' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm\$") stale_src=$(grep -a 'P-DREVAL-STALEFLAG' "$OUT/dmesg_$A.txt" | grep -a "name=$nm\$" | grep -ao 'stale_src=[0-9]*' | sort -u | cut -d= -f2 | tr '\n' ',') audit_miss=$(grep -a 'P165-AFFINE-AUDIT-MISS' "$OUT/dmesg_$A.txt" | grep -ac "name=$nm ")"
done
echo "  INFO B lock-timeout lines: $(grep -ac 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt") ($(grep -a 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt" | grep -ao 'ino=[0-9]* ag=[0-9]* [a-z]*=[0-9]* req=[A-Z]*' | sort | uniq -c | tr '\n' ';'))"
echo "  INFO A trace tail (last 12 dentry lines): $(grep -a 'P-DREVAL' "$OUT/dmesg_$A.txt" | tail -12 | sed 's/^\[\([^]]*\)\] mxfs: /\1 /' | cut -c1-110 | tr '\n' ';')"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window): no corruption/shutdown/wedge/withdraw/lock-timeout/BUG/Oops/typemiss" "$health" "0"
# The denominator: how many of leg 3's lookups ARRIVED at the affine exit
# (every one was diverted at 100%), read from the trace and from the audit
# counters.  s522e/s522f: 297 and 196 arrivals, gone=0 — and no audited
# lookup can fall inside the window after the peer's unlink, because the
# child is flagged stale (P-DREVAL-STALEFLAG stale_src=5, the unlink's own
# peer invalidation) before A's next lookup; the trace's ordering assertions
# above carry that half.
aud3=$(grep -a 'P-DREVAL-AFFINE-FAST' "$OUT/dmesg_$A.txt" | grep -ac "name=f3 .*audited=1")
gone3=$(echo "$stats3" | grep -ao 'gone=[0-9]*' | cut -d= -f2)
n3=$(echo "$stats3" | grep -ao 'n=[0-9]*' | cut -d= -f2)
echo "  D-AFFINE-MEASURE $LABEL leg3 affine_arrivals_audited=$aud3 audit_n=${n3:-?} audit_gone=${gone3:-?} (the exit IS the path these lookups take; a zero miss count is quoted with its denominator)"
ckge "D-AFFINE leg3 (denominator): >=100 of A's f3 lookups arrived at the affine exit and were audited" "$aud3" 100
ck "D-AFFINE leg3: the audit's coordinated verdict disagreed with the exit's blessing ZERO times (gone/rebind/incarn)" "$(echo "$stats3" | grep -ao 'gone=[0-9]* rebind=[0-9]* incarn=[0-9]*')" "gone=0 rebind=0 incarn=0"
# once a name's child is flagged stale it must never be blessed by the exit
# again (ordering on A's own clock, no cross-node clock involved)
# After a stale-flag rejection of (name, ino), the exit may bless that
# binding again ONLY once a coordinated re-lookup has re-verified it on disk
# (P-EVICT-RESULT ... name=<name> for that ino — the sess91 path that clears
# a flag whose incarnation is current).  s522h: a stale eviction-ring entry
# flagged the live f2, the re-lookup cleared it, and 13 blessings followed
# before the peer even took the directory — legitimate; the assertion below
# is what separates that from a blessing of a binding never re-verified.
late=$(python3 - "$OUT/dmesg_$A.txt" <<'PY'
import re, sys
lines = open(sys.argv[1], errors='replace').read().splitlines()
flagged = {}   # (name, ino) -> True while flagged and not yet re-verified
late = 0
for l in lines:
    m = re.search(r'P-DREVAL-STALEFLAG ino=(\d+) .*name=(\S+)$', l)
    if m:
        flagged[(m.group(2), m.group(1))] = True
        continue
    m = re.search(r'P-EVICT-RESULT ino=(\d+) .*name=(\S+)', l)
    if m:
        flagged.pop((m.group(2), m.group(1)), None)
        continue
    # a fresh VFS lookup of the name (0.75.39 trace) re-verifies whatever
    # binding it now instantiates: every flag under that name is discharged
    m = re.search(r'P-VNLOOKUP dp=\d+ ino=(\d+) mode=\S+ name=(\S+)$', l)
    if m:
        for k in [k for k in flagged if k[0] == m.group(2)]:
            flagged.pop(k, None)
        continue
    m = re.search(r'P-DREVAL-AFFINE-FAST dp=\d+ name=(\S+) ino=(\d+) .*audited=0', l)
    if m and flagged.get((m.group(1), m.group(2))):
        late += 1
        if late <= 5:
            print("  INFO late blessing without re-verification:", l[:140], file=sys.stderr)
print(late)
PY
)
ck "D-AFFINE (trace): ZERO affine blessings of a flagged binding before a coordinated re-lookup re-verified it" "$late" "0"
ck "leg1/leg2 ran with the audit off (no audit line names f1/f2)" "$(grep -a 'P165-AFFINE-AUDIT-MISS' "$OUT/dmesg_$A.txt" | grep -ac 'name=f1 \|name=f2 ')" "0"
ck "D-AFFINE (trace): ZERO affine blessings of any name while dp's grant was NL" "$(grep -a 'P-DREVAL-AFFINE-FAST' "$OUT/dmesg_$A.txt" | grep -ac 'dp_mode=0 audited=0')" "0"
for n in $A $B; do
    measure "$n" 20 "$OUT/${n}_mounted_after.txt" '^[0-9]+$' "the mount count on $n after the lap" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes still mounted" "$(cat "$OUT/${A}_mounted_after.txt" "$OUT/${B}_mounted_after.txt" | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
