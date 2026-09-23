#!/bin/bash
# d482_phantom_epoch_2node.sh — D-PHANTOM-GRANT-BAIL-SKIPS-EPOCH-BUMP-DCACHE-ABA-482
# on the two-node TCP rig.
#
# The defect: the P106 phantom-grant bail (a CACHED EX grant found to have no
# backing record) demoted the directory's mode to NL without advancing
# i_dlm_epoch, so a dentry stamped under the phantom tenure kept taking the
# zero-I/O revalidation fast path after the grant was disavowed and
# re-acquired (an ABA on the validity token).  Fix 0.66.1 bumps the epoch in
# the bail; this harness is the verification the record demands: make the
# wire lose A's grant behind A's cache with the one-shot injection (0.75.36:
# a real wire release, then the real backing-record check — the 0.75.35 form
# merely lied to the check while the master still held A's EX, and the peer's
# BAST against a grant A could not prove wedged A into shutdown, s521a), open
# an authority gap with the one-shot pause, let the peer change the namespace
# inside it, and assert the invariant, not merely that nothing crashed:
#   (a) the branch fired exactly once (P106-INJECT-CONSUMED, P106-STALE-EX-BAIL);
#   (b) the mode passed through NL (the bail line is printed only on that path);
#   (c) the epoch advanced E -> E+1 (P-DREVAL-EPOCH-FAST epoch=E before,
#       P106-STALE-EX-BAIL epoch=E+1);
#   (d) neither the positive nor the negative dentry cached under E takes the
#       fast path afterwards (zero P-DREVAL-EPOCH-FAST for them after the
#       bail) and A's lookups return the CURRENT namespace: the name B removed
#       is ENOENT, the name B created exists.
# The positive name is a SUBDIRECTORY: a regular file in A's own affine AG
# exits d_revalidate through the affine fast path, which returns before the
# d_time stamp, so it never enters the epoch fast path at all (s521a measured
# pos=0; that population is D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED's).
# Also: p106_check_n (the denominator) grew, both one-shots read back consumed,
# and the FULL mxfs kernel window of both nodes (saved to the evidence dir)
# carries no wedge/shutdown/withdraw/lock-timeout line.
#
# the budget rule (derived): prep 50 s measured (2/tcp QNAP) + setup 10 s + pause 5 s +
# slow-path re-acquire and stats ~10 s + capture 10 s = ~90 s; chain bound
# 300 (prep manifest) + 120 = 420 s.
#
# Usage: tests/d482_phantom_epoch_2node.sh <label> [PAUSE_MS=5000]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2; A = first, B = second)
set -u
LABEL=${1:?label}
PAUSE_MS=${2:-5000}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# MXFS_DEV: the caller's, else prep_cluster's per-transport rig default
# (no other rig's device path is assumed here)
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
P=/sys/module/mxfs/parameters
D=d482_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d482_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
ckgt() { if [ "${2:-0}" -gt "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 > $3)"; else echo "  FAIL $1 got=${2:-?} want>$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.  The bounded create (its
# own timeout inside) reports itself; only a hung ssh (124) is left to the
# verdict on its missing line.
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
PAT='P106-\|P-DREVAL-EPOCH-FAST\|P247-AUTH-PHANTOM\|Corruption\|shutting down\|BUG:\|Oops\|P95-OPEN-PROTECT'
# kernel-health verdict pattern, applied CASE-INSENSITIVELY to the full window
# (s521a's shutdown printed 'Shutting down filesystem' and P-INODE-WEDGE, and
# a case-sensitive grep for the filtered lines read 0)
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|P-LKTIMEOUT\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'

echo "=== d482_phantom_epoch_2node label=$LABEL A=$A B=$B pause_ms=$PAUSE_MS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat $P/force_transport) knobs=\$(ls $P/dbg_p106_inject_ino $P/dbg_p106_inject_shots $P/dbg_p106_bail_pause_ms $P/p106_check_n $P/dbg_dreval_trace_ino 2>/dev/null | wc -l)" | tr -d '\n')"
done
ck "both nodes mounted on the tree's build" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
value_now_into rv1 "$A" 20 "$OUT/rv_rv1_1.txt" '^[0-9]+$' "rv1 on $A" "ls $P/dbg_p106_inject_ino $P/dbg_p106_inject_shots $P/dbg_p106_bail_pause_ms $P/p106_check_n $P/dbg_dreval_trace_ino 2>/dev/null | wc -l"
ck "A has the 0.75.35 D-482 knobs" "$rv1" "5"

MK="D482-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

# 1. A owns the directory (cached EX after its own creates), caches a positive
#    dentry (pos, a subdirectory) and a negative one (neg), and proves both
#    take the zero-I/O fast path under epoch E.  pos is made durable so B can
#    remove it inside the gap.
value_now_into ino "$A" 30 "$OUT/rv_ino_2.txt" '^[0-9]+$' "ino on $A" "mkdir $MNT/$D && mkdir $MNT/$D/pos && sync -f $MNT && stat -c %i $MNT/$D"
echo "  INFO A dir ino=$ino"
ckge "A created $D (ino)" "$ino" 1
pre=$(rs 30 "$A" "stat -c %i $MNT/$D/pos >/dev/null; stat $MNT/$D/neg 2>/dev/null; echo $ino > $P/dbg_dreval_trace_ino; for i in 1 2 3; do stat -c %n $MNT/$D/pos >/dev/null; stat $MNT/$D/neg >/dev/null 2>&1; done; echo checks_before=\$(cat $P/p106_check_n) trace=\$(cat $P/dbg_dreval_trace_ino)" | tail -1)
echo "  INFO A pre: $pre"
chk0=$(echo "$pre" | grep -ao 'checks_before=[0-9]*' | cut -d= -f2)
rs 30 "$A" "dmesg | sed -n '/$MK/,\$p' | grep -a 'P-DREVAL-EPOCH-FAST dp=$ino '" > "$OUT/fast_pre_$A.txt"
fpos=$(grep -ac 'name=pos d_time=[0-9]* epoch=[0-9]* positive=1' "$OUT/fast_pre_$A.txt")
fneg=$(grep -ac 'name=neg d_time=[0-9]* epoch=[0-9]* positive=0' "$OUT/fast_pre_$A.txt")
E=$(grep -a 'name=pos ' "$OUT/fast_pre_$A.txt" | grep -ao 'epoch=[0-9]*' | tail -1 | cut -d= -f2)
En=$(grep -a 'name=neg ' "$OUT/fast_pre_$A.txt" | grep -ao 'epoch=[0-9]*' | tail -1 | cut -d= -f2)
echo "  INFO A fast-path before: pos=$fpos neg=$fneg epoch_pos=${E:-none} epoch_neg=${En:-none}"
ckge "A: positive dentry pos was fast-path valid before (P-DREVAL-EPOCH-FAST positive=1)" "$fpos" 1
ckge "A: negative dentry neg was fast-path valid before (P-DREVAL-EPOCH-FAST positive=0)" "$fneg" 1
ck "A: both stamped under the same epoch E" "${En:-x}" "${E:-y}"

# 2. Arm the one-shots on A, then drive a dir-EX modify serve (a create) that
#    reaches the backing-record check; the injection answers "not held", the
#    bail demotes to NL, bumps the epoch and parks for PAUSE_MS.
value_now_into armed "$A" 15 "$OUT/rv_armed_3.txt" '^armed ' "armed on $A" "echo $ino > $P/dbg_p106_inject_ino; echo $PAUSE_MS > $P/dbg_p106_bail_pause_ms; echo 1 > $P/dbg_p106_inject_shots; echo armed ino=\$(cat $P/dbg_p106_inject_ino) shots=\$(cat $P/dbg_p106_inject_shots) pause=\$(cat $P/dbg_p106_bail_pause_ms)"
echo "  INFO A $armed"
ck "A armed" "$armed" "armed ino=$ino shots=1 pause=$PAUSE_MS"
( rsx $(( PAUSE_MS / 1000 + 90 )) "$A" "s=\$(date +%s%N); timeout $(( PAUSE_MS / 1000 + 60 )) touch $MNT/$D/x; rc=\$?; e=\$(date +%s%N); echo A_TOUCH rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) end=\$(date -u +%T.%N)" > "$OUT/touch_$A.txt"; echo $? > "$OUT/touch_$A.rc" ) &
TPID=$!
# wait (bounded, on the node) for the pause to open before B moves
value_now_into gap "$A" 20 "$OUT/rv_gap_4.txt" '^gap_open=' "gap on $A" "for i in \$(seq 1 60); do dmesg | sed -n '/$MK/,\$p' | grep -aq 'P106-BAIL-PAUSE ino=$ino ' && { echo gap_open=1 at=\$(date -u +%T.%N); exit 0; }; sleep 0.1; done; echo gap_open=0"
echo "  INFO A $gap"
ck "A: the authority gap opened (P106-BAIL-PAUSE) within 6 s of the create" "$(echo "$gap" | grep -ac 'gap_open=1')" "1"

# 3. Inside the gap, B removes the positive name and creates the negative one.
value_now_into bops "$B" $(( PAUSE_MS / 1000 + 60 )) "$OUT/rv_bops_5.txt" '^B_OPS ' "bops on $B" "s=\$(date +%s%N); timeout $(( PAUSE_MS / 1000 + 40 )) sh -c 'rmdir $MNT/$D/pos && touch $MNT/$D/neg'; rc=\$?; e=\$(date +%s%N); echo B_OPS rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) end=\$(date -u +%T.%N)"
echo "  INFO B $bops"
ck "B: rmdir pos + touch neg completed rc=0" "$(echo "$bops" | grep -ac 'B_OPS rc=0')" "1"
wait $TPID
loop_require "$(cat "$OUT/touch_$A.rc")" "$OUT/touch_$A.txt" '^A_TOUCH rc=' "A's create through the pause"
echo "  INFO A touch: $(cat "$OUT/touch_$A.txt")"
ck "A: the create completed after the bail (slow-path re-acquire) rc=0" "$(grep -ac 'A_TOUCH rc=0' "$OUT/touch_$A.txt")" "1"
ckge "A: the create's wall covered the pause (ms)" "$(grep -ao 'wall_ms=[0-9]*' "$OUT/touch_$A.txt" | cut -d= -f2)" "$PAUSE_MS"

# 4. A's lookups after the bail: exactly one stat each, then the trace is off.
value_now_into post "$A" 30 "$OUT/rv_post_6.txt" '^post ' "post on $A" "stat $MNT/$D/pos >/dev/null 2>&1; p=\$?; stat $MNT/$D/neg >/dev/null 2>&1; n=\$?; echo 0 > $P/dbg_dreval_trace_ino; echo 0 > $P/dbg_p106_inject_ino; echo post pos_rc=\$p neg_rc=\$n checks_after=\$(cat $P/p106_check_n) shots=\$(cat $P/dbg_p106_inject_shots) pause=\$(cat $P/dbg_p106_bail_pause_ms) x=\$(stat -c %n $MNT/$D/x 2>/dev/null | wc -l)"
echo "  INFO A $post"
chk1=$(echo "$post" | grep -ao 'checks_after=[0-9]*' | cut -d= -f2)
ck "D-482 (d): A sees the CURRENT namespace — pos is gone (ENOENT)" "$(echo "$post" | grep -ao 'pos_rc=[0-9]*' | cut -d= -f2)" "1"
ck "D-482 (d): A sees the CURRENT namespace — neg exists" "$(echo "$post" | grep -ao 'neg_rc=[0-9]*' | cut -d= -f2)" "0"
ck "A's own create x landed" "$(echo "$post" | grep -ao 'x=[0-9]*' | cut -d= -f2)" "1"
ck "one-shot injection consumed (shots reads 0)" "$(echo "$post" | grep -ao 'shots=[0-9-]*' | cut -d= -f2)" "0"
ck "one-shot pause consumed (pause reads 0)" "$(echo "$post" | grep -ao 'pause=[0-9]*' | cut -d= -f2)" "0"
ckgt "the denominator grew (p106_check_n after > before)" "${chk1:-0}" "${chk0:-0}"

# 5. Capture (the FULL mxfs window minus ledger-page noise, plus the probe
#    subset) and the kernel-side assertions.
for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
    grep -a "$PAT\|^DMESG_END\$" "$OUT/dmesg_full_$n.txt" > "$OUT/dmesg_$n.txt"
done
# the same captures by name, so the per-node verdicts below read from a
# path the boundary was crossed for
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
capture_require "$OUT/dmesg_$A.txt" '^DMESG_END$' "the filtered kernel log on $A"
capture_require "$OUT/dmesg_$B.txt" '^DMESG_END$' "the filtered kernel log on $B"
inj=$(grep -ac "P106-INJECT-CONSUMED ino=$ino " "$OUT/dmesg_$A.txt")
bail=$(grep -ac "P106-STALE-EX-BAIL ino=$ino " "$OUT/dmesg_$A.txt")
bail_e=$(grep -a "P106-STALE-EX-BAIL ino=$ino " "$OUT/dmesg_$A.txt" | grep -ao 'epoch=[0-9]*' | head -1 | cut -d= -f2)
inj_e=$(grep -a "P106-INJECT-CONSUMED ino=$ino " "$OUT/dmesg_$A.txt" | grep -ao 'epoch=[0-9]*' | head -1 | cut -d= -f2)
inj_mode=$(grep -a "P106-INJECT-CONSUMED ino=$ino " "$OUT/dmesg_$A.txt" | grep -ao 'mode=[0-9]* state=[0-9]* ex_h=[0-9]* pr_h=[0-9]* pin=[0-9]*' | head -1)
inj_wire=$(grep -a "P106-INJECT-CONSUMED ino=$ino " "$OUT/dmesg_$A.txt" | grep -ao 'unlock_rc=[0-9-]* resample_held=[0-9]* sampled=[0-9]*' | head -1)
pause_n=$(grep -ac "P106-BAIL-PAUSE ino=$ino " "$OUT/dmesg_$A.txt")
pause_end=$(grep -ac "P106-BAIL-PAUSE-END ino=$ino" "$OUT/dmesg_$A.txt")
post_fast=$(sed -n "/P106-STALE-EX-BAIL ino=$ino /,\$p" "$OUT/dmesg_$A.txt" | grep -a 'P-DREVAL-EPOCH-FAST' | grep -ac 'name=pos \|name=neg ')
echo "  D482-MEASURE $LABEL inject_consumed=$inj bail=$bail inject_epoch=${inj_e:-none} bail_epoch=${bail_e:-none} E=${E:-none} inject_state='${inj_mode:-none}' pause=$pause_n pause_end=$pause_end post_bail_fast_pos_neg=$post_fast checks=${chk0:-?}->${chk1:-?} b_ops='$bops'"
echo "  INFO A P106 lines: $(grep -a 'P106-' "$OUT/dmesg_$A.txt" | sed 's/^\[[^]]*\] mxfs: //' | cut -c1-110 | tr '\n' ';')"
ck "D-482 (a): the injection was consumed exactly once" "$inj" "1"
ck "D-482 (a)+(b): the phantom bail fired exactly once (mode passed through NL)" "$bail" "1"
ck "injection saw the prerequisite state (cached EX, ex_h=1, pin=0)" "$(echo "$inj_mode" | grep -ac 'mode=5 state=[0-9]* ex_h=1 pr_h=0 pin=0')" "1"
ck "injection released the grant on the wire and the REAL check then read it as not held" "${inj_wire:-none}" "unlock_rc=0 resample_held=0 sampled=1"
ck "D-482 (c): the injection ran at epoch E" "${inj_e:-x}" "${E:-y}"
ck "D-482 (c): the bail advanced the epoch to E+1" "${bail_e:-x}" "$(( ${E:-0} + 1 ))"
ck "the authority gap opened and closed once" "$pause_n/$pause_end" "1/1"
ck "D-482 (d): zero fast-path blessings of pos/neg after the bail" "$post_fast" "0"
ck "B: no phantom/authority-loss lines (B's grant was real)" "$(grep -ac 'P106-STALE\|P247-AUTH-PHANTOM' "$OUT/dmesg_$B.txt")" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
[ "$health" != 0 ] && echo "  INFO health lines: $(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ai "$HEALTH" | head -5 | cut -c1-160 | tr '\n' ';')"
ck "kernel health A+B (full window): no corruption/shutdown/wedge/withdraw/lock-timeout/BUG/Oops" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
