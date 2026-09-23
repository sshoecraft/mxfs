#!/bin/bash
# agifc_churn_experiment.sh — instrumented experiment driver for the sess399
# AGI-freecount "+1" divergence (ledger: the 0.23.9 AG0/AG5 regression).
#
# One experiment = fresh 32/caw prep -> knobs -> tmpfile churn (mode) ->
# fleet sweep of the P-AGIFC audits (0.23.10) + P72/Internal-error counters
# -> host-side platter decode of the two-owner AGs (tools/mxfs_agi_dump.py)
# -> chk_mxfs error lines.  Everything lands in $OUT; the summary is printed.
#
# Usage: tests/agifc_churn_experiment.sh <label> <mode: pernode|shared> [inj=0] [iters=200] [nodes=32] [--no-prep]
# Env:   AGIFC_OUT (dir; default mktemp -d under the scratchpad if set, else /tmp)
#        MXFS_MKFS_OPTS (default "-d 50G" — the 25-AG geometry that shares AGs 0..6)
#
# budget: every step is bounded by its MEASURED wall (prep 83 s measured sess398
# -> 180 s cap incl. preflight; churn derives its own budget; sweep 60 s/node
# in parallel; platter decode < 5 s).  A step that overruns is recorded FAIL.
# the unkillable-wedge rule: all remote calls bounded, per-node rc captured, no pgrep -f.

LABEL=${1:?label}; MODE=${2:?pernode|shared}; INJ=${3:-0}; ITERS=${4:-200}; NODES=${5:-32}
PREP=1; [ "${6:-}" = --no-prep ] && PREP=0
cd "$(dirname "$0")/.." || exit 2
OUT=${AGIFC_OUT:-$(mktemp -d)}; mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
export MXFS_MKFS_OPTS=${MXFS_MKFS_OPTS:--d 50G}
echo "=== agifc_churn_experiment label=$LABEL mode=$MODE inj=$INJ iters=$ITERS nodes=$NODES prep=$PREP out=$OUT $(date -u +%FT%TZ) ==="

t0=$(date +%s)
if [ $PREP = 1 ]; then
	export D385_OUT=$OUT MXFS_KEEP_ARTIFACTS=1
	D385_STEP="arm_prep TREATMENT" timeout 180 tests/d385_publication_verify.sh 3 $NODES > "$OUT/prep.log" 2>&1
	rc=$?; echo "prep rc=$rc wall=$(( $(date +%s) - t0 ))s  $(grep -m1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-120)"
	[ $rc = 0 ] || { echo "PREP FAILED — see $OUT/prep.log"; exit 3; }
fi

# knobs: fossil fix on, injector as requested; verify version + mount on every node
D=$(mktemp -d)
for i in $(seq 1 $NODES); do ( timeout 40 $SSH test$i "echo 1 > /sys/module/mxfs/parameters/iunl_fossil_fix; echo $INJ > /sys/module/mxfs/parameters/iunl_fossil_inject; echo ver=\$(cat /sys/module/mxfs/srcversion) fix=\$(cat /sys/module/mxfs/parameters/iunl_fossil_fix) inj=\$(cat /sys/module/mxfs/parameters/iunl_fossil_inject) rel=\$(cat /sys/module/mxfs/parameters/agifc_release_audit 2>/dev/null) m=\$(grep -c ' mxfs ' /proc/mounts)" >$D/t$i 2>/dev/null; echo $? >$D/rc$i ) & done; wait
for i in $(seq 1 $NODES); do echo "test$i rc=$(cat $D/rc$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/t$i | tr '\n' ' ')"; done > "$OUT/knobs.txt"
echo "knobs: $(grep -c 'm=1' "$OUT/knobs.txt")/$NODES mounted, versions: $(grep -oE 'ver=[0-9A-F]+' "$OUT/knobs.txt" | sort | uniq -c | tr '\n' ' ')"

# churn
t1=$(date +%s)
TMPC_MODE=$MODE TMPC_OUT=$OUT/churn tests/tmpfile_churn.sh $NODES $ITERS > "$OUT/churn.txt" 2>&1
echo "churn rc=$? wall=$(( $(date +%s) - t1 ))s  pass=$(grep -c 'verdict=PASS' "$OUT/churn.txt") fail=$(grep -c 'verdict=FAIL' "$OUT/churn.txt")"
grep -E '^test' "$OUT/churn.txt" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(rc|mxfs|done|errs)=/) printf "%s ", $i; print $1}' | sort | uniq -c | sort -rn | head -8

# let inodegc/drains settle, then sweep
sleep 5
D=$(mktemp -d)
for i in $(seq 1 $NODES); do ( timeout 60 $SSH test$i "echo am=\$(dmesg | grep -c 'P-AGIFC-MISMATCH') ar=\$(dmesg | grep -c 'P-AGIFC-RELEASE-MISMATCH') nt=\$(dmesg | grep -c 'P-IUNL-RM-NOTENURE') ptu=\$(dmesg | grep -c 'P-AGMETA-PRIORTENURE-UNDESTAGED') p72=\$(dmesg | grep -c 'P72-INSTR finobt-near-fail') ie=\$(dmesg | grep -c 'Internal error i != 1') d117=\$(dmesg | grep -c 'P-DIALLOC .*err=-117') sd=\$(dmesg | grep -c 'Shutting down') dc=\$(dmesg | grep -c 'Corruption of in-memory') m=\$(grep -c ' mxfs ' /proc/mounts); dmesg | grep -E 'P-AGIFC-MISMATCH|P-AGIFC-RELEASE' | head -12 | cut -c1-420" >$D/t$i 2>/dev/null; echo $? >$D/rc$i ) & done; wait
for i in $(seq 1 $NODES); do echo "test$i rc=$(cat $D/rc$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/t$i | head -1)"; grep -av '^Unauthorized\|^Warning:\|^If you' $D/t$i | tail -n +2 | sed 's/^/    /'; done > "$OUT/sweep.txt"
sum() { grep -oE " $1=[0-9]+" "$OUT/sweep.txt" | cut -d= -f2 | awk '{s+=$1} END {print s+0}'; }
echo "sweep: am=$(sum am) ar=$(sum ar) nt=$(sum nt) ptu=$(sum ptu) p72=$(sum p72) ie=$(sum ie) d117=$(sum d117) sd=$(sum sd) dc=$(sum dc) nodes_firing=$(grep -E '^test' "$OUT/sweep.txt" | grep -vcE ' am=0 ar=0 ')"
grep -E 'P-AGIFC' "$OUT/sweep.txt" | head -20

# Optional (AGIFC_UMOUNT=1): clean-unmount the whole fleet BEFORE chk.  A
# chk on a live LUN is NOT a consistency oracle for a HELD AG: the owner's
# in-core image is authoritative mid-tenure and the platter may legitimately
# carry a btree write that landed before its AGI write (sess400 E4: AG 23
# read AGI=62 vs btrees=63 at chk time, 63==63==63 at the same LSN minutes
# later).  Only a released AG (drained at unlock) must be consistent on the
# medium.  32-way parallel umount measured ~100 s (sess342); 150 s/node cap.
if [ "${AGIFC_UMOUNT:-0}" = 1 ]; then
	t2=$(date +%s); D=$(mktemp -d)
	for i in $(seq 1 $NODES); do ( timeout 160 $SSH test$i "timeout 150 umount /mnt/shared; echo rc=\$? m=\$(grep -c ' mxfs ' /proc/mounts)" >$D/t$i 2>/dev/null; echo $? >$D/rc$i ) & done; wait
	for i in $(seq 1 $NODES); do echo "test$i ssh_rc=$(cat $D/rc$i) $(grep -av '^Unauthorized\|^Warning:\|^If you' $D/t$i | tr '\n' ' ')"; done > "$OUT/umount.txt"
	echo "umount: wall=$(( $(date +%s) - t2 ))s unmounted=$(grep -c ' m=0' "$OUT/umount.txt")/$NODES still_mounted=$(grep -v ' m=0' "$OUT/umount.txt" | awk '{print $1}' | tr '\n' ' ')"
fi

# chk (gives xfs_data_offset) + platter view of the two-owner AGs 0..6
HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
timeout 240 tools/chk_mxfs -v "$HOST_IMG" > "$OUT/chk.txt" 2>&1; echo "chk rc=$? errors: $(grep -c 'ERROR' "$OUT/chk.txt")  $(grep 'AGI freecount' "$OUT/chk.txt" | head -5 | tr '\n' ';')"
XOFF=$(grep -oE 'xfs_data_offset=[0-9]+' "$OUT/chk.txt" | head -1 | cut -d= -f2)
HOST_IMG=$(tools/mxfs_host_image.sh) || { echo "$HOST_IMG"; exit 2; }
[ -n "$XOFF" ] && timeout 120 python3 tools/mxfs_agi_dump.py --img "$HOST_IMG" --xfs-off "$XOFF" 0 1 2 3 4 5 6 > "$OUT/platter.txt" 2>&1
grep -E '^AG [0-9]+ AGI' "$OUT/platter.txt" 2>/dev/null | awk '{print $1,$2,$4,$5}' | tr '\n' ';'; echo
echo "=== done label=$LABEL total=$(( $(date +%s) - t0 ))s out=$OUT ==="
