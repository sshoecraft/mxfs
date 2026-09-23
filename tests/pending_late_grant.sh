#!/bin/bash
# tests/pending_late_grant.sh — a grant that completes a DLM pending entry at
# the instant its waiter's attempt times out: is it kept, and is nothing freed
# under the completion?
#
# THE SUBJECT (D-A-GRANT-COMPLETING-A-PENDING-ENTRY-RACES-THE-WAITERS-TIMEOUT-
# FREE).  Every attempt of a queued DLM request waits MXFS_LOCK_ACQUIRE_WAIT_MS
# (1 s) on its pending entry, then removes the entry from the bucket and frees
# it and re-sends.  The completion of that entry — a grant received from the
# master, a promotion by the local master, a membership change's fail-all —
# used to find the entry under the bucket lock, DROP the lock, and only then
# complete it.  A waiter that timed out in that gap unlinked and freed the
# entry first, and the completion then locked a destroyed mutex in freed
# memory.  0.89.69 completes the entry under the bucket lock and makes a
# timed-out waiter re-read the entry after its remove, so a completion that
# landed as the attempt timed out is an answer the waiter keeps
# (P-PENDING-LATE-GRANT-KEPT, counted in dl_pending_late_kept_n).
#
# THE INSTRUMENT.  dl_pending_complete_delay_ms (TEST ONLY, 0.89.69) holds a
# completion between the lookup and pending_complete.  Set above the attempt
# wait (1500 ms > 1000 ms) on the requesting node, every completion of a
# queued request there lands after its attempt timed out — on the old
# ordering that is the use-after-free, deterministically; on the new one the
# waiter's remove waits behind the completion and keeps the grant.  So the
# lap is the fix's verification: the late-kept line and counter must appear,
# every write both nodes made must be present afterwards, and neither node
# may log a BUG, an Oops or a slab warning.  The old ordering cannot be
# witnessed here without slab poisoning on the guest kernel (slub_debug=FZP),
# which this lap does not arrange; it is the reproduction if the fix is ever
# doubted, with this same knob.
#
# THE WORKLOAD.  Both nodes append, with fsync, to the SAME eight files in
# turn for WORK_S seconds: every append needs the inode's EX, the other node
# holds it or wants it, and mastership is page-aligned over the two node ids,
# so from each node about half the files are remotely mastered (a grant on
# the wire) and half locally (a promotion) — both completion paths carry the
# knob.  Each node's lines carry its name and a sequence number, so the
# integrity check is a count: every line each node reports having written
# must be in the file.
#
# THE BUDGET (derived): boot-wait 200 + prep 300 (measured 48-137 s) + arm
# 20 + the workload WORK_S 90 (native XFS does an append+fsync in ~1 ms; MXFS
# with a 1.5 s hold on every grant of a contended inode does dozens per file,
# not thousands — the workload is bounded by the clock, not by a count) +
# settle and integrity 40 + windows 40 + disarm 20 = 710.  Caller bound 750.
#
# Usage: tests/pending_late_grant.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2), DELAY_MS (1500), WORK_S (90), NFILES (8).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
[ "$A" = "$B" ] && { echo "ABORT: this lap needs two distinct nodes (MXFS_NODE_LIST=$MXFS_NODE_LIST)"; exit 2; }
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
DELAY_MS=${DELAY_MS:-1500}
WORK_S=${WORK_S:-90}
NFILES=${NFILES:-8}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_plgrant_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="PLGRANT-MARK-$LABEL"
DIR=$MNT/plgrant_$LABEL
echo "=== pending_late_grant label=$LABEL A=$A B=$B delay_ms=$DELAY_MS work_s=$WORK_S nfiles=$NFILES $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
vac() { echo "  VACUOUS $1"; echo "RESULT: VACUOUS label=$LABEL reason=$2 evidence=$OUT wall=$(el)s"; exit 3; }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
DISARMED=0
disarm() {
    [ "$DISARMED" = 1 ] && return 0
    DISARMED=1
    for n in "$A" "$B"; do
        rs 20 "$n" "echo 0 > $PARM/dl_pending_complete_delay_ms 2>/dev/null; cat $PARM/dl_pending_complete_delay_ms 2>/dev/null || echo -" > "$OUT/${n}_disarm.txt" 2>/dev/null
    done
    echo "STAGE disarmed dl_pending_complete_delay_ms on both nodes (now '$(tail -1 "$OUT/${A}_disarm.txt" 2>/dev/null)' / '$(tail -1 "$OUT/${B}_disarm.txt" 2>/dev/null)') at +$(el)s"
}
trap disarm EXIT

# ---- 0. the build must carry the fix's line and its knob
for sym in P-PENDING-LATE-GRANT-KEPT dl_pending_complete_delay_ms dl_pending_late_kept_n; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
for n in "$A" "$B"; do
    st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
    [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
done
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ "$prc" = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    rs 20 "$n" "cat /sys/module/mxfs/srcversion" > "$OUT/${n}_srcversion.txt" 2>/dev/null
    ck "prep deployed the tree build on $n" "$(tail -1 "$OUT/${n}_srcversion.txt")" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy evidence=$OUT"; exit 2; }

# ---- 1. the files, the marks, the knob on BOTH nodes (each is a requester
#         of the other's masters, and each promotes its own waiters)
measure "$A" 30 "$OUT/A_mkfiles.txt" '^FILES_END$' "the shared files created from $A" \
    "mkdir -p $DIR && for i in \$(seq 1 $NFILES); do : > $DIR/f\$i; done && sync -f $DIR && ls $DIR | wc -l && echo FILES_END"
for n in "$A" "$B"; do
    rs 15 "$n" "echo $MARK > /dev/kmsg" >/dev/null 2>&1
    value_now_into k "$n" 20 "$OUT/${n}_arm.txt" '^KNOB=[0-9]+ KEPT0=[0-9]+$' "the knob and the counter on $n after arming" \
        "echo $DELAY_MS > $PARM/dl_pending_complete_delay_ms; echo KNOB=\$(cat $PARM/dl_pending_complete_delay_ms) KEPT0=\$(cat $PARM/dl_pending_late_kept_n)"
    echo "STAGE $n armed: $k at +$(el)s"
    eval "KEPT0_${n//[^A-Za-z0-9_]/_}=\${k#*KEPT0=}"
done

# ---- 2. the workload, both nodes at once, bounded by the clock
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, time
d, who, secs, nfiles = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
t0 = time.monotonic(); n = 0; i = 0; errs = 0
while time.monotonic() - t0 < secs:
    f = os.path.join(d, "f%d" % (i % nfiles + 1)); i += 1
    try:
        fd = os.open(f, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, ("%s %d\n" % (who, n)).encode()); os.fsync(fd); n += 1
        finally:
            os.close(fd)
    except OSError as e:
        errs += 1
        if errs <= 5: print("WRITER_ERR %s %s" % (f, e))
        time.sleep(0.05)
print("WRITER_DONE who=%s written=%d errors=%d wall=%.1f" % (who, n, errs, time.monotonic() - t0))
PY
)
for n in "$A" "$B"; do
    rs 20 "$n" "echo $WRITER_B64 | base64 -d > /run/plgrant_writer.py; nohup python3 /run/plgrant_writer.py $DIR $n $WORK_S $NFILES > /run/plgrant_writer.out 2>&1 & echo STARTED \$!" > "$OUT/${n}_start.txt" 2>/dev/null
    capture_require "$OUT/${n}_start.txt" '^STARTED [0-9]+$' "the writer start on $n"
done
echo "STAGE both writers running for ${WORK_S}s at +$(el)s"
sleep $((WORK_S + 10))
for n in "$A" "$B"; do
    measure "$n" $((WORK_S + 30)) "$OUT/${n}_writer.txt" '^WRITER_DONE ' "the writer's result on $n" \
        "for i in \$(seq 1 $((WORK_S + 20))); do grep -q WRITER_DONE /run/plgrant_writer.out 2>/dev/null && break; sleep 1; done; cat /run/plgrant_writer.out"
    echo "  $n: $(grep -a '^WRITER_DONE' "$OUT/${n}_writer.txt" | head -1)"
done

# ---- 3. the counters, the windows, the integrity
for n in "$A" "$B"; do
    value_now_into k "$n" 20 "$OUT/${n}_kept.txt" '^KEPT=[0-9]+$' "the late-kept counter on $n" "echo KEPT=\$(cat $PARM/dl_pending_late_kept_n)"
    eval "KEPT_${n//[^A-Za-z0-9_]/_}=\${k#KEPT=}"
    window_into "$OUT/${n}_win.txt" "$n" 60 "$MARK"
done
disarm
measure "$A" 60 "$OUT/A_integrity.txt" '^INTEGRITY_END$' "every line both nodes wrote, read back from $A" \
    "sync -f $DIR; for who in $A $B; do echo \$who=\$(cat $DIR/f* | grep -c \"^\$who \"); done; echo INTEGRITY_END"
kA=$(eval echo "\$KEPT_${A//[^A-Za-z0-9_]/_}"); kB=$(eval echo "\$KEPT_${B//[^A-Za-z0-9_]/_}")
k0A=$(eval echo "\$KEPT0_${A//[^A-Za-z0-9_]/_}"); k0B=$(eval echo "\$KEPT0_${B//[^A-Za-z0-9_]/_}")
wA=$(grep -ao 'written=[0-9]*' "$OUT/${A}_writer.txt" | head -1 | cut -d= -f2)
wB=$(grep -ao 'written=[0-9]*' "$OUT/${B}_writer.txt" | head -1 | cut -d= -f2)
eA=$(grep -ao 'errors=[0-9]*' "$OUT/${A}_writer.txt" | head -1 | cut -d= -f2)
eB=$(grep -ao 'errors=[0-9]*' "$OUT/${B}_writer.txt" | head -1 | cut -d= -f2)
rA=$(grep -a "^$A=" "$OUT/A_integrity.txt" | cut -d= -f2)
rB=$(grep -a "^$B=" "$OUT/A_integrity.txt" | cut -d= -f2)
count_file_into lA "$OUT/${A}_win.txt" 'P-PENDING-LATE-GRANT-KEPT'
count_file_into lB "$OUT/${B}_win.txt" 'P-PENDING-LATE-GRANT-KEPT'
# The slab signatures are the allocator's own complaint lines, not the word
# "slab" anywhere: s151e FAILed on three `? __memcg_slab_post_alloc_hook`
# frames inside a P36-STACK diagnostic dump (the first-timeout wait-site
# dump this contended workload provokes on purpose).
BADPAT='BUG:\|Oops\|kernel NULL pointer\|slab-out-of-bounds\|slab-use-after-free\|Slab corruption\|Redzone overwritten\|Object already free\|KASAN\|general protection\|Poison overwritten\|refcount_t'
count_file_into badA "$OUT/${A}_win.txt" "$BADPAT"
count_file_into badB "$OUT/${B}_win.txt" "$BADPAT"
count_file_into shutA "$OUT/${A}_win.txt" 'hutting down filesystem\|P-WITHDRAW'
count_file_into shutB "$OUT/${B}_win.txt" 'hutting down filesystem\|P-WITHDRAW'
echo "STAGE late-kept: $A $((kA - k0A)) (lines $lA), $B $((kB - k0B)) (lines $lB); written $A=$wA $B=$wB errors $eA/$eB; read back $A=$rA $B=$rB; bad lines $badA/$badB; shutdowns $shutA/$shutB at +$(el)s"
grep -a 'P-PENDING-LATE-GRANT-KEPT' "$OUT/${A}_win.txt" "$OUT/${B}_win.txt" | head -3 | cut -c1-230 | sed 's/^/    /'

# ---- 4. the verdict
if [ $((kA - k0A + kB - k0B)) -lt 1 ]; then
    vac "no completion landed after its waiter's timeout on either node (dl_pending_late_kept_n unchanged: $k0A->$kA, $k0B->$kB) with the knob at ${DELAY_MS} ms — the workload produced no queued request, so the ordering was not exercised" no-late-completion
fi
ckge "a completion that landed as its waiter timed out was kept, on at least one node (late-kept total)" "$((kA - k0A + kB - k0B))" 1
ck "every line $A reported written is in the files" "$rA" "$wA"
ck "every line $B reported written is in the files" "$rB" "$wB"
ck "$A's writer hit no error" "${eA:-x}" 0
ck "$B's writer hit no error" "${eB:-x}" 0
ck "no BUG/Oops/slab/KASAN/poison line on $A" "$badA" 0
ck "no BUG/Oops/slab/KASAN/poison line on $B" "$badB" 0
ck "no filesystem shutdown or withdrawal on $A" "$shutA" 0
ck "no filesystem shutdown or withdrawal on $B" "$shutB" 0
echo "=== pending_late_grant $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ $fails -eq 0 ]; then
    echo "RESULT: PASS label=$LABEL late_kept=$((kA - k0A + kB - k0B)) written=$((wA + wB)) fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL late_kept=$((kA - k0A + kB - k0B)) written=$((wA + wB)) fails=$fails wall=$(el)s evidence=$OUT"; exit 1
