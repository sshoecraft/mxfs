#!/bin/bash
# tcp_stale_resend.sh — a re-send of a LOCK_REQ that reaches the master AFTER
# the requester consumed the grant and released it: is it refused by name, or
# queued as a fresh request and granted to a wait that no longer exists?
#
# The shape was caught by chance in s594c (D-0958): W's PR request was queued,
# granted, served and released by W's own BAST, and 1.1 s later a SECOND grant
# arrived for it with no pending entry and no live wait — a re-send that left
# before the grant and was processed after the release as a new request on a
# free resource.  W bounced it (P958-ACQ-GRANT-BOUNCED, a release back to the
# master), harmless as measured, but it is the duplicate-pending-after-release
# gap the idempotent-master requirement names: between the phantom grant and
# the bounce the master believes W holds a lock W knows nothing about.
#
# 0.84.13 closes it: a LOCK_RELEASE says whether the releaser's acquisition is
# OVER (acq_done — no live record re-sending that name), the master tombstones
# the consumed acquisition, and a later LOCK_REQ carrying it is refused
# (P958-CONSUMED-RESEND-REFUSED) with the same silence as a cancelled one.
#
# The lap produces the shape deterministically with a TEST ONLY knob on W
# (dl_stale_resend_ino): the last LOCK_REQ for the target is re-sent once,
# unchanged, right after W's next LOCK_RELEASE of it — so the master meets a
# stale re-send exactly as it would from the wire.  W reads the target (its
# request goes out and is kept), H rewrites it (BAST, W releases, the copy
# follows the release), and both nodes' logs say what the master did with it.
# CONTROL=1 sets dl_no_consumed_tomb=1 on the MASTER (H) so the pre-0.84.13
# outcome is measured on the same build: the fresh entry, the second grant and
# W's bounce.
#
# the budget rule (derived): preflight ~10 s + 8 candidates ~5 s + search
# <= 8 x 13 s + the read/rewrite ~5 s + an 8 s settle + captures ~10 s = 140 s.
#
# Usage: tests/tcp_stale_resend.sh <label> [W=test2] [H=test1]
# Env:   MXFS_MNT (default /mnt/shared), CONTROL=0|1 (default 0).
# Leaves both nodes mounted and the knobs cleared.  Exit 0 PASS, 1 FAIL,
# 2 INFRA/ABORT.
set -u
LABEL=${1:?label}
W=${2:-test2}; H=${3:-test1}
CONTROL=${CONTROL:-0}
case "$CONTROL" in 0|1) ;; *) echo "ABORT: CONTROL must be 0 or 1"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_staleresend_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): the kernel-log captures
# a verdict is counted from cross the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.
. "$(dirname "$0")/lib/rig.sh"
hd() { rs 25 "$1" "dmesg | sed -n \"/$MARK/,\\\$p\""; }   # polling only; never counted
disarm() {
    timeout 20 $SSH "$W" "echo 0 > $P/dl_stale_resend_ino; echo 0 > $P/dl_drop_lockreq_ino" >/dev/null 2>&1
    timeout 20 $SSH "$H" "echo 0 > $P/dl_no_consumed_tomb" >/dev/null 2>&1
}
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }

echo "=== tcp_stale_resend label=$LABEL W=$W H=$H control=$CONTROL out=$OUT $(date -u +%FT%TZ) ==="
TREESV=$(modinfo mxfs.ko 2>/dev/null | sed -n 's/^srcversion: *//p')
for n in "$W" "$H"; do
    info=$(timeout 20 $SSH "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) m=\$(grep -c ' mxfs ' /proc/mounts) k=\$(test -w $P/dl_stale_resend_ino && test -r $P/dl_stale_resend_n && test -w $P/dl_no_consumed_tomb && test -w $P/dl_drop_lockreq_ino && test -r $P/dl_drop_lockreq_n && echo 1 || echo 0)" 2>/dev/null | filt | tr -d '\r')
    echo "  INFO $n $info"
    [[ "$info" == *"sv=$TREESV"* ]] || { echo "ABORT: $n srcversion != tree '$TREESV' ($info)"; exit 2; }
    [[ "$info" == *"m=1"* ]]        || { echo "ABORT: $n not mounted ($info)"; exit 2; }
    [[ "$info" == *"k=1"* ]]        || { echo "ABORT: $n lacks the 0.84.13 knobs (dl_stale_resend_ino/_n, dl_no_consumed_tomb) ($info)"; exit 2; }
done
MARK="STALERESEND-$LABEL-$$"
for n in "$W" "$H"; do timeout 15 $SSH "$n" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1; done
DM="dmesg | awk '/$MARK/{f=1} f'"

# 1. H writes eight candidates; W finds one remotely mastered from W with the
#    request-drop probe (its firing is the proof), exactly as the black-hole
#    harness does.  Counts are read from the knob's own per-arm counter.
timeout 40 $SSH "$H" "
    for i in 1 2 3 4 5 6 7 8; do
        f='$MNT/.staleresend_${LABEL}_'\$i
        dd if=/dev/urandom of=\"\$f\" bs=4096 count=4 status=none || exit 1
        echo \$i \$(stat -c %i \"\$f\") \$(md5sum \"\$f\" | cut -d' ' -f1)
    done
    sync
  " 2>"$OUT/h_setup.err" | filt > "$OUT/h_setup.txt"
[ "$(grep -ac . "$OUT/h_setup.txt")" = "8" ] || {
    echo "ABORT: H setup wrote $(grep -ac . "$OUT/h_setup.txt")/8 candidates: [$(filt < "$OUT/h_setup.err" | tail -3 | tr '\n' ' ')]"; exit 2; }
TARGET=""; CAND=""
while read -r idx ino md5 <&3; do
    [ -n "$ino" ] || continue
    f="$MNT/.staleresend_${LABEL}_$idx"
    timeout 20 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; echo $ino > $P/dl_drop_lockreq_ino" </dev/null >/dev/null 2>&1
    timeout 20 $SSH "$W" "nohup sh -c 'md5sum \"$f\" > /tmp/sr_probe.out 2>&1' >/dev/null 2>&1 &" </dev/null >/dev/null 2>&1
    sleep 9
    got=$(timeout 20 $SSH "$W" "cat $P/dl_drop_lockreq_n" </dev/null 2>/dev/null | filt | tr -dc '0-9')
    echo "  INFO candidate idx=$idx ino=$ino drop_hits=${got:-0} at +$(el)s"
    timeout 20 $SSH "$W" "echo 0 > $P/dl_drop_lockreq_ino" </dev/null >/dev/null 2>&1
    sleep 4
    if [ "${got:-0}" -ge 1 ]; then TARGET=$ino; CAND=$idx; break; fi
done 3< "$OUT/h_setup.txt"
[ -n "$TARGET" ] || { echo "ABORT: no candidate inode is remotely mastered from $W"; disarm; exit 2; }
F="$MNT/.staleresend_${LABEL}_$CAND"
echo "  INFO target ino=$TARGET file=$F at +$(el)s"

# 2. Arm.  W keeps its next LOCK_REQ for the target; H (the master) keeps or
#    drops the consumed tombstone.  W's cached grant from the probe is evicted
#    with the inode so the read below sends a real request.
timeout 20 $SSH "$H" "echo $CONTROL > $P/dl_no_consumed_tomb; cat $P/dl_no_consumed_tomb" </dev/null >/dev/null 2>&1
timeout 20 $SSH "$W" "echo 3 > /proc/sys/vm/drop_caches; echo $TARGET > $P/dl_stale_resend_ino" </dev/null >/dev/null 2>&1

# 3. W reads (the request goes out and its copy is kept; the grant is served);
#    H rewrites (EX: W is notified, releases, and the copy follows the release).
md5_w1=$(timeout 30 $SSH "$W" "md5sum '$F' | cut -d' ' -f1" </dev/null 2>/dev/null | filt | grep -aoE '^[0-9a-f]{32}' | head -1)
sleep 1
value_now_into md5_h "$H" 30 "$OUT/rv_md5_h_1.txt" '^[0-9a-f]{32}$' "md5_h on $H" "dd if=/dev/urandom of='$F' bs=4096 count=4 conv=notrunc status=none && sync && md5sum '$F' | cut -d' ' -f1"; md5_h=$(printf '%s\n' "$md5_h" | grep -aoE '^[0-9a-f]{32}')
echo "  INFO W read md5=${md5_w1:-none}; H rewrote md5=${md5_h:-none} at +$(el)s"
[ -n "$md5_w1" ] && [ -n "$md5_h" ] || { echo "ABORT: the read or the rewrite failed"; disarm; exit 2; }
# Settle: the stale copy, the master's answer (or its fresh grant and W's
# bounce) all land within the re-send cadence.
sleep 8
value_now_into stale_n "$W" 20 "$OUT/rv_stale_n_2.txt" '^-?[0-9]+$' "stale_n on $W" "cat $P/dl_stale_resend_n"

# 4. W reads again with the knob cleared: the resource must be usable and
#    coherent after whatever the master did with the stale copy.
timeout 20 $SSH "$W" "echo 0 > $P/dl_stale_resend_ino" </dev/null >/dev/null 2>&1
value_now_into md5_w2 "$W" 60 "$OUT/rv_md5_w2_1.txt" '^[0-9a-f]{32}$' "md5_w2 on $W" "echo 3 > /proc/sys/vm/drop_caches; md5sum '$F' | cut -d' ' -f1"; md5_w2=$(printf '%s\n' "$md5_w2" | grep -aoE '^[0-9a-f]{32}')
sleep 2
measure "$W" 25 "$OUT/dmesg_$W.txt" '^DMESG_END$' "the kernel log on $W from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
measure "$H" 25 "$OUT/dmesg_$H.txt" '^DMESG_END$' "the kernel log on $H from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
disarm

sent=$(grep -a 'P958-STALE-RESEND-SENT' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")
sent_line=$(grep -a 'P958-STALE-RESEND-SENT' "$OUT/dmesg_$W.txt" | grep -a "ino=$TARGET " | head -1 | cut -c1-220)
acq_done=$(echo "$sent_line" | grep -ao 'acq_done=[0-9]' | cut -d= -f2)
refused=$(grep -a 'P958-CONSUMED-RESEND-REFUSED' "$OUT/dmesg_$H.txt" | grep -ac "ino=$TARGET ")
bounced=$(grep -a 'P958-ACQ-GRANT-BOUNCED' "$OUT/dmesg_$W.txt" | grep -ac "ino=$TARGET ")
retx=$(grep -a 'P958-ACQ-RETX' "$OUT/dmesg_$H.txt" | grep -ac "ino=$TARGET ")
bast_h=$(grep -ac "P7S-BAST-FIRE ino=$TARGET " "$OUT/dmesg_$H.txt")
echo "  INFO W: stale copies sent=${stale_n:-?} (probe lines $sent: [${sent_line:-none}]); bounced grants for the target=$bounced"
echo "  INFO H: consumed re-sends refused for the target=$refused; re-sends absorbed (RETX)=$retx; notifications fired for the target=$bast_h"
echo "--- verdict ---"
ck "the stale copy was sent once after W's release (dl_stale_resend_n)" "${stale_n:-0}" "1"
ck "the release that preceded it said the acquisition was over (acq_done=1)" "${acq_done:-x}" "1"
ck "W reads the target after the lap with H's bytes (the resource is coherent and usable)" "$([ -n "$md5_w2" ] && [ "$md5_w2" = "$md5_h" ] && echo same || echo differ)" "same"
if [ "$CONTROL" = "1" ]; then
    ck "control: the master did not refuse the stale re-send (tombstone disabled)" "$refused" "0"
    ck "control: the stale re-send was queued afresh, granted, and W bounced it (P958-ACQ-GRANT-BOUNCED >= 1)" "$([ "$bounced" -ge 1 ] && echo 1 || echo 0)" "1"
else
    ck "the master refused the stale re-send by name (P958-CONSUMED-RESEND-REFUSED >= 1 for the target)" "$([ "$refused" -ge 1 ] && echo 1 || echo 0)" "1"
    ck "no phantom grant reached W for the target (P958-ACQ-GRANT-BOUNCED = 0)" "$bounced" "0"
fi
for n in "$W" "$H"; do
    s=$(grep -aEc 'BUG:|Oops|Shutting down filesystem|Corruption of in-memory' "$OUT/dmesg_$n.txt"); ck "zero splats/shutdowns on $n" "$s" "0"
done
timeout 20 $SSH "$H" "rm -f '$MNT'/.staleresend_${LABEL}_1 '$MNT'/.staleresend_${LABEL}_2 '$MNT'/.staleresend_${LABEL}_3 '$MNT'/.staleresend_${LABEL}_4 '$MNT'/.staleresend_${LABEL}_5 '$MNT'/.staleresend_${LABEL}_6 '$MNT'/.staleresend_${LABEL}_7 '$MNT'/.staleresend_${LABEL}_8" >/dev/null 2>&1
echo "=== tcp_stale_resend $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" -eq 0 ]
