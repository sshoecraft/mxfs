#!/bin/bash
# tests/d0965_successor_killed_after_register.sh <A> <B> [label]
#
# D-0965 negative case for the held-admission fix, second arm: a same-boot
# successor that REGISTERS its (identical per-boot) PR key and then dies
# before it can settle its predecessor's RETIRE_PENDING record leaves
# exactly the state the fix holds admission on — key PRESENT, no heartbeat
# slot claimed, the PR ledger naming the successor's new node id.  A peer
# mounting into that state must NOT be held past the mount-thread grace:
# it withdraws the record, fences the key, recovers the slot and mounts;
# the victim, rebooted, re-registers a new per-boot key and rejoins.
#
# Sequence (both nodes start mounted; A is a libvirt VM on this host):
#   1. B unmounts, then A unmounts (both carry same-boot records)
#   2. A's READ KEYS is slowed 1.5 s (dbg_pr_read_keys_delay_ms) so its
#      REGISTER lands ~0.5 s into the mount and its settle ~8 s in; A's
#      mount starts in the background and A is virsh-destroyed KILL_AT_S
#      later (default 3): registered, ledger published, unsettled
#   3. the PR table (chk_mxfs --pr-keys from B) must still carry A's key;
#      a poller on B then samples the table once a second for KEY_WATCH_S
#      (key_poll.txt) so the key's lifetime after the death is measured
#   4. B mounts alone under MOUNT_BOUND, within a few seconds of the kill;
#      from B's ring since the mark:
#        SEEN_PRESENT  P304-RETIRE-WORKER ... result=PRESENT (the first
#                      sight itself is logged state=UNKNOWN)
#        GRACE / HELD  P304-RETIRE-PRESENT-GRACE / P-ADMIT-RETIRE-PENDING-HELD
#        EXPIRED       P304-RETIRE-EXPIRED-WITHDRAWN ... immediate=1
#        PEER          P304-RETIRE-COMPLETED-BY-PEER (settled ABSENT)
#        CERT          P236-FENCE-CERTIFIED
#        ABORTED       'MXFS mount ABORTED'
#      expect rc=0 and GRACE>=1, then ONE of two lawful outcomes, reported:
#        - the key outlived the grace: EXPIRED>=1 with 'after N ms' >=
#          MIN_GRACE_MS (the mount-thread grace, 10000) and CERT>=1
#        - the target dropped the dead session's registration inside the
#          grace (an iSCSI target may retire a lost nexus's key itself):
#          PEER>=1 and the poll shows the key vanishing
#      and A's key ABSENT afterwards either way
#   5. A is started again, prepped (tests/setup/prep_node.sh tcp) and must
#      mount without a refusal; a file written on B reads on A
# RESULT PASS / FAIL as above; INCONCLUSIVE when B never met the key
# (KEY_AFTER_KILL=ABSENT or SEEN_PRESENT=0).  On any failure the fleet is
# left as it is and the recovery needed is printed.
# budget: umounts ~6 s + kill window ~5 s + keys 10 s + B mount <= 90 s
# (10 s grace + fence + clean-slice replay + purge, 12 s measured) + VM
# boot to ssh <= 180 s + prep <= 120 s + checks 15 s: bound 430 s.
set -u
cd /src/mxfs || exit 1
A=${1:?node A (the VM killed after its REGISTER)}; B=${2:?node B (the peer that mounts into the corpse)}
LABEL=${3:-d0965kill}
DELAY_MS=${DELAY_MS:-1500}; KILL_AT_S=${KILL_AT_S:-3}
MOUNT_BOUND=${MOUNT_BOUND:-90}; UMOUNT_BOUND=${UMOUNT_BOUND:-100}
BOOT_BOUND=${BOOT_BOUND:-180}; MIN_GRACE_MS=${MIN_GRACE_MS:-10000}
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
MNT=${MXFS_MNT:-/mnt/shared}
PARAMS=/sys/module/mxfs/parameters
CHK=/src/mxfs/tools/chk_mxfs
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0965kill_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/window_count_into/mxfs_dev_resolve (tests/lib/rig.sh):
# every count a verdict is taken from is acquired into its own file and
# validated in the parent shell first; a failed ssh is an ABORT, never a
# count of zero.
. "$(dirname "$0")/lib/rig.sh"
MARK="D0965KILL-$LABEL-$$"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
echo "=== d0965_successor_killed_after_register A=$A B=$B delay_ms=$DELAY_MS kill_at_s=$KILL_AT_S mount_bound=$MOUNT_BOUND out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
for n in $A $B; do
  nsv=$(rs 15 "$n" "cat /sys/module/mxfs/srcversion" | tr -dc 'A-F0-9')
  [ "$nsv" = "$want" ] || { echo "RESULT FAIL d0965kill: $n srcversion '$nsv' != tree '$want'"; exit 2; }
  rs 15 "$n" "grep -q ' $MNT mxfs ' /proc/mounts && echo mounted" | grep -q mounted || { echo "RESULT FAIL d0965kill: $MNT not mounted on $n at start"; exit 2; }
done
$VIRSH domstate "$A" 2>/dev/null | grep -q running || { echo "RESULT FAIL d0965kill: $A is not a running libvirt domain on this host"; exit 2; }
mxfs_dev_resolve "$A"
DEV=$MXFS_DEV_RESOLVED
echo "  INFO device=$DEV (from $A's live mount)"
# cnt: POLLING ONLY (the REGISTERED wait); never feeds a verdict
cnt() { rs 20 "$1" "dmesg | sed -n \"/$2/,\\\$p\" | grep -ac '$3'" | tr -dc '0-9'; }
# keys_into <file>: the PR key table via chk_mxfs on B, across the boundary
# (the sentinel follows chk_mxfs's success, so a failed probe is an ABORT,
# never an empty table); read the keys back with keys_of <file>
keys_into() { measure "$B" 40 "$1" '^KEYS_END$' "the PR key table via chk_mxfs on $B" "$CHK --pr-keys $DEV && echo KEYS_END"; }
keys_of() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | sort -u; }
mnt() { # <node> <bound> -> "rc=N wall_ms=M"
  rs $(( $2 + 15 )) "$1" "T0=\$(date +%s%N); timeout $2 mount -t mxfs $DEV $MNT; R=\$?; echo rc=\$R wall_ms=\$(( (\$(date +%s%N) - T0) / 1000000 ))" | grep -ao 'rc=[0-9]* wall_ms=[0-9]*'
}
for n in $A $B; do rs 15 "$n" "echo '$MARK' > /dev/kmsg" >/dev/null; done
# 1. both leave (B first, then A)
for n in $B $A; do
  o=$(rs $((UMOUNT_BOUND+10)) "$n" "timeout $UMOUNT_BOUND umount $MNT; echo UMOUNT_RC=\$?")
  echo "$o" | grep -q 'UMOUNT_RC=0' || { echo "RESULT FAIL d0965kill: umount on $n failed: $o"; exit 2; }
done
window_into "$OUT/rv_akey_1.txt" "$A" 20; akey=$(cat "$OUT/rv_akey_1.txt" | grep -ao 'P-PRKEY-REGISTERED .mxfs. key=0x[0-9a-f]*' | tail -1 | grep -o 'key=0x[0-9a-f]*' | cut -d= -f2)
[ -n "$akey" ] && akey=$(printf '0x%016x' "$akey")
echo "  INFO A's per-boot key=${akey:-?}"
# 2. A mounts slowly in the background and is killed once its REGISTER has
#    landed.  A fixed KILL_AT_S sleep killed A BEFORE the PROUT on the first
#    run (s50kill: a_mount empty, A's record read ABSENT on B, no key in the
#    table): the ssh login, the mount's pre-observe bracket (one delayed READ
#    KEYS) and the REGISTER itself take longer than 3 s under the delay.  So
#    A's ring is polled for its own P-PRKEY-REGISTERED line after the mark
#    (bounded by KILL_WAIT_S) and A is destroyed the moment it appears; its
#    settle is ~8 s further in under the delay, so a ~1 s poll is inside the
#    window.  KILL_AT_S is now the floor the poll starts from.
KILL_WAIT_S=${KILL_WAIT_S:-25}
rs 15 "$A" "echo $DELAY_MS > $PARAMS/dbg_pr_read_keys_delay_ms" >/dev/null
# A's mount ssh runs in its own session so the whole client can be killed the
# moment A is destroyed: waiting for it to notice the dead peer took 96 s
# (s51kill), by which time the target had already dropped the corpse's
# registration and B mounted into an ABSENT key — the arm never ran.
setsid bash -c "$SSH $A 'timeout $MOUNT_BOUND mount -t mxfs $DEV $MNT; echo AMOUNT_RC=\$?' > '$OUT/a_mount.txt' 2>&1" &
apid=$!
TM=$(date +%s%N)
sleep "$KILL_AT_S"
regd=0
while [ $(( ( $(date +%s%N) - TM ) / 1000000000 )) -lt "$KILL_WAIT_S" ]; do
  if [ "$(cnt "$A" "$MARK" 'P-PRKEY-REGISTERED .mxfs. key=')" -ge 1 ] 2>/dev/null; then regd=1; break; fi
done
TK=$(date +%s%N)
$VIRSH destroy "$A" >/dev/null 2>&1 || { echo "RESULT FAIL d0965kill: virsh destroy $A failed"; exit 2; }
kill -- -"$apid" 2>/dev/null; wait "$apid" 2>/dev/null
echo "  INFO $A destroyed $(( ( $(date +%s%N) - TK ) / 1000000 )) ms after the request, $(( ( TK - TM ) / 1000000 )) ms into its mount, registered_seen=$regd"
ck "A's REGISTER landed before the kill (P-PRKEY-REGISTERED seen on A)" "$regd" "1"
# 3. the corpse's registration must still be in the table, and its lifetime
#    from here is measured: a poller on B reads the key table once a second
#    for KEY_WATCH_S while B mounts (PR IN beside a mount is harmless), so
#    the ring's PRESENT/ABSENT verdicts can be set against the target's own
#    behaviour — an iSCSI target may drop a dead session's registration by
#    itself, in which case B settles the record ABSENT instead of withdrawing
#    it; both are lawful, and which one happened is reported, not assumed.
KEY_WATCH_S=${KEY_WATCH_S:-75}
keys_into "$OUT/keys_after_kill.txt"
kpresent=$([ -n "$akey" ] && keys_of "$OUT/keys_after_kill.txt" | grep -cx "$akey" || echo 0)
echo "  INFO $(( ( $(date +%s%N) - TK ) / 1000000 )) ms after the kill: A's key ${akey:-?} $([ "$kpresent" = 1 ] && echo PRESENT || echo ABSENT) in the PR table"
( rs $((KEY_WATCH_S+20)) "$B" "T0=\$(date +%s%N); for i in \$(seq 1 $KEY_WATCH_S); do k=\$($CHK --pr-keys $DEV 2>/dev/null | grep -oE '^  0x[0-9a-f]+' | tr -d ' ' | tr '\n' ,); echo \"\$(( (\$(date +%s%N) - T0) / 1000000 )) \${k:-none}\"; sleep 1; done" > "$OUT/key_poll.txt" 2>&1 ) &
ppid=$!
if [ -z "$akey" ]; then echo "  FAIL could not learn A's key before the kill"; fails=$((fails+1)); fi
# 4. B mounts into it
TB=$(date +%s%N)
bm=$(mnt "$B" "$MOUNT_BOUND"); brc=${bm#rc=}; brc=${brc%% *}; bwall=${bm##*wall_ms=}
echo "  INFO B's mount started $(( ( TB - TK ) / 1000000 )) ms after the kill"
wait "$ppid" 2>/dev/null
vanish=$(grep -v "$akey" "$OUT/key_poll.txt" | head -1 | cut -d' ' -f1)
lastseen=$(grep "$akey" "$OUT/key_poll.txt" | tail -1 | cut -d' ' -f1)
echo "  INFO key poll on $B: A's key last seen at ${lastseen:-never} ms, first absent at ${vanish:-never} ms after the poll started ($(wc -l < "$OUT/key_poll.txt") samples)"
# the first sight is logged state=UNKNOWN (table not yet read) and the
# retire worker's classification follows as 'result=PRESENT' (s51kill2)
window_count_into seenp "$B" 20 "$MARK" 'P304-RETIRE-WORKER.*result=PRESENT\|P304-RETIRE-PENDING-SEEN.*state=PRESENT' "seenp"; window_count_into grace "$B" 20 "$MARK" 'P304-RETIRE-PRESENT-GRACE' "grace"
window_count_into held "$B" 20 "$MARK" 'P-ADMIT-RETIRE-PENDING-HELD' "held"; window_count_into exp "$B" 20 "$MARK" 'P304-RETIRE-EXPIRED-WITHDRAWN.*immediate=1' "exp"
window_count_into expany "$B" 20 "$MARK" 'P304-RETIRE-EXPIRED-WITHDRAWN' "expany"; window_count_into peer "$B" 20 "$MARK" 'P304-RETIRE-COMPLETED-BY-PEER' "peer"
window_count_into cert "$B" 20 "$MARK" 'P236-FENCE-CERTIFIED' "cert"; window_count_into abrt "$B" 20 "$MARK" 'MXFS mount ABORTED' "abrt"
window_into "$OUT/rv_expms_2.txt" "$B" 20 "$MARK"; expms=$(cat "$OUT/rv_expms_2.txt" | grep -a 'P304-RETIRE-EXPIRED-WITHDRAWN' | grep -ao 'after [0-9]* ms' | head -1 | grep -o '[0-9]*')
measure "$B" 40 "$OUT/b_ring.txt" '^DMESG_END$' "the kernel log on $B from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\" | grep -a 'P30[1345]-\|P-ADMIT-RETIRE\|P163-\|P236-\|P-PR-FENCE\|P-PRKEY-\|MXFS mount\|mount REFUSED\|Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption\|Ending clean mount'; echo DMESG_END"
echo "  RESULT B_mount rc=${brc:-none} wall_ms=${bwall:-none} KEY_AFTER_KILL=$([ "$kpresent" = 1 ] && echo PRESENT || echo ABSENT) SEEN_PRESENT=$seenp GRACE=$grace HELD=$held EXPIRED_MOUNT_THREAD=$exp EXPIRED_ANY=$expany expired_after_ms=${expms:-none} SETTLED_ABSENT_BY_PEER=$peer CERT=$cert ABORTED=$abrt"
ck "B mounted into the corpse's registration (rc=0)" "${brc:-none}" "0"
if [ "$kpresent" = 1 ] && { [ "${seenp:-0}" -ge 1 ] || [ "${grace:-0}" -ge 1 ]; }; then
  reached=1
  ck "B held admission for the grace first (GRACE >= 1)" "$([ "${grace:-0}" -ge 1 ] && echo yes || echo no)" "yes"
  if [ "${expany:-0}" -ge 1 ]; then
    echo "  INFO outcome: the key outlived the grace; B's mount thread withdrew the record and fenced it"
    ck "the withdraw was the mount thread's (EXPIRED immediate=1 >= 1)" "$([ "${exp:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "the withdraw waited at least the mount-thread grace (after >= $MIN_GRACE_MS ms)" "$([ "${expms:-0}" -ge "$MIN_GRACE_MS" ] && echo yes || echo no)" "yes"
    ck "the corpse's key was fenced (P236-FENCE-CERTIFIED >= 1)" "$([ "${cert:-0}" -ge 1 ] && echo yes || echo no)" "yes"
  else
    echo "  INFO outcome: the target dropped the dead session's registration inside the grace (absent at ${vanish:-?} ms of the poll); B settled the record ABSENT without a fence"
    ck "B settled the record ABSENT by proof (P304-RETIRE-COMPLETED-BY-PEER >= 1)" "$([ "${peer:-0}" -ge 1 ] && echo yes || echo no)" "yes"
    ck "the key poll saw the key vanish (first absent sample exists)" "$([ -n "$vanish" ] && echo yes || echo no)" "yes"
  fi
else
  reached=0
  echo "  NOTE the arm was not reached: A's key was $([ "$kpresent" = 1 ] && echo PRESENT || echo ABSENT) right after the kill and B saw PRESENT $seenp times — the target retired the dead session's registration before B's mount thread could meet it"
fi
ck "no mount abort on B" "${abrt:-na}" "0"
ck "B's mount inside the bound (wall <= ${MOUNT_BOUND}000 ms)" "$([ "${bwall:-999999}" -le $((MOUNT_BOUND*1000)) ] && echo yes || echo no)" "yes"
keys_into "$OUT/keys_after_b_mount.txt"
[ -n "$akey" ] && ck "A's key $akey ABSENT after B's mount" "$(keys_of "$OUT/keys_after_b_mount.txt" | grep -cx "$akey")" "0"
ck "no shutdown/corruption lines on B" "$(grep -ac 'Filesystem has been shut down\|force_shutdown\|Corruption detected\|Metadata corruption' "$OUT/b_ring.txt")" "0"
# 5. A comes back and rejoins
$VIRSH start "$A" >/dev/null 2>&1 || { echo "  FAIL virsh start $A"; fails=$((fails+1)); }
T0=$SECONDS; up=0
while [ $((SECONDS - T0)) -lt "$BOOT_BOUND" ]; do
  rs 10 "$A" "echo up" | grep -q up && { up=1; break; }
  sleep 5
done
echo "  INFO $A ssh $([ $up = 1 ] && echo "up after $((SECONDS - T0)) s" || echo "NOT up after $BOOT_BOUND s")"
ck "$A rebooted and answers ssh inside $BOOT_BOUND s" "$up" "1"
if [ $up = 1 ]; then
  # a freshly booted node has no /src: the tree is NFS and the prep script
  # lives on it (s50kill: 'prep_node.sh: No such file' read as a prep
  # failure), so mount it first, retrying while the network settles
  # the preparation's own record (NODE_PREP_OK/FAIL) is required: a missing
  # /src, an absent prep script or a failed mount is an ABORT, never a
  # count of zero refusals
  measure "$A" 200 "$OUT/rv_o_3.txt" '^[0-9]+$' "the re-prep and remount of $A" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; MXFS_DEV=$DEV timeout 120 /src/mxfs/tests/setup/prep_node.sh tcp 2>&1 | tail -3; dmesg | grep -ac 'mount REFUSED\|P305-PR-PREDECESSOR-KEY-PRESENT' || [ \$? = 1 ]"
  prep_require "$OUT/rv_o_3.txt" "the node preparation on $A"
  o=$(cat "$OUT/rv_o_3.txt")
  echo "$o" | sed 's/^/  INFO prep: /'
  ck "$A re-prepped and mounted (NODE_PREP_OK)" "$(echo "$o" | grep -c NODE_PREP_OK)" "1"
  ck "$A's remount was not refused" "$(echo "$o" | tail -1 | tr -dc '0-9')" "0"
  rs 20 "$B" "echo $LABEL-$$ > $MNT/.d0965kill_$LABEL && sync && echo w" | grep -q w || { echo "  FAIL write on $B"; fails=$((fails+1)); }
  measure "$A" 20 "$OUT/rv_rv1_1.txt" '^READ_RC=[0-9]+$' "rv1 on $A" "cat $MNT/.d0965kill_$LABEL; printf '\nREAD_RC=%s\n' \$?"; rv1=$(grep -av '^READ_RC=' "$OUT/rv_rv1_1.txt" | tr -dc 'A-Za-z0-9_-')
  # the filter keeps every character the label can carry: under the gate the
  # label holds underscores, and a filter of a-z0-9- turned the correct read
  # into a FAIL against the unfiltered expectation (s59h)
  ck "$A reads $B's write" "$rv1" "$LABEL-$$"
  rs 20 "$B" "rm -f $MNT/.d0965kill_$LABEL" >/dev/null
fi
echo "  INFO fails=$fails reached=$reached evidence=$OUT"
[ "$fails" = 0 ] || { echo "RESULT FAIL d0965kill: fails=$fails reached=$reached out=$OUT (fleet: check $A is prepped and both nodes mounted)"; exit 1; }
[ "$reached" = 1 ] || { echo "RESULT INCONCLUSIVE d0965kill: B never met the dead successor's registration (the target had already retired it); B mounted clean and the victim rejoined out=$OUT"; exit 3; }
echo "RESULT PASS d0965kill: B held admission on the dead successor's registration for the grace, $([ "${expany:-0}" -ge 1 ] && echo "withdrew and fenced it" || echo "then settled it ABSENT once the target dropped it") and mounted; the victim rejoined out=$OUT"
exit 0
