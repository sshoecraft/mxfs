#!/bin/bash
# tests/lone_mount_create.sh — sess432 directed measurement for the
# single-node double-allocation (D-SINGLENODE-FALSE-FRESH-DISCARDS-PINNED-AGMETA).
#
# Shape: exactly ONE node mounts the shared LUN (dlm_caw single_node=true:
# caw_lock's single-node fast path grants in memory and returns a
# NON-PROVING grant result, no authority epoch).  The node then does the
# smallest write workload that needs two AG acquires with a committed but
# unlanded AG-meta update in between: mkdir, then create a file inside it.
# The vergate loop arm showed the second acquire is judged "fresh"
# (P243-AGAUTH-UNBOUND cached-fast -> P130-FALSE-FRESH), invalidate_ag_meta
# stales the PINNED finobt/inobt/AGI buffers (P131-INVAL-DISCARD pin=1), the
# platter images are re-read and the same inode number is allocated twice
# ("Allocated a known in-use inode", forced shutdown).
#
# PASS = mkdir + 4 creates + fsync succeed, zero P131-INVAL-DISCARD, zero
#        "Allocated a known in-use inode", zero shutdown since the marker.
# FAIL = any of those.  Prints the evidence lines either way.
#
# derived time budget: fleet umount sweep <=20 s (32 nodes parallel, 12 s each),
# mount <=15 s, workload <2 s, umount <=10 s  => caller bound 60 s.
#
# ARMS (4th arg, sess432 step 2 — design-consult ruling's directed coverage):
#   fixed (default): production knobs; expect PASS.
#   p130 : single_era_hint_keep=0 re-creates the pre-0.39.11 trigger (hint
#          dropped on every re-acquire); expect the P130 invariant to STOP the
#          mount (P130-FALSE-FRESH-REFUSED, shutdown=1) and ZERO double
#          allocation ('in-use inode' = 0).
#   p131 : same trigger with false_fresh_enforce=0 so the acquire reaches the
#          invalidation; expect the preflight to refuse (P131-INVAL-REFUSED,
#          shutdown=1) and ZERO double allocation.
#   remount (D-0355): after the workload, force-shutdown WITHOUT a log flush
#          (XFS_IOC_GOINGDOWN NOLOGFLUSH — only after /proc/mounts proves the
#          path is the mxfs mount), umount, and mount ALONE again: expect
#          mrc2=0, the dirty own slice replayed by the mount barrier, and the
#          fsync'd file present (file=1).  Bound: barrier 30 s + replay.
#   remount_snx (D-0355 / D-379(B), sess433): the remount arm with the
#          operator's single_node_exclusive=1 assertion.  0.40.0 keeps the PR
#          key on a dirty departure (P302-PR-KEY-RETAINED-FENCE-TARGET) and
#          the successor's plain REGISTER conflicts on the retained key; under
#          snx=1 it is REPLACED (P305-PR-PREDECESSOR-KEY-REPLACED), fence kind
#          17 proves exclusion, the slice replays: expect p302>=1 p305r>=1
#          mrc2=0 file=1.
#   remount_refused (sess433): same dirty departure WITHOUT the assertion:
#          expect p302>=1, P305-PR-PREDECESSOR-KEY-PRESENT (p305p>=1) and the
#          remount REFUSED (mrc2!=0) — a same-nexus successor cannot fence its
#          predecessor.  Teardown clears the LU's PR table (sg_persist) so the
#          next prep is unaffected.
# Knobs are restored to their defaults on the node afterwards.
#
# usage: tests/lone_mount_create.sh <label> [node=test1] [nodes=32] [arm=fixed]
set -u
LABEL=${1:?label}; N=${2:-test1}; NN=${3:-32}; ARM=${4:-fixed}
P=/sys/module/mxfs/parameters
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
SSH=tools/mxfs_sshpass.sh
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "$N"; LUN=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lone_mount_create_$LABEL
mkdir -p "$OUT"
MARK="LONE-$LABEL-$$"
echo "=== lone_mount_create label=$LABEL node=$N out=$OUT $(date -u +%FT%TZ) ==="

# 1. nobody else may be mounted: bounded per-node umount sweep, per-node rc
for i in $(seq 1 "$NN"); do
  ( timeout 12 $SSH "test$i" "umount /mnt/shared 2>/dev/null; mount -t mxfs | grep -c shared" > "$OUT/umount_test$i.txt" 2>&1; echo "rc=$?" >> "$OUT/umount_test$i.txt" ) &
done
wait
STILL=$(grep -l '^1' "$OUT"/umount_test*.txt 2>/dev/null | wc -l)
echo "sweep: nodes still mounted after umount=$STILL"
[ "$STILL" = "0" ] || { echo "RESULT: FAIL | lone_mount_create | precondition: $STILL node(s) still mounted"; exit 1; }
sleep 3

# 2. arm knobs (only on builds that have them; a missing knob = FAIL for the
#    fault arms, ignored for 'fixed')
case "$ARM" in
  fixed) KN="true";;
  p130)  KN="echo 0 > $P/single_era_hint_keep";;
  p131)  KN="echo 0 > $P/single_era_hint_keep && echo 0 > $P/false_fresh_enforce";;
  remount) KN="true";;
  remount_snx) KN="echo 1 > $P/single_node_exclusive";;
  remount_refused) KN="true";;
  *) echo "RESULT: FAIL | lone_mount_create | unknown arm '$ARM'"; exit 1;;
esac
KR=$(timeout 15 $SSH "$N" "$KN 2>&1 && echo knobs_ok; cat $P/single_era_hint_keep $P/false_fresh_enforce $P/agmeta_inval_enforce 2>/dev/null | tr '\n' ','" 2>/dev/null | tr '\n' ' ')
echo "arm=$ARM knobs: $KR"
case "$KR" in *knobs_ok*) ;; *) echo "RESULT: FAIL | lone_mount_create | arm=$ARM knobs not settable ('$KR')"; exit 1;; esac

# 3. lone mount + workload on $N
R=$(timeout 40 $SSH "$N" "echo $MARK > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrc=\$?; sleep 1; dmesg | grep -ac 'single_node = true'; mkdir /mnt/shared/lone_$LABEL 2>&1; echo mkdir_rc=\$?; for k in 1 2 3 4; do echo x > /mnt/shared/lone_$LABEL/f\$k 2>&1; echo create\${k}_rc=\$?; done; sync; echo sync_rc=\$?; ls /mnt/shared/lone_$LABEL | wc -l" 2>/dev/null | tr '\n' ' ')
echo "workload: $R"
R2=""
case "$ARM" in remount|remount_snx|remount_refused)
  # dirty shutdown of the lone mount, then a second lone mount of the same fs
  R2=$(timeout 75 $SSH "$N" "python3 - <<'EOF'
import os, fcntl, struct, sys
ok=any(len(l.split())>2 and l.split()[1]=='/mnt/shared' and l.split()[2]=='mxfs' for l in open('/proc/mounts'))
if not ok:
    print('NOT-MXFS-MOUNT'); sys.exit(0)
fd=os.open('/mnt/shared', os.O_RDONLY)
fcntl.ioctl(fd, 0x8004587d, struct.pack('I', 2))   # GOINGDOWN NOLOGFLUSH
os.close(fd); print('shutdown-ok')
EOF
umount /mnt/shared 2>&1; echo urc1=\$?; echo $MARK-REMOUNT > /dev/kmsg; mount -t mxfs $LUN /mnt/shared 2>&1; echo mrc2=\$?; dmesg | sed -n '/$MARK-REMOUNT/,\$p' | grep -ac 'Starting recovery\|replayed=\|recovery complete\|P163-RECOVERY-COMPLETE'; grep -q x /mnt/shared/lone_$LABEL/f1 2>/dev/null && echo file=1 || echo file=0" 2>/dev/null | tr '\n' ' ')
  echo "remount: $R2";;
esac
# 4. evidence since marker
timeout 20 $SSH "$N" "dmesg | sed -n '/$MARK/,\$p' | grep -a 'single_node\|P243-AGAUTH\|P130-FALSE\|P131-INVAL\|in-use inode\|P-DIALLOC\|Internal error\|Shutting down\|SHUTDOWN\|Corruption\|P302-\|P305-\|P277-\|P301-\|P300-\|P274-\|P308-\|P309-\|fence kind\|FENCE' | cut -c1-520" > "$OUT/dmesg_$N.txt" 2>/dev/null
P131=$(grep -c 'P131-INVAL-DISCARD' "$OUT/dmesg_$N.txt"); INUSE=$(grep -c 'in-use inode' "$OUT/dmesg_$N.txt"); SD=$(grep -c 'Shutting down' "$OUT/dmesg_$N.txt"); P130=$(grep -c 'P130-FALSE-FRESH' "$OUT/dmesg_$N.txt")
P130R=$(grep -c 'P130-FALSE-FRESH-REFUSED' "$OUT/dmesg_$N.txt"); P131R=$(grep -c 'P131-INVAL-REFUSED' "$OUT/dmesg_$N.txt")
# sess439: with the derived per-boot key a same-boot remount REUSES its
# registration (P305-PR-SAME-BOOT-KEY-REUSED) and the dirty-predecessor
# refusal is P305-PR-SAME-BOOT-DIRTY-PREDECESSOR; under snx the same line
# says 'proceeding'.  Both older tags are still accepted (pre-0.45.1 builds).
P302=$(grep -c 'P302-PR-KEY-RETAINED' "$OUT/dmesg_$N.txt")
P305P=$(grep -c 'P305-PR-PREDECESSOR-KEY-PRESENT\|P305-PR-SAME-BOOT-DIRTY-PREDECESSOR.*Refusing' "$OUT/dmesg_$N.txt")
P305R=$(grep -c 'P305-PR-PREDECESSOR-KEY-REPLACED\|P305-PR-SAME-BOOT-DIRTY-PREDECESSOR.*proceeding' "$OUT/dmesg_$N.txt")
cat "$OUT/dmesg_$N.txt"
# sess440 (0.45.1): after a same-boot dirty REFUSAL the registration must
# still be on the nexus — dm_pr_register's rollback of a failed plain
# REGISTER unregistered the retained key on 0.45.0 (P302 then
# P305-PR-SWAP-NOKEY).  Read the LU's key table BEFORE teardown clears it and
# require the key named by the retention line to be present.  KEYHELD=-1 when
# the arm does not apply.
KEYHELD=-1
if [ "$ARM" = remount_refused ]; then
  RKEY=$(grep -ao 'P302-PR-KEY-RETAINED[A-Z-]* .*key=0x[0-9a-f]*' "$OUT/dmesg_$N.txt" | tail -1 | grep -o 'key=0x[0-9a-f]*' | cut -d= -f2)
  timeout 20 $SSH "$N" "sg_persist -i -k $LUN 2>&1" > "$OUT/prkeys_after_refusal.txt" 2>/dev/null
  if [ -n "$RKEY" ]; then
    KEYHELD=$(grep -aic "$RKEY" "$OUT/prkeys_after_refusal.txt")
  else
    KEYHELD=0
  fi
  echo "after refusal: retained_key=${RKEY:-none} keyheld=$KEYHELD keys: $(grep -a '0x' "$OUT/prkeys_after_refusal.txt" | tr '\n' ' ')"
fi
# 5. teardown + knob restore
PRCLR=true
[ "$ARM" = remount_refused ] && PRCLR="sg_persist --out --register-ignore --param-sark=0x5eed $LUN >/dev/null 2>&1; sg_persist --out --clear --param-rk=0x5eed $LUN >/dev/null 2>&1; echo prclear_rc=\$?"
timeout 30 $SSH "$N" "umount /mnt/shared 2>&1; echo urc=\$?; echo 1 > $P/single_era_hint_keep 2>/dev/null; echo 1 > $P/false_fresh_enforce 2>/dev/null; echo 0 > $P/single_node_exclusive 2>/dev/null; $PRCLR" 2>/dev/null | tr '\n' ' '; echo
OK=1
case "$ARM" in
  fixed)
    case "$R" in *"mrc=0 "*"mkdir_rc=0 create1_rc=0 create2_rc=0 create3_rc=0 create4_rc=0 sync_rc=0 4"*) [ "$P131" = 0 ] && [ "$INUSE" = 0 ] && [ "$SD" = 0 ] && OK=0;; esac;;
  p130)
    case "$R" in *"mrc=0 "*"mkdir_rc=0"*) [ "$P130R" -ge 1 ] && [ "$INUSE" = 0 ] && [ "$SD" -ge 1 ] && OK=0;; esac;;
  p131)
    case "$R" in *"mrc=0 "*"mkdir_rc=0"*) [ "$P131R" -ge 1 ] && [ "$INUSE" = 0 ] && [ "$SD" -ge 1 ] && OK=0;; esac;;
  remount)
    case "$R" in *"mrc=0 "*"mkdir_rc=0 create1_rc=0"*) case "$R2" in *"shutdown-ok"*"mrc2=0 "*"file=1"*) [ "$INUSE" = 0 ] && [ "$P131" = 0 ] && OK=0;; esac;; esac;;
  remount_snx)
    case "$R" in *"mrc=0 "*"mkdir_rc=0 create1_rc=0"*) case "$R2" in *"shutdown-ok"*"mrc2=0 "*"file=1"*) [ "$INUSE" = 0 ] && [ "$P131" = 0 ] && [ "$P302" -ge 1 ] && [ "$P305R" -ge 1 ] && [ "$P305P" = 0 ] && OK=0;; esac;; esac;;
  remount_refused)
    case "$R" in *"mrc=0 "*"mkdir_rc=0 create1_rc=0"*) case "$R2" in *"shutdown-ok"*"mrc2=0 "*) ;; *"shutdown-ok"*"mrc2="*) [ "$P302" -ge 1 ] && [ "$P305P" -ge 1 ] && [ "$P305R" = 0 ] && [ "$KEYHELD" -ge 1 ] && OK=0;; esac;; esac;;
esac
if [ $OK = 0 ]; then echo "RESULT: PASS | lone_mount_create arm=$ARM | p130=$P130 p130r=$P130R p131=$P131 p131r=$P131R inuse=$INUSE shutdown=$SD p302=$P302 p305p=$P305P p305r=$P305R keyheld=$KEYHELD"; else echo "RESULT: FAIL | lone_mount_create arm=$ARM | p130=$P130 p130r=$P130R p131=$P131 p131r=$P131R inuse=$INUSE shutdown=$SD p302=$P302 p305p=$P305P p305r=$P305R keyheld=$KEYHELD workload='$R' remount='$R2'"; fi
echo "=== lone_mount_create $LABEL done out=$OUT $(date -u +%FT%TZ) ==="
exit $OK
