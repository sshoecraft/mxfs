#!/bin/bash
# tests/orphan_audit_arm.sh — verify chk_mxfs's orphan inode audit against
# REAL torn state (D-DESTAGE-TEAR-BUCKETLESS-ORPHAN, GPT work item (e)).
#
#   NEG arm: quiesced clean device -> audit must report OK, exit 0.
#   POS arm: produce the tear with the REAL producer — A holds the file
#     open, B rm's it and dies mid-destage (dirent+nlink=0 land, AGI bucket
#     insert lost), then A is killed BEFORE its survivor sweep repairs it
#     (everyone-crashed residual).  Offline chk must then:
#       detect  (check-only: orphan error, exit 4)
#       repair  (-y: push onto AGI bucket, exit 1)
#       verify  (recheck: bucketed zombie = legal residue, exit 0)
#   The tear is probabilistic per death — retries up to MAX_TRIES.
#
# Budget (RULE 0): NEG ~40s (umount+chk+remount).  Per POS try: setup ~10s
# + B kill ~3s + A kill ~3s + A boot/restore ~90s + 3x chk ~30s + B boot +
# 2x prep ~120s  => ~5 min/try.  3 tries + NEG => cap 18 min.
#
# usage: orphan_audit_arm.sh [A=test1] [B=test2]
set -u
NA="${1:-test1}"
NB="${2:-test2}"
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
CHK=/src/mxfs/tools/chk_mxfs
RUNID="oaa_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
PAY="ORPHAN-$RUNID"
MAX_TRIES="${MAX_TRIES:-3}"

say() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "RESULT: FAIL | case=orphan_audit | $*"; exit 1; }

DEV=$($SSH "$NA" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -z "$DEV" ] && DEV=/dev/mapper/mpatha
KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')

boot_nomount() { # boot_nomount <node> — start VM, restore /src + iSCSI, NO mxfs
  $VIRSH start "$1" >/dev/null 2>&1
  local t=0
  while [ $t -lt 180 ]; do
    $SSH "$1" "echo up" >/dev/null 2>&1 && break
    sleep 5; t=$((t+5))
  done
  $SSH "$1" "
    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1
    iscsiadm -m session --rescan >/dev/null 2>&1
    multipath >/dev/null 2>&1" >/dev/null 2>&1
  local t2=0
  while [ $t2 -lt 90 ]; do
    $SSH "$1" "[ -e '$DEV' ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && return 0
    $SSH "$1" "multipath >/dev/null 2>&1" >/dev/null 2>&1
    sleep 5; t2=$((t2+5))
  done
  return 1
}

rejoin() { # rejoin <node> — prep_node (module + mount)
  $SSH "$1" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KOMD5' bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
  $SSH "$1" "mount -t mxfs | grep -q mxfs" >/dev/null 2>&1
}

# ── NEG arm: clean quiesced device must audit OK ──────────────────────────
say "NEG: quiescing (umount $NA + $NB)"
$SSH "$NB" "umount /mnt/shared" >/dev/null 2>&1
$SSH "$NA" "umount /mnt/shared" >/dev/null 2>&1
NEGOUT=$($SSH "$NA" "$CHK -v $DEV 2>&1 | grep -E 'Orphan inode audit|^chk_mxfs:'"; )
echo "$NEGOUT" | sed 's/^/    /'
echo "$NEGOUT" | grep -q "Orphan inode audit ...... OK" || fail "NEG: audit not OK on clean device"
echo "$NEGOUT" | grep -q "filesystem clean" || fail "NEG: chk not clean on clean device"
say "NEG PASS — remounting"
rejoin "$NA" || fail "NEG: $NA remount failed"
rejoin "$NB" || fail "NEG: $NB remount failed"

# ── POS arm: real tear, offline detect/repair/verify ──────────────────────
TRY=0
while [ $TRY -lt "$MAX_TRIES" ]; do
  TRY=$((TRY+1))
  say "POS try $TRY/$MAX_TRIES: A=$NA holds fd, B=$NB unlinks + dies, A dies pre-sweep"
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null | tr -d ' \r\n')
  [ -z "$INO" ] && fail "POS: victim create failed"
  say "victim ino=$INO"
  $SSH "$NA" "nohup bash -c 'exec 9<$D/f; sleep 900' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 1
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  $VIRSH destroy "$NB" >/dev/null 2>&1
  sleep 2
  $VIRSH destroy "$NA" >/dev/null 2>&1
  say "both dead; booting $NA without mounting"
  boot_nomount "$NA" || fail "POS: $NA boot/restore failed"

  # detect (check-only)
  CO=$($SSH "$NA" "$CHK $DEV 2>&1"); CRC=$?
  ORPH=$(echo "$CO" | grep -c "on NO AGI unlinked bucket")
  say "check-only: rc=$CRC orphan_lines=$ORPH"
  if [ "$ORPH" -eq 0 ]; then
    say "no tear this try (unlink fully landed or evaporated) — rejoining and retrying"
    rejoin "$NA" || fail "POS: $NA rejoin failed mid-retry"
    boot_nomount "$NB" >/dev/null 2>&1
    rejoin "$NB" || fail "POS: $NB rejoin failed mid-retry"
    continue
  fi
  echo "$CO" | grep -E "inode .*orphaned|Orphan inode audit" | sed 's/^/    /'
  [ "$CRC" -eq 4 ] || fail "POS: detect exit=$CRC want 4"

  # repair
  RO=$($SSH "$NA" "$CHK -y $DEV 2>&1"); RRC=$?
  echo "$RO" | grep -E "REPAIRED.*unlinked bucket|Orphan inode audit" | sed 's/^/    /'
  echo "$RO" | grep -q "REPAIRED: inode .* linked onto AG" || fail "POS: repair did not run (rc=$RRC)"
  [ "$RRC" -eq 1 ] || fail "POS: repair exit=$RRC want 1"

  # verify (recheck: repaired orphan is now a legal bucketed zombie)
  VO=$($SSH "$NA" "$CHK -v $DEV 2>&1"); VRC=$?
  echo "$VO" | grep -E "Orphan inode audit|^chk_mxfs:" | sed 's/^/    /'
  [ "$VRC" -eq 0 ] || fail "POS: post-repair recheck exit=$VRC want 0"
  echo "$VO" | grep -q "Orphan inode audit ...... OK" || fail "POS: post-repair audit not OK"

  say "POS PASS — restoring cluster"
  rejoin "$NA" || fail "POS: $NA final rejoin failed"
  boot_nomount "$NB" >/dev/null 2>&1
  rejoin "$NB" || fail "POS: $NB final rejoin failed"
  # Post-restore observation: the chk-repaired bucketed zombie must be
  # converged online by one of the kernel reapers — single-node dirty-log
  # mount recovery (all-64 sweep), the mount-settle own-bucket rescan, or
  # the guarded unclaimed-bucket pass (fires +20s after mount, retries
  # every 30s).  P82-REM = iunlink_remove in the freeing transaction.
  REAP=0; T=0
  while [ $T -lt 90 ]; do
    REAP=$($SSH "$NA" "dmesg | grep -cE 'P89-REAP-DONE ino=${INO}\b|P98-ORPHAN-ADOPT ino=${INO}\b|P82-REM ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
    [ "${REAP:-0}" -gt 0 ] && break
    sleep 10; T=$((T+10))
  done
  say "post-restore online convergence for ino=$INO: evidence=$REAP after ${T}s"
  echo "RESULT: PASS | case=orphan_audit | neg=OK pos=detect+repair+verify ino=$INO tries=$TRY reap_after_mount=$REAP"
  exit 0
done
fail "POS: no tear produced in $MAX_TRIES tries — arm inconclusive"
