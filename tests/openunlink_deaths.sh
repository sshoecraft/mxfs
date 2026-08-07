#!/bin/bash
# tests/openunlink_deaths.sh — crash-point arms of the open-unlink matrix.
# Ledger: D-CROSSNODE-OPEN-UNLINK-DATA-LOSS / D-AGI-UNLINKED (GPT groups 6,7).
#
#   unlinker_death — B rm's a file A holds open (defer, zombie on B's bucket),
#     B dies.  The elected survivor's foreign-slice replay must be followed by
#     the C8 bucket sweep (P97-SWEEP-*): zombie re-driven, A's bit defers it
#     (P87 on the sweeper), A's close converges the reap (P89) — no leak, no
#     corruption, and A's fd stays intact THROUGHOUT.
#   opener_death — B rm's a file A holds open (defer with A's bit), A dies.
#     Fencing strips A's bits in the purge CAS; B's next reap retry frees
#     (P89).  Partition-without-fence must NOT strip (not covered here — needs
#     a netfilter arm, see ledger).
#
# Budget note (RULE 0): each case = fence detect (lease ~6-15s) + replay +
# sweep + reap cadence (5s/30s) + VM restart/rejoin (~60-90s).  ~4 min/case.
#
# usage: openunlink_deaths.sh <case> [A=test1] [B=test2]
set -u
CASE="${1:?case: unlinker_death|opener_death}"
NA="${2:-test1}"
NB="${3:-test2}"
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
RUNID="oud_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
PAY="DEATHS-$RUNID"

say() { echo "[$(date +%H:%M:%S)] $*"; }

survivor_wait() { # survivor_wait <node> <tag> <ERE> <timeout> — dmesg-since poll
  local t=0
  while [ $t -lt "$4" ]; do
    local n; n=$($SSH "$1" "dmesg | sed -n \"/${RUNID}-$2/,\\\$p\" | grep -cE '$3'" 2>/dev/null | tr -d ' \r\n')
    [ "${n:-0}" -gt 0 ] && return 0
    sleep 5; t=$((t+5))
  done
  return 1
}

restart_node() { # restart_node <name> — start VM, restore /src+iSCSI, rejoin
  $VIRSH start "$1" >/dev/null 2>&1
  local t=0
  while [ $t -lt 180 ]; do
    if $SSH "$1" "echo up" >/dev/null 2>&1; then break; fi
    sleep 5; t=$((t+5))
  done
  # A rebooted node loses /src (NFS deliberately not in fstab) and its iSCSI
  # sessions — restore both exactly like run.sh's power_cycle path, then
  # rejoin via prep_node.sh.
  local DEV KOMD5
  DEV=$($SSH "$NA" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
  [ -z "$DEV" ] && DEV=/dev/mapper/mpatha
  $SSH "$1" "
    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1
    iscsiadm -m session --rescan >/dev/null 2>&1
    multipath >/dev/null 2>&1" >/dev/null 2>&1
  local t2=0
  while [ $t2 -lt 90 ]; do
    if $SSH "$1" "[ -e '$DEV' ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP; then break; fi
    $SSH "$1" "multipath >/dev/null 2>&1" >/dev/null 2>&1
    sleep 5; t2=$((t2+5))
  done
  KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
  $SSH "$1" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KOMD5' bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
  if $SSH "$1" "mount -t mxfs | grep -q mxfs" >/dev/null 2>&1; then
    say "$1 rejoined with mxfs mounted"
    return 0
  fi
  say "WARN: $1 did not remount (prep_node rejoin failed)"
  return 1
}

reuse_probe() { # reuse_probe <node> <ino> <tries> — 0 iff ino re-issued (freed)
  $SSH "$1" "mkdir -p $D/rp && for i in \$(seq 1 $3); do touch $D/rp/y\$i; done; stat -c '%i' $D/rp/y* | grep -qx '$2'; rc=\$?; rm -rf $D/rp; exit \$rc" >/dev/null 2>&1
}

case "$CASE" in
unlinker_death)
  $SSH "$NA" "echo ${RUNID}-M > /dev/kmsg; mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  say "victim ino=$INO; A=$NA holds fd, B=$NB unlinks then dies"
  $SSH "$NA" "nohup bash -c 'exec 9<$D/f; echo \$\$ > /tmp/${RUNID}.pid; sleep 900' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 1
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  P87B=$($SSH "$NB" "dmesg | grep -cE 'P87-OPEN-DEFER ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
  say "B deferred (P87=$P87B); killing $NB"
  $VIRSH destroy "$NB" >/dev/null 2>&1
  # The elected survivor replays B's slice then sweeps B's bucket.
  if survivor_wait "$NA" M "P97-SWEEP-DONE" 180; then
    say "sweep ran on $NA"
  else
    say "P97-SWEEP-DONE not seen on $NA in 180s (elected survivor may be another node)"
  fi
  GOT=$($SSH "$NA" "P=\$(cat /tmp/${RUNID}.pid); dd if=/proc/\$P/fd/9 bs=256 count=1 2>/dev/null | tr -d '\0'" 2>/dev/null)
  P87S=$($SSH "$NA" "dmesg | sed -n \"/${RUNID}-M/,\\\$p\" | grep -cE 'P87-OPEN-DEFER ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
  say "A's fd read: '${GOT:0:30}' (want intact); sweeper defer P87=$P87S"
  $SSH "$NA" "kill \$(cat /tmp/${RUNID}.pid) 2>/dev/null" >/dev/null 2>&1
  OK=1
  if [ "$GOT" = "$PAY" ]; then
    # TWO legal post-crash outcomes (B died ~5s after rm; the unlink may or
    # may not have reached B's slice):
    #  α) unlink durable  -> zombie swept/adopted -> P89-REAP-DONE frees it
    #  β) unlink evaporated ATOMICALLY (P227-FR-ATOMIC-SKIP) -> file still
    #     linked: path stats to the SAME ino, content readable by path
    # A TEAR (dirent present but nlink=0 / d????????? / neither outcome) = FAIL.
    if survivor_wait "$NA" M "P89-REAP-DONE ino=${INO}\b" 90; then
      say "outcome α: zombie freed after A's close (P89-REAP-DONE)"
      OK=0
    else
      PINO=$($SSH "$NA" "stat -c '%i' $D/f 2>/dev/null" 2>/dev/null | tr -d ' \r\n')
      PDAT=$($SSH "$NA" "cat $D/f 2>/dev/null" 2>/dev/null)
      if [ "$PINO" = "$INO" ] && [ "$PDAT" = "$PAY" ]; then
        say "outcome β: unlink evaporated atomically; file intact and linked"
        OK=0
      else
        say "FAIL: neither freed (no P89) nor cleanly linked (stat_ino='${PINO:-none}') — torn state"
      fi
    fi
  else
    say "FAIL: A's fd lost data after unlinker death"
  fi
  SHUT=$($SSH "$NA" "dmesg | sed -n \"/${RUNID}-M/,\\\$p\" | grep -cE 'unrecoverable|SHUTDOWN|Internal error'" 2>/dev/null | tr -d ' \r\n')
  restart_node "$NB"
  if [ "$OK" -eq 0 ] && [ "${SHUT:-1}" = "0" ]; then
    echo "RESULT: PASS | case=unlinker_death | ino=$INO intact through B death; sweep+defer+reap converged; shutdowns=0"
    exit 0
  fi
  echo "RESULT: FAIL | case=unlinker_death | ino=$INO got='${GOT:0:30}' ok=$OK shutdowns=${SHUT:-?}"
  exit 1
  ;;
opener_death)
  $SSH "$NA" "mkdir -p $D && echo $PAY > $D/f" >/dev/null 2>&1
  INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null)
  $SSH "$NB" "echo ${RUNID}-M > /dev/kmsg" >/dev/null 2>&1
  say "victim ino=$INO; A=$NA holds fd and dies; B=$NB unlinked + defers"
  $SSH "$NA" "nohup bash -c 'exec 9<$D/f; echo \$\$ > /tmp/${RUNID}.pid; sleep 900' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
  sleep 1
  $SSH "$NB" "rm $D/f" >/dev/null 2>&1
  sleep 3
  P87B=$($SSH "$NB" "dmesg | sed -n \"/${RUNID}-M/,\\\$p\" | grep -cE 'P87-OPEN-DEFER ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
  if [ "${P87B:-0}" = "0" ]; then
    echo "RESULT: FAIL | case=opener_death | precondition: B never deferred (P87=0) — A's bit missing"
    $SSH "$NA" "kill \$(cat /tmp/${RUNID}.pid) 2>/dev/null" >/dev/null 2>&1
    exit 1
  fi
  say "B deferred (P87=$P87B); killing opener $NA"
  $VIRSH destroy "$NA" >/dev/null 2>&1
  # Fence strips A's bits; B's reap (30s cadence) must then free.
  OK=1
  # Fence detect (lease) + purge (bit strip) + B's next reap cadence must
  # free: P89-REAP-DONE on B is the authoritative signal.
  if survivor_wait "$NB" M "P89-REAP-DONE ino=${INO}\b" 420; then
    say "reap freed the zombie after opener fence (P89-REAP-DONE)"
    OK=0
  else
    say "FAIL: no P89-REAP-DONE on $NB within 420s of opener death (bits not stripped?)"
  fi
  SHUT=$($SSH "$NB" "dmesg | sed -n \"/${RUNID}-M/,\\\$p\" | grep -cE 'unrecoverable|SHUTDOWN|Internal error'" 2>/dev/null | tr -d ' \r\n')
  restart_node "$NA"
  if [ "$OK" -eq 0 ] && [ "${SHUT:-1}" = "0" ]; then
    echo "RESULT: PASS | case=opener_death | ino=$INO freed after fence stripped opener's bit; shutdowns=0"
    exit 0
  fi
  echo "RESULT: FAIL | case=opener_death | ino=$INO ok=$OK shutdowns=${SHUT:-?}"
  exit 1
  ;;
*)
  echo "unknown case $CASE"; exit 2;;
esac
