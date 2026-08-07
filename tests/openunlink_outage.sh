#!/bin/bash
# tests/openunlink_outage.sh — FULL-OUTAGE open-bit residue arm (C6 audit item,
# D-CROSSNODE-OPEN-UNLINK).  Requires a 2-node prep (2/caw) so that killing
# both nodes is a genuine full-cluster outage: A opens the victim, B unlinks it
# (A's open bit publishes under B's EX BAST; free defers), then BOTH nodes are
# virsh-destroyed with the bit + zombie durable on disk and NO survivor to
# fence-strip.  On reboot+remount the ONLINE machinery alone (mount recovery,
# settle scans, reap worker) must converge the zombie — a stale open bit from
# the pre-outage incarnation must not defer the reap unboundedly.
#
# PASS: zombie freed (P82-REM/P89-REAP-DONE for the ino) within CONV_S of the
#       second remount, with no manual chk repair.
# FAIL: not freed in time (stale-bit wedge) — that is a NEW confirmed defect.
#
# Budget (RULE 0): setup 20s + destroy 5s + boot 2x ~120s (parallel) +
# prep 2x ~60s + converge <=240s => cap 540s.
#
# usage: openunlink_outage.sh [A=test1] [B=test2]
set -u
NA="${1:-test1}"
NB="${2:-test2}"
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
RUNID="oou_$(date +%s)_$$"
D="/mnt/shared/.${RUNID}"
KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
CONV_S=240

say() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "RESULT: FAIL | case=openunlink_outage | $*"; exit 1; }

DEV=$($SSH "$NA" "mount -t mxfs | awk '{print \$1; exit}'" 2>/dev/null | tr -d ' \r\n')
[ -z "$DEV" ] && DEV=/dev/mapper/mpatha

for n in "$NA" "$NB"; do
  $SSH "$n" "mount -t mxfs | grep -q mxfs" || fail "$n not mounted (prep 2/caw first)"
done
N_MOUNTED=$($SSH "$NA" "dmesg | grep -c 'disklock: claimed heartbeat slot'" 2>/dev/null)

boot_rejoin() { # boot_rejoin <node>
  local node="$1" t=0
  $VIRSH start "$node" >/dev/null 2>&1
  while [ $t -lt 180 ]; do
    $SSH "$node" "echo up" >/dev/null 2>&1 && break
    sleep 5; t=$((t+5))
  done
  $SSH "$node" "
    mountpoint -q /src || { mkdir -p /src; mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
    iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
    iscsiadm -m node --login >/dev/null 2>&1
    iscsiadm -m session --rescan >/dev/null 2>&1
    multipath >/dev/null 2>&1" >/dev/null 2>&1
  local t2=0
  while [ $t2 -lt 90 ]; do
    $SSH "$node" "[ -e '$DEV' ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && break
    $SSH "$node" "multipath >/dev/null 2>&1" >/dev/null 2>&1
    sleep 5; t2=$((t2+5))
  done
  $SSH "$node" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KOMD5' bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
  $SSH "$node" "mount -t mxfs | grep -q mxfs"
}

# ── setup: A holds fd, B unlinks (bit publishes, free defers) ─────────────
$SSH "$NA" "mkdir -p $D && echo OUTAGE-$RUNID > $D/f" >/dev/null 2>&1
INO=$($SSH "$NA" "stat -c '%i' $D/f" 2>/dev/null | tr -d ' \r\n')
[ -z "$INO" ] && fail "victim create failed"
$SSH "$NA" "nohup bash -c 'exec 9<$D/f; sleep 900 9<&-; :' </dev/null >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 1
# ino numbers are heavily reused and dmesg persists across remounts: EVERY
# detection below is count-growth against these pre-unlink baselines.
PAT_DEFER="P87-OPEN-DEFER ino=${INO} |P128-INACT-DEFER ino=${INO} "
PAT_PUB="P90-OPEN-PUBLISH ino=${INO} "
PAT_FREE="P89-REAP-DONE ino=${INO}\b|P82-REM ino=${INO} "
D0=$($SSH "$NB" "dmesg | grep -cE '$PAT_DEFER'" 2>/dev/null | tr -d ' \r\n')
P0=$($SSH "$NA" "dmesg | grep -cE '$PAT_PUB'" 2>/dev/null | tr -d ' \r\n')
FA0=$($SSH "$NA" "dmesg | grep -cE '$PAT_FREE'" 2>/dev/null | tr -d ' \r\n')
FB0=$($SSH "$NB" "dmesg | grep -cE '$PAT_FREE'" 2>/dev/null | tr -d ' \r\n')
say "victim ino=$INO; unlinking from $NB"
$SSH "$NB" "rm $D/f" >/dev/null 2>&1
sleep 4
D1=$($SSH "$NB" "dmesg | grep -cE '$PAT_DEFER'" 2>/dev/null | tr -d ' \r\n')
P1=$($SSH "$NA" "dmesg | grep -cE '$PAT_PUB'" 2>/dev/null | tr -d ' \r\n')
DEFER=$(( ${D1:-0} - ${D0:-0} )); PUB=$(( ${P1:-0} - ${P0:-0} ))
say "pre-outage: publish_delta(A)=$PUB defer_delta(B)=$DEFER (need the free DEFERRED, not done)"
FB1=$($SSH "$NB" "dmesg | grep -cE '$PAT_FREE'" 2>/dev/null | tr -d ' \r\n')
FREED_PRE=$(( ${FB1:-0} - ${FB0:-0} ))
if [ "${FREED_PRE:-0}" -gt 0 ]; then
  echo "RESULT: RETRY | case=openunlink_outage | free was NOT deferred (no open protection engaged?) ino=$INO"
  exit 2
fi

# ── the outage: kill BOTH nodes — no survivor, no fencing ─────────────────
say "destroying BOTH nodes (full outage; bit + zombie durable, unfenced)"
$VIRSH destroy "$NB" >/dev/null 2>&1
$VIRSH destroy "$NA" >/dev/null 2>&1
sleep 3

# ── recovery: boot + remount both, ONLINE machinery only ──────────────────
say "booting + remounting both"
boot_rejoin "$NA" &
P1=$!
boot_rejoin "$NB" &
P2=$!
wait $P1 || fail "$NA failed to rejoin after outage"
wait $P2 || fail "$NB failed to rejoin after outage"
say "both remounted; watching for online convergence of ino=$INO (cap ${CONV_S}s)"

# Both nodes were destroyed and rebooted: their dmesg is FRESH, so any free
# line for this ino on this boot is genuinely post-outage.
T=0; WHO=""
while [ $T -lt $CONV_S ]; do
  for n in "$NA" "$NB"; do
    C=$($SSH "$n" "dmesg | grep -cE '$PAT_FREE'" 2>/dev/null | tr -d ' \r\n')
    if [ "${C:-0}" -gt 0 ]; then WHO="$n"; break 2; fi
  done
  sleep 15; T=$((T+15))
done
if [ -z "$WHO" ]; then
  DEF2=$($SSH "$NA" "dmesg | grep -cE 'P87-OPEN-DEFER ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
  DEF3=$($SSH "$NB" "dmesg | grep -cE 'P87-OPEN-DEFER ino=${INO} '" 2>/dev/null | tr -d ' \r\n')
  fail "zombie ino=$INO NOT freed within ${CONV_S}s of remount — stale-bit wedge? post-outage defer counts A=$DEF2 B=$DEF3"
fi
L=$($SSH "$WHO" "dmesg | grep -E 'P89-REAP-DONE ino=${INO}\b|P82-REM ino=${INO} ' | tail -1" 2>/dev/null | tr -d '\r')
say "converged on $WHO: '$L'"
echo "RESULT: PASS | case=openunlink_outage | ino=$INO freed_by=$WHO after=${T}s pre_outage_defer=$DEFER publish=$PUB — stale open bit did not wedge online recovery"
exit 0
