#!/bin/bash
# Reproduce the SCST strictly-serialized block_count leak on the ISOLATED
# disk2 scratch target (separate scst_device from production disk1).
#
# Strategy: drive MIXED load on N concurrent iSCSI sessions to disk2 ---
# high-iodepth random READS (non-serialized -> keep dev->on_dev_cmd_count > 1)
# plus a stream of COMPARE AND WRITE (strictly serialized) at LBA 0. With
# on_dev_cmd_count > 1 when a CAW arrives, SCST takes the
# strictly_serialized_cmd_waiting (sscw) path. Then ALL sessions are
# force_closed simultaneously mid-flight (target-side, scoped to disk2),
# mirroring mass initiator teardown. scst_mon.py watches disk2's block_count
# and reports a persistent leak.
#
# disk1 (production) is a different scst_device and is never touched.
# Requires: the 8 repro ifaces/sessions created by --setup first.
#
# Usage:
#   scst_caw_repro.sh --setup       # create 8 ifaces + login 8 sessions
#   scst_caw_repro.sh [ROUNDS]      # run repro loop (default 80)
#   scst_caw_repro.sh --teardown    # logout + remove repro sessions/ifaces
set -u
# Target/device are overridable via env so the same harness drives the fast
# fileio scratch (disk2) or the high-latency dm-delay scratch (delaydisk).
T=${T:-iqn.2026-05.local.mxfs:disk2}
MONDEV=${MONDEV:-disk2}
IFP=${IFP:-d2}                       # iscsi iface name prefix
INIP=${INIP:-iqn.2026-06.repro:d2}   # initiator name prefix
P=127.0.0.1:3260
N=8
SROOT="/sys/kernel/scst_tgt/targets/iscsi/$T/sessions"
MON="sudo PYTHONPATH=/home/steve/.local/lib/python3.12/site-packages python3 /src/mxfs/scripts/scst_mon.py $MONDEV"
PERDEV=${PERDEV:-6}
NUM=${NUM:-8}

devs() { sudo iscsiadm -m session -P3 2>/dev/null | awk -v t="$T" '
  /Target:/{c=$2} /Attached scsi disk/{if(c==t)print "/dev/"$4}' | sort -u; }
sessions() { ls $SROOT/ 2>/dev/null; }

setup() {
  for i in $(seq 1 $N); do
    sudo iscsiadm -m iface -I ${IFP}_$i -o new >/dev/null 2>&1
    sudo iscsiadm -m iface -I ${IFP}_$i -o update -n iface.initiatorname \
         -v ${INIP}-$i >/dev/null 2>&1
    sudo iscsiadm -m node -T $T -p $P -I ${IFP}_$i -o new >/dev/null 2>&1
    sudo iscsiadm -m node -T $T -p $P -I ${IFP}_$i --login >/dev/null 2>&1
  done
  sleep 3
  echo "sessions: $(sessions | wc -l)  devices: $(devs | tr '\n' ' ')"
}

teardown() {
  for i in $(seq 1 $N); do
    sudo iscsiadm -m node -T $T -p $P -I ${IFP}_$i -u >/dev/null 2>&1
    sudo iscsiadm -m node -T $T -p $P -I ${IFP}_$i -o delete >/dev/null 2>&1
    sudo iscsiadm -m iface -I ${IFP}_$i -o delete >/dev/null 2>&1
  done
  echo "torn down"
}

relogin() {
  for i in $(seq 1 $N); do
    [ -d "$SROOT/${INIP}-$i" ] && continue
    sudo iscsiadm -m node -T $T -p $P -I ${IFP}_$i --login >/dev/null 2>&1
  done
}

run() {
  local rounds=${1:-80} r D j
  for r in $(seq 1 $rounds); do
    relogin
    local DEVS; DEVS=$(devs)
    local nd; nd=$(echo "$DEVS" | grep -c /dev/)
    [ "$nd" -lt 1 ] && { sleep 1; continue; }
    local D1; D1=$(echo "$DEVS" | head -1)
    sudo dd if=$D1 bs=512 count=$NUM of=/tmp/caw_cmp 2>/dev/null
    cat /tmp/caw_cmp /tmp/caw_cmp > /tmp/caw_buf

    # monitor self-exits after 8s (covers settle + load + drain); avoids
    # signalling across sudo (kill -TERM to sudo would not reach python).
    $MON 8 >/tmp/scst_mon.$r.out 2>&1 &
    local MONPID=$!
    sleep 2

    # non-serialized read load: keep on_dev_cmd_count > 1
    for D in $DEVS; do
      sudo fio --name=r --filename=$D --direct=1 --rw=randread --bs=4k \
        --iodepth=32 --numjobs=2 --ioengine=libaio --time_based \
        --runtime=4 >/dev/null 2>&1 &
    done
    # SCSI-atomic CAW stream at LBA0 (overlapping -> atomic-blocker chains)
    local PIDS=""
    for D in $DEVS; do for j in $(seq 1 $PERDEV); do
      ( for k in $(seq 1 800); do
          sudo sg_compare_and_write --in=/tmp/caw_buf --lba=0 --num=$NUM -q $D \
            >/dev/null 2>&1 || break
        done ) &
      PIDS="$PIDS $!"
    done; done
    # SERIALIZED PR-OUT churn (register/unregister) -> exercises block_count
    # path concurrently with CAW, mirroring PR fencing + CAW lock transport.
    local ki=0
    for D in $DEVS; do
      ki=$((ki+1)); local KEY=$(printf "0x%016x" $((0xbeef0000 + ki)))
      ( for k in $(seq 1 400); do
          sudo sg_persist -o -G -S $KEY $D >/dev/null 2>&1
          sudo sg_persist -o -G -K $KEY -S 0 $D >/dev/null 2>&1 || break
        done ) &
      PIDS="$PIDS $!"
    done

    sleep 1.5
    # simultaneous abrupt teardown of all sessions
    for s in $(sessions); do echo 1 | sudo tee $SROOT/$s/force_close >/dev/null 2>&1 & done
    wait $(jobs -p 2>/dev/null) 2>/dev/null

    kill $PIDS 2>/dev/null
    sudo pkill -f "sg_compare_and_write --in=/tmp/caw_buf" 2>/dev/null
    sudo pkill -f "fio --name=r" 2>/dev/null
    sudo pkill -f "sg_persist -o" 2>/dev/null
    wait $MONPID 2>/dev/null   # monitor self-exits at its 8s timeout
    local S; S=$(grep SUMMARY /tmp/scst_mon.$r.out 2>/dev/null)
    echo "round $r: $S"
    if echo "$S" | grep -q "leak=(" ; then
      echo "!!! LEAK REPRODUCED round $r"
      grep -E "LEAK|SUMMARY" /tmp/scst_mon.$r.out
      return 9
    fi
  done
  echo "no leak after $rounds rounds"
}

case "${1:-run}" in
  --setup) setup ;;
  --teardown) teardown ;;
  *) run "${1:-80}" ;;
esac
