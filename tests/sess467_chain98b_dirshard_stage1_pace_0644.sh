#!/bin/bash
# sess467 chain 98b: directory sharding stage 1 on a module that actually
# dispatches the ioctls, then the pace laps.
#
# Chain 97 (frozen 0.64.0) failed every stage-1 selftest check with ENOTTY on
# MXFS_IOC_DIRSHARD_MKDIR: the sess466 dispatch went into pal/linux/xfs_ioctl.c,
# which is NOT in Kbuild — the module's xfs_file_ioctl is the xfs/xfs_stubs.c
# stub (GOINGDOWN only), and objdump found no reference to mxfs_dirshard_ioctl
# anywhere in the module.  0.64.4 wires the private-ioctl dispatch into the
# stub.  This chain replaces the parked chain 98 (killed in its gate loop):
#   1. wait for chain 97 DONE (its board is the 0.64.0 regression gate);
#   2. install the frozen 0.64.4 (SCRATCH_KO/SCRATCH_SV) + tools into the tree
#      and prove the dispatch is linked (objdump);
#   3. prep 32/caw; tests/dirshard_stage1_selftest.sh test1 test2; user-mode
#      format selftest; fleet unmount + chk_mxfs (parents=2 published=2 ...);
#   4. exec the chain 98 body (its gate is already satisfied): prep + 5 x
#      crash_consistency for baseline / private / sharded 16/32/64.
# budget: install 30; objdump 60; prep 300 (86-117 s measured); selftest 240;
# format selftest 30; unmount 120 + chk 120; then chain 98's own budgets.
cd /src/mxfs || exit 1
LABEL=${1:-s467d}
GATE=${GATE:-tests/evidence/sess466_chain97_dirshard_stage1_s466b.log}
LOG=tests/evidence/sess467_chain98b_dirshard_stage1_$LABEL.log
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess467 chain98b START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  SCRATCH_KO=${SCRATCH_KO:-}
  SCRATCH_SV=${SCRATCH_SV:-}
  brc=1
  if [ -n "$SCRATCH_KO" ] && [ -f "$SCRATCH_KO" ] && \
     [ "$(modinfo "$SCRATCH_KO" | awk '/srcversion/{print $2}')" = "$SCRATCH_SV" ]; then
    cp "$SCRATCH_KO" mxfs.ko; brc=$?
    for t in "$(dirname "$SCRATCH_KO")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
  fi
  DISP=$(timeout 60 objdump -dr --disassemble=xfs_file_ioctl mxfs.ko 2>/dev/null | grep -c 'mxfs_dirshard_ioctl')
  echo "STAGE install rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$SCRATCH_KO ioctl_dispatch_linked=$DISP chk_dirshard=$(strings -a tools/chk_mxfs | grep -c 'Directory sharding')"
  if [ "$brc" -ne 0 ] || [ "${DISP:-0}" = 0 ]; then echo "ABORT: install (dispatch not linked)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi

  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts; dmesg | grep -a "MXFS envelope" | tail -1' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 240 "dirshard_stage1 selftest test1 test2" tests/dirshard_stage1_selftest.sh test1 test2
  lap 30 "dirshard_format_selftest (user-mode)" tests/selftest/dirshard_format_selftest.sh

  T1=$(date +%s)
  UM=tests/evidence/sess467_chain98b_umount_$LABEL
  mkdir -p "$UM"
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | grep -a '^rc=' | tail -1 > "$UM/um_test$i.txt" ) &
  done
  wait
  echo "STAGE fleet_umount wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l '^rc=0' "$UM"/um_test*.txt | wc -l)/32 nonzero=$(grep -L '^rc=0' "$UM"/um_test*.txt | xargs -r -n1 basename | tr '\n' ' ')"
  T1=$(date +%s)
  timeout 120 tools/chk_mxfs -v "$IMG" > tests/evidence/sess467_chain98b_chk_$LABEL.txt 2>&1; crc=$?
  echo "STAGE chk rc=$crc wall=$(( $(date +%s) - T1 ))s errors=$(grep -ac 'ERROR' tests/evidence/sess467_chain98b_chk_$LABEL.txt) dirshard_line=$(grep -a 'Directory sharding' tests/evidence/sess467_chain98b_chk_$LABEL.txt | head -1)"
  grep -a 'dirshard' tests/evidence/sess467_chain98b_chk_$LABEL.txt | head -20
  echo "=== handing over to the chain 98 body $(date -u +%FT%TZ) ==="
} >> "$LOG" 2>&1
# chain 98's own gate (chain 97 DONE) is satisfied; it logs to its own file.
exec bash tests/sess466_chain98_dirshard_pace.sh s466c
