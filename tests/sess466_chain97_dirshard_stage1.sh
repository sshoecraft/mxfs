#!/bin/bash
# sess466 chain 97: directory sharding stage 1 on the rig (tree 0.64.0,
# docs/dir-sharding.md "Stage 1 wiring checklist"), then the full 32/caw board
# as the regression gate for the tree-wide changes it carries (sb incompat bit
# 29, MXFS_PROTO_GEN 17->18 => every node re-mkfs's, dinode verifier, BLFT 30 in
# replay, dispatch hooks in iops/file/dentry).
#   1. install the frozen 0.64.0 module + tools (SCRATCH_KO/SCRATCH_SV) into
#      the tree, else build the tree;
#   2. prep_cluster 32/caw (gen-18 format);
#   3. tests/dirshard_stage1_selftest.sh test1 test2 (two-node functional
#      contract) + tests/selftest/dirshard_format_selftest.sh (user-mode);
#   4. fleet unmount, tools/chk_mxfs -v on the LUN image: 'Directory sharding
#      ...... OK' with parents=2 published=2 containers=82 (16+64+2 holders),
#      zero ERROR;
#   5. prep_cluster + the full 32/caw board (production defaults; no board
#      directory is sharded — the feature is ioctl opt-in);
#   6. prep_final.
# Gated on chain 96 DONE.
# the budget rule (derived): install 30 / build 420; prep 300 (measured 86-106 s);
# selftest 240 (header budgets); format selftest 30; unmount 120 (d526
# measured) + chk 120; board 1200 (~690 s of walls + 12 s x 28 rows); prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s466b}
GATE=${GATE:-tests/evidence/sess466_chain96_crashcut5_s466a.log}
LOG=tests/evidence/sess466_chain97_dirshard_stage1_$LABEL.log
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
  echo "=== sess466 chain97 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  SCRATCH_KO=${SCRATCH_KO:-}
  SCRATCH_SV=${SCRATCH_SV:-}
  if [ -n "$SCRATCH_KO" ] && [ -f "$SCRATCH_KO" ] && \
     [ "$(modinfo "$SCRATCH_KO" | awk '/srcversion/{print $2}')" = "$SCRATCH_SV" ]; then
    cp "$SCRATCH_KO" mxfs.ko; brc=$?
    for t in "$(dirname "$SCRATCH_KO")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
    echo "STAGE install rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$SCRATCH_KO dirshard_string=$(strings -a mxfs.ko | grep -c 'P-DIRSHARD-CORRUPT') chk_dirshard=$(strings -a tools/chk_mxfs | grep -c 'Directory sharding') mkfs_gate=$(strings -a tools/mkfs_mxfs | grep -c 'MXFS_DIRSHARD' )"
  else
    timeout 420 make modules > tests/evidence/sess466_chain97_build_$LABEL.log 2>&1; brc=$?
    echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess466_chain97_build_$LABEL.log) dirshard_string=$(strings -a mxfs.ko | grep -c 'P-DIRSHARD-CORRUPT')"
    lap 120 tools make tools
  fi
  if [ "$brc" -ne 0 ] || [ "$(strings -a mxfs.ko | grep -c 'P-DIRSHARD-CORRUPT')" = 0 ]; then echo "ABORT: build/install (no dirshard markers)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  echo "chk_mxfs --dirshard-hash vector: $(tools/chk_mxfs --dirshard-hash 000102030405060708090a0b0c0d0e0f hex:000102030405060708090a0b0c0d0e)"

  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts; dmesg | grep -a "MXFS envelope" | tail -1' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"

  lap 240 "dirshard_stage1 selftest test1 test2" tests/dirshard_stage1_selftest.sh test1 test2
  lap 30 "dirshard_format_selftest (user-mode)" tests/selftest/dirshard_format_selftest.sh

  # fleet unmount, then the platter check with the sharded dirs in place
  T1=$(date +%s)
  UM=tests/evidence/sess466_chain97_umount_$LABEL
  mkdir -p "$UM"
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | grep -a '^rc=' | tail -1 > "$UM/um_test$i.txt" ) &
  done
  wait
  echo "STAGE fleet_umount wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l '^rc=0' "$UM"/um_test*.txt | wc -l)/32 nonzero=$(grep -L '^rc=0' "$UM"/um_test*.txt | xargs -r -n1 basename | tr '\n' ' ')"
  T1=$(date +%s)
  timeout 120 tools/chk_mxfs -v "$IMG" > tests/evidence/sess466_chain97_chk_$LABEL.txt 2>&1; crc=$?
  echo "STAGE chk rc=$crc wall=$(( $(date +%s) - T1 ))s errors=$(grep -ac 'ERROR' tests/evidence/sess466_chain97_chk_$LABEL.txt) dirshard_line=$(grep -a 'Directory sharding' tests/evidence/sess466_chain97_chk_$LABEL.txt | head -1) gates=$(grep -a 'features_incompat' tests/evidence/sess466_chain97_chk_$LABEL.txt | head -1)"
  grep -a 'dirshard' tests/evidence/sess466_chain97_chk_$LABEL.txt | head -20

  lap 300 prep_board ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 1320 ./run.sh 32 caw > tests/evidence/sess466_chain97_board_32caw_$LABEL.log 2>&1; echo "STAGE board 32/caw rc=$? wall=$(( $(date +%s) - T1 ))s"
  grep -a 'Total:\|FAIL \|POLICY' tests/evidence/sess466_chain97_board_32caw_$LABEL.log | tail -n 8 | cut -c1-200
  echo "dirshard lines fleet after board: $(for n in test1 test2 test9 test17; do printf '%s=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -c P-DIRSHARD' 2>/dev/null | tr -d '\r\n ')"; done)"
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
