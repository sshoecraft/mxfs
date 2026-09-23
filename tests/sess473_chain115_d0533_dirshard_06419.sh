#!/bin/bash
# sess473 chain 115: D-0533 verification on frozen 0.64.20 (0.64.18 + the
# dirshard probe revalidation: a cached member shell whose generation
# disagrees with the manifest is arbitrated against the platter and adopted in
# place; expect_ftype carries the manifest's type through the typeflip guard).
# Also carries the stage-1 selftest step-7 harness fix (info JSON header).
#
# Stages (chain-109 shape + the directed lap):
#   1. install frozen prod, prep 32/caw
#   2. tests/dirshard_stage1_selftest.sh test1 test2   — the N=64 stage is the
#      D-0533 reproducer (peer readdir after the vectors dir's number reuse)
#   3. tests/dirshard_reuse_peer_list.sh test1 test2 20 — directed reuse laps,
#      arm A peer list / arm B peer rmdir, 2x-native-XFS ceiling 300 ms per listing
#   4. dmesg capture both nodes (markers), fleet umount, chk_mxfs
#   5. 3 cc sharded16 laps (regression guard for the readdir/free paths)
# Verdict wanted: selftest VERDICT PASS, reuse VERDICT PASS with ADOPTED>0,
# P-DIRSHARD-STRANGER=0 and P-DIRSHARD-SHELL-UNCONVERGED=0 on both nodes,
# zero splats, chk errors=0 / leaked=0, cc 3/3.
# derived time budgets: install 30; prep 300 (80-123 s measured); selftest 240;
# reuse laps 240 (20 laps x ~6 ssh calls, ~3-8 s per lap); capture 60;
# umount 120; chk 120; cc lap 160 each.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s473a}
GATE=${GATE:-tests/evidence/sess469_chain108_inactcert_s472u.log}
LOG=tests/evidence/sess473_chain115_d0533_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess473_frozen_06420/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-3}
REUSE_LAPS=${REUSE_LAPS:-20}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
DM=tests/evidence/sess473_chain115_dmesg_$LABEL
mkdir -p "$DM"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
install_ko() { # <ko> <sv> <label>
  local ko="$1" sv="$2" l="$3" t rc=1
  if [ -f "$ko" ] && [ "$(modinfo "$ko" | awk '/srcversion/{print $2}')" = "$sv" ]; then
    cp "$ko" mxfs.ko; rc=$?
    for t in "$(dirname "$ko")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
  fi
  echo "STAGE install_$l rc=$rc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$ko"
  return $rc
}
capture() { # <tag> <node...>
  local tag="$1" n f; shift
  for n in "$@"; do
    f="$DM/${tag}_$n.txt"
    timeout 40 $SSH "$n" 'dmesg -T 2>/dev/null || dmesg' 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$' > "$f"
    echo "CAPTURE $tag $n lines=$(wc -l < "$f") first=$(head -1 "$f" | cut -c1-32) last=$(tail -1 "$f" | cut -c1-32)"
    echo "  MARKERS $tag $n: $(for m in 'WARNING: CPU' xfs_assert_ilocked P-DIRSHARD-SHELL-ADOPTED P-DIRSHARD-SHELL-UNCONVERGED 'P-DIRSHARD-SHELL ' P-DIRSHARD-BLK-REFRESH P-DIRSHARD-BLK-KEEP P-RESET-STALE-AF shortform_verify 'Metadata corruption' P-DIRSHARD-STRANGER P-DIRSHARD-GONE P-DIRSHARD-IGET-FAIL P-DIRSHARD-LOAD-FAIL P-DIRSHARD-CORRUPT P-DIRSHARD-ABANDON P-DIRSHARD-INACTIVE P95D-READDIR-WAIT P-IMAP-UNTRUSTED-FREE P-IMAP-UNTRUSTED-NOREC 'Structure needs cleaning' P-IGET-ENOENT 'Internal error' shutdown; do printf '%s=%s ' "$m" "$(grep -ac -- "$m" "$f")"; done)"
    grep -a 'P-DIRSHARD-SHELL\|P-DIRSHARD-STRANGER\|P-DIRSHARD-GONE\|P-DIRSHARD-CORRUPT' "$f" | head -30 | cut -c1-260
  done
}
{
  echo "=== sess473 chain115 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') LAPS=$LAPS REUSE_LAPS=$REUSE_LAPS ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "STAGE markers $(for s in P-DIRSHARD-SHELL-ADOPTED P-DIRSHARD-SHELL-UNCONVERGED P-DIRSHARD-STRANGER P-DIRSHARD-IGET-FAIL; do printf '%s=%s ' $s "$(strings -a mxfs.ko | grep -c "$s")"; done) chk_dirshard=$(strings -a tools/chk_mxfs | grep -c 'Directory sharding')"

  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 240 "dirshard_stage1 selftest test1 test2" tests/dirshard_stage1_selftest.sh test1 test2
  lap 30 "dirshard_format_selftest (user-mode)" tests/selftest/dirshard_format_selftest.sh
  lap 240 "dirshard_reuse_peer_list test1 test2 $REUSE_LAPS" tests/dirshard_reuse_peer_list.sh test1 test2 "$REUSE_LAPS"
  # sess473 D-0535 item 4: the generic (xattr on a plain file) shape of the
  # phantom-attr-fork reuse, victim test1 / peer test2, then the mirror pair.
  lap 60 "d0535 xattr reuse test1<-test2" tests/d0535_xattr_reuse.sh test1 test2 64
  lap 60 "d0535 xattr reuse test3<-test4" tests/d0535_xattr_reuse.sh test3 test4 64
  capture stage1 test1 test2
  T1=$(date +%s)
  UM=tests/evidence/sess473_chain115_umount_$LABEL
  mkdir -p "$UM"
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | grep -a '^rc=' | tail -1 > "$UM/um_test$i.txt" ) &
  done
  wait
  echo "STAGE fleet_umount wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l '^rc=0' "$UM"/um_test*.txt | wc -l)/32 nonzero=$(grep -L '^rc=0' "$UM"/um_test*.txt | xargs -r -n1 basename | tr '\n' ' ')"
  T1=$(date +%s)
  timeout 120 tools/chk_mxfs -v "$IMG" > tests/evidence/sess473_chain115_chk_$LABEL.txt 2>&1; crc=$?
  echo "STAGE chk rc=$crc wall=$(( $(date +%s) - T1 ))s errors=$(grep -ac 'ERROR' tests/evidence/sess473_chain115_chk_$LABEL.txt) leaked=$(grep -ac 'leaked internal inode' tests/evidence/sess473_chain115_chk_$LABEL.txt) dirshard_line=$(grep -a 'Directory sharding' tests/evidence/sess473_chain115_chk_$LABEL.txt | head -1)"
  grep -a 'dirshard\|ERROR' tests/evidence/sess473_chain115_chk_$LABEL.txt | head -20

  lap 300 prep_sharded16 ./run.sh 32 caw prep_cluster
  for l in $(seq 1 "$LAPS"); do
    T1=$(date +%s)
    out=$(MXFS_TEST_ENV="CC_SHARDED=16" timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
    echo "STAGE cc variant=sharded16 lap=$l rc=$rc wall=$(( $(date +%s) - T1 ))s $(echo "$out" | grep -a '^  \(PASS\|FAIL\) *crash_consistency' | tail -1 | tr -s ' ' | cut -c1-200)"
    echo "$out" | grep -a 'cc sharded\|EOPNOTSUPP\|BUDGET_EXHAUSTED\|NO_TERMINAL' | head -4 | cut -c1-200
  done
  capture cc test1 test2
  echo "RESULTS: selftest=$(grep -a 'VERDICT.*dirshard_stage1' "$LOG" | tail -1 | cut -c1-120) reuse=$(grep -a 'VERDICT.*dirshard_reuse_peer' "$LOG" | tail -1 | cut -c1-120) d0535=$(grep -a '^RESULT .* d0535' "$LOG" | tail -2 | cut -c1-100 | tr '\n' ';') chk_errors=$(grep -ac 'ERROR' tests/evidence/sess473_chain115_chk_$LABEL.txt) cc=$(grep -a '^STAGE cc ' "$LOG" | grep -ac ' PASS ')/$LAPS"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
