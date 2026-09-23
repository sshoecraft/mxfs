#!/bin/bash
# sess470 chain 109: dir-sharding stage 1 re-run on frozen 0.64.12 (0.64.11 + the design-consult review items: probe split, locator removed in the holder-free txn) — the three
# roots taken from chain 103's 0.64.6 lap (docs/dir-sharding.md "0.64.11"):
#   (1) creator-side: mxfs_dirshard_alloc_parent/alloc_container never ran
#       xfs_setup_iops -> empty i_op -> DCACHE_AUTODIR_TYPE -> every op under
#       the new sharded dir returned -ENOTDIR on the node that made it;
#   (2) peer-side: mxfs_dirshard_iget used XFS_IGET_UNTRUSTED, whose inobt
#       check reads the AGI/inobt WITHOUT the AG DLM lock -> -EINVAL for every
#       peer-allocated member; mxfs_dirshard_free_container read -EINVAL as
#       "already freed" and leaked container 133 (chk ERROR);
#   (3) xfs_readdir's IOLOCK assertion WARNed 588x for containers; the
#       per-shard consumer refresh / stale-reload settle was missing
#       (P173-RELOAD-SELFREAD deferred under our own ILOCK_SHARED).
# Verdict wanted: stage-1 selftest VERDICT PASS on test1/test2, zero
# 'WARNING: CPU' / xfs_assert_ilocked on both nodes, zero P-IMAP-UNTRUSTED-*
# and P-DIRSHARD-IGET-FAIL / P-DIRSHARD-LOAD-FAIL, chk errors=0 with no
# 'leaked internal inode' after the fleet unmount, and 3/3 cc sharded16 laps
# PASS (lap 1 FAILED on every sharded variant on 0.64.6).
# derived time budgets: install 30; prep 300 (80-117 s measured); selftest 240;
# format selftest 30; dmesg capture 60; umount 120; chk 120; cc lap 160 each.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s470a}
GATE=${GATE:-tests/evidence/sess468_chain106_peerloss_s468e.log}
LOG=tests/evidence/sess470_chain109_dirshard_06411_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess470_frozen_06412/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-3}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
DM=tests/evidence/sess470_chain109_dmesg_$LABEL
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
# Save each node's whole kernel ring NOW (it wraps within minutes under load;
# node journald is volatile) and count the markers that decide the verdict.
capture() { # <tag> <node...>
  local tag="$1" n f; shift
  for n in "$@"; do
    f="$DM/${tag}_$n.txt"
    timeout 40 $SSH "$n" 'dmesg -T 2>/dev/null || dmesg' 2>/dev/null | grep -av '^Unauthorized\|^If you\|^$' > "$f"
    echo "CAPTURE $tag $n lines=$(wc -l < "$f") first=$(head -1 "$f" | cut -c1-32) last=$(tail -1 "$f" | cut -c1-32)"
    echo "  MARKERS $tag $n: $(for m in 'WARNING: CPU' xfs_assert_ilocked P-IMAP-UNTRUSTED-FREE P-IMAP-UNTRUSTED-NOREC P-DIRSHARD-IGET-FAIL P-DIRSHARD-LOAD-FAIL P-DIRSHARD-STRANGER P-DIRSHARD-GONE P-DIRSHARD-CORRUPT P-DIRSHARD-ABANDON P-DIRSHARD-INACTIVE P95D-READDIR-WAIT P173-RELOAD-SELFREAD 'Not a directory' 'P-IGET-ENOENT'; do printf '%s=%s ' "$m" "$(grep -ac -- "$m" "$f")"; done)"
    grep -a 'P-DIRSHARD-\|P-IMAP-UNTRUSTED\|P95D-READDIR-WAIT' "$f" | head -20 | cut -c1-220
  done
}
{
  echo "=== sess470 chain109 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') LAPS=$LAPS ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "STAGE markers $(for s in P-DIRSHARD-IGET-FAIL P-DIRSHARD-LOAD-FAIL P-IMAP-UNTRUSTED-FREE P95D-READDIR-WAIT P-DIRSHARD-STRANGER; do printf '%s=%s ' $s "$(strings -a mxfs.ko | grep -c "$s")"; done) chk_dirshard=$(strings -a tools/chk_mxfs | grep -c 'Directory sharding')"

  # ── 1. stage-1 functional contract + platter walk ──
  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 240 "dirshard_stage1 selftest test1 test2" tests/dirshard_stage1_selftest.sh test1 test2
  lap 30 "dirshard_format_selftest (user-mode)" tests/selftest/dirshard_format_selftest.sh
  capture stage1 test1 test2
  T1=$(date +%s)
  UM=tests/evidence/sess470_chain109_umount_$LABEL
  mkdir -p "$UM"
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | grep -a '^rc=' | tail -1 > "$UM/um_test$i.txt" ) &
  done
  wait
  echo "STAGE fleet_umount wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l '^rc=0' "$UM"/um_test*.txt | wc -l)/32 nonzero=$(grep -L '^rc=0' "$UM"/um_test*.txt | xargs -r -n1 basename | tr '\n' ' ')"
  T1=$(date +%s)
  timeout 120 tools/chk_mxfs -v "$IMG" > tests/evidence/sess470_chain109_chk_$LABEL.txt 2>&1; crc=$?
  echo "STAGE chk rc=$crc wall=$(( $(date +%s) - T1 ))s errors=$(grep -ac 'ERROR' tests/evidence/sess470_chain109_chk_$LABEL.txt) leaked=$(grep -ac 'leaked internal inode' tests/evidence/sess470_chain109_chk_$LABEL.txt) dirshard_line=$(grep -a 'Directory sharding' tests/evidence/sess470_chain109_chk_$LABEL.txt | head -1)"
  grep -a 'dirshard\|ERROR' tests/evidence/sess470_chain109_chk_$LABEL.txt | head -20

  # ── 2. cc sharded16 laps (lap 1 failed on every sharded variant on 0.64.6) ──
  lap 300 prep_sharded16 ./run.sh 32 caw prep_cluster
  for l in $(seq 1 "$LAPS"); do
    T1=$(date +%s)
    out=$(MXFS_TEST_ENV="CC_SHARDED=16" timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
    echo "STAGE cc variant=sharded16 lap=$l rc=$rc wall=$(( $(date +%s) - T1 ))s $(echo "$out" | grep -a '^  \(PASS\|FAIL\) *crash_consistency' | tail -1 | tr -s ' ' | cut -c1-200)"
    echo "$out" | grep -a 'cc sharded\|EOPNOTSUPP\|BUDGET_EXHAUSTED\|NO_TERMINAL' | head -4 | cut -c1-200
  done
  capture cc test1 test2
  echo "RESULTS: selftest=$(grep -a 'VERDICT' "$LOG" | tail -1 | cut -c1-120) chk_errors=$(grep -ac 'ERROR' tests/evidence/sess470_chain109_chk_$LABEL.txt) cc=$(grep -a '^STAGE cc ' "$LOG" | grep -ac ' PASS ')/$LAPS"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
