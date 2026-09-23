#!/bin/bash
# sess468 chain 103: frozen production 0.64.6 =
#   0.64.5  fix shape B (D-FOREIGN-SLICE-INTENTS-ABANDONED): the iunlink
#           di_next_unlinked image of an inode cluster is classified under the
#           AG grant (pal/linux/xfs_buf_item.c mxfs_buf_iunlink_ag_authorized,
#           replayer shape guard xfs/xfs_log_recover.c P-IUNLINK-AGCLASS-SHAPE)
#   0.64.6  dir-sharding stage-1 locator fix (xfs/xfs_mxfs_dirshard.c
#           mxfs_dirshard_locator_set: INIT_XATTRS makes an EMPTY EXTENTS attr
#           fork, the guard demanded LOCAL -> every sharded mkdir EUCLEAN on
#           0.64.4, chain 98b) + named refusals P-DIRSHARD-LOCATOR-FORK /
#           P-DIRSHARD-STEPA-FAIL.
#
# Stages, in order:
#   1. install the frozen 0.64.6 + tools into the tree; objdump proof of the
#      ioctl dispatch; marker strings.
#   2. prep 32/caw; tests/dirshard_stage1_selftest.sh test1 test2 (VERDICT
#      PASS wanted this time); user-mode format selftest; fleet unmount +
#      chk_mxfs platter walk (parents=2 published=2 containers=80).
#   3. pace: crash_consistency x LAPS (default 3, first functional pass) for
#      baseline / private / sharded16 / sharded32 / sharded64 — the D-401 /
#      D-32NODE-SHARED-DIR-CREATE-PACE build-order item 2 measurement.
#   4. intents burst lap (tests/d_intents_undischarged_verify.sh burst) — fix
#      shape B's measurable delta: P-IUNLINK-AGCLASS on the producer and
#      P227-TOKENSUM dino_none=0 on the replayer (the 39 inactivation bmbt
#      images stay classless until fix shape A lands, so the txn is still
#      POLICY-REFUSED: classless must drop from 41 to 39, not to 0).
#   5. node_death_replay x 2 (D-0524's owed NDR on a build carrying its fix;
#      chains 94 and 97 both had the row cut by an under-derived wrapper).
#   6. the full 32/caw board (D-0524 'unchanged board' half; item-1 criterion
#      (2)).  Wrapper = WEDGE BOUND, not a walls sum: per-row pace is already
#      enforced by run.sh from tests/suite/manifest, so the outer timeout only
#      bounds a wedge — sum of row budgets 2060 + node_death_replay 470 + 12 s
#      x 28 harness = 2866 -> 2900 s.  (Chains 94/97 used 1200/1320 = walls
#      sum + margin and were cut at 1303/1296 s under host load 24 with every
#      completed row inside its budget.)
# derived time budgets: install 30; prep 300 (80-117 s measured); selftest 240;
# format 30; unmount 120; chk 120; cc lap 160 (90 s row + harness); burst 180;
# NDR 500 (342-392 s measured); board 2900 (wedge bound, see above).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s468b}
GATE=${GATE:-tests/evidence/sess468_chain102_d377_cond45_s468a.log}
LOG=tests/evidence/sess468_chain103_dirshard_intentsB_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess468_frozen_0646/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
LAPS=${LAPS:-3}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
IMG=$(tools/mxfs_host_image.sh) || { echo "$IMG"; exit 2; }
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
  echo "STAGE install_$l rc=$rc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) from=$ko"
  return $rc
}
{
  echo "=== sess468 chain103 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') LAPS=$LAPS ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  DISP=$(timeout 60 objdump -dr --disassemble=xfs_file_ioctl mxfs.ko 2>/dev/null | grep -c 'mxfs_dirshard_ioctl')
  echo "STAGE markers dispatch=$DISP $(for s in P-IUNLINK-AGCLASS P-IUNLINK-AGCLASS-SHAPE P-DIRSHARD-LOCATOR-FORK P-DIRSHARD-STEPA-FAIL P-DIRSHARD-CORRUPT; do printf '%s=%s ' $s "$(strings -a mxfs.ko | grep -c "$s")"; done) chk_dirshard=$(strings -a tools/chk_mxfs | grep -c 'Directory sharding')"
  if [ "${DISP:-0}" = 0 ]; then echo "ABORT: dispatch not linked"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi

  # ── 2. stage-1 functional contract + platter walk ──
  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 240 "dirshard_stage1 selftest test1 test2" tests/dirshard_stage1_selftest.sh test1 test2
  lap 30 "dirshard_format_selftest (user-mode)" tests/selftest/dirshard_format_selftest.sh
  echo "dirshard refusal lines: $(for n in test1 test2; do printf '%s=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -a -c "P-DIRSHARD-LOCATOR-FORK\|P-DIRSHARD-STEPA-FAIL\|P-DIRSHARD-ABANDON\|P-DIRSHARD-CORRUPT"' 2>/dev/null | tr -d '\r\n ')"; done)"
  T1=$(date +%s)
  UM=tests/evidence/sess468_chain103_umount_$LABEL
  mkdir -p "$UM"
  for i in $(seq 1 32); do
    ( timeout 120 $SSH "test$i" "if grep -q ' $MNT mxfs ' /proc/mounts; then timeout 100 umount $MNT; echo rc=\$?; else echo rc=0; fi" 2>/dev/null | grep -a '^rc=' | tail -1 > "$UM/um_test$i.txt" ) &
  done
  wait
  echo "STAGE fleet_umount wall=$(( $(date +%s) - T1 ))s rc0=$(grep -l '^rc=0' "$UM"/um_test*.txt | wc -l)/32 nonzero=$(grep -L '^rc=0' "$UM"/um_test*.txt | xargs -r -n1 basename | tr '\n' ' ')"
  T1=$(date +%s)
  timeout 120 tools/chk_mxfs -v "$IMG" > tests/evidence/sess468_chain103_chk_$LABEL.txt 2>&1; crc=$?
  echo "STAGE chk rc=$crc wall=$(( $(date +%s) - T1 ))s errors=$(grep -ac 'ERROR' tests/evidence/sess468_chain103_chk_$LABEL.txt) dirshard_line=$(grep -a 'Directory sharding' tests/evidence/sess468_chain103_chk_$LABEL.txt | head -1)"
  grep -a 'dirshard' tests/evidence/sess468_chain103_chk_$LABEL.txt | head -20

  # ── 3. pace matrix ──
  for variant in baseline private sharded16 sharded32 sharded64; do
    case "$variant" in
      baseline)  ENV="" ;;
      private)   ENV="CC_PRIVATE=1" ;;
      sharded16) ENV="CC_SHARDED=16" ;;
      sharded32) ENV="CC_SHARDED=32" ;;
      sharded64) ENV="CC_SHARDED=64" ;;
    esac
    lap 300 "prep_$variant" ./run.sh 32 caw prep_cluster
    for l in $(seq 1 "$LAPS"); do
      T1=$(date +%s)
      if [ -n "$ENV" ]; then
        out=$(MXFS_TEST_ENV="$ENV" timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
      else
        out=$(timeout 160 ./run.sh 32 caw crash_consistency 2>&1); rc=$?
      fi
      echo "STAGE cc variant=$variant lap=$l rc=$rc wall=$(( $(date +%s) - T1 ))s $(echo "$out" | grep -a '^  \(PASS\|FAIL\) *crash_consistency' | tail -1 | tr -s ' ' | cut -c1-200)"
      echo "$out" | grep -a 'cc sharded\|EOPNOTSUPP\|BUDGET_EXHAUSTED\|NO_TERMINAL' | head -4 | cut -c1-200
    done
    if [ -n "$ENV" ] && [ "${ENV#CC_SHARDED}" != "$ENV" ]; then
      echo "manifest $variant: $(timeout 30 $SSH test1 "python3 /src/mxfs/tests/dirshard_ioctl.py info /mnt/shared/.crash_consistency | head -1" 2>/dev/null | grep -a '^state=')"
      echo "dirshard dmesg $variant: $(for n in test1 test2 test17; do printf '%s=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -c "P-DIRSHARD-CORRUPT\|P-DIRSHARD-STRANGER\|P-DIRSHARD-ABANDON\|P-DIRSHARD-LOCATOR-FORK\|P-DIRSHARD-STEPA-FAIL"' 2>/dev/null | tr -d '\r\n ')"; done)"
    fi
  done

  # ── 4. intents burst (fix shape B delta) ──
  lap 300 prep_burst ./run.sh 32 caw prep_cluster
  lap 180 "intents burst (fix B)" tests/d_intents_undischarged_verify.sh ${LABEL}b burst
  echo "fixB census: $(for n in test1 test2; do printf '%s: agclass=%s tokcls=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -a -c P-IUNLINK-AGCLASS' 2>/dev/null | tr -d '\r\n ')" "$(timeout 20 $SSH $n 'dmesg | grep -a P228-TOKCLASS | tail -1' 2>/dev/null | grep -ao 'iunlink_ag=[0-9]*')"; done)"
  echo "fixB replayer: $(D=$(ls -dt tests/evidence/*_intents_burst 2>/dev/null | head -1); echo "$D"; grep -ah 'P227-TOKENSUM' "$D"/dmesg_*.txt 2>/dev/null | grep -ao 'classless=[0-9]* untagged=[0-9]*\|dino_none=[0-9]* dino_agsib=[0-9]*' | sort | uniq -c | tr '\n' ';')"

  # ── 5. node_death_replay x 2 ──
  for ndr in 1 2; do
    lap 300 "prep_ndr$ndr" ./run.sh 32 caw prep_cluster
    lap 500 "node_death_replay$ndr" ./run.sh 32 caw node_death_replay
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
  done

  # ── 6. the full board ──
  lap 300 prep_board ./run.sh 32 caw prep_cluster
  T1=$(date +%s); timeout 2900 ./run.sh 32 caw > tests/evidence/sess468_chain103_board_32caw_$LABEL.log 2>&1; echo "STAGE board 32/caw rc=$? wall=$(( $(date +%s) - T1 ))s"
  grep -a 'Total:\|FAIL \|POLICY\|node_death_replay' tests/evidence/sess468_chain103_board_32caw_$LABEL.log | tail -n 8 | cut -c1-200
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
