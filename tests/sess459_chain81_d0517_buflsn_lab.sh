#!/bin/bash
# sess459 chain 81: D-ICLUS-RELMARK-POSTMARK-CRASH-ALLOC-FREE-CORE-UNLINKED-
# DANGLING-0517 — instrument step 2, hypothesis H4 (cross-slice on-disk LSN skip in
# xlog_recover_buf_commit_pass2 drops token-admitted AGI/inobt/finobt images).
# Gated on chain 80 DONE (tests/sess456_chain80_d0517_lab_postmark.sh, ends on
# the PRODUCTION build).  Same shape as chain 80 so the laps are comparable:
#   1  LAB build: make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 (abort
#      unless modinfo mxfs_iclus_relmark_lab=1 and the P-FR-BUF-LSN string is
#      in the module — the 0.61.3 probe at the skip site)
#   2  prep_cluster with MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
#   3  N laps of tests/iclus_relmark_faults.sh <lapdir> postmark_crash with a
#      `dmesg -w` stream from every node (victims' journald is volatile) and a
#      per-lap fleet sweep for P-FR-BUF-LSN (verdict=SKIP names the dropped
#      image: blkno/magic/blft/txn_lsn/disk_lsn), the completion line's
#      buflsn_skips=, P-ALLOC-FREE-CORE, P273/P163.
#      EXPECTED under H4: every lap whose chk reports 'FREE core' carries
#      P-FR-BUF-LSN verdict=SKIP lines for the victim AG's AGI (agno*4194304
#      +2), inobt root (+24) and finobt root (+32) with disk_lsn in ANOTHER
#      slice's range; a lap with SKIP lines and a clean chk is still an
#      occurrence (the drop was masked by a later rewrite).
#   4  PRODUCTION rebuild + prep (leave the fleet on the production build)
# budget: build 600 (measured 286-326 s in tree), prep 300, lap 420 (harness
# bound) + 120 sweep, prod build 600, prep 300.  Streams bounded at 560 s.
cd /src/mxfs || exit 1
LABEL=${1:-s459a}
LAPS=${2:-4}
GATE=${GATE:-tests/evidence/sess456_chain80_d0517_lab_s456b.log}
LOG=tests/evidence/sess459_chain81_d0517_buflsn_$LABEL.log
EV=tests/evidence/sess459_d0517buflsn_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
sweep() { # <lapdir> <since-minutes>: full lines per node, one file each, per-node rc
  local d=$1 m=$2 i pids=()
  for i in $(seq 1 32); do
    ( timeout 25 $SSH test$i "journalctl -k --since -${m}min --no-pager 2>/dev/null | grep -a 'P-FR-BUF-LSN\|foreign replay of slot\|P-DINO-CLOBBER\|P-FR-DINO-BUF\|P-ALLOC-FREE-CORE\|P273-SHADOW-EVAL\|P163-RECOVERY-COMPLETE\|P309-LOGTAIL\|P227-TOKEN '" > "$d/sweep_test$i.txt" 2>/dev/null; echo $? > "$d/sweep_test$i.rc" ) &
    pids+=($!)
  done; wait "${pids[@]}"
  echo "sweep: P-FR-BUF-LSN lines=$(cat "$d"/sweep_test*.txt | grep -ac 'P-FR-BUF-LSN') SKIP=$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -ac 'verdict=SKIP') APPLY=$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -ac 'verdict=APPLY'); completion: $(cat "$d"/sweep_test*.txt | grep -a 'foreign replay of slot' | grep -ao 'slot [0-9]* complete (sbclean_skips=[0-9]* buflsn_skips=[0-9]*)' | tr '\n' ';'); P-DINO-CLOBBER lines=$(cat "$d"/sweep_test*.txt | grep -ac 'P-DINO-CLOBBER'); ssh_fail=$(grep -L '^0$' "$d"/sweep_test*.rc 2>/dev/null | wc -l)"
  cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -a 'verdict=SKIP' | sed 's/^.*kernel: //' | cut -c1-260 | head -24
  cat "$d"/sweep_test*.txt | grep -a 'P309-LOGTAIL' | sed 's/^.*kernel: //' | cut -c1-200 | tail -4
}
{
  echo "=== sess459 chain81 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  timeout 600 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess459_chain81_build_lab_$LABEL.log 2>&1; brc=$?
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  PROBE=$(strings -a mxfs.ko | grep -c 'P-FR-BUF-LSN')
  echo "STAGE build_lab rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$LAB sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess459_chain81_build_lab_$LABEL.log) probe_string=$PROBE"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ] || [ "$PROBE" = 0 ]; then echo "ABORT: lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 120 tools make tools
  export MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
  lap 300 prep_lab ./run.sh 32 caw prep_cluster
  unset MXFS_EXTRA_MODARGS
  echo "knob check: $(for i in 1 16; do printf 'test%s:%s ' $i "$(timeout 20 $SSH test$i 'cat /sys/module/mxfs/parameters/dino_clobber_check /sys/module/mxfs/parameters/icluster_dlm 2>/dev/null | tr "\n" ,' 2>/dev/null)"; done)"
  for n in $(seq 1 "$LAPS"); do
    D=$EV/lap$n; mkdir -p "$D"
    echo "=== lap $n START $(date -u +%FT%TZ) ==="
    for i in $(seq 1 32); do ( timeout 560 $SSH test$i "dmesg -w" > "$D/dmesgw_test$i.txt" 2>/dev/null; echo $? > "$D/dmesgw_test$i.rc" ) & done
    sleep 3
    T0=$(date +%s)
    timeout 540 tests/iclus_relmark_faults.sh "$D" postmark_crash; echo "STAGE lap$n rc=$? wall=$(( $(date +%s) - T0 ))s"
    grep -a '^rc=\|^chk\|^FAIL\|^VERDICT\|FREE core\|P-ALLOC-FREE-CORE' "$D/matrix.txt" "$D/postmark_crash/chk.txt" 2>/dev/null | cut -c1-300 | head -12
    sweep "$D" 12
    echo "victims' streamed P-DINO-CLOBBER (pre-kill): $(cat "$D"/dmesgw_test*.txt 2>/dev/null | grep -ac 'P-DINO-CLOBBER')"
    wait
  done
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess459_chain81_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess459_chain81_build_prod_$LABEL.log)"
  lap 300 prep_prod ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
