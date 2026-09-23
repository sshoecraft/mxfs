#!/bin/bash
# sess459 chain 82: D-ICLUS-RELMARK-POSTMARK-CRASH-ALLOC-FREE-CORE-UNLINKED-
# DANGLING-0517 — instrument step 2b (fix verification).  Gated on chain 81 DONE
# (tests/sess459_chain81_d0517_buflsn_lab.sh = the probe-only PROOF laps).
# The tree must carry the 0.61.4 fix (class-gated bypass of the upstream
# on-disk-LSN veto for token-APPLY AG/INODE images under untrusted replay)
# before this chain's LAB build starts — abort unless the OVERRIDE string is
# in the module.
#   1  LAB build (RELMARK_READY=1), abort unless modinfo lab=1 and the
#      P-FR-BUF-LSN + OVERRIDE-APPLY strings are present
#   2  prep_cluster icluster_dlm=1 dino_clobber_check=1
#   3  N laps postmark_crash (same arm as chains 80/81) with dmesg -w streams,
#      per-lap sweep: verdict=SKIP must be 0 for APPLY images, verdict=
#      OVERRIDE-APPLY > 0 proves the new path was exercised, chk clean.
#      PASS criterion for the record: every lap chk clean (non-SB errors 0),
#      SKIP=0, and at least one lap with OVERRIDE-APPLY>0.
#   4  PRODUCTION rebuild + prep
# budget: build 600 (measured 286-326 s), prep 300, lap 420 + 120 sweep,
# prod build 600, prep 300.  Streams bounded at 560 s.
cd /src/mxfs || exit 1
LABEL=${1:-s459e}
LAPS=${2:-3}
GATE=${GATE:-tests/evidence/sess459_chain82_d0517_fixverify_s459b.log}
LOG=tests/evidence/sess459_chain85_d0517_fixverify_$LABEL.log
EV=tests/evidence/sess459_d0517slots_$LABEL
SSH=tools/mxfs_sshpass.sh
mkdir -p "$EV"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
sweep() { # <lapdir> <since-minutes>
  local d=$1 m=$2 i pids=()
  for i in $(seq 1 32); do
    ( timeout 25 $SSH test$i "journalctl -k --since -${m}min --no-pager 2>/dev/null | grep -a 'P-FR-BUF-LSN\|foreign replay of slot\|P-DINO-CLOBBER\|P-ALLOC-FREE-CORE\|P273-SHADOW-EVAL\|P163-RECOVERY-COMPLETE\|P309-LOGTAIL\|P227-TOKEN '" > "$d/sweep_test$i.txt" 2>/dev/null; echo $? > "$d/sweep_test$i.rc" ) &
    pids+=($!)
  done; wait "${pids[@]}"
  echo "sweep: P-FR-BUF-LSN lines=$(cat "$d"/sweep_test*.txt | grep -ac 'P-FR-BUF-LSN') SKIP=$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -ac 'verdict=SKIP') OVERRIDE=$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -ac 'verdict=OVERRIDE-APPLY') APPLY=$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -ac 'verdict=APPLY'); completion: $(cat "$d"/sweep_test*.txt | grep -a 'foreign replay of slot' | grep -ao 'slot [0-9]* complete (sbclean_skips=[0-9]* buflsn_skips=[0-9]* buflsn_overrides=[0-9]*)' | tr '\n' ';'); ssh_fail=$(grep -L '^0$' "$d"/sweep_test*.rc 2>/dev/null | wc -l)"
  cat "$d"/sweep_test*.txt | grep -a 'P-FR-BUF-LSN' | grep -a 'verdict=SKIP\|verdict=OVERRIDE' | sed 's/^.*kernel: //' | cut -c1-260 | head -24
  cat "$d"/sweep_test*.txt | grep -a 'P309-LOGTAIL' | sed 's/^.*kernel: //' | cut -c1-200 | tail -4
}
{
  echo "=== sess459 chain85 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  timeout 600 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess459_chain85_build_lab_$LABEL.log 2>&1; brc=$?
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  PROBE=$(strings -a mxfs.ko | grep -c 'P-FR-BUF-LSN')
  FIX=$(strings -a mxfs.ko | grep -c 'OVERRIDE-APPLY')
  echo "STAGE build_lab rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$LAB sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess459_chain85_build_lab_$LABEL.log) probe_string=$PROBE fix_string=$FIX"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ] || [ "$PROBE" = 0 ] || [ "$FIX" = 0 ]; then echo "ABORT: lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 120 tools make tools
  export MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
  lap 300 prep_lab ./run.sh 32 caw prep_cluster
  unset MXFS_EXTRA_MODARGS
  echo "knob check: $(for i in 1 16; do printf 'test%s:%s ' $i "$(timeout 20 $SSH test$i 'cat /sys/module/mxfs/parameters/dino_clobber_check /sys/module/mxfs/parameters/icluster_dlm 2>/dev/null | tr "\n" ,' 2>/dev/null)"; done)"
  # sess459 D-0517 closure step: the full 4-arm iclus_relmark_faults matrix
  # (premark_crash publish_fail postmark_crash cas_fail) on the fixed LAB build
  # — every arm must be chk clean (the D-0517 record's closure criteria).
  M=$EV/matrix; mkdir -p "$M"
  echo "=== matrix START $(date -u +%FT%TZ) ==="
  T0=$(date +%s)
  timeout 1500 tests/iclus_relmark_faults.sh "$M"; echo "STAGE matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  grep -a '^=== arm\|^rc=\|^chk\|^FAIL\|^VERDICT' "$M/matrix.txt" 2>/dev/null | cut -c1-300 | head -24
  sweep "$M" 26
  for n in $(seq 1 "$LAPS"); do
    D=$EV/lap$n; mkdir -p "$D"
    echo "=== lap $n START $(date -u +%FT%TZ) ==="
    for i in $(seq 1 32); do ( timeout 560 $SSH test$i "dmesg -w" > "$D/dmesgw_test$i.txt" 2>/dev/null; echo $? > "$D/dmesgw_test$i.rc" ) & done
    sleep 3
    T0=$(date +%s)
    TCK_VICTIMS=auto:slots:25,26 timeout 540 tests/iclus_relmark_faults.sh "$D" postmark_crash; echo "STAGE lap$n rc=$? wall=$(( $(date +%s) - T0 ))s"
    grep -a '^rc=\|^chk\|^FAIL\|^VERDICT\|FREE core\|P-ALLOC-FREE-CORE' "$D/matrix.txt" "$D/postmark_crash/chk.txt" 2>/dev/null | cut -c1-300 | head -12
    sweep "$D" 12
    wait
  done
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess459_chain85_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess459_chain85_build_prod_$LABEL.log)"
  lap 300 prep_prod ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
