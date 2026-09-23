#!/bin/bash
# sess456 chain 80: D-ICLUS-RELMARK-POSTMARK-CRASH-ALLOC-FREE-CORE-UNLINKED-
# DANGLING-0517 — instrument step 2 (instrumented reproduction).  Gated on chain 79
# DONE (tests/sess456_chain79_0612_incmis.sh, ends on the PRODUCTION build).
#   1  LAB build: make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 (abort
#      unless modinfo mxfs_iclus_relmark_lab=1 and the P-DINO-CLOBBER string
#      is in the module)
#   2  prep_cluster with MXFS_EXTRA_MODARGS='icluster_dlm=1 dino_clobber_check=1'
#      (every inode-cluster write FUA-verifies against the platter; a slot whose
#      in-core changecount is below the platter's logs P-DINO-CLOBBER with
#      comm/pid/foreign_replay/buffer state + 8 stacks; the foreign replay logs
#      P-FR-DINO-BUF per inode-cluster image with cached_before=)
#   3  3 laps of tests/iclus_relmark_faults.sh <lapdir> postmark_crash (stage 21:
#      marker durable, 60 s pause before the unlock CAS, two shared-AG victims
#      killed ~20 s into the churn, survivors replay, chk_mxfs per lap).  Before
#      each lap a `dmesg -w` stream from EVERY node is captured into the lap
#      dir (the victims' journald is volatile — trap sess433 — so their
#      pre-kill lines survive only through the stream); after each lap the
#      fleet is swept for P-DINO-CLOBBER / P-FR-DINO-BUF / P-ALLOC-FREE-CORE
#      with full lines per node.
#   4  PRODUCTION rebuild + prep (leave the fleet on the production build)
# budget: build 600 (measured 286-326 s in tree), prep 300, lap 420 (harness
# bound) + 120 sweep, prod build 600, prep 300.  Streams bounded at 560 s.
cd /src/mxfs || exit 1
LABEL=${1:-s456b}
LAPS=${2:-3}
GATE=tests/evidence/sess456_chain79_0612_incmis_s456a.log
LOG=tests/evidence/sess456_chain80_d0517_lab_$LABEL.log
EV=tests/evidence/sess456_d0517lab_$LABEL
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
    ( timeout 25 $SSH test$i "journalctl -k --since -${m}min --no-pager 2>/dev/null | grep -a 'P-DINO-CLOBBER\|P-FR-DINO-BUF\|P-ALLOC-FREE-CORE\|P273-SHADOW-EVAL\|P163-RECOVERY-COMPLETE\|P-RELMARK-ICLUS'" > "$d/sweep_test$i.txt" 2>/dev/null; echo $? > "$d/sweep_test$i.rc" ) &
    pids+=($!)
  done; wait "${pids[@]}"
  echo "sweep: P-DINO-CLOBBER lines=$(cat "$d"/sweep_test*.txt | grep -ac 'P-DINO-CLOBBER') nodes=$(grep -l 'P-DINO-CLOBBER' "$d"/sweep_test*.txt 2>/dev/null | wc -l); P-FR-DINO-BUF lines=$(cat "$d"/sweep_test*.txt | grep -ac 'P-FR-DINO-BUF') cached_before=1:$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-DINO-BUF' | grep -ac 'cached_before=1') LSN-SKIP:$(cat "$d"/sweep_test*.txt | grep -a 'P-FR-DINO-BUF' | grep -ac 'verdict=LSN-SKIP'); ssh_fail=$(grep -L '^0$' "$d"/sweep_test*.rc 2>/dev/null | wc -l)"
  cat "$d"/sweep_test*.txt | grep -a 'P-DINO-CLOBBER' | sed 's/^.*kernel: //' | cut -c1-400 | head -12
}
{
  echo "=== sess456 chain80 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  timeout 600 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess456_chain80_build_lab_$LABEL.log 2>&1; brc=$?
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  echo "STAGE build_lab rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$LAB sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess456_chain80_build_lab_$LABEL.log) clobber_string=$(strings -a mxfs.ko | grep -c 'P-DINO-CLOBBER')"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ] || [ "$(strings -a mxfs.ko | grep -c 'P-DINO-CLOBBER')" = 0 ]; then echo "ABORT: lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
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
  timeout 600 make modules > tests/evidence/sess456_chain80_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc wall=$(( $(date +%s) - T0 ))s modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess456_chain80_build_prod_$LABEL.log)"
  lap 300 prep_prod ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
