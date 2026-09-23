#!/bin/bash
# sess465 chain 95: CAW same-node reconcile exerciser, second REAL run, on the
# 0.63.2 tree build (chain 90's first run on 0.63.0 was vacuous: every local
# arm was granted at once because the peer's cache handler released the
# exerciser's raw EX on the first BAST — P141-UNLK-EXCLR noreg=1 — so the
# give-up path was never entered, fails=29).  0.63.2 holds inode BASTs for the
# exerciser's pseudo-inode for the whole run (v5_mount.c samenode_bast_guard,
# P275-SAMENODE-BAST-HELD).  defect-bar closure vehicle for
# D-SAMENODE-WAITER-CANCEL-COLLISION, D-RECONCILE-SLOT-IDENTITY-UNCHECKED,
# D-RECONCILE-EXHAUSTION-SILENT, D-TRACK-PUBLISH-ORDERING.
# Gated on chain 94 DONE (the tree build replaces the frozen 0.63.1 module the
# fleet carries; every prep insmods the tree's mxfs.ko).
# budget: build 420 (measured 311-332 s), tools 120, prep 300 (measured
# 86-106 s), per exerciser invocation 150 (header: 4 arms x ~26 s + harvest
# ≈ 110 s); 3 laps test1/test2 + pair test7/test19 ≈ 8 min.
cd /src/mxfs || exit 1
LABEL=${1:-s465b}
GATE=${GATE:-tests/evidence/sess465_chain94_d0524_s465a.log}
LOG=tests/evidence/sess465_chain95_samenode_$LABEL.log
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess465 chain95 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  T0=$(date +%s)
  # frozen scratch build of the 0.63.2 sources (SCRATCH_KO/SCRATCH_SV from the
  # session) so later tree edits cannot leak into this run; else build the tree
  SCRATCH_KO=${SCRATCH_KO:-}
  SCRATCH_SV=${SCRATCH_SV:-}
  if [ -n "$SCRATCH_KO" ] && [ -f "$SCRATCH_KO" ] && \
     [ "$(modinfo "$SCRATCH_KO" | awk '/srcversion/{print $2}')" = "$SCRATCH_SV" ]; then
    cp "$SCRATCH_KO" mxfs.ko; brc=$?
    for t in "$(dirname "$SCRATCH_KO")"/tools/*; do
      [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/
    done
    echo "STAGE install rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$SCRATCH_KO bastheld_string=$(strings -a mxfs.ko | grep -c 'P275-SAMENODE-BAST-HELD')"
  else
    timeout 420 make modules > tests/evidence/sess465_chain95_build_$LABEL.log 2>&1; brc=$?
    echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess465_chain95_build_$LABEL.log) bastheld_string=$(strings -a mxfs.ko | grep -c 'P275-SAMENODE-BAST-HELD')"
    lap 120 tools make tools
  fi
  if [ "$brc" -ne 0 ]; then echo "ABORT: build/install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  echo "fleet: $(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  for lapn in 1 2 3; do
    T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test1 test2 all; echo "STAGE samenode lap=$lapn rc=$? wall=$(( $(date +%s) - T1 ))s"
  done
  T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test7 test19 all; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T1 ))s"
  echo "bast-held lines: $(for n in test2 test19; do printf '%s=%s ' $n "$(timeout 20 $SSH $n 'dmesg | grep -c P275-SAMENODE-BAST-HELD' 2>/dev/null | tr -d '\r\n ')"; done)"
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
