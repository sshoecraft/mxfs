#!/bin/bash
# sess448 chain 60: ICLUS certificate fault-injection matrix (ruling evidence
# 6.3) under the LAB build with icluster_dlm=1.  Gated on chain 59 DONE (which
# ends on the PRODUCTION build), so this chain rebuilds LAB, runs
# tests/iclus_relmark_faults.sh, then rebuilds PRODUCTION again.
# budget: build 300, prep 300, matrix 4 arms x <=420 s + sweeps => 2000 s bound.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain59_iclus_relmark_lab_s448b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448c}
LOG=tests/evidence/sess448_chain60_iclus_relmark_faults_$LABEL.log
{
  echo "=== sess448 chain60 start $(date -u +%FT%TZ) VERSION=$(cat VERSION) ==="
  timeout 300 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess448_chain60_build_lab_$LABEL.log 2>&1; brc=$?
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  echo "STAGE build_lab rc=$brc modinfo_lab=$LAB errors=$(grep -c 'error:' tests/evidence/sess448_chain60_build_lab_$LABEL.log)"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ]; then echo "ABORT: lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  MXFS_EXTRA_MODARGS='icluster_dlm=1' timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_lab rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 2000 tests/iclus_relmark_faults.sh tests/evidence/sess448_iclusfaults_$LABEL; echo "STAGE faults rc=$? wall=$(( $(date +%s) - T0 ))s"
  cat tests/evidence/sess448_iclusfaults_$LABEL/matrix.txt 2>/dev/null | cut -c1-300
  timeout 300 make modules > tests/evidence/sess448_chain60_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') errors=$(grep -c 'error:' tests/evidence/sess448_chain60_build_prod_$LABEL.log)"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_prod rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
