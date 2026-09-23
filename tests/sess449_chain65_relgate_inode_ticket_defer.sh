#!/bin/bash
# sess449 chain 65: INODE-class flush-ticket proof-failure DEFERRAL (0.55.1,
# D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516 prerequisite) on the PRODUCTION
# build chain 63/64 leave in the tree (fleet prepped, icluster_dlm=0).
# tests/relgate_fault_inject.sh inode: forced stages 7/9/10 on test2; stage 10
# must now print P228-RELBAR-TICKET-DEFER and a class=1 defer cert, resolve
# without a wedge, cas_noproof_v2==0.
# budget: per stage = arm (~2 s) + 15 s churn window + 5 s settle + dmesg
# dump (~5 s) ~ 27-30 s; 3 stages x <=2 cycles = 180 s + counters/liveness
# ~20 s => bound 260 s.  Gated on chain 64 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain64_matrix_r8_s448g.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s449a}
LOG=tests/evidence/sess449_chain65_relgate_inode_$LABEL.log
{
  echo "=== sess449 chain65 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) modinfo_lab=$(modinfo mxfs.ko | grep -c '_lab') tkdefer_str=$(strings -a mxfs.ko | grep -c 'P228-RELBAR-TICKET-DEFER') ==="
  T0=$(date +%s); timeout 260 tests/relgate_fault_inject.sh inode test2 3 32; echo "STAGE relgate_inode rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
