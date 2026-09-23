#!/bin/bash
# sess448 chain 59: ICLUS clean-release certificate LAB verification (0.55.0,
# D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY; design-consult ruling ccmemory
# docs/rulings/iclus-relmark-certificate-and-sequencing.md).
# The production validator refuses icluster_dlm=1 (MXFS_ICLUS_RELMARK_READY=0);
# a LAB build (KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1) is the only way to mount
# the marker path.  Shape: LAB build in place (rig idle after chain 58), prep
# with MXFS_EXTRA_MODARGS=icluster_dlm=1 (production defaults otherwise),
# assert every node P-DOMAIN-ADMITTED ... ICLUS-RELMARK-LAB-BUILD, then
# node_death_replay x3 (tmpfile churn = regular files = routed inodes) and
# unlinker_death x2, collecting per lap: the victim_slot summary
# (REDUNDANT_CLEAN / relmarks), fleet counts of P-RELMARK-ICLUS-UNMARKED and
# P-RELMARK-ICLUS-REINSTALL-REFUSED (expect 0 outside injection) and a
# survivor's debugfs relmark block (iclus_marked must be > 0).  Ends by
# rebuilding the PRODUCTION module (no KCFLAGS) so the tree's mxfs.ko is the
# shipping build again, and preps once to prove it.
# the budget rule bounds: incremental build 300 s (chain 55 measured well inside),
# prep 300, node_death_replay 500 (walls 376-382 s on 0.54.0), unlinker_death
# 400 (chain 56 bound).  Waits for chain 58 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain58_phase5_s448a.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448b}
LOG=tests/evidence/sess448_chain59_iclus_relmark_lab_$LABEL.log
sweep() { # $1 pattern -> per-node counts since 15 min
  for i in $(seq 1 32); do printf "%s " "$(timeout 20 tools/mxfs_sshpass.sh test$i "journalctl -k --since -15min --no-pager 2>/dev/null | grep -ac '$1'" 2>/dev/null | tr -dc '0-9')"; done; echo
}
{
  echo "=== sess448 chain59 start $(date -u +%FT%TZ) VERSION=$(cat VERSION) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 300 make modules KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 > tests/evidence/sess448_chain59_build_lab_$LABEL.log 2>&1; brc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  LAB=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')
  echo "STAGE build_lab rc=$brc old_sv=$OLD new_sv=$NEW errors=$(grep -c 'error:' tests/evidence/sess448_chain59_build_lab_$LABEL.log) modinfo_lab=$LAB iclusstr=$(strings -a mxfs.ko | grep -c 'P-RELMARK-ICLUS')"
  if [ "$brc" -ne 0 ] || [ "$LAB" -ne 1 ] || [ "$(strings -a mxfs.ko | grep -c 'P-RELMARK-ICLUS')" -eq 0 ]; then echo "ABORT: lab build failed or not a lab build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  MXFS_EXTRA_MODARGS='icluster_dlm=1' timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_lab rc=$prc"
  echo "LAB-ADMITTED nodes: $(sweep 'ICLUS-RELMARK-LAB-BUILD')"
  echo "DOMAIN-REFUSED nodes: $(sweep 'P-DOMAIN-REFUSED')"
  if [ "$prc" -ne 0 ]; then echo "ABORT: lab prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for lap in 1 2 3; do
    [ $lap -gt 1 ] && { MXFS_EXTRA_MODARGS='icluster_dlm=1' timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_ndr$lap rc=$?"; }
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    for l in shared single; do
      echo "LAP$lap $l: $(grep -a '^VERDICT\|WAIT ' $D/$l.log 2>/dev/null | head -2 | cut -c1-140 | tr '\n' ' ')"
      grep -a 'victim_slot=' $D/$l.log 2>/dev/null | sed 's/^/LAP'$lap' '$l' /' | grep -ao 'LAP[0-9] [a-z]* victim_slot=[0-9]* \|WOULD_APPLY=[0-9]*\|REDUNDANT_CLEAN=[0-9]*\|redundant_skipped=[0-9]*\|relmarks=[0-9]*\|relmark_overflow=[0-9]*' | tr '\n' ' '; echo
    done
    echo "LAP$lap ICLUS-UNMARKED: $(sweep 'P-RELMARK-ICLUS-UNMARKED')"
    echo "LAP$lap ICLUS-REINSTALL-REFUSED: $(sweep 'P-RELMARK-ICLUS-REINSTALL-REFUSED')"
    echo "LAP$lap FR-REDUNDANT-SKIP: $(sweep 'P227-FR-REDUNDANT-SKIP')"
    echo "LAP$lap survivor test1 relmark block: $(timeout 20 tools/mxfs_sshpass.sh test1 'f=$(find /sys/kernel/debug -name inode_authority 2>/dev/null | head -1); [ -n "$f" ] && sed -n "/^relmark/,/iclus_reinst_ref/p" "$f" | tr "\n" " "' 2>/dev/null)"
    echo "LAP$lap f4truth: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ao 'truth=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
  done
  for i in 1 2; do
    MXFS_EXTRA_MODARGS='icluster_dlm=1' timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_oud$i rc=$?"
    EV=tests/evidence/sess448_chain59_oud${i}_$LABEL; mkdir -p "$EV"
    T0=$(date +%s); timeout 400 tests/openunlink_deaths.sh unlinker_death test1 test2 > "$EV/deaths.txt" 2>&1; rc=$?
    echo "STAGE unlinker_death$i rc=$rc wall=$(( $(date +%s) - T0 ))s $(grep -a 'RESULT' "$EV/deaths.txt" | head -1 | cut -c1-160)"
    echo "OUD$i ICLUS-UNMARKED: $(sweep 'P-RELMARK-ICLUS-UNMARKED')"
  done
  # back to the PRODUCTION build
  timeout 300 make modules > tests/evidence/sess448_chain59_build_prod_$LABEL.log 2>&1; brc=$?
  echo "STAGE build_prod rc=$brc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') errors=$(grep -c 'error:' tests/evidence/sess448_chain59_build_prod_$LABEL.log)"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_prod rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
