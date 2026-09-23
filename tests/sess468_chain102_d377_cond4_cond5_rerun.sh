#!/bin/bash
# sess468 chain 102: D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377 review-#5
# conditions 4 (cas_nocaw_arms per writer class) and 5 (proutsettle), re-run
# on the frozen production 0.64.4 with the harness defects of chain 86 fixed.
#
# Chain 86 (0.61.7, tests/evidence/sess460_chain86_review6_s460a.log) is the
# ONLY run of these arms and it proved nothing about the conditions:
#   - heartbeat/restamp/empty/settleown/guard died INFRA 'cannot read the
#     victim's heartbeat slot' (volatile journal, 20 s grep bound — trap
#     sess429); cas_nocaw_arms.sh now uses the depart_crash_cuts.sh lookup
#     (indexed journal query + dmesg + platter host_uuid scan).
#   - milestone: victim readmission PREP_RC=127 (a rebooted node has no NFS
#     /src; restore_victim now mounts it first).
#   - release: victim readmission refused with P236-CLAIM-UNCERTIFIED on
#     ANOTHER victim's stage-1 guard slot and a PR 'reservation conflict' on
#     the victim's own write — captured in full this time (dmesg kept).
#   - proutsettle: ordering PASSED (A/B=1, unordered=0, EMPTY once, unheld=0)
#     but victim 2 PREP_RC=127 (same NFS root) and the victim's remount was
#     mount(2) EBUSY with no kernel reason captured; both fixed/captured in
#     settle_token_arms.sh.
# Budgets are chain 86's measured walls (proutsettle 281 s, release 127 s,
# milestone 168 s) with the NFS restore step (12 s) added to the arms that
# restore a victim.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s468a}
GATE=${GATE:-tests/evidence/sess467_chain101_fln_churn_s467c.log}
LOG=tests/evidence/sess468_chain102_d377_cond45_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess467_frozen_0644/mxfs.ko}
PROD_SV=${PROD_SV:-560373F42636687E425F26D}
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
  echo "=== sess468 chain102 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  if [ "$(modinfo mxfs.ko | awk '/srcversion/{print $2}')" != "$PROD_SV" ] || [ "$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab)" != 0 ]; then
    install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  fi
  s3=$(strings -a mxfs.ko | grep -c 'P-DBG-CAS-NOCAW'); s4=$(strings -a mxfs.ko | grep -c 'P-DBG-SETTLE-PAUSE')
  echo "STAGE module sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') lab=$(modinfo mxfs.ko | grep -c mxfs_iclus_relmark_lab) strings nocaw=$s3 settlepause=$s4"
  if [ "$s3" = 0 ] || [ "$s4" = 0 ]; then echo "ABORT: injector strings missing"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 330 "cond5 settle arm=proutsettle victim=test22" env SETTLE_VICTIM2=test23 tests/settle_token_arms.sh 32 test22 test1 proutsettle
  lap 200 "cond4 nocaw arm=heartbeat victim=test15" tests/cas_nocaw_arms.sh 32 test15 test1 heartbeat
  lap 200 "cond4 nocaw arm=release victim=test16"   tests/cas_nocaw_arms.sh 32 test16 test1 release
  lap 200 "cond4 nocaw arm=restamp victim=test17"   tests/cas_nocaw_arms.sh 32 test17 test1 restamp
  lap 140 "cond4 nocaw arm=empty victim=test18"     tests/cas_nocaw_arms.sh 32 test18 test1 empty
  lap 90  "cond4 nocaw arm=settleown victim=test19" tests/cas_nocaw_arms.sh 32 test19 test1 settleown
  lap 280 "cond4 nocaw arm=guard victim=test20"     tests/cas_nocaw_arms.sh 32 test20 test1 guard
  lap 280 "cond4 nocaw arm=milestone victim=test21" tests/cas_nocaw_arms.sh 32 test21 test1 milestone
  lap 300 prep_after ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
