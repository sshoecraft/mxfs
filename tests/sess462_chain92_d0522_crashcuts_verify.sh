#!/bin/bash
# sess462 chain 92: the verification laps the chain-86 harvest left owed, on
# the PRODUCTION build the fleet runs after chain 91 (no rebuild here):
#   - D-RETIRE-QUARANTINE-DOUBLE-ADD-SELF-LOOP-MOUNT-PANIC-0522: settle arms
#     workerhang + workerhangheld on 0.62.1+ — exactly one P304-RETIRE-WORKER-
#     STUCK plus one P304-RETIRE-QUARANTINE-AGAIN, the post-hang remount
#     ADMITTED after one P304-RETIRE-WORKER-REAPED, zero faults on the
#     victim's serial console (the harness now bounds the remount ssh and
#     reads /var/log/libvirt/qemu/<victim>-serial.log after a mark).
#   - D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377 cond3: depart_crash_cuts
#     1/2/3/5 with the fixed harness (NFS /src restored before prep_node.sh;
#     slot lookup persisted with a platter fallback) for the admission
#     verdict that chain 86 could not reach (prep_rc=127 / INFRA).
#   - D-377 cond4: domain_admission_matrix again on the R8 print-ordering fix
#     (0.62.0+, pal/linux/xfs_super.c mxfs_domain_admitted_announce).
# Gated on chain 91 (tests/sess461_chain91_settle_arms_0617.sh) DONE.
# derived time budgets are chain 86's: prep 300, workerhang 200, workerhangheld 240,
# crash cuts 300 each (measured 106/75 s on the failing path), matrix 240
# (measured 51 s).
cd /src/mxfs || exit 1
LABEL=${1:-s462a}
GATE=${GATE:-tests/evidence/sess461_chain91_settle_arms_s461c.log}
LOG=tests/evidence/sess462_chain92_d0522_crashcuts_$LABEL.log
SSH=tools/mxfs_sshpass.sh
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  SV=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  FSV=$(timeout 20 $SSH test1 'cat /sys/module/mxfs/srcversion' 2>/dev/null | grep -aE '^[0-9A-F]{20,}$')
  echo "=== sess462 chain92 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$SV fleet_sv=$FSV modinfo_lab=$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab') fix_string=$(strings -a mxfs.ko | grep -c 'P304-RETIRE-QUARANTINE-AGAIN') r8_string=$(strings -a mxfs.ko | grep -c 'mxfs_domain_admitted_announce\|P-DOMAIN-ADMITTED') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P304-RETIRE-QUARANTINE-AGAIN')" = 0 ] || [ "$(modinfo mxfs.ko | grep -c 'mxfs_iclus_relmark_lab')" != 0 ]; then echo "ABORT: tree mxfs.ko is not the production build carrying the D-0522 fix"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 200 "d0522 settle arm=workerhang victim=test5"      tests/settle_token_arms.sh 32 test5 test1 workerhang
  lap 240 "d0522 settle arm=workerhangheld victim=test7"  env SETTLE_VICTIM2=test8 tests/settle_token_arms.sh 32 test7 test1 workerhangheld
  lap 300 prep_after_settle ./run.sh 32 caw prep_cluster
  lap 300 "cond3 crashcut 1 precas victim=test9"     tests/depart_crash_cuts.sh 32 test9  test1 1
  lap 300 "cond3 crashcut 2 postcas victim=test10"   tests/depart_crash_cuts.sh 32 test10 test1 2
  lap 300 "cond3 crashcut 3 preunreg victim=test11"  tests/depart_crash_cuts.sh 32 test11 test1 3
  lap 300 "cond3 crashcut 5 postunreg victim=test12" tests/depart_crash_cuts.sh 32 test12 test1 5
  lap 240 "cond4 domain_admission_matrix test32"     tests/domain_admission_matrix.sh $LABEL test32
  echo "=== laps done $(date -u +%FT%TZ) ==="
  grep -a '^STAGE\|PASS @\|FAIL\|VERDICT' "$LOG" | tail -40
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
