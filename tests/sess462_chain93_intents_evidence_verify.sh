#!/bin/bash
# sess462 chain 93: D-FOREIGN-SLICE-INTENTS-ABANDONED item 5 increment 2 on
# the PRODUCTION build the fleet runs after chain 92 (0.63.0+, no rebuild
# here): the intents verifier's burst arm (dbg_efd_hold_ms holds the EFD
# after a durable EFI; the victim is destroyed inside the hold) must show
#   P226-ICENSUS intents>=1 open>=1, the terminal refusal (reason 1 or 8),
#   ZERO P163-RECOVERY-COMPLETE for the victim slot,
# and — when the images were admitted so the census classifies the open EFI
# as RECOVER (P226-ICENSUS-SPLIT recover>=1) — the obligation evidence:
#   P226-OBL-WRITE, P226-OBL-EVIDENCE, zero -FAIL/-LOST, and chk_mxfs
#   --show-quarantine reading the record (TERMINAL-EVIDENCE count>=1) and the
#   list (VALID) back from the platter.
# The clean arm must stay clean (open=0, published normally).  Both arms
# leave the victim destroyed+restarted and (burst) a quarantined slot, so
# each is followed by a prep.  Gated on chain 92 DONE.
# budget: harness header derives ~115 s per arm, caller bound 180; prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s462b}
GATE=${GATE:-tests/evidence/sess462_chain92_d0522_crashcuts_s462a.log}
LOG=tests/evidence/sess462_chain93_intents_evidence_$LABEL.log
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
  echo "=== sess462 chain93 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$SV fleet_sv=$FSV obl_string=$(strings -a mxfs.ko | grep -c 'P226-OBL-WRITE') chk_obl=$(strings -a tools/chk_mxfs | grep -c 'obligation list') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P226-OBL-WRITE')" = 0 ] || [ "$(strings -a tools/chk_mxfs | grep -c 'obligation list')" = 0 ]; then echo "ABORT: tree mxfs.ko/chk_mxfs do not carry item-5 increment 2"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 180 "intents burst lap1" tests/d_intents_undischarged_verify.sh ${LABEL}a burst
  lap 300 prep_after_burst ./run.sh 32 caw prep_cluster
  lap 180 "intents clean" tests/d_intents_undischarged_verify.sh ${LABEL}b clean
  lap 300 prep_after_clean ./run.sh 32 caw prep_cluster
  lap 180 "intents burst lap2" tests/d_intents_undischarged_verify.sh ${LABEL}c burst
  echo "=== laps done $(date -u +%FT%TZ) ==="
  grep -a '^STAGE\|fails=\|FAIL ' "$LOG" | tail -40
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
