#!/bin/bash
# sess454 chain 75: the 0.60.0 group-1 admission arms on a spare node, gated
# on chain 74 (tests/sess452_chain71_retire_pending.sh s454a) printing DONE
# so the probe node's departure cannot perturb the settlement laps.
#   B  tests/vergate.sh test32 noncaw_refuse      (override alone refused at
#      P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED; override+snx reaches P311)
#   C  tests/fence_capability_admission.sh test32 (3 arms on a no-PR loop)
#   then a prep_cluster so the fleet is whole again.
# budget: vergate loop arm ~90 s (header) -> 120; fence_cap 3 arms measured
# 10 s on 0.60.0 (sess454 first run, all refused early) -> 120; prep 300.
# Optional arg: the srcversion the tree's mxfs.ko MUST carry.
cd /src/mxfs || exit 1
LABEL=${1:-s454b}
EXPECT_SV=${2:-}
GATE=tests/evidence/sess452_chain71_retire_pending_s454a.log
LOG=tests/evidence/sess454_chain75_admission_arms_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess454 chain75 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  if [ -n "$EXPECT_SV" ] && [ "$(modinfo mxfs.ko | awk '/srcversion/{print $2}')" != "$EXPECT_SV" ]; then echo "ABORT: mxfs.ko srcversion != expected $EXPECT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 120 "vergate noncaw_refuse test32" tests/vergate.sh test32 noncaw_refuse
  lap 120 "fence_cap_admission test32"   tests/fence_capability_admission.sh test32
  lap 300 prep_after ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
