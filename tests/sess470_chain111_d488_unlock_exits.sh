#!/bin/bash
# sess470 chain 111: D-488 unlock-exit arms (design-consult disposition ruling,
# measurement 1) + the D-0528 out-of-window own-bit measure (the noslot arm)
# on frozen 0.64.13 (= 0.64.12 + the dlm_caw.c caw_inject_unlk_* knobs).
# Two node pairings.  Installs the frozen ko, preps 32/caw, runs the four
# arms per pairing with a prep between pairings (arms leave no state, but the
# strand arm's readopt is worth a clean slate).
# budget: install 30; prep 300; each arm 240 (measured shape < 3 min).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s470c}
GATE=${GATE:-tests/evidence/sess470_chain110_d0527_s470b.log}
LOG=tests/evidence/sess470_chain111_d488_exits_$LABEL.log
# sess472: default moved to the 0.64.14 freeze (0.64.13 knobs + D-0529/D-0530
# fixes — 0.64.13 shuts the fs down on the first deferred-free evict, which the
# arms' rm steps trigger; see D-0529).
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess472_frozen_06414/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
install_ko() {
  local ko="$1" sv="$2" l="$3" t rc=1
  if [ -f "$ko" ] && [ "$(modinfo "$ko" | awk '/srcversion/{print $2}')" = "$sv" ]; then
    cp "$ko" mxfs.ko; rc=$?
    for t in "$(dirname "$ko")"/tools/*; do [ -f "$t" ] && [ -x "$t" ] && file "$t" | grep -q ELF && cp "$t" tools/; done
  fi
  echo "STAGE install_$l rc=$rc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') from=$ko"
  return $rc
}
{
  echo "=== sess470 chain111 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "STAGE markers $(for s in P470-UNLK-INJECT caw_inject_unlk_noslot caw_inject_unlk_cas_eio; do printf '%s=%s ' $s "$(strings -a mxfs.ko | grep -c "$s")"; done)"
  lap 300 prep ./run.sh 32 caw prep_cluster
  for arm in findslot_eio cas_eio1 cas_eio2 noslot; do
    lap 240 "arm $arm test1/test2" tests/d488_unlock_exit_arms.sh test1 test2 $arm ${LABEL}a
  done
  lap 300 prep2 ./run.sh 32 caw prep_cluster
  for arm in findslot_eio cas_eio1 cas_eio2 noslot; do
    lap 240 "arm $arm test5/test9" tests/d488_unlock_exit_arms.sh test5 test9 $arm ${LABEL}b
  done
  echo "RESULTS: $(grep -a '^RESULT ' "$LOG" | cut -c1-110 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
