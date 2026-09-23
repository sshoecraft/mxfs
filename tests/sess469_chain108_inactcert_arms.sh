#!/bin/bash
# sess469 chain 108: fix shape A (D-FOREIGN-SLICE-INTENTS-ABANDONED) mandatory
# verification arms (design-consult sess469 ruling) on frozen production 0.64.10
# (PROD_KO/PROD_SV), via tests/inact_cert_arms.sh on test1 of the 32/caw
# fleet.  Non-shutdown arms first on one prep; each fail-closed arm shuts
# test1's fs down and is followed by a fresh prep_cluster.
# budget: prep 300 s (80-117 s measured); refuse 120; escalate 330; others 60.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s469b}
GATE=${GATE:-tests/evidence/sess469_chain107_samenode_s469a.log}
LOG=tests/evidence/sess469_chain108_inactcert_$LABEL.log
PROD_KO=${PROD_KO:-/src/mxfs/tests/evidence/sess469_frozen_06410/mxfs.ko}
PROD_SV=${PROD_SV:?PROD_SV required}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
install_ko() { # <ko> <sv> <label>
  [ -f "$1" ] || { echo "install_ko: missing $1"; return 1; }
  cp "$1" mxfs.ko || return 1
  for t in mkfs_mxfs chk_mxfs resize_mxfs fua_verify; do [ -f "$(dirname "$1")/tools/$t" ] && cp "$(dirname "$1")/tools/$t" tools/$t; done
  local sv; sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "install_ko $3: sv=$sv want=$2"
  [ "$sv" = "$2" ]
}
{
  echo "=== sess469 chain108 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  install_ko "$PROD_KO" "$PROD_SV" prod || { echo "ABORT: prod install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  lap 300 prep ./run.sh 32 caw prep_cluster
  # sess473: the P-INACT-CERT line has a 96-per-module-load cap and the defer
  # arm's 1100-file filler burns it (s472u: the foreign arm then printed
  # nothing) — defer runs LAST, on the fresh module the escalate prep loads.
  # sess474: ARMS_NOSHUT / ARMS_SHUT / DEFER_ARM=0 select a subset (a rerun of
  # the shutdown arms alone: ARMS_NOSHUT= ARMS_SHUT="foreign gone evictforeign evictactive" DEFER_ARM=0).
  for arm in ${ARMS_NOSHUT-refuse edeadlk advance}; do
    b=60; [ "$arm" = refuse ] && b=120
    lap $b "arm $arm" tests/inact_cert_arms.sh $arm test1 $LABEL
  done
  for arm in ${ARMS_SHUT-foreign gone escalate}; do
    b=70; [ "$arm" = escalate ] && b=330
    lap $b "arm $arm" tests/inact_cert_arms.sh $arm test1 $LABEL
    lap 300 "prep after $arm" ./run.sh 32 caw prep_cluster
  done
  [ "${DEFER_ARM:-1}" = 1 ] && lap 90 "arm defer" tests/inact_cert_arms.sh defer test1 $LABEL
  echo "RESULTS: $(grep -ah '^RESULT ' "$LOG" | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
