#!/bin/bash
# sess472 chain 114: two single-node / two-node arms on the tree's installed
# module (0.64.18 after chain 113): the D-0532 reuse lap (create -> DEFERRED
# free -> reuse recycles the corpse; P71 must stay 0) and the peer-readdir
# pace measure for D-READDIR-PEER-CACHED-DIR-PACE.  No prep: the fleet is
# mounted from the previous chain.  budget: d0532 90 s, rdpace 120 s.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s472w}
GATE=${GATE:-tests/evidence/sess470_chain110_d0527_s472k.log}
LOG=tests/evidence/sess472_chain114_d0532_rdpace_$LABEL.log
WANT_SV=${WANT_SV:-}
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
{
  echo "=== sess472 chain114 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') want=$WANT_SV ==="
  if [ -n "$WANT_SV" ] && [ "$(modinfo mxfs.ko | awk '/srcversion/{print $2}')" != "$WANT_SV" ]; then echo "ABORT: tree module is not $WANT_SV"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 90 "d0532 reuse lap test1" tests/d0532_reuse_lap.sh test1 100 ${LABEL}a
  lap 90 "d0532 reuse lap test5" tests/d0532_reuse_lap.sh test5 100 ${LABEL}b
  lap 120 "rdpace test1->test2" tests/readdir_peer_pace.sh test1 test2 20 200 ${LABEL}a
  lap 120 "rdpace test3->test9" tests/readdir_peer_pace.sh test3 test9 20 200 ${LABEL}b
  echo "RESULTS: $(grep -a '^RESULT ' "$LOG" | cut -c1-120 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
