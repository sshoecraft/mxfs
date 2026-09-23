#!/bin/bash
# sess419_master_chain.sh — the whole sess419 rig sequence, relay-proof
# (setsid+nohup, everything logged under tests/evidence/).  Replaces the
# chained rig_after waiters after the post-chain sequence died at 05:28Z.
#
#  0. build VERSION (make modules + make tools), then PROVE the build is
#     complete: a second `make modules` must compile nothing (the NFS clock
#     skew warning "build may be incomplete" is real; a half-rebuilt module
#     after a struct-layout change is memory corruption on the rig).
#  1. 32/caw prep; tests/f2_iclus_refusal.sh (gate item 2)
#  2. 32/tcp prep (mpatha condition); tests/d0287_remaster_measure.sh
#     (MODE=umount) — first instrumented measurement of D-0287
#  3. 32/caw prep; tests/vergate.sh test32 mixed_build (gate item 7 / B4)
#  4. TCP race laps p1..p4 (tests/d0286_depart_race.sh, prep each)
#  5. 32/caw prep; tests/d0133_sb_mutation_gate.sh
#  6. tests/crossnode_unlink_ubsweep.sh (leaves the fleet unmounted)
#  7. purge arms: prep + tests/d_purge_nonatomic_verify.sh x3
#  8. 32/caw prep; full board (tests/sess416_board_0286.sh: armed knobs +
#     28 rows + gate-3 sweep) — regression for 0.29.1-0.29.3
#
# the budget rule (derived): build 2x ~450 s; preps 236 s (cap 300) x ~12; tests as
# their own headers (90+200+150+4x160+100+400+3x200); board chain ~29 min
# => ~2 h 15 min total.
# Usage: setsid nohup tests/sess419_master_chain.sh <label>
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/sess419_master_${LABEL}.log
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
E=tests/evidence
prep_caw() { timeout 300 ./run.sh 32 caw prep_cluster > "$E/sess419_master_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep caw $1 rc=$?"; }
prep_tcp() { env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "$E/sess419_master_${LABEL}_prep_$1.log" 2>&1; echo "STAGE prep tcp $1 rc=$?"; }
{
  echo "=== master chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  B="$E/sess419_master_${LABEL}_build.log"
  timeout 500 make modules > "$B" 2>&1; brc=$?
  timeout 120 make tools >> "$B" 2>&1; trc=$?
  echo "STAGE build rc=$brc tools_rc=$trc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "$B") skew=$(grep -c 'Clock skew' "$B")"
  if [ $brc -ne 0 ] || [ $trc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 500 make modules > "$B.2" 2>&1
  cc2=$(grep -c '^  CC ' "$B.2")
  echo "STAGE build-complete-proof second_make_cc_lines=$cc2 sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  if [ "$cc2" -ne 0 ]; then echo "ABORT: first build was incomplete ($cc2 objects rebuilt on the second pass) — investigate clock skew"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  prep_caw 1
  timeout 90 tests/f2_iclus_refusal.sh "$LABEL" test5; echo "STAGE f2_iclus rc=$?"
  prep_tcp 1
  timeout 200 tests/d0287_remaster_measure.sh "$LABEL"; echo "STAGE d0287 rc=$?"
  prep_caw 2
  timeout 150 tests/vergate.sh test32 mixed_build; echo "STAGE vergate_mixed_build rc=$?"
  for p in 1 2 3 4; do
    prep_tcp "race_p$p"
    timeout 160 tests/d0286_depart_race.sh "${LABEL}tcp" "$p"; echo "STAGE tcp race p$p rc=$?"
  done
  prep_caw 3
  timeout 100 tests/d0133_sb_mutation_gate.sh "$LABEL" test5; echo "STAGE d0133 rc=$?"
  timeout 400 tests/crossnode_unlink_ubsweep.sh "$LABEL"; echo "STAGE ubsweep rc=$?"
  for arm in concurrent midscan prefinal; do
    prep_caw "purge_$arm"
    timeout 200 tests/d_purge_nonatomic_verify.sh "$LABEL" "$arm"; echo "STAGE purge $arm rc=$?"
  done
  echo "--- board chain $(date -u +%FT%TZ)"
  timeout 1900 bash tests/sess416_board_0286.sh; echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
