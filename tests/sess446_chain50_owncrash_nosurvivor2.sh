#!/bin/bash
# sess446 chain 50 (0.53.0, lap 2 after the harness bootstrap-era fix): D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE closure lap —
# the record closes when tests/no_survivor_crash_replay.sh reaches 32 replays
# including the rebooter's OWN predecessor slice under a SELF_SUCCESSION_DONE
# certificate.  Chain 36 (0.52.0, bootstrap_full_restart) already showed that
# shape (slot 0 victim = test1's previous boot, P236-FENCEKIND
# SELF_SUCCESSION_DONE, K=0 replayed, RECOVERY_COMPLETE, payload 32/32); this
# runs the harness the record names, on the current build.
# budget: prep (300); no_survivor_crash_replay (its own derived bound, mount
# wall ~200-300 s on the ring build -> 900); prep2 (300).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain49_ndr_repro_s446f.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446g}
LOG=tests/evidence/sess446_chain50_owncrash_nosurvivor2_$LABEL.log
{
  echo "=== sess446 chain50 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 1000 tests/no_survivor_crash_replay.sh $LABEL 32 test1; echo "STAGE no_survivor_crash_replay rc=$? wall=$(( $(date +%s) - T0 ))s"
  D=$(ls -dt tests/evidence/*_nosurv | head -1); echo "EVIDENCE $D"
  for f in $D/*dmesg*.txt; do [ -f $f ] || continue
    echo "OWNCRASH $(basename $f): selfsucc=$(grep -ac 'SELF_SUCCESSION_DONE' $f) complete=$(grep -ac 'foreign replay of slot [0-9]* complete' $f) refused=$(grep -ac 'POLICY-REFUSED\|REFUSED slot' $f) recovery_complete=$(grep -ac 'P-BOOT-RECOVERY-COMPLETE' $f)"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
