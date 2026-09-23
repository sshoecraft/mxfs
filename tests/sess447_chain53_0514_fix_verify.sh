#!/bin/bash
# sess447 chain 53: BUILD 0.53.3 (D-0514 fix: no inline bucket sweep in the
# foreign-replay work item; the reap worker sweeps) once chain 52 has released
# the rig, then the instrumented verification:
#   lap F (forced shape, knob dbg_sweep_hold_ms=30000 on test1, two auto:shared
#     victims 20 s apart): the sweep now runs in the reap worker, so the hold
#     must NOT delay victim B — B's P238-RECOV-LEASE must land while the hold is
#     in force (between P-DBG-SWEEP-HOLD and P-DBG-SWEEP-HOLD-END) and the
#     replay work item must print P-FREPLAY-PHASE phase=SWEEP-DEFERRED;
#   then the board row node_death_replay x3 (shared + single laps each) under
#     the unchanged budget, knob OFF.
# budget: build ~180 s (300); prep 80 (300); lap F ~290 s measured chain 52
# (500); 3 x (prep 80 (300) + row 372 s measured chain 49 lap 2 (500)); prep2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain52_0514_forced_repro_s447b.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447c}
LOG=tests/evidence/sess447_chain53_0514_fix_verify_$LABEL.log
{
  echo "=== sess447 chain53 start $(date -u +%FT%TZ) pre-build sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 300 make modules > tests/evidence/sess447_chain53_build_$LABEL.log 2>&1; brc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE build rc=$brc old_sv=$OLD new_sv=$NEW errors=$(grep -c 'error:' tests/evidence/sess447_chain53_build_$LABEL.log)"
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 30000 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms; echo knob=\$(cat /sys/module/mxfs/parameters/dbg_sweep_hold_ms)" 2>/dev/null | grep -a knob
  OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0514_fixF_$LABEL; mkdir -p "$OUT"
  T0=$(date +%s); TCK_PARAMS="target_cache_protected=1 foreign_replay_token_enforce=1" TCK_VICTIM_GAP=20 TCK_OUT="$OUT" timeout 500 tests/tmpfile_churn_kill.sh d0514F_$LABEL auto:shared 20 2000 32 --no-prep; echo "STAGE lapF rc=$? wall=$(( $(date +%s) - T0 ))s out=$OUT"
  echo "--- test1 D-0514 trail (lap F) ---"
  grep -a 'P-FREPLAY-\|P97-SWEEP\|P-DBG-SWEEP\|P238-RECOV-LEASE\|elected\|foreign replay of\|RECOVERY-COMPLETE' "$OUT/recov_test1.txt" 2>/dev/null | cut -c1-230
  # verdict: B's lease timestamp must fall between HOLD and HOLD-END
  th=$(grep -a 'P-DBG-SWEEP-HOLD ' "$OUT/recov_test1.txt" | head -1 | awk '{print $3}'); te=$(grep -a 'P-DBG-SWEEP-HOLD-END' "$OUT/recov_test1.txt" | head -1 | awk '{print $3}')
  tl=$(grep -a 'P238-RECOV-LEASE' "$OUT/recov_test1.txt" | tail -1 | awk '{print $3}')
  echo "LAPF hold=$th hold_end=$te last_lease=$tl deferred=$(grep -ac 'SWEEP-DEFERRED' "$OUT/recov_test1.txt") inline=$(grep -ac 'phase=INLINE-SWEEP' "$OUT/recov_test1.txt")"
  if [ -n "$th" ] && [ -n "$te" ] && [ -n "$tl" ] && [[ "$tl" > "$th" ]] && [[ "$tl" < "$te" ]]; then echo "LAPF VERDICT PASS: victim B's lease landed during the parked sweep"; else echo "LAPF VERDICT FAIL: lease not inside the hold window"; fi
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 0 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms" 2>/dev/null
  for lap in 1 2 3; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    for l in shared single; do echo "LAP$lap $l: $(grep -a '^VERDICT\|WAIT ' $D/$l.log 2>/dev/null | head -2 | cut -c1-160 | tr '\n' ' ')"; done
    echo "LAP$lap steps>=1s: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ac 'P97-SWEEP-STEP') deferred: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ac 'SWEEP-DEFERRED')"
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
