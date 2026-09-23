#!/bin/bash
# sess447 chain 54: D-0514 fix verification lap F' on 0.53.3 (after chain 53).
# Chain 53's lap F used TCK_VICTIM_GAP=20: with the fix the replay work item
# exits right after victim A's completion and the reap worker's (parked) sweep
# only starts ~30 s later, so victim B's death (+20 s) preceded the sweep and
# the forced shape never formed; its verdict also read chain 52's hold window
# (the recov capture spans 20 min).  This lap: gap 45 s, so B dies while the
# reap worker's sweep of A's bucket is PARKED by dbg_sweep_hold_ms on test1;
# verdict is scoped to lines after the lap's own kill time.
# PASS iff, after the lap's first KILL: P-FREPLAY-PHASE phase=SWEEP-DEFERRED
# printed; P-DBG-SWEEP-HOLD (reap-worker sweep parked) precedes B's
# P-FREPLAY-NOTIFY; B's P238-RECOV-LEASE lands BEFORE P-DBG-SWEEP-HOLD-END;
# lap VERDICT PASS.
# budget: prep 300; lap: churn 11 + gap 45 + detect 62 + replay 5 + park/hold
# <= 150 + B replay 70 + wait 95 ~= 440 s (bound 600); prep2 300.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain53_0514_fix_verify_s447c.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447d}
LOG=tests/evidence/sess447_chain54_0514_lapF2_$LABEL.log
{
  echo "=== sess447 chain54 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 30000 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms; echo knob=\$(cat /sys/module/mxfs/parameters/dbg_sweep_hold_ms)" 2>/dev/null | grep -a knob
  OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0514_fixF2_$LABEL; mkdir -p "$OUT"
  T0=$(date +%s); TCK_PARAMS="target_cache_protected=1 foreign_replay_token_enforce=1" TCK_VICTIM_GAP=45 TCK_OUT="$OUT" timeout 600 tests/tmpfile_churn_kill.sh d0514F2_$LABEL auto:shared 20 2000 32 --no-prep; echo "STAGE lapF2 rc=$? wall=$(( $(date +%s) - T0 ))s out=$OUT"
  K0=$(grep -ao '^KILL .* 20[0-9-]*T[0-9:.]*Z' "$OUT/kills.txt" 2>/dev/null | head -1 | grep -o '[0-9][0-9]:[0-9][0-9]:[0-9][0-9]' | head -1)
  echo "--- test1 D-0514 trail (lap F2, lines after first kill $K0) ---"
  awk -v k="$K0" '{ t=$3; sub(/\..*/,"",t); if (k=="" || t>=k) print }' "$OUT/recov_test1.txt" 2>/dev/null | grep -a 'P-FREPLAY-\|P97-SWEEP\|P-DBG-SWEEP\|P238-RECOV-LEASE\|elected\|foreign replay of\|RECOVERY-COMPLETE' | cut -c1-230 > "$OUT/lapF2_trail.txt"; cat "$OUT/lapF2_trail.txt"
  tsof() { grep -a "$1" "$OUT/lapF2_trail.txt" | head -1 | awk '{print $3}'; }
  # sess447 correction: the HOLD line prints only after the park loop OBSERVES
  # the new dead slot, so it always trails B's notify; the park START is the
  # reap worker's P97-SWEEP-START.  Window = [sweep-start, hold-start + hold].
  th=$(tsof 'P97-SWEEP-START'); te=$(tsof 'P-DBG-SWEEP-HOLD-END'); [ -z "$te" ] && te=$(tsof 'P-DBG-SWEEP-HOLD ' | awk -F: '{printf "%02d:%02d:%06.3f", $1, $2+int(($3+30)/60), ($3+30)%60}'); tn=$(grep -a 'P-FREPLAY-NOTIFY' "$OUT/lapF2_trail.txt" | sed -n '2p' | awk '{print $3}'); tl=$(grep -a 'P238-RECOV-LEASE' "$OUT/lapF2_trail.txt" | sed -n '2p' | awk '{print $3}')
  dfr=$(grep -ac 'SWEEP-DEFERRED' "$OUT/lapF2_trail.txt"); inl=$(grep -ac 'phase=INLINE-SWEEP' "$OUT/lapF2_trail.txt")
  echo "LAPF2 hold=$th notifyB=$tn leaseB=$tl hold_end=$te deferred=$dfr inline=$inl"
  if [ "$inl" -eq 0 ] && [ "$dfr" -ge 1 ] && [ -n "$th" ] && [ -n "$tn" ] && [ -n "$tl" ] && [ -n "$te" ] && [[ "$th" < "$tn" ]] && [[ "$tl" < "$te" ]]; then echo "LAPF2 VERDICT PASS: victim B's replay ran while the reap worker's sweep of A was parked"; else echo "LAPF2 VERDICT FAIL: shape or ordering not met"; fi
  timeout 30 tools/mxfs_sshpass.sh test1 "echo 0 > /sys/module/mxfs/parameters/dbg_sweep_hold_ms" 2>/dev/null
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
