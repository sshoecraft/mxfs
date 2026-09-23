#!/bin/bash
# sess439 chain 21: re-run fence_live_node churn on the DEPLOYED 0.44.0 with
# the harness fix (it derived the victim/peer PR keys from node_id; since
# 0.43.0 the key is the 64-bit per-boot key in P-PRKEY-PUBLISHED, so chain 20
# s439b reported 'victim key 0xff9d9cd4 not present' while the peers had in
# fact fenced slot 19 and replayed it).  Gated on chain 20 DONE.  Budgets:
# prep 66-95 s (bound 300), fln_churn 88 s measured (bound 420), V restart 45 s.
cd /src/mxfs || exit 1
LABEL=${1:-s439c}
LOG=tests/evidence/sess439_chain21_fln_rerun_0440_$LABEL.log
EV=tests/evidence/sess439_chain21_fln_rerun_0440_$LABEL
GATE=tests/evidence/sess439_chain20_0440_bootstrap_prkey_verify_s439b.log
VIRSH="sudo virsh -c qemu:///system"
SSH="tools/mxfs_sshpass.sh"
mkdir -p "$EV"
{
  echo "=== sess439 chain21 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain20 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  T0=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 420 tests/fence_live_node.sh $LABEL churn test20 test1 32 --no-prep; echo "STAGE fln_churn rc=$?"
  timeout 30 $SSH test1 "journalctl -k --since '$T0' | grep -a 'P236-FENCE-INTENT\|P236-FENCEKIND\|P-PRKEY-FENCED\|P-PRKEY-VICTIM-UNKNOWN\|NO_VICTIM_KEY' | cut -c1-230 | head -12" > "$EV/fence_test1.txt" 2>&1
  echo "--- test1 fence lines: $(grep -ac 'P236\|P-PRKEY' "$EV/fence_test1.txt")"; grep -a 'P236\|P-PRKEY' "$EV/fence_test1.txt" | head -8
  $VIRSH start test20 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
