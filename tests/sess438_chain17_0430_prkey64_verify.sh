#!/bin/bash
# sess438 chain 17: build 0.43.0 (64-bit per-boot PR key + HB identity block +
# PR registrant ledger region, proto_gen 12 — docs/whole-cluster-restart.md
# item 2), rebuild the tools (mkfs lays the new region out; prep re-mkfs's),
# deploy via prep_cluster, then the item-2 verification:
#   chk        chk_mxfs -v on the LUN from test1: identity blocks + ledger
#   prkey      P-PRKEY-* lines on test1/test8 (SELECTED/REUSED, REGISTERED)
#   fln_churn  fence_live_node churn arm — the P&A must name a 64-bit key
#              (P236-FENCE-INTENT key=..., P-PRKEY-FENCED)
#   takeover   radv takeover arm (fence + takeover under the new key)
#   zeroinc    zero-epoch arm (fence re-drive under the new key)
# Gated on chain 16 DONE.  Budgets: build ~3 min (bound 500), tools 120,
# prep ~95 s (bound 300), fln_churn ~7 min (bound 420), takeover ~200 s
# (bound 300), zeroinc ~205 s (bound 300).
cd /src/mxfs || exit 1
LABEL=${1:-s438c}
LOG=tests/evidence/sess438_chain17_0430_prkey64_verify_$LABEL.log
EV=tests/evidence/sess438_chain17_0430_prkey64_verify_$LABEL
GATE=tests/evidence/sess438_chain16_zeroinc_rerun_s438b.log
VIRSH="sudo virsh -c qemu:///system"
SSH="tools/mxfs_sshpass.sh"
mkdir -p "$EV"
{
  echo "=== sess438 chain17 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain16 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' "$EV/build.txt" | sed 's/^/build errors=/'
  grep -a 'warning:' "$EV/build.txt" | grep -v 'compiler differs' | cut -c1-200 | head -20
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  # chk: identity blocks on every ACTIVE record + the registrant ledger
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  timeout 90 $SSH test1 "/src/mxfs/tools/chk_mxfs -v $MXFS_DEV 2>&1" > "$EV/chk_after_prep.txt"; echo "STAGE chk rc=$?"
  echo "chk: identity lines=$(grep -ac 'identity host=' "$EV/chk_after_prep.txt") crc_err=$(grep -ac 'identity crc expected' "$EV/chk_after_prep.txt") ledger: $(grep -a 'PR registrant ledger' "$EV/chk_after_prep.txt" | cut -c1-160)"
  grep -a 'prledger entry\|prkey_offset' "$EV/chk_after_prep.txt" | head -5 | cut -c1-200
  for n in test1 test8; do
    timeout 30 $SSH $n "journalctl -k --since '$T0' | grep -a 'P-PRKEY\|P-HOSTID\|P-PR-FENCE-NOKEY\|P-PRKEY-CONFLICT' | cut -c1-230 | head -12" > "$EV/prkey_$n.txt" 2>&1
    echo "--- $n P-PRKEY lines: $(grep -ac 'P-PRKEY' "$EV/prkey_$n.txt")"; head -6 "$EV/prkey_$n.txt"
  done
  timeout 420 tests/fence_live_node.sh $LABEL churn test20 test1 32 --no-prep; echo "STAGE fln_churn rc=$?"
  T1=$(date -u '+%Y-%m-%d %H:%M:%S')
  timeout 30 $SSH test1 "journalctl -k --since '$T0' | grep -a 'P236-FENCE-INTENT\|P236-FENCE-CERTIFIED\|P-PRKEY-FENCED\|P-PRKEY-VICTIM-UNKNOWN\|P-PRKEY-FENCE-REFUSED\|NO_VICTIM_KEY' | cut -c1-230 | head -12" > "$EV/fence_test1.txt" 2>&1
  echo "--- test1 fence lines: $(wc -l < "$EV/fence_test1.txt")"; head -8 "$EV/fence_test1.txt"
  $VIRSH start test20 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 300 tests/d_recov_advance_bounded_verify.sh $LABEL takeover; echo "STAGE radv_takeover rc=$?"
  sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  timeout 300 tests/d_recov_zero_epoch_verify.sh $LABEL; echo "STAGE zeroinc rc=$?"
  $VIRSH start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep4 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
