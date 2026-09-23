#!/bin/bash
# sess439 chain 20: build 0.44.0 (bootstrap record region + proto_gen 13 +
# register-before-ledger derived PR key — docs/whole-cluster-restart.md §5 and
# "Item 2 correction"), rebuild the tools (mkfs lays the new region out; prep
# re-mkfs's), deploy via prep_cluster, then verify:
#   prep       MUST mount 32/32 (0.43.0 mounted 1/32: P-PRKEY-PREPARE-FAILED -52)
#   chk        chk_mxfs -v: 'bootstrap: IDLE' + ledger with 32 REGISTERED
#   nodes      P-BOOT-STATE IDLE, P-PRKEY-SELECTED/PUBLISHED, P-PRKEY-REGISTERED
#   fln_churn  fence_live_node churn arm — P&A names the derived 64-bit key
#   takeover   radv takeover arm (harness fix: python mod 2^64)
#   zeroinc    zero-epoch arm
#   deaths     openunlink_deaths unlinker_death with token enforcement armed
# Gated on chain 19 DONE.  Budgets (measured): build ~3 min (bound 500), tools
# 120, prep 66-95 s (bound 300), fln_churn ~7 min (bound 420), takeover ~112 s
# (bound 300), zeroinc ~150 s (bound 300), deaths (chain 14 wall) bound 900.
cd /src/mxfs || exit 1
LABEL=${1:-s439b}
LOG=tests/evidence/sess439_chain20_0440_bootstrap_prkey_verify_$LABEL.log
EV=tests/evidence/sess439_chain20_0440_bootstrap_prkey_verify_$LABEL
GATE=tests/evidence/sess439_chain19_takeover_rerun2_s439a.log
VIRSH="sudo virsh -c qemu:///system"
SSH="tools/mxfs_sshpass.sh"
mkdir -p "$EV"
{
  echo "=== sess439 chain20 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain19 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
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
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  timeout 90 $SSH test1 "/src/mxfs/tools/chk_mxfs -v $MXFS_DEV 2>&1" > "$EV/chk_after_prep.txt"; echo "STAGE chk rc=$?"
  echo "chk: bootstrap: $(grep -a 'bootstrap' "$EV/chk_after_prep.txt" | cut -c1-220 | head -3)"
  echo "chk: identity lines=$(grep -ac 'identity host=' "$EV/chk_after_prep.txt") crc_err=$(grep -ac 'identity crc expected' "$EV/chk_after_prep.txt") ledger: $(grep -a 'PR registrant ledger' "$EV/chk_after_prep.txt" | cut -c1-160)"
  echo "chk: REGISTERED entries=$(grep -ac 'prledger entry .*REGISTERED' "$EV/chk_after_prep.txt") PREPARED=$(grep -ac 'prledger entry .*PREPARED' "$EV/chk_after_prep.txt")"
  for n in test1 test8 test32; do
    timeout 30 $SSH $n "journalctl -k --since '$T0' | grep -a 'P-PRKEY\|P-HOSTID\|P-BOOT-\|P305' | cut -c1-230 | head -14" > "$EV/prkey_$n.txt" 2>&1
    echo "--- $n: prkey=$(grep -ac 'P-PRKEY' "$EV/prkey_$n.txt") boot=$(grep -ac 'P-BOOT-STATE' "$EV/prkey_$n.txt") p305=$(grep -ac 'P305' "$EV/prkey_$n.txt")"; grep -a 'P-PRKEY-SELECTED\|P-PRKEY-PUBLISHED\|P-PRKEY-REGISTERED\|P-BOOT-STATE\|P305\|COLLISION\|FAILED' "$EV/prkey_$n.txt" | head -6
  done
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on 0.44.0 — see per-node NODE_PREP_FAIL above"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 420 tests/fence_live_node.sh $LABEL churn test20 test1 32 --no-prep; echo "STAGE fln_churn rc=$?"
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
  timeout 400 tests/openunlink_deaths.sh unlinker_death test1 test2 > "$EV/deaths_unlinker_death.txt" 2>&1; echo "STAGE deaths rc=$?"; grep -a 'PASS\|FAIL\|RESULT\|forensics\|armed' "$EV/deaths_unlinker_death.txt" | tail -8
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep5 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
