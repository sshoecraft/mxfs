#!/bin/bash
# drc_grantgen_probe.sh (sess50 ccloop 4cb2d0a2) — RULE-4 decisive measurement.
#
# HYPOTHESIS (GPT-5.5 grant-epoch design): the durable dir-block clobber buffer
# (comm=xfsaild, 1-behind durable disk) carries an OLD b_mxfs_grant_gen (lingered
# across a release/reacquire) while a LEGIT removal (comm=rm) carries the CURRENT
# i_dlm_cached_grant_gen.  sess69 PROVED content/dirty/pin/in_ail are byte-identical
# between the two — grant_gen is the only candidate temporal discriminator.
#
# This runs 8-node dir_reuse in dataclobber=1 DETECT mode (no skip, just the
# P-DATACLOBBER-SKIP detector which now logs buf_grantgen/cur_grantgen/gg_mismatch)
# and tallies gg_mismatch by comm.  If clobbers (xfsaild) are gg_mismatch=1 and
# legit rm are gg_mismatch=0 -> grant_gen DISCRIMINATES -> implement the gate.
#
# Usage: tests/drc_grantgen_probe.sh [rounds] [N] [attempts]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ROUNDS="${1:-16}"; N="${2:-8}"; ATTEMPTS="${3:-3}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
CAPDIR="$REPO/tests/_grantgen_cap"; mkdir -p "$CAPDIR"
ALL="test1 test2 test3 test4 test5 test6 test7 test8"
NODES=$(echo $ALL | tr ' ' '\n' | head -n "$N" | tr '\n' ' ')
TS=$(date -u +%Y%m%dT%H%M%SZ)

# full clean reboot of the node set (trust slow results)
for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break; sleep 3
done
sleep 20
echo "########## GRANTGEN PROBE rounds=$ROUNDS N=$N attempts=$ATTEMPTS ts=$TS @ $(date -u +%T) ##########"

for a in $(seq 1 $ATTEMPTS); do
  echo "===== attempt $a/$ATTEMPTS @ $(date -u +%T) ====="
  OUT=$(env MXFS_EXTRA_MODARGS='dataclobber=1' MXFS_TEST_ENV="DRC_ROUNDS=$ROUNDS" \
        ./run.sh "$N" tcp dir_reuse_coherency 2>&1)
  VERD=$(echo "$OUT" | grep -E 'nodes_pass=' | tail -1)
  echo "VERDICT: $VERD"
  # always harvest P-DATACLOBBER lines (detector fires on detect even if test passes)
  RAW="$CAPDIR/gg_${TS}_a${a}.txt"
  : > "$RAW"
  for n in $NODES; do
    timeout 25 $SSH $n $PASS "dmesg | grep 'P-DATACLOBBER-SKIP'" 2>/dev/null \
      | grep -vE "^Warning:|^Unauthorized|^If you" | sed "s/^/$n: /" >> "$RAW"
  done
  CNT=$(wc -l < "$RAW")
  echo "captured $CNT P-DATACLOBBER lines -> $RAW"
  if [ "$CNT" -gt 0 ]; then
    echo "--- tally by comm x gg_mismatch (kind=data only) ---"
    grep 'kind=data' "$RAW" | grep -oE 'gg_mismatch=[01] .*comm=[^ ]+' \
      | sed -E 's/.*(gg_mismatch=[01]).*comm=([^ ]+).*/\2 \1/' \
      | awk '{c=$1; sub(/\/.*/,"",c); print c" "$2}' | sort | uniq -c | sort -rn
    echo "--- xfsaild (clobber) sample lines ---"
    grep 'kind=data' "$RAW" | grep 'comm=xfsaild' | head -6
    echo "--- rm (legit) sample lines ---"
    grep 'kind=data' "$RAW" | grep 'comm=rm' | head -4
  fi
done
echo "########## probe done @ $(date -u +%T) -> $CAPDIR ##########"
