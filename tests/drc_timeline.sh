#!/bin/bash
# drc_timeline.sh (sess50 ccloop) — RULE-4: reconstruct daddr-120 dirent-count
# timeline across all nodes to find the BACKWARD step (sess69 reversion root).
# Runs dirwr=1 (P50-RD read-completion + P50-WR write-submit counts; lightweight,
# no per-write disk read), gathers all P50 lines for the storm dir block-0,
# global-merge-sorts by realns (nodes UTC-synced), prints the count timeline.
#
# Usage: tests/drc_timeline.sh [rounds] [N] [owner] [daddr]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ROUNDS="${1:-16}"; N="${2:-8}"; OWNER="${3:-131}"; DADDR="${4:-120}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
CAPDIR="$REPO/tests/_timeline_cap"; mkdir -p "$CAPDIR"
ALL="test1 test2 test3 test4 test5 test6 test7 test8"
NODES=$(echo $ALL | tr ' ' '\n' | head -n "$N" | tr '\n' ' ')
TS=$(date -u +%Y%m%dT%H%M%SZ)

for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
sleep 3
for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
for t in $(seq 1 50); do
  ok=1; for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
  [ $ok = 1 ] && break; sleep 3
done
sleep 20
echo "########## TIMELINE rounds=$ROUNDS N=$N owner=$OWNER daddr=$DADDR ts=$TS @ $(date -u +%T) ##########"
OUT=$(env MXFS_EXTRA_MODARGS='dirwr=1 dataclobber=1' MXFS_TEST_ENV="DRC_ROUNDS=$ROUNDS" \
      ./run.sh "$N" tcp dir_reuse_coherency 2>&1)
VERD=$(echo "$OUT" | grep -E 'nodes_pass=' | tail -1)
echo "VERDICT: $VERD"

RAW="$CAPDIR/tl_${TS}.txt"; : > "$RAW"
for n in $NODES; do
  timeout 30 $SSH $n $PASS "dmesg | grep -E 'P50-RD|P50-WR|P-DATACLOBBER-SKIP' | grep -E 'owner=$OWNER .*daddr=$DADDR |owner=$OWNER daddr=$DADDR '" 2>/dev/null \
    | grep -vE "^Warning:|^Unauthorized|^If you" | sed "s/^/$n /" >> "$RAW"
done
echo "captured $(wc -l < "$RAW") lines -> $RAW"
# global timeline: extract (realns, node, kind, cnt, fua_fresh, comm) sort by realns
echo "--- daddr=$DADDR GLOBAL TIMELINE (realns-sorted) ---"
awk '{
  node=$1; line=$0;
  kind="?"; if(line ~ /P50-RD/) kind="RD"; else if(line ~ /P50-WR/) kind="WR"; else if(line ~ /P-DATACLOBBER/) kind="CLOB";
  cnt=""; for(i=1;i<=NF;i++){ if($i ~ /^cnt=/){cnt=$i} if($i ~ /^buf_cnt=/){cnt=$i} }
  dc=""; for(i=1;i<=NF;i++){ if($i ~ /^disk_cnt=/){dc=$i} }
  ff=""; for(i=1;i<=NF;i++){ if($i ~ /^fua_fresh=/){ff=$i} if($i ~ /^fresh=/){ff=$i} }
  rn=""; for(i=1;i<=NF;i++){ if($i ~ /^realns=/){rn=$i; sub(/realns=/,"",rn)} }
  cm=""; for(i=1;i<=NF;i++){ if($i ~ /^comm=/){cm=$i} }
  printf "%s %s %-4s %-12s %-12s %-10s %s\n", rn, node, kind, cnt, dc, ff, cm
}' "$RAW" | sort -n | tail -120
echo "########## timeline done @ $(date -u +%T) ##########"
