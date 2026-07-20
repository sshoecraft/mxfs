#!/bin/bash
# drc_trace.sh — sess43: rotation-IMMUNE single-victim trace for the 8/tcp
# dir_reuse readdir=799 loss.  drc_cap8.sh's dland ring (4096 entries) only
# retains the LAST rounds' rm-rf teardown; the failing round's CREATE wave
# rotates out.  This harness forwards DRC_STREAM=1 (per-node dmesg --follow to
# tests/tcp/drc_cap/stream_rank<R>.log, NFS-shared to the dev host, rotation-
# immune) + a REDUCED DRC_ROUNDS so the whole run's kernel log (P13-NADD adds,
# P-DLAND dumps, P40 incarnation-skips, RDMISS/CLASS) is captured in full.
#
# On a FAIL: the victim name is in the RDMISS line; grep the stream files for
# its P13-NADD/LADD (which daddr+round it was added to), then the dland dump and
# the writes to that daddr — decide added-then-clobbered vs never-stably-added.
#
# Usage: tests/drc_trace.sh [iters] [rounds] [nfiles] [extra_modargs]
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd); cd "$REPO"
ITERS="${1:-6}"; ROUNDS="${2:-8}"; NFILES="${3:-50}"; MODARGS="${4:-dirland=1}"
SSH=tools/mxfs_sshpass.sh; PASS=/tmp/.mxfs_pass
NODES="test1 test2 test3 test4 test5 test6 test7 test8"
mkdir -p "$REPO/tests/tcp/drc_cap" 2>/dev/null
reboot_clean() {
  for d in $NODES; do virsh -c qemu:///system destroy $d >/dev/null 2>&1; done
  sleep 3
  for d in $NODES; do virsh -c qemu:///system start $d >/dev/null 2>&1; done
  for t in $(seq 1 50); do
    ok=1
    for n in $NODES; do timeout 6 $SSH $n $PASS true 2>/dev/null || ok=0; done
    [ $ok = 1 ] && break
    sleep 3
  done
  sleep 20
  rm -f "$REPO/tests/tcp/drc_cap/stream_rank"*.log 2>/dev/null
  for n in $NODES; do timeout 8 $SSH $n $PASS "rm -f /root/drc_stream_rank*.log; dmesg -C" >/dev/null 2>&1; done
}
for i in $(seq 1 "$ITERS"); do
  echo "########## TRACE ITER $i/$ITERS rounds=$ROUNDS nfiles=$NFILES @ $(date -u +%T) ##########"
  reboot_clean
  OUT=$(env MXFS_EXTRA_MODARGS="$MODARGS" \
       MXFS_TEST_ENV="DRC_STREAM=1 DRC_ROUNDS=$ROUNDS DRC_NFILES=$NFILES" \
       ./run.sh 8 tcp dir_reuse_coherency 2>&1)
  res=$(echo "$OUT" | grep -E 'dir_reuse_coherency' | tail -1)
  echo "TRACE ITER $i: $res"
  if echo "$res" | grep -q 'PASS'; then continue; fi
  echo "===== FAIL — victim + stream summary ====="
  # victim names from the per-node RDMISS across the stream files
  grep -hoE "mxfs-drc-RDMISS round=[0-9]+ rank=[0-9]+ readdir=[0-9]+ missing_from_readdir=\[[^]]*\]" \
       "$REPO/tests/tcp/drc_cap/stream_rank"*.log 2>/dev/null | sort -u | head
  VIC=$(grep -hoE "missing_from_readdir=\[[^]]*\]" "$REPO/tests/tcp/drc_cap/stream_rank"*.log 2>/dev/null | \
        head -1 | sed -E 's/.*\[([^ ]+).*/\1/')
  echo "VICTIM=$VIC"
  echo "--- P13-NADD/LADD for victim across streams ---"
  grep -hE "P13-(NADD|LADD)" "$REPO/tests/tcp/drc_cap/stream_rank"*.log 2>/dev/null | grep -F "$VIC" | head
  echo "--- stream file sizes ---"; ls -la "$REPO/tests/tcp/drc_cap/stream_rank"*.log 2>/dev/null
  break
done
echo "########## drc_trace done ##########"
