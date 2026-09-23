#!/bin/bash
# sess470 chain 110: D-0527 measurement — does a peer's XFS_IGET_UNTRUSTED
# iget (NFS/handle path) refuse a creator-allocated inode because its cached
# inobt was read without the AG DLM lock?  tests/d0527_untrusted_iget_peer.sh
# on the fleet chain 109 leaves mounted (frozen 0.64.12, which carries the
# P-IMAP-UNTRUSTED-FREE/-NOREC probes).  Three pairings so the creator's
# affine AG differs.  Pure measurement: no install, no prep.
# budget: each harness run < 60 s (budget 90).
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s470b}
GATE=${GATE:-tests/evidence/sess470_chain109_dirshard_06411_s470a.log}
LOG=tests/evidence/sess470_chain110_d0527_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { local b="$1" l="$2"; shift 2; local T0=$(date +%s); timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"; }
{
  echo "=== sess470 chain110 START $(date -u +%FT%TZ) tree sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  echo "fleet: $(timeout 20 tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/srcversion; grep -c " mxfs " /proc/mounts' 2>/dev/null | grep -av '^Unauthorized\|^$\|^If you' | tr '\n' ' ')"
  lap 90 "d0527 test1->test2" tests/d0527_untrusted_iget_peer.sh test1 test2 ${LABEL}a
  lap 90 "d0527 test3->test1" tests/d0527_untrusted_iget_peer.sh test3 test1 ${LABEL}b
  lap 90 "d0527 test2->test4" tests/d0527_untrusted_iget_peer.sh test2 test4 ${LABEL}c
  echo "RESULTS: $(grep -a '^RESULT ' "$LOG" | cut -c1-90 | tr '\n' ';')"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
