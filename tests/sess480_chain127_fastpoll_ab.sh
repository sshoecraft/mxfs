#!/bin/bash
# sess480 chain 127: the caw_inode_fastpoll A/B that the source has been asking
# for since v0.10.39 and that nobody has run.
#
# dlm/dlm_caw.c:552-559, verbatim:
#
#   v0.10.39: runtime gate for the inode-acquire fresh-handoff fast poll
#   (MXFS_CAW_INODE_FASTPOLL_MS window at 2ms).  Default ON -- it removes up
#   to 25ms of exponential-backoff quantization from a BAST-driven handoff
#   (measured 45->30ms per unlink).  A/B lever: under a 31-waiter dir-EX
#   convoy the window adds ~32 slot reads per waiter per wait, suspected of
#   slowing the hot slot's CAS traffic at the target.
#
# A 31-waiter directory-EX convoy is exactly the 32-node shared-directory
# crash_consistency row, which is now the ONLY thing standing between the
# 0.64.37 board and criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES.  So the
# source carries a written, quantified suspicion that a default-ON optimisation
# HURTS the precise workload blocking the project's top critical record, and it
# has never been tested.  The arithmetic is unfavourable at scale: 31 waiters
# polling every 2 ms for 64 ms is ~32 reads each, ~992 extra FUA slot reads
# against the one hot slot per wait, all serialised at a single SCSI target --
# and dlm_caw.h:63-66 already measured that a comparable read storm ("~28
# waiters x 40 reads/s = >1100 FUA reads/s serialized at the one SCSI target")
# WAS ITSELF the 21.6 ms handoff latency it was trying to observe.
#
# The knob is module_param 0644, so it flips at runtime with no rebuild and no
# reprep -- both legs run against the identical module, minutes apart, which is
# the cleanest A/B available anywhere in this campaign.
#
# WHAT THIS IS NOT.  Turning the knob off is not a fix and must never be read as
# one: it would be a default change requiring its own evidence, and the 45->30ms
# per-unlink gain it was introduced for is real and would have to be re-measured
# at every node count before anyone touched the default.  This chain measures
# whether the suspicion is TRUE at 32 nodes.  Nothing more.
#
# budget: prep 300 s (measured 88-117 s); the cc row keeps its UNCHANGED 90 s
# budget, enforced by run.sh, plus ~37 s measured startup -> 160 s per leg.  Legs
# alternate and repeat, because one pair of a 4x-variance row is a draw and not
# a difference.
set -u
cd /src/mxfs || exit 1
LABEL=${1:-s480m}
GATE=${GATE:-tests/evidence/sess480_chain126_cc_private_s480l.log}
LOG=tests/evidence/sess480_chain127_fastpoll_$LABEL.log
O=tests/evidence/sess480_fastpoll_$LABEL
PROD_KO=${PROD_KO:?PROD_KO required}
PROD_SV=${PROD_SV:?PROD_SV required}
SSH=tools/mxfs_sshpass.sh
mkdir -p "$O"
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess480 chain127 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) ==="
  bash tests/rig_wait_free.sh 7200 || { echo "ABORT: rig not free"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  cp "$PROD_KO" mxfs.ko || { echo "ABORT: install"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE install_prod sv=$sv want=$PROD_SV"
  [ "$sv" = "$PROD_SV" ] || { echo "ABORT: srcversion mismatch"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  timeout 300 ./run.sh 32 caw prep_cluster >/dev/null 2>&1; prc=$?
  echo "STAGE prep rc=$prc"
  [ "$prc" = 0 ] || { echo "ABORT: prep rc=$prc"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }

  for lap in 1 2; do
  for fp in 1 0; do
    echo "--- lap $lap caw_inode_fastpoll=$fp ($([ "$fp" = 1 ] && echo 'DEFAULT' || echo 'the suspected-harmful window OFF')) ---"
    # Set the knob on every node and READ IT BACK.  A knob that silently failed
    # to take would make both legs the same run reported as a comparison, which
    # is the exact shape of fabricated evidence this campaign keeps finding.
    ok=0
    for i in $(seq 1 32); do
      v=$(timeout 15 $SSH "test$i" "echo $fp > /sys/module/mxfs/parameters/caw_inode_fastpoll 2>/dev/null; cat /sys/module/mxfs/parameters/caw_inode_fastpoll" 2>/dev/null | tr -dc '0-9' | head -c 1)
      [ "$v" = "$fp" ] && ok=$((ok+1))
    done
    echo "STAGE knob fastpoll=$fp confirmed_on=$ok/32"
    if [ "$ok" -ne 32 ]; then
      echo "LEG fastpoll=$fp lap $lap NOT SCORED: the knob read back as $fp on only $ok of 32 nodes, so this leg is not the configuration it claims to be."
      continue
    fi
    # harness-lint: ok - pinned before the row and compared with $post below
    pre=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    timeout 160 ./run.sh 32 caw crash_consistency > "$O/cc_fp${fp}_$lap.out" 2>&1
    echo "STAGE cc_fp${fp}_$lap rc=$?"
    # harness-lint: ok - compared against $pre, which is the freshness check
    post=$(ls -dt tests/evidence/run_crash_consistency_* 2>/dev/null | head -1)
    if [ "$post" = "$pre" ] || [ -z "$post" ]; then
      echo "LEG fastpoll=$fp lap $lap NOT SCORED: no new evidence directory (still '$pre')."
      continue
    fi
    grep -aE 'crash_consistency' "$O/cc_fp${fp}_$lap.out" | grep -a 'nodes_pass' | cut -c1-300 | sed "s/^/  fp=$fp lap$lap ROW: /"
    echo -n "  fp=$fp lap$lap PARKED: "
    for f in "$post"/test*[0-9]; do [ -f "$f" ] || continue; grep -ao 'step=cc barrier [a-z]*' "$f" 2>/dev/null | tail -1; done 2>/dev/null | sort | uniq -c | tr '\n' ' '
    echo
    echo "  fp=$fp lap$lap EVIDENCE $post"
  done
  done

  # Leave the fleet on the DEFAULT.  A diagnostic knob left flipped is how a
  # later criterion silently measures a configuration nobody chose.
  back=0
  for i in $(seq 1 32); do
    v=$(timeout 15 $SSH "test$i" "echo 1 > /sys/module/mxfs/parameters/caw_inode_fastpoll 2>/dev/null; cat /sys/module/mxfs/parameters/caw_inode_fastpoll" 2>/dev/null | tr -dc '0-9' | head -c 1)
    [ "$v" = 1 ] && back=$((back+1))
  done
  echo "STAGE restore_default fastpoll=1 confirmed_on=$back/32"
  [ "$back" -eq 32 ] || echo "WARN: the fleet is NOT uniformly back on the default — do not run a production criterion until it is."
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
