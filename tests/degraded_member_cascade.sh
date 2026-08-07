#!/bin/bash
# tests/degraded_member_cascade.sh — is the Aug-1 23:32Z board signature
# (cache_coherency 1/654 failed, zero_silent_loss 10/644 failed, IDENTICALLY
# on all 32 nodes) produced by ONE degraded member rather than by any
# filesystem defect?
#
# Mechanism under test: every coordinated suite test counts coord_barrier as
# a CHECK.  A barrier fails on EVERY node when any single node fails to
# arrive, so one sick member yields the same small failed-check count on all
# N nodes — exactly the recorded shape.  On Aug 1 test32's root disk was
# 100% full and its NFS was stuck, i.e. it was that sick member.
#
# Arms (N nodes, default 8; victim = testN), selected by MODE:
#   freeze  — virsh-suspend the victim so it answers NOTHING.  MEASURED
#             RESULT (sess43, 8/caw): every node reports NO_TERMINAL_RECORD
#             (the run dies on its budget).  This does NOT match the
#             recorded incident, because for cache_coherency the harness
#             sets COORD_TIMEOUT=120 above a 60s budget: a barrier stall is
#             always killed before it can be COUNTED as a failed check.
#   fsdown  — (default) the victim keeps answering MQTT barriers but loses
#             its mount mid-run, so only its FILESYSTEM operations fail.
#             This is the faithful analogue of Aug-1 test32: alive on the
#             network, broken on storage (root disk 100% full, truncated
#             module, stuck NFS).  Predicted signature: the survivors run
#             EVERY check and fail exactly those naming the victim's
#             artifacts — a small identical failed-check count on all
#             nodes, which is the recorded 1-of-654 / 10-of-644 shape.
#
# Drives the REAL harness (./run.sh) so the coordination environment is
# identical to a board run — a hand-rolled launcher does not reproduce it.
# Results go to a SCRATCH criteria file (MXFS_CRIT), so this diagnostic
# never writes the real board.
#
# This is a diagnostic, not an FS criterion: the degraded arm is EXPECTED to
# fail checks.  The verdict is about WHICH checks fail (the reason must name
# a barrier) and whether the survivors' shape matches the recorded incident.
#
# STATUS (sess43): the freeze arm is measured and conclusive (it yields
# NO_TERMINAL_RECORD, which does NOT match the incident).  The fsdown arm is
# NOT yet conclusive: cache_coherency's filesystem body is only a few seconds
# long inside a ~60s run.sh invocation, so both a fixed delay (12s) and a
# kmsg-phase-marker trigger failed to land the degradation inside the window
# (the marker watcher also risks running past the arm's own budget).  To
# finish this arm, drive it against a LONGER test (dirent_durability, soak)
# or add a test-side hook that pauses at a named phase until released.  Do
# not read a REFUTED verdict from the fsdown arm as evidence until the drop
# is confirmed to have landed mid-body ("MOUNT DROPPED" printed BEFORE the
# run's completion line).
#
# Budget (RULE 0): baseline ~90s, degraded ~90s + 45s thaw/settle.
#
# usage: degraded_member_cascade.sh [N=8] [test=cache_coherency]
set -u
N="${1:-8}"
TEST="${2:-cache_coherency}"
MODE="${3:-fsdown}"          # fsdown | freeze
SSH=tools/mxfs_sshpass.sh
VIRSH="virsh -c qemu:///system"
VICTIM="test$N"
SCRATCH=$(mktemp -d)/criteria_scratch.json
say() { echo "[$(date +%H:%M:%S)] $*"; }
cleanup() {
  # sess43 SELF-INFLICTED-DAMAGE FIX (cost a board chunk): the fsdown
  # watcher runs ON the victim inside its own ssh.  When this script was
  # killed by its outer timeout, the trap remounted the victim and THEN the
  # orphaned watcher reached its own deadline and ran `umount -l` on the
  # freshly restored mount — leaving test32 unmounted, which pre-asserted
  # the next two board tests.  Kill any watcher on the victim FIRST, then
  # restore.  (This is the same shape as the Aug-1 test32 breakage: a test
  # script's side effect, not a filesystem defect.)
  $VIRSH resume "$VICTIM" >/dev/null 2>&1
  $SSH "$VICTIM" "pkill -f 'mxfs-CCph rank=' 2>/dev/null; pkill -f 'PHASE=cv-write-done' 2>/dev/null; true" >/dev/null 2>&1
  sleep 2
  $SSH "$VICTIM" "mountpoint -q /mnt/shared" >/dev/null 2>&1 || \
    $SSH "$VICTIM" "MXFS_DEV=/dev/mapper/mpatha MXFS_KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}') bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

cp criteria.json "$SCRATCH"

cell() { # cell <field> — read this test's cell from the scratch file
  jq -r --arg n "$TEST" --arg c "${N}/caw" \
     '.categories[].tests[] | select(.name==$n) | .runs[$c] | '"$1"' // ""' \
     "$SCRATCH" 2>/dev/null | head -1
}

# ── baseline ───────────────────────────────────────────────────────────────
say "=== baseline: all $N nodes healthy, running $TEST via the real harness ==="
MXFS_CRIT="$SCRATCH" timeout 300 ./run.sh "$N" caw "$TEST" >/dev/null 2>&1
BST=$(cell .status); BME=$(cell .measured)
say "baseline: $BST | $BME"
if [ "$BST" != PASS ]; then
  echo "RESULT: INCONCLUSIVE | case=degraded_member_cascade | baseline $TEST is already failing ($BST) — fix the rig before attributing anything"
  exit 2
fi

# ── degraded ───────────────────────────────────────────────────────────────
say "=== degraded ($MODE): $VICTIM degraded a few seconds into the run ==="
if [ "$MODE" = freeze ]; then
  ( sleep 12; $VIRSH suspend "$VICTIM" >/dev/null 2>&1 && echo "[$(date +%H:%M:%S)] $VICTIM SUSPENDED" ) &
else
  # Lazy-unmount: the node stays up and keeps answering MQTT barriers, but
  # every subsequent FS operation on the shared mount fails.  run.sh's
  # pre-assert has already passed at this point (it asserts before launch),
  # which is exactly the incident's ordering.
  #
  # TRIGGER: the test's own kmsg phase marker, watched ON the victim.  A
  # fixed sleep cannot hit the window — the FS body of an 8..32-node
  # cache_coherency run is only a few seconds inside a ~60s run.sh
  # invocation, so every fixed delay tried (12s) landed after the test had
  # already finished and the arm read as a false REFUTED.
  ( $SSH "$VICTIM" "
      for i in \$(seq 1 600); do
        dmesg | tail -40 | grep -q 'mxfs-CCph rank=$N PHASE=cv-write-done' && break
        sleep 0.2
      done
      umount -l /mnt/shared 2>/dev/null && echo DROPPED" 2>/dev/null | grep -q DROPPED \
    && echo "[$(date +%H:%M:%S)] $VICTIM MOUNT DROPPED at cv-write-done (node alive, barriers still answered)" ) &
fi
DEGRADER=$!
MXFS_CRIT="$SCRATCH" timeout 400 ./run.sh "$N" caw "$TEST" >/dev/null 2>&1
wait "$DEGRADER" 2>/dev/null
DST=$(cell .status); DME=$(cell .measured); DRE=$(cell .reason)
if [ "$MODE" = freeze ]; then
  $VIRSH resume "$VICTIM" >/dev/null 2>&1 && say "$VICTIM resumed"
else
  KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
  $SSH "$VICTIM" "MXFS_DEV=/dev/mapper/mpatha MXFS_KO_MD5='$KOMD5' bash /src/mxfs/tests/setup/prep_node.sh caw" >/dev/null 2>&1
  say "$VICTIM remounted"
fi
say "degraded: $DST | $DME"
say "degraded reason: ${DRE:0:300}"

# settle, then confirm the rig survived the freeze
sleep 30
INTACT=0
for i in $(seq 1 "$N"); do
  $SSH "test$i" "mount -t mxfs | grep -q shared" >/dev/null 2>&1 && INTACT=$((INTACT+1))
done
say "post-thaw mounts intact: $INTACT/$N"

NFAIL=$(sed -n 's/.*nodes_pass=\([0-9]*\)\/\([0-9]*\).*/\2-\1/p' <<<"$DME")
NFAIL=$(( ${NFAIL:-0} )) 2>/dev/null || NFAIL=0
BARRIER=0
case "$DRE" in *barrier*) BARRIER=1;; esac

echo "---"
if [ "$DST" != PASS ] && [ "$BARRIER" = 1 ]; then
  echo "RESULT: CONFIRMED | case=degraded_member_cascade | one frozen member failed the run with barrier-named checks on the survivors — the Aug-1 23:32 all-nodes-agree signature is a DEGRADED-MEMBER CASCADE, not an FS coherency defect | degraded=$DME | mounts_intact=$INTACT/$N"
elif [ "$DST" != PASS ]; then
  echo "RESULT: PARTIAL | case=degraded_member_cascade | freeze failed the run but no reason named a barrier — inspect | degraded=$DME reason=${DRE:0:200} | mounts_intact=$INTACT/$N"
else
  echo "RESULT: REFUTED | case=degraded_member_cascade | freezing a member did NOT fail the run — the 23:32 signature needs another explanation | mounts_intact=$INTACT/$N"
fi
