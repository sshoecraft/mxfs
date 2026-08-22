#!/bin/bash
# d513_forged_record_checks.sh — the sess333 RULE-5 "pre-rig unit checks" for
# D-FOREIGN-REPLAY-REFUSAL-CLUSTERWIDE-SUICIDE-513, run against the REAL LUN
# and the REAL mount path.
#
# The containment machinery has three consumers of an on-disk terminal
# recovery-outcome record — the disklock monitor, the registration-time
# 64-slot scan (mxfs_v5_dlm_recovery_scan_outcomes), and the shared classifier
# (mxfs_freplay_classify_terminal -> mxfs_freplay_import_verdict).  The ruling
# requires proof that a MALFORMED or MISPLACED record makes every one of them
# fail CLOSED, and that a refusing path never rewrites the sector it refused.
# Nothing in the tree can produce those inputs; tools/recov_forge does.
#
# Method, per shape:
#   1. save the target heartbeat sector (an unused slot) to a file
#   2. unmount ONE node (the rest of the cluster stays up)
#   3. forge the shape into that sector
#   4. mount the node again — its admission barrier's requires-recovery sweep
#      picks the forged slot up (get_recovery_pending_slots: any GUARD record
#      with a sub-complete descriptor) and classifies it
#   5. record the mount's exit status, wall time and dmesg
#   6. re-read the sector and compare its crc32c: a refusing path must have
#      left it byte-identical
#   7. restore the sector and bring the node back up
#
# Usage: tests/d513_forged_record_checks.sh <shape> [slot] [target_node]
#   shapes: desc-crc ident badcrc-oc badkind badreason agmask0 slotmismatch
#           valid legacy
#   default slot 40 (unused on a 32-node rig), target test32
#
# Exit 0 = the shape's expectations held.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
FORGE=/src/mxfs/tools/recov_forge
DEV=/dev/mapper/mpatha
MNT=/mnt/shared

SHAPE="${1:?usage: d513_forged_record_checks.sh <shape> [slot] [target_node]}"
SLOT="${2:-40}"
TARGET="${3:-test32}"
PROBE="${PROBE:-test1}"
SAVE="/tmp/d513_forge_slot${SLOT}.bin"

# RULE 0 budget.  Measured on this rig: umount ~2 s, a clean mount ~8-15 s.
# A forged terminal slot aborts the barrier on its first classification, so it
# is FASTER than a clean mount, not slower.  90 s covers the mount plus the ssh
# fan-out; anything beyond that is a wedge, not a slow success.
MOUNT_BUDGET="${MOUNT_BUDGET:-90}"

case "$SHAPE" in
  desc-crc)     FORGE_ARGS="--break-desc-crc" ;;
  ident)        FORGE_ARGS="--victim-slot $(( (SLOT + 1) % 64 ))" ;;
  badcrc-oc)    FORGE_ARGS="--oc badcrc" ;;
  badkind)      FORGE_ARGS="--oc badkind" ;;
  badreason)    FORGE_ARGS="--oc badreason" ;;
  agmask0)      FORGE_ARGS="--oc agmask0" ;;
  slotmismatch) FORGE_ARGS="--oc slotmismatch" ;;
  valid)        FORGE_ARGS="--oc valid --oc-agmask 0x1" ;;
  legacy)       FORGE_ARGS="" ;;
  # A PRE-MKFS GHOST: same shapes, but stamped with a FOREIGN fs_gen.  Every
  # disklock sweep treats a record whose fs_gen differs from ours as a ghost of
  # an earlier mkfs generation and ignores it (hb_gen_foreign).  These shapes
  # ask whether every CONSUMER of a terminal outcome record agrees.
  ghost)        FORGE_ARGS="--fsgen 0xdeadbeef --oc valid --oc-agmask 0x1" ;;
  ghost-fswide) FORGE_ARGS="--fsgen 0xdeadbeef --oc fswide" ;;
  ghost-badkind) FORGE_ARGS="--fsgen 0xdeadbeef --oc badkind" ;;
  # A verdict the ADMISSION BARRIER cannot see but the registration-time scan
  # can: get_recovery_pending_slots skips a descriptor at stage >=
  # GRANTS_RELEASED ("complete, awaiting slot zeroing"), so the barrier never
  # classifies this slot.  The registration scan reads every slot regardless.
  # This is the late-mount case the scan exists for, with our OWN fs_gen.
  late-fswide)  FORGE_ARGS="--stage 5 --oc fswide" ;;
  late-valid)   FORGE_ARGS="--stage 5 --oc valid --oc-agmask 0x1" ;;
  # sess383 ruling Q5: surface the shapes the first nine did not cover.
  # A MISPLACED descriptor paired with a crc-valid NONZERO outcome — the
  # passing legacy/backfill shape only proved the all-zero-outcome form is
  # rejected, because backfill is the only path that checked descriptor
  # identity at all.
  desc-slot-oc) FORGE_ARGS="--victim-slot $(( (SLOT + 1) % 64 )) --oc valid" ;;
  # An AG mask made only of bits for AGs this filesystem does not have:
  # "nonzero" passes, but the quarantine is empty — fail-OPEN.
  agmask-oob)   FORGE_ARGS="--oc valid --oc-agmask 0x8000000000000000" ;;
  # Noncanonical FSWIDE: domain says whole-filesystem, mask says otherwise.
  fswide-mask)  FORGE_ARGS="--oc fswidemask --oc-agmask 0x1" ;;
  *) echo "unknown shape $SHAPE"; exit 2 ;;
esac

# Shapes that must leave the sector byte-identical (the refusing paths).
# `legacy` is the deliberate exception: backfill SYNTHESIZES a verdict, so the
# sector MUST change.  `valid` is already terminal, so nothing rewrites it.
case "$SHAPE" in
  legacy) EXPECT_PRESERVED=0 ;;
  *)      EXPECT_PRESERVED=1 ;;
esac

# Shapes that must refuse the mount FSWIDE.  `valid` is AG-scoped: the mount
# admits and only the quarantined AGs fail with EIO.
# A ghost record belongs to a previous mkfs generation: nothing may act on it,
# so the mount must admit AND import no quarantine at all.
case "$SHAPE" in
  valid)            EXPECT_MOUNT=0; EXPECT_QUAR=1 ;;
  ghost|ghost-fswide|ghost-badkind)
                    EXPECT_MOUNT=0; EXPECT_QUAR=0 ;;
  late-fswide)      EXPECT_MOUNT=1; EXPECT_QUAR=1 ;;
  desc-slot-oc|agmask-oob|fswide-mask)
                    EXPECT_MOUNT=1; EXPECT_QUAR=1 ;;
  late-valid)       EXPECT_MOUNT=0; EXPECT_QUAR=1 ;;
  *)                EXPECT_MOUNT=1; EXPECT_QUAR=1 ;;
esac

say() { echo "[$(date -u +%T)] $*"; }
node() { timeout 60 "$SSH" "$1" "$2" 2>/dev/null | grep -v '^Warning:\|Unauthorized access\|disconnect immediately'; }

# Is the filesystem mounted?  Read /proc/mounts — NEVER `mountpoint -q`.
# `mountpoint` stats the mount root, which is inode 128 in AG 0, and an
# AG-scoped quarantine covering AG 0 makes that stat fail with EIO exactly as
# designed.  A shape that quarantines AG 0 therefore made `mountpoint -q`
# report "not mounted" on a perfectly mounted filesystem (measured sess383),
# so the harness skipped its own umount, the remount hit "already mounted",
# and five later shapes refused to run against the wreckage.  /proc/mounts is
# answered by the VFS and never touches the filesystem.
is_mounted() { node "$1" "grep -qs ' $MNT mxfs ' /proc/mounts && echo YES || echo NO" | tail -1 | tr -d '[:space:]'; }


say "=== d513_forged_record_checks shape=$SHAPE slot=$SLOT target=$TARGET ==="

# 0a. The target must START mounted.  A shape that runs against an already-down
#     node produces assertions about the PREVIOUS shape's wreckage, not this
#     one's — that is how a contaminated matrix run reports three bogus
#     failures in a row (sess383).  Try once to recover, then refuse.
m0=$(is_mounted "$TARGET")
if [ "$m0" != "YES" ]; then
    say "target $TARGET is not mounted — attempting one recovery mount"
    node "$TARGET" "mount -t mxfs $DEV $MNT 2>&1 | tail -2; grep -qs ' $MNT mxfs ' /proc/mounts && echo YES || echo NO"
    m0=$(is_mounted "$TARGET")
fi
if [ "$m0" != "YES" ]; then
    echo "FAIL: $TARGET will not mount — refusing to run a shape against a"
    echo "      node that is already down (results would describe the wreckage"
    echo "      of a previous shape, not this one)"
    exit 1
fi

# 0. The slot must be unused: forging over a live node's heartbeat would be a
#    different (and destructive) experiment.
pre=$(node "$PROBE" "$FORGE $DEV dump $SLOT")
echo "$pre"
if echo "$pre" | grep -q "flags=ACTIVE"; then
    echo "FAIL: slot $SLOT is a LIVE heartbeat — pick an unused slot"
    exit 1
fi

say "--- saving slot $SLOT"
node "$PROBE" "$FORGE $DEV save $SLOT $SAVE" || { echo "FAIL: save"; exit 1; }
base_crc=$(node "$PROBE" "$FORGE $DEV dump $SLOT" | sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' | head -1)
say "baseline sector_crc32c=$base_crc"

say "--- unmounting $TARGET"
node "$TARGET" "dmesg --clear; umount $MNT; echo umount_rc=\$?"

say "--- forging shape=$SHAPE"
forged=$(node "$PROBE" "$FORGE $DEV mkguard $SLOT $FORGE_ARGS") || { echo "FAIL: forge"; exit 1; }
echo "$forged"
FORGED_CRC=$(echo "$forged" | sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' | head -1)
say "forged sector_crc32c=$FORGED_CRC"

say "--- mounting $TARGET (budget ${MOUNT_BUDGET}s)"
t0=$(date +%s)
mrc=$(timeout "$MOUNT_BUDGET" "$SSH" "$TARGET" \
        "mount -t mxfs $DEV $MNT >/tmp/d513mount.log 2>&1; echo MOUNT_RC=\$?" 2>/dev/null \
        | grep -o 'MOUNT_RC=[0-9]*' | cut -d= -f2)
t1=$(date +%s)
wall=$((t1 - t0))
: "${mrc:=TIMEOUT}"
say "mount rc=$mrc wall=${wall}s"

post_dump=$(node "$PROBE" "$FORGE $DEV dump $SLOT")
post_crc=$(echo "$post_dump" | sed -n 's/.*sector_crc32c=\(0x[0-9a-f]*\).*/\1/p' | head -1)
say "post sector_crc32c=$post_crc"
echo "$post_dump"

say "--- target dmesg (D-513 containment lines)"
dm=$(node "$TARGET" "dmesg")
echo "$dm" | grep -E "P241-RECOV|P240-QUAR|foreign replay slot=|mount ABORTED|Filesystem has been shut down|BACKFILL" | tail -30

pass=1

# (a) mount disposition
if [ "$EXPECT_MOUNT" -eq 1 ]; then
    if [ "$mrc" = "0" ]; then
        echo "FAIL: mount SUCCEEDED on a shape that must refuse FSWIDE"
        pass=0
    else
        echo "OK: mount refused (rc=$mrc)"
    fi
else
    if [ "$mrc" != "0" ]; then
        echo "FAIL: mount refused (rc=$mrc) on an AG-scoped shape that must admit"
        pass=0
    else
        echo "OK: mount admitted (AG-scoped quarantine)"
    fi
fi

# (b) byte preservation
if [ "$EXPECT_PRESERVED" -eq 1 ]; then
    if [ "$post_crc" = "$base_crc" ]; then
        echo "FAIL: sector reverted to baseline — the forge never landed"
        pass=0
    fi
    # The forged image is what must survive; capture it from the forge output.
    if [ -n "${FORGED_CRC:-}" ] && [ "$post_crc" != "$FORGED_CRC" ]; then
        echo "FAIL: refusing path REWROTE the sector it refused"
        pass=0
    fi
else
    echo "NOTE: shape $SHAPE is expected to rewrite the sector (backfill)"
fi

# (b2) quarantine expectation
nq=$(echo "$dm" | grep -c "P240-QUAR-IMPORT")
nscan=$(echo "$dm" | grep -c "P241-RECOV-TERMINAL-SCAN")
echo "quarantine imports=$nq registration-scan imports=$nscan (expect_quar=$EXPECT_QUAR)"
if [ "$EXPECT_QUAR" -eq 0 ] && [ "$nq" -ne 0 ]; then
    echo "FAIL: a PRE-MKFS GHOST record (foreign fs_gen) was acted on"
    echo "$dm" | grep -E "P241-RECOV-TERMINAL-SCAN|P240-QUAR-IMPORT" | tail -5
    pass=0
elif [ "$EXPECT_QUAR" -eq 0 ]; then
    echo "OK: ghost record ignored by every consumer"
fi

# (c) no shutdown on the target, and none on the rest of the cluster
if echo "$dm" | grep -q "Filesystem has been shut down"; then
    echo "FAIL: target took a filesystem shutdown — the D-513 suicide"
    pass=0
else
    echo "OK: no shutdown on $TARGET"
fi

say "--- restoring slot $SLOT and remounting $TARGET"
node "$PROBE" "$FORGE $DEV restore $SLOT $SAVE"
# Always cycle the mount: a shape that ADMITTED carries the imported quarantine
# in its live m_mxfs_quar map, and leaving it behind would poison every later
# test on this node with EIO on the quarantined AGs.
remount=$(node "$TARGET" "grep -qs ' $MNT mxfs ' /proc/mounts && umount $MNT; mount -t mxfs $DEV $MNT >/tmp/d513remount.log 2>&1; grep -qs ' $MNT mxfs ' /proc/mounts && echo REMOUNTED || echo REMOUNT_FAILED")
echo "$remount"
if echo "$remount" | grep -q REMOUNT_FAILED; then
    echo "FAIL: $TARGET did not come back up after the shape — the rig is left"
    echo "      degraded and every later shape would be contaminated"
    node "$TARGET" "tail -3 /tmp/d513remount.log; dmesg | tail -5"
    pass=0
fi

if [ "$pass" -eq 1 ]; then
    say "=== d513_forged_record_checks PASS (shape=$SHAPE) ==="
    exit 0
fi
say "=== d513_forged_record_checks FAIL (shape=$SHAPE) ==="
exit 1
