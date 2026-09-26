#!/bin/bash
# MXFS filesystem prep — run ON a node, ONCE per cluster (the shared LUN is
# shared, so one mkfs serves every node).
#
# Config-layer script (not a test): puts a fresh MXFS on the shared device.
# Transport-agnostic — mkfs just formats the LUN; TCP-vs-CAW is decided later
# when the module is loaded (see prep_node.sh).
#
# Usage (on the node):  tests/setup/prep_fs.sh
# Env (defaults):
#   MXFS_REPO   /src/mxfs            MXFS_DEV   /dev/sda
#   NFS_SERVER  192.168.120.1:/src     NFS_MOUNT  /src       MXFS_MOUNT /mnt/shared
#
# Prints FS_PREP_OK on success, FS_PREP_FAIL: <reason> + exit 1 on failure.

set -u

MXFS_REPO="${MXFS_REPO:-/src/mxfs}"
MXFS_DEV="${MXFS_DEV:-/dev/sda}"
MXFS_MOUNT="${MXFS_MOUNT:-/mnt/shared}"
NFS_SERVER="${NFS_SERVER:-192.168.120.1:/src}"
NFS_MOUNT="${NFS_MOUNT:-/src}"
MKFS="$MXFS_REPO/tools/mkfs_mxfs"
CHK="$MXFS_REPO/tools/chk_mxfs"

fail() { echo "FS_PREP_FAIL: $*" >&2; exit 1; }

# 0. NEVER mkfs a device another layer has claimed (sess44).  On the current
# caw rig the legacy tcp/cawp default /dev/sda enumerates as a PATH MEMBER of
# the caw multipath map — mkfs'ing it writes into a live path of the shared
# caw LUN; only multipathd's exclusive claim turned that into a lucky EBUSY.
# A claimed device means the condition's rig is NOT wired on this fleet:
# refuse with a diagnosis instead of depending on that luck.
DEV_BASE=$(basename "$(readlink -f "$MXFS_DEV" 2>/dev/null)" 2>/dev/null)
if [ -n "$DEV_BASE" ] && [ -d "/sys/block/$DEV_BASE/holders" ] &&
   [ -n "$(ls -A "/sys/block/$DEV_BASE/holders" 2>/dev/null)" ]; then
    fail "$MXFS_DEV ($DEV_BASE) is claimed by: $(ls "/sys/block/$DEV_BASE/holders" | tr '\n' ' ')— it is a member of a device-mapper map, not a free LUN. This deployment condition's rig is not wired on this fleet."
fi

# 1. NFS /src must be present to reach the mkfs tool (idempotent).
if ! mountpoint -q "$NFS_MOUNT"; then
    mkdir -p "$NFS_MOUNT"
    mount -t nfs "$NFS_SERVER" "$NFS_MOUNT" \
        -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp,rsize=1048576,wsize=1048576 \
        || fail "NFS mount $NFS_SERVER -> $NFS_MOUNT failed"
fi
[ -x "$MKFS" ] || fail "mkfs tool not found/executable at $MKFS"

# 2. Device must be present as a block device.
[ -b "$MXFS_DEV" ] || fail "$MXFS_DEV is not a block device"

# 3. Safety: the device must not be in use on THIS node when we mkfs it.
#    (Cluster-wide 'no node has it mounted' is the harness's job; this guards
#    the local node only.)
if mountpoint -q "$MXFS_MOUNT"; then
    umount "$MXFS_MOUNT" 2>/dev/null || fail "$MXFS_MOUNT is mounted and won't unmount — refusing to mkfs a live FS"
fi
if mount | grep -q " on .* type mxfs .*$MXFS_DEV"; then
    fail "$MXFS_DEV appears mounted somewhere on this node — refusing to mkfs"
fi

# 3a. NEVER mkfs under a live heartbeat writer (measured s62e: a node from
#     the previous lap was still mounted and heartbeating while mkfs zeroed
#     and re-read the disklock region; the readback found the 'K' of its MXLK
#     slot magic at 67118080 and mkfs blamed the storage, the prep FAILed, and
#     the next lap started on the previous incarnations' records).  The
#     cluster-wide teardown is the harness's job, but this is the last point
#     at which a writer can still be caught: dump the heartbeat table twice,
#     one heartbeat interval (2 s) plus slack apart, and refuse if any
#     record's stamp advanced.  A dump that cannot be read is a refusal too —
#     an unread table may hold anything.
HBDUMP="$MXFS_REPO/tools/disklock_hb_dump.py"
if [ -f "$HBDUMP" ]; then
    hb1=$(python3 "$HBDUMP" "$MXFS_DEV" 2>&1) || fail "heartbeat table unreadable before mkfs ($MXFS_DEV): $(echo "$hb1" | tail -1)"
    sleep 3
    hb2=$(python3 "$HBDUMP" "$MXFS_DEV" 2>&1) || fail "heartbeat table unreadable before mkfs ($MXFS_DEV): $(echo "$hb2" | tail -1)"
    writers=$(awk '
        /^slot/ { slot=$2; ts=""; node="";
                  for (i=1;i<=NF;i++) { if ($i ~ /^ts_ms=/) ts=substr($i,7); if ($i ~ /^node=/) node=substr($i,6) }
                  if (FNR==NR) { first[slot]=ts } else if ((slot in first) && first[slot] != "" && ts != "" && ts+0 > first[slot]+0) printf "slot %s node %s ts_ms %s->%s; ", slot, node, first[slot], ts }
    ' <(echo "$hb1") <(echo "$hb2"))
    if [ -n "$writers" ]; then
        fail "a node is still heartbeating into $MXFS_DEV — refusing to mkfs under a live writer: $writers(unmount it or power it off, then retry)"
    fi
    echo "heartbeat table: no live writer over 3 s"
fi

# 3b. Clear stale SCSI persistent reservations.  A hard node reboot leaves the
#     LUN reserved (WE-RO) by a dead I_T nexus; this node's fresh session is
#     unregistered, so every write gets RESERVATION CONFLICT (EBADE "Invalid
#     exchange") and mkfs fails at its first pwrite.  Register a scratch key
#     (REGISTER AND IGNORE) and CLEAR — releases all keys + the reservation.
if command -v sg_persist >/dev/null 2>&1; then
    sg_persist --out --register-ignore --param-sark=0x5eed "$MXFS_DEV" >/dev/null 2>&1
    sg_persist --out --clear --param-rk=0x5eed "$MXFS_DEV" >/dev/null 2>&1
fi

# 4. mkfs (-f: non-interactive, destroys existing FS — intended for a fresh LUN).
#    -n: per-node log slices = max cluster members (D-LOG-SLICE-SHARED-
#    MULTIWRITER: a slot's slice is the identically numbered slice, so the
#    32-node rig needs 32 slices; mkfs errors — not clamps — if the device
#    cannot host them).
MXFS_LOG_SLICES="${MXFS_LOG_SLICES:-32}"
# sess389: MXFS_MKFS_OPTS passthrough (e.g. "-d 50G" to reproduce a smaller
# device's agcount on the 128 GiB LUN for the agcount<nodes correctness arm).
MXFS_MKFS_OPTS="${MXFS_MKFS_OPTS:-}"
echo "mkfs: $MKFS -f -n $MXFS_LOG_SLICES $MXFS_MKFS_OPTS $MXFS_DEV"
# shellcheck disable=SC2086
"$MKFS" -f -n "$MXFS_LOG_SLICES" $MXFS_MKFS_OPTS "$MXFS_DEV" || fail "mkfs_mxfs -f -n $MXFS_LOG_SLICES $MXFS_MKFS_OPTS $MXFS_DEV returned $?"

# 5. Validate with chk_mxfs (geometry / clean) if available — non-fatal warn.
if [ -x "$CHK" ]; then
    if "$CHK" -v "$MXFS_DEV" >/tmp/prep_fs_chk.out 2>&1; then
        echo "chk_mxfs: clean ($(grep -iE 'agcount|agblocks|isize' /tmp/prep_fs_chk.out | tr '\n' ' '))"
    else
        echo "WARN: chk_mxfs reported issues on fresh FS:"; sed 's/^/  /' /tmp/prep_fs_chk.out
    fi
fi

echo "FS_PREP_OK device=$MXFS_DEV"
