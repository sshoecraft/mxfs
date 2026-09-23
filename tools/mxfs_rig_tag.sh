#!/bin/bash
# mxfs_rig_tag.sh — which PHYSICAL RIG is this cluster on?
#
# Several measurements are only meaningful against a yardstick captured on the
# same hardware: the native-XFS fio baseline and the raw N-sharer ceiling are
# per-rig files, and scoring one rig's numbers against another's produces a
# confident verdict about the wrong machine.  It has happened: a 1 GbE iSCSI
# LUN's 109 MiB/s was scored against a local SCST/mpath rig's 820 MiB/s
# baseline and recorded as a 62% FAIL with no filesystem change behind it.
#
# The rig used to be inferred from HOW THE DEVICE HAPPENED TO BE SPELLED — a
# by-path name containing "qnap" resolved, /dev/sda did not, and the two are
# the same LUN.  So the identity of the hardware depended on which spelling
# whoever last prepped the cluster typed, and when it did not resolve the
# measurement was declined rather than scored.  This resolves it from the
# hardware itself, and everything that needs the answer asks here so there is
# one rule and not three.
#
# Order, strongest first:
#   1. MXFS_RIG_TAG              — an explicit override always wins.
#   2. .cluster_marker.json .rig — recorded at prep time by run.sh, which is
#                                  the moment the rig identity is actually
#                                  established.  Survives later invocations
#                                  that reuse the cluster without touching the
#                                  device.
#   3. the device spelling       — MXFS_DEV or the marker's dev, for a by-path
#                                  name that names its vendor.
#   4. the LUN's own SCSI vendor — read from a prepped node.  This is the one
#                                  that cannot be defeated by a rename.
#
# Prints the tag and exits 0, or prints nothing and exits 1 when the rig cannot
# be established.  Callers must treat exit 1 as "do not score", never as "use
# whatever yardstick is lying around".
#
# Usage: tools/mxfs_rig_tag.sh [device]
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
MARKER="$REPO/.cluster_marker.json"

mk() {  # mk <key> — one field out of the cluster marker, empty if absent
    [ -s "$MARKER" ] || return 0
    python3 - "$MARKER" "$1" <<'PY' 2>/dev/null
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], "") or "")
except Exception:
    print("")
PY
}

# A tag becomes part of a filename, so keep it to what a filename can hold
# without quoting.  A SCSI vendor string arrives space-padded ("QNAP    "), so
# trim before separating: squeezing spaces away instead of turning them into a
# separator would render "QNAP Lab 1" and "QNAPLab1" as the same rig.  `tr -cd`
# discards the trailing newline along with everything else outside the set, so
# it is re-supplied — a resolver that prints its answer without one runs into
# whatever is echoed next.
sanitise() {
    printf '%s' "$1" \
      | tr 'A-Z' 'a-z' \
      | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
      | tr -s ' _' '-' \
      | tr -cd 'a-z0-9-'
    echo
}

emit() { [ -n "${1:-}" ] && { sanitise "$1"; exit 0; }; return 0; }

# 1. explicit override
emit "${MXFS_RIG_TAG:-}"

# 2. recorded when the cluster was prepped
emit "$(mk rig)"

# 3. a device name that carries the vendor
DEV="${1:-${MXFS_DEV:-}}"
[ -z "$DEV" ] && DEV=$(mk dev)
case "$DEV" in
    *qnap*) echo qnap; exit 0 ;;
esac

# 4. ask the hardware.  Whoever is holding the LUN can read the SCSI vendor
#    string out of sysfs; that is a property of the array, not of the path
#    anyone used to reach it.
#
#    LOCALLY FIRST, and that is not an optimisation.  The suite's detectors run
#    ON THE NODES (their results spool through /run/mxfs-suite), and a node has
#    no ssh credentials for its peers — the lab secrets live on the dev host
#    only.  A resolver that could only reach the hardware over ssh therefore
#    answered "unknown" in the one place the answer was needed, while sitting
#    on the very device it was asking about.  On the dev host the device is not
#    present, so the ssh path below is what runs there.
[ -n "$DEV" ] || exit 1

vendor_of() {  # vendor_of <device> — the SCSI vendor of a device on THIS host
    local d b
    d=$(readlink -f "$1" 2>/dev/null) || return 1
    [ -b "$d" ] || return 1
    b=$(basename "$d")
    # A partition has no `device` link of its own; fall back to the disk it
    # sits on so a device named with a partition suffix still resolves.
    [ -r "/sys/block/$b/device/vendor" ] || b=$(echo "$b" | sed 's/[0-9]*$//')
    cat "/sys/block/$b/device/vendor" 2>/dev/null
}

vendor=$(vendor_of "$DEV")
if [ -z "${vendor:-}" ]; then
    NODE=$(mk node_list | cut -d, -f1)
    [ -n "$NODE" ] && [ -x "$REPO/tools/mxfs_sshpass.sh" ] || exit 1
    vendor=$(timeout 25 "$REPO/tools/mxfs_sshpass.sh" "$NODE" "
        d=\$(readlink -f '$DEV' 2>/dev/null) || exit 1
        b=\$(basename \"\$d\")
        [ -r /sys/block/\$b/device/vendor ] || b=\$(echo \"\$b\" | sed 's/[0-9]*\$//')
        cat /sys/block/\$b/device/vendor 2>/dev/null
      " 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you\|^$' | head -1)
fi
vendor=$(sanitise "${vendor:-}")
[ -n "$vendor" ] || exit 1
echo "$vendor"
