#!/bin/bash
# fence_capability_admission.sh — the NEGATIVE criterion for
# D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT and, from 0.73.1, for
# D-PRLESS-DEVICE-ADMITTED-UNFENCED-BOTH-TRANSPORTS-0904.
#
# The positive side is easy and is covered by any normal prep: on the real LUN
# every node logs P303-FENCECAP-OK and mounts.  What that cannot show is that
# the check has TEETH.  This does.
#
# It builds a device with genuinely NO SCSI persistent reservations at all — a
# plain loop device — puts a real MXFS on it, and runs three arms ON EACH DLM
# TRANSPORT (CAW = the default, TCP = force_transport=1):
#
#   ARM 1 (default)                        the mount is REFUSED, and the log
#                                          says which condition failed
#                                          (P303-FENCECAP-*).
#   ARM 2 (fence_capability_override=1)    sess453 (0.60.0, review-#3 D5
#                                          ruling): the override ALONE is
#                                          REFUSED for a clustered RW mount
#                                          (P303-FENCECAP-OVERRIDE-REFUSED-
#                                          CLUSTERED) — a member that can
#                                          neither fence nor be fenced blocks
#                                          the cluster on its own death.
#   ARM 3 (override + single_node_exclusive=1)
#                                          the FENCE-CAPABILITY gate admits,
#                                          and the log says loudly that this
#                                          mount has weaker-than-production
#                                          recovery semantics
#                                          (P303-FENCECAP-OVERRIDE): exclusion
#                                          is asserted by topology.
#
# Arms 2 and 3 matter as much as arm 1.  The sess93 design-consult ruling requires that
# a rig which cannot produce fencing evidence be EXPLICITLY single-node/
# read-only/otherwise-provided-for rather than silently degraded — so the
# operator must have a way to say so, and taking it must be loud and
# attributable.  Arm 3 is also the compatibility check on this change: a non-PR
# device used to mount silently, and now it only mounts when someone says it
# may AND states that nothing else can write it.
#
# The TCP arms exist because until 0.73.1 only the CAW mount branch ran the
# gate: on force_transport=1 the same loop device came up READ-WRITE with no
# P303 line at all (D-PRLESS-...-0904).  Every arm now names its transport in
# the refusal line (transport=TCP / 'TCP mount REFUSED').
#
# the budget rule (derived): one arm = rmmod + insmod + a refused mount + a dmesg
# scan, ~10 s; setup (truncate + mkfs_mxfs on 1 GiB) ~5 s; six arms + setup +
# teardown ~80 s.  Every remote step carries its own bound below; the whole
# harness must finish inside 300 s.
#
# Usage:  fence_capability_admission.sh [node] [caw|tcp|both]   (default test32 both)
#   The node must NOT be part of the live cluster — it is unmounted first.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
NODE="${1:-test32}"
WHICH="${2:-both}"
IMG=/var/tmp/mxfs_nopr.img
MNT=/mnt/nopr
SZ_MB=1024
# sess454: the durability-domain validator (0.54.0, sess447) refuses a
# clustered RW mount with fua_disable=1 unless the operator declares
# target_cache_protected=1 (P-DOMAIN-REFUSED) — BEFORE the fence-capability
# gate this harness exercises.  Load the module with the same domain knobs
# the fleet prep uses (tests/setup/prep_node.sh caw MODARGS) so the arms
# reach the gate under test.
KNOBS="target_cache_protected=1"

say() { echo "[$(date -u +%H:%M:%S)] $*"; }
fail=0

say "=== fence-capability admission test on $NODE (device with NO SCSI PR), transports=$WHICH"

# Leave the cluster and unload, so the loop mount is this node's only MXFS.
timeout 200 "$SSH" "$NODE" "
    timeout 150 umount /mnt/shared 2>/dev/null
    for t in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null && break; sleep 5; done
    mkdir -p $MNT" >/dev/null 2>&1

# Build the no-PR device.  A loop device has no pr_ops at all, so
# PERSISTENT RESERVE IN / REPORT CAPABILITIES cannot even be issued -- which is
# precisely the "this rig cannot fence" condition, obtained honestly rather
# than by faking a return code.
setup=$(timeout 180 "$SSH" "$NODE" "
    mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
    mountpoint -q /src || { echo SRC_MISSING; exit 1; }
    losetup -D 2>/dev/null
    rm -f $IMG
    truncate -s ${SZ_MB}M $IMG || exit 1
    L=\$(losetup -f --show $IMG) || exit 1
    echo LOOP=\$L
    $REPO/tools/mkfs_mxfs -f \$L >/dev/null 2>&1 || echo MKFS_FAIL
    echo PR_OPS=\$(ls /sys/block/\$(basename \$L)/ 2>/dev/null | grep -c pr || echo 0)
" 2>&1)
echo "$setup" | grep -v -E 'Warning:|Unauthorized|authorized|^$'
LOOP=$(echo "$setup" | sed -n 's/^LOOP=//p')
[ -n "$LOOP" ] || { echo "RESULT: SETUP-FAIL — no loop device"; exit 2; }
echo "$setup" | grep -q MKFS_FAIL && { echo "RESULT: SETUP-FAIL — mkfs_mxfs failed"; exit 2; }

# sess505: load the TREE's module, never whatever prep last left under
# /lib/modules on this node — a node outside the live cluster can carry a
# build many versions old, and a verdict against a stale module is vacuous.
KO=/var/tmp/mxfs_fca.ko
timeout 60 "$SSH" "$NODE" SCP "$REPO/mxfs.ko" "$KO" >/dev/null 2>&1 || { echo "RESULT: SETUP-FAIL — could not copy mxfs.ko to $NODE"; exit 2; }
say "module under test: $(timeout 30 "$SSH" "$NODE" "modinfo $KO | grep srcversion" 2>/dev/null | grep srcversion)"

# one_arm <tag> <extra module knobs> — reload the module with the given knobs,
# attempt the mount, and print mount_rc / mounted / the P303 and refusal lines
# logged after the arm's kmsg marker.
one_arm() {
    local tag=$1 knobs=$2
    timeout 180 "$SSH" "$NODE" "
        timeout 60 umount $MNT 2>/dev/null
        rmmod mxfs 2>/dev/null
        insmod $KO $KNOBS $knobs 2>&1 | head -2
        echo 'MXFS-FENCECAP-$tag' > /dev/kmsg
        timeout 60 mount -t mxfs $LOOP $MNT 2>&1; echo mount_rc=\$?
        echo mounted=\$(grep -c ' $MNT ' /proc/mounts)
        dmesg | awk '/MXFS-FENCECAP-$tag/{f=1;next} f' | grep -E 'P303-FENCECAP|P311-CAW-ADMISSION-REFUSED|P-DOMAIN-REFUSED|mount REFUSED|refusing|aborting mount' | tail -8
    " 2>&1 | grep -v -E 'Warning:|Unauthorized|authorized|^$'
}

# run_arms <CAW|TCP> <transport knobs>
run_arms() {
    local tr=$1 tknobs=$2 out mounted

    # ------------------------------------------------------------ ARM 1
    say "--- $tr ARM 1: default (fence_capability_override=0) — mount must be REFUSED"
    out=$(one_arm "${tr}1" "$tknobs")
    echo "$out"
    mounted=$(echo "$out" | sed -n 's/^mounted=//p')
    if [ "${mounted:-1}" = 0 ]; then
        if echo "$out" | grep -q 'P303-FENCECAP'; then
            say "$tr ARM 1 PASS — mount refused AND the reason is named in the log"
        else
            say "$tr ARM 1 FAIL — mount refused but no P303-FENCECAP reason was logged"; fail=1
        fi
    else
        say "$tr ARM 1 FAIL — a device that cannot fence came up READ-WRITE anyway"; fail=1
    fi

    # ------------------------------------------------------------ ARM 2
    say "--- $tr ARM 2: fence_capability_override=1 ALONE — clustered RW mount must be REFUSED (0.60.0)"
    out=$(one_arm "${tr}2" "$tknobs fence_capability_override=1")
    echo "$out"
    mounted=$(echo "$out" | sed -n 's/^mounted=//p')
    if [ "${mounted:-1}" = 0 ]; then
        if echo "$out" | grep -q 'P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED'; then
            say "$tr ARM 2 PASS — the override alone was refused, and the refusal is named"
        else
            say "$tr ARM 2 FAIL — refused but P303-FENCECAP-OVERRIDE-REFUSED-CLUSTERED was not logged"; fail=1
        fi
    else
        say "$tr ARM 2 FAIL — the override ALONE admitted a clustered RW mount on a device that cannot fence"; fail=1
    fi

    # ------------------------------------------------------------ ARM 3
    say "--- $tr ARM 3: override + single_node_exclusive=1 — the FENCE-CAPABILITY gate must admit, loudly"
    # sess454: on this loop device the fence-capability gate is not the last
    # gate.  A loop device has no COMPARE AND WRITE either, so after
    # P303-FENCECAP-OVERRIDE (the gate under test admitting) the mount may be
    # refused by the lock-slot CAS admission (P311-CAW-ADMISSION-REFUSED,
    # D-0359 step 1, which refuses a definitive UNSUPPORTED even under
    # single_node_exclusive=1).  The arm therefore proves the
    # override+exclusive combination passes THIS gate: the
    # P303-FENCECAP-OVERRIDE line must be present, and the mount is then
    # either admitted or refused ONLY by a later NAMED admission gate.
    out=$(one_arm "${tr}3" "$tknobs fence_capability_override=1 single_node_exclusive=1")
    echo "$out"
    mounted=$(echo "$out" | sed -n 's/^mounted=//p')
    if ! echo "$out" | grep -q 'P303-FENCECAP-OVERRIDE '; then
        say "$tr ARM 3 FAIL — override + single_node_exclusive did not pass the fence-capability gate (no P303-FENCECAP-OVERRIDE line)"; fail=1
    elif [ "${mounted:-0}" = 1 ]; then
        say "$tr ARM 3 PASS — admitted under override + topology assertion, and it said so"
    elif echo "$out" | grep -q 'P311-CAW-ADMISSION-REFUSED\|P-DOMAIN-REFUSED\|claim_slot failed .* refusing to derive an unclaimed slot'; then
        # The TCP branch reaches the loop device's missing COMPARE AND WRITE at
        # the disklock slot claim rather than at P311; on a sliced volume that
        # is a named refusal too ('refusing to derive an unclaimed slot').
        say "$tr ARM 3 PASS — fence-capability gate admitted (P303-FENCECAP-OVERRIDE); the mount was then refused only by a later named admission gate, as a loop device may be"
    else
        say "$tr ARM 3 FAIL — fence-capability gate admitted but the mount failed for another reason (rc above)"; fail=1
    fi
}

case "$WHICH" in
    caw)  run_arms CAW "" ;;
    tcp)  run_arms TCP "force_transport=1" ;;
    both) run_arms CAW ""; run_arms TCP "force_transport=1" ;;
    *)    echo "RESULT: SETUP-FAIL — unknown transport selector '$WHICH' (caw|tcp|both)"; exit 2 ;;
esac

# ---------------------------------------------------------------- teardown
timeout 180 "$SSH" "$NODE" "
    timeout 60 umount $MNT 2>/dev/null
    rmmod mxfs 2>/dev/null
    losetup -d $LOOP 2>/dev/null
    rm -f $IMG /var/tmp/mxfs_fca.ko" >/dev/null 2>&1

echo
if [ "$fail" = 0 ]; then
    echo "RESULT: PASS | test=fence_capability_admission | node=$NODE | transports=$WHICH | every arm behaved"
else
    echo "RESULT: FAIL | test=fence_capability_admission | node=$NODE | transports=$WHICH"
fi
exit "$fail"
