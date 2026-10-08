#!/bin/bash
# rig_unmount_cover_race.sh — can an unmount free the DLM context under a
# runtime SB cover that is still running?
#
# The log worker's runtime cover (mxfs_sb_runtime_cover) checks the mount once,
# then takes the cluster summary lock through the DLM context.  put_super
# waits out a cover in flight only through m_mxfs_sb_summary_mutex, inside
# mxfs_sb_summary_final_sync, and that function returns before taking the
# mutex when the mount is shut down or its log unwritable.  The DLM context is
# freed before xfs_unmountfs cancels the log worker.  On the DRBD rig a node
# oopsed in mxfs_tauth_page_write under xfs_log_worker during exactly such an
# unmount (D-UNMOUNT-FREES-DLM-CONTEXT-UNDER-AN-IN-FLIGHT-RUNTIME-SB-COVER-OOPS).
#
# Steps, on NODE of a mounted rig cluster:
#   1. the log worker every second (fs.mxfs.xfssyncd_centisecs=100), a file
#      written and synced so the log will need covering;
#   2. dbg_sb_cover_park_ms=PARK_MS: the next runtime cover parks inside its
#      summary lock, holding the DLM context it read; wait for P-SB-COVER-PARK;
#   3. shut the filesystem down (xfs_io -x -c shutdown) and unmount it, while
#      the cover is parked.
# PASS: the unmount returns, the node answers afterwards, and neither its
# kernel log nor the host's netconsole capture holds an Oops or BUG since the
# mark.  FAIL otherwise.
#
# Usage: tests/rig_unmount_cover_race.sh [label]
# Env:   NODE (test1), PARK_MS (20000), MNT (/mnt/shared)
# Budget: arm ~5 s + the park's wait (the worker runs each second once the log
# needs covering: <= 40 s) + the unmount (PARK_MS + 30 s) + reads.
# Evidence: tests/evidence/rig_unmount_cover_race/<UTC stamp>[-label]/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
NODE=${NODE:-test1}
PARK_MS=${PARK_MS:-20000}
MNT=${MNT:-/mnt/shared}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID="$REPO/tests/evidence/rig_unmount_cover_race/$STAMP${1:+-$1}"
mkdir -p "$EVID" || exit 2
MARK="mxfs-test: rig_unmount_cover_race $STAMP start"
NETCON="$REPO/tests/evidence/netconsole.log"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <cmd> [timeout]
    timeout "${2:-30}" "$SSHP" "$NODE" "$1" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

net0=$(stat -c %s "$NETCON" 2>/dev/null || echo 0)
say "$NODE: $(on "echo build=\$(cat /sys/module/mxfs/srcversion) mounted=\$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\"' /proc/mounts | wc -l)" 20 | tr '\n' ' ')"
on "echo '<5>$MARK' > /dev/kmsg; echo 100 > /proc/sys/fs/mxfs/xfssyncd_centisecs; dd if=/dev/zero of=$MNT/coverrace.$STAMP bs=64k count=16 conv=fsync status=none; sync; echo $PARK_MS > /sys/module/mxfs/parameters/dbg_sb_cover_park_ms; echo armed" 30 | grep -q armed \
    || { say "could not arm $NODE"; exit 2; }
parked=""
for i in $(seq 1 40); do
    # only this run's park: a node not rebooted keeps earlier runs' lines
    parked=$(on "dmesg | awk -v m='$MARK' 'index(\$0, m) {p=1} p' | grep -a 'P-SB-COVER-PARK slot' | tail -1" 10)
    [ -n "$parked" ] && break
    sleep 1
done
[ -n "$parked" ] || { say "no runtime cover parked within 40 s; unexercised"; on "echo 0 > /sys/module/mxfs/parameters/dbg_sb_cover_park_ms" 10; echo "RESULT FAIL (unexercised)" | tee -a "$EVID/log"; exit 1; }
say "parked: ${parked#*mxfs: }"
say "shutdown: $(on "xfs_io -x -c shutdown $MNT 2>&1; echo rc=\$?" 20 | tr '\n' ' ')"
t0=$(date +%s)
um=$(on "timeout $(( PARK_MS / 1000 + 30 )) umount $MNT 2>&1; echo rc=\$?" $(( PARK_MS / 1000 + 45 )))
say "umount after $(( $(date +%s) - t0 )) s: $(tr '\n' ' ' <<<"$um")"
fail=0
grep -q 'rc=0' <<<"$um" || fail=1
alive=""
for i in $(seq 1 10); do
    alive=$(on "echo alive" 8) && [ "$alive" = alive ] && break
    alive=""
    sleep 3
done
if [ "$alive" = alive ]; then
    on "dmesg | awk -v m='$MARK' 'index(\$0, m) {p=1} p' | grep -aE 'mxfs|XFS|Oops|BUG|panic|RIP' | cut -c1-220" 20 > "$EVID/klog"
    grep -aE 'P-SB-COVER-PARK|Oops|BUG:|panic' "$EVID/klog" | tail -6 | sed 's/^/  klog: /' | tee -a "$EVID/log"
    grep -qaE 'Oops|BUG:|panic' "$EVID/klog" && fail=1
else
    say "$NODE does not answer after the unmount"
    fail=1
fi
tail -c +"$(( net0 + 1 ))" "$NETCON" 2>/dev/null | tr -d '\r' > "$EVID/netconsole"
if grep -qaE 'Oops|BUG:|Kernel panic' "$EVID/netconsole"; then
    grep -aE 'Oops|BUG:|RIP:|Kernel panic' "$EVID/netconsole" | head -6 | sed 's/^/  netconsole: /' | tee -a "$EVID/log"
    fail=1
fi
say "evidence $EVID"
[ "$fail" = 0 ] && { say "RESULT PASS"; exit 0; }
say "RESULT FAIL"
exit 1
