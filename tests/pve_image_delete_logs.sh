#!/bin/bash
# pve_image_delete_logs.sh — both hosts of an MXFS-on-DRBD Proxmox pair delete
# large, fragmented files at the same second, as Proxmox does when VMs on both
# hosts are destroyed together, and neither host's kernel log may read as a
# fault: no warning-level mxfs line, no "Found unrecovered unlinked inode", no
# Call Trace.
#
# The end of the physical pair's 7-install soak (0.90.106, 2026-10-08) printed
# upstream XFS's "Found unrecovered unlinked inode ... Initiating recovery" on
# pve1 four times while both hosts destroyed VMs: a PEER's in-flight unlinked
# inode met while walking an AGI unlinked list, which is not recovery.  On a
# cluster mount that reload is recorded only as the P83-UNL-RELOAD /
# P83-UNL-BUCKET-RELOAD probes, which this test turns on for its run and
# counts, so a run can show the path was taken as well as that it was quiet.
#
#  1. layout: each host, at once, writes IMAGES files of IMAGE_MB in 1 MiB
#     O_DIRECT writes taken round-robin across its files, so each file ends
#     up in many extents interleaved with the other host's (a VM image's
#     shape after an install); graded against LAYOUT_BUDGET
#  2. delete: both hosts remove their files at one wall-clock second, ARM_S
#     ahead, while holding each open for HOLD_S more (a VM's disk is still
#     open when Proxmox removes it), so both hosts' unlinked inodes sit on
#     the AGI unlinked lists of the AGs their extents share; each graded
#     against DELETE_BUDGET plus HOLD_S
#  3. both hosts must see every file gone; each host's kernel log since the
#     run began is counted
#
# Usage: tests/pve_image_delete_logs.sh [label]
# Env:
#   PVE_PAIR       "<addr> <addr>" (default the physical pair)
#   IMAGES         files per host (3)
#   IMAGE_MB       size of each (256)
#   ARM_S          seconds ahead the deletes are armed (10)
#   LAYOUT_BUDGET  seconds for the layout (180: 768 MiB a host at ~10 MB/s
#                  with both hosts writing on this pair, twice over)
#   HOLD_S         seconds each file stays open after its unlink (5)
#   DELETE_BUDGET  seconds for one host's delete and sync after the files
#                  close (10: native XFS frees these in under a second; one
#                  ~20 ms durable lock commit per AG (16) per file, three
#                  files, twice over)
# Exit 0 only when every phase is within budget, every file is gone on both
# hosts and neither kernel log has a warning-level mxfs line, a "Found
# unrecovered unlinked inode" or a Call Trace.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
LABEL=${1:-run}
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#H[@]}" = 2 ] || { echo "pve_image_delete_logs: PVE_PAIR must name two hosts"; exit 2; }
MNT=/mnt/shared
IMAGES=${IMAGES:-3}
IMAGE_MB=${IMAGE_MB:-256}
ARM_S=${ARM_S:-10}
HOLD_S=${HOLD_S:-5}
LAYOUT_BUDGET=${LAYOUT_BUDGET:-180}
DELETE_BUDGET=${DELETE_BUDGET:-10}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
D=$MNT/imgdel/$STAMP-$LABEL
EVID="$REPO/tests/evidence/pve_image_delete_logs/$STAMP-$LABEL"
mkdir -p "$EVID" || exit 2
bad=0

on() {  # <host> <cmd> <timeout>
    timeout "$3" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }

T_START=$(date +%s)
say "label=$LABEL dir=$D images=${IMAGES}x${IMAGE_MB}MiB per host evidence=$EVID"
for h in "${H[@]}"; do
    on "$h" "echo 'module mxfs format \"P83-UNL\" +p' > /proc/dynamic_debug/control && echo probes-on" 20 \
        | grep -q probes-on || { say "FAIL: $h: could not turn the P83-UNL probes on"; exit 1; }
done

# 1. layout, both hosts at once, each with its own output and exit code
for i in 0 1; do
    h=${H[$i]}
    (
        t0=$(date +%s%N)
        out=$(on "$h" "mkdir -p $D/$h && cd $D/$h && for c in \$(seq 0 $((IMAGE_MB - 1))); do for f in \$(seq 1 $IMAGES); do dd if=/dev/zero of=img\$f bs=1M count=1 seek=\$c conv=notrunc oflag=direct status=none || exit 1; done; done && sync && ls -l | grep -c img" "$LAYOUT_BUDGET")
        rc=$?
        echo "layout host=$h rc=$rc wall_ms=$(( ($(date +%s%N) - t0) / 1000000 )) files=$out" > "$EVID/layout-$i"
    ) &
done
wait
for i in 0 1; do
    cat "$EVID/layout-$i" | tee -a "$EVID/log"
    grep -q ' rc=0 ' "$EVID/layout-$i" || bad=1
done
[ "$bad" = 0 ] || { say "FAIL: layout did not finish within ${LAYOUT_BUDGET}s on every host"; }

# 2. delete, armed for one wall-clock second on both hosts
if [ "$bad" = 0 ]; then
    T=$(( $(date +%s) + ARM_S ))
    say "deletes armed for $(date -d @$T +%H:%M:%S)"
    for i in 0 1; do
        h=${H[$i]}
        # each image held open on a sleeper's stdin across its unlink
        on "$h" "cd $D/$h || exit 1; sleep \$(( $T - \$(date +%s) )) 2>/dev/null; for f in img*; do sleep $HOLD_S < \$f & done; t0=\$(date +%s%N); timeout $DELETE_BUDGET rm -f img*; rc=\$?; wait; [ \$rc = 0 ] && { timeout $DELETE_BUDGET sync; rc=\$?; }; echo \"delete host=$h rc=\$rc wall_ms=\$(( (\$(date +%s%N) - t0) / 1000000 ))\"" $((ARM_S + DELETE_BUDGET + HOLD_S + 30)) > "$EVID/delete-$i" 2>&1 &
    done
    wait
    for i in 0 1; do
        cat "$EVID/delete-$i" | tee -a "$EVID/log"
        grep -q ' rc=0 ' "$EVID/delete-$i" || { bad=1; say "FAIL: ${H[$i]}: delete not done within ${DELETE_BUDGET}s"; }
    done
fi

# 3. what each host sees and what each kernel logged since the run began
for h in "${H[@]}"; do
    left=$(on "$h" "ls $D/*/ 2>/dev/null | grep -c '^img'" 30)
    [ "${left:-x}" = 0 ] || { bad=1; say "FAIL: $h still sees ${left:-?} files"; }
    on "$h" "echo 'module mxfs format \"P83-UNL\" -p' > /proc/dynamic_debug/control" 20 >/dev/null
    on "$h" "journalctl -k --since @$T_START --no-pager -o short-precise" 60 > "$EVID/kmsg-$h.txt"
    on "$h" "journalctl -k --since @$T_START --no-pager -p warning -o cat" 60 > "$EVID/kwarn-$h.txt"
    warn=$(grep -aci mxfs "$EVID/kwarn-$h.txt")
    unrec=$(grep -ac 'Found unrecovered unlinked' "$EVID/kmsg-$h.txt")
    trace=$(grep -ac 'Call Trace' "$EVID/kmsg-$h.txt")
    p83=$(grep -ac 'P83-UNL-RELOAD ' "$EVID/kmsg-$h.txt")
    p83b=$(grep -ac 'P83-UNL-BUCKET-RELOAD' "$EVID/kmsg-$h.txt")
    say "$h kernel log: warning-level mxfs=$warn found-unrecovered=$unrec call-trace=$trace P83-UNL-RELOAD=$p83 P83-UNL-BUCKET-RELOAD=$p83b"
    [ "$warn" = 0 ] && [ "$unrec" = 0 ] && [ "$trace" = 0 ] || bad=1
done
on "${H[0]}" "rm -rf $D" 60 >/dev/null
[ "$bad" = 0 ] && say "RESULT: PASS" || say "RESULT: FAIL"
exit "$bad"
