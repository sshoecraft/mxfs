#!/bin/bash
#
# vm_reclaim_disk.sh — give a libvirt VM's qcow2 image back the space its
# guest has freed, and keep it that way.
#
# qcow2 grows whenever the guest writes a block it has not written before and,
# without discard, never shrinks when the guest frees one.  The rig's busiest
# nodes churn constantly (a per-prep kernel-log stream deleted every prep,
# DKMS builds, the rsync tree), so their images reached the full 26 GB virtual
# disk while each guest held ~5 GB.
#
# Per domain:
#   1. discard='unmap' detect_zeroes='unmap' on every qcow2 disk driver in the
#      persistent definition, so a guest's TRIM (and any all-zero write)
#      punches the freed clusters out of the image file
#   2. a cold start on that definition: shut down if running (ACPI, then
#      destroy past SHUTDOWN_S), start, wait for ssh
#   3. fstrim -av in the guest: every free block of every mounted filesystem
#      is discarded, which is the reclaim; Ubuntu's weekly fstrim.timer keeps
#      it that way afterwards
#   4. back to the power state it was found in
# Prints the image's allocated size before and after.
#
# Budgets: an ACPI shutdown of a rig guest takes ~5-10 s -> SHUTDOWN_S=90,
# then destroy; a rig guest whose iSCSI records still log in at boot waits
# 2 min for the absent SCST target (open-iscsi.service 2min 2s; test5
# answered ssh at 172 s) -> BOOT_S=240; fstrim of a 26 GB filesystem ~10 s
# -> TRIM_S=120.
#
# Usage: scripts/vm_reclaim_disk.sh <domain> [domain ...]
#   Addresses come from tools/mxfs_lab.sh (the lab file's addr, else the
#   resolver).  A domain whose guest never answers ssh still gets the new
#   definition and is returned to its power state; it is reported NO-TRIM.
#
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
VIRSH="virsh -c qemu:///system"
SHUTDOWN_S=90
BOOT_S=240
TRIM_S=120

say() { echo "[$(date +%T)] $*"; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect|System is booting up"; return "${PIPESTATUS[0]}"; }
images() { $VIRSH domblklist "$1" --details | awk '$1 == "file" && $2 == "disk" {print $4}'; }
alloc_mb() { local t=0 f k; for f in $(images "$1"); do k=$(du -k "$f" | cut -f1); t=$((t + k)); done; echo $((t / 1024)); }
state() { $VIRSH domstate "$1" 2>/dev/null | head -1; }

stop() {  # ACPI shutdown, destroy past the budget
    local d=$1 t0
    [ "$(state "$d")" = "shut off" ] && return 0
    $VIRSH shutdown "$d" >/dev/null 2>&1
    t0=$(date +%s)
    while [ "$(state "$d")" != "shut off" ]; do
        if [ $(( $(date +%s) - t0 )) -ge $SHUTDOWN_S ]; then
            say "$d: no ACPI shutdown within ${SHUTDOWN_S} s, destroying"
            $VIRSH destroy "$d" >/dev/null 2>&1
            break
        fi
        sleep 2
    done
}

add_discard() {  # persistent definition: discard + zero detection on qcow2 disks
    local d=$1 x
    x=$(mktemp --suffix=.xml)
    $VIRSH dumpxml --inactive "$d" | python3 -c '
import sys, xml.etree.ElementTree as ET
t = ET.parse(sys.stdin)
n = 0
for disk in t.getroot().iter("disk"):
    drv = disk.find("driver")
    if disk.get("device") == "disk" and drv is not None and drv.get("type") == "qcow2":
        drv.set("discard", "unmap"); drv.set("detect_zeroes", "unmap"); n += 1
t.write(sys.stdout, encoding="unicode")
sys.stderr.write("qcow2 disks updated: %d\n" % n)
' > "$x" && $VIRSH define "$x" >/dev/null
    local rc=$?
    rm -f "$x"
    return $rc
}

for d in "$@"; do
    was=$(state "$d")
    [ -n "$was" ] || { say "$d: no such domain"; continue; }
    before=$(alloc_mb "$d")
    if $VIRSH dumpxml --inactive "$d" | grep -q "discard='unmap'"; then
        say "$d: discard already in the definition"
    else
        add_discard "$d" || { say "$d: FAILED to redefine"; continue; }
        # a running guest keeps its old disk settings until a cold start
        [ "$was" = running ] && stop "$d"
    fi
    [ "$(state "$d")" = running ] || $VIRSH start "$d" >/dev/null || { say "$d: FAILED to start"; continue; }
    a=$(lab_addr "$d"); t0=$(date +%s); up=0
    while [ $(( $(date +%s) - t0 )) -lt $BOOT_S ]; do
        # ssh answering is enough: fstrim needs the filesystems mounted, not
        # boot finished, and some rig guests hold /run/nologin for minutes
        on "$a" 10 "echo up" | grep -q up && { up=1; break; }
        sleep 3
    done
    if [ $up = 1 ]; then
        trimmed=$(on "$a" $TRIM_S "fstrim -av" | tr '\n' ' ')
        tag=TRIMMED
    else
        trimmed="guest $a did not answer ssh within ${BOOT_S} s"
        tag=NO-TRIM
    fi
    [ "$was" = running ] || stop "$d"
    after=$(alloc_mb "$d")
    say "$d: $tag ${before} MB -> ${after} MB (state $was -> $(state "$d")) | $trimmed"
done
