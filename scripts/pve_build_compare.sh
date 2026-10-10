#!/bin/bash
# pve_build_compare.sh — the same concurrent VM builds (scripts/pve_pair_builds.sh)
# on MXFS and on LVM-on-DRBD over the physical pair's spare disks, in
# alternating legs, each starting from the same disk state.
#
# The spare disks (KINGSTON SVP100S, 2011-era SATA SSDs) slow down for minutes
# after heavy writes: a run of the same raw-device writer stalled on cache
# flushes 69% of the time first and 37% four minutes later, whatever ran
# beside it (tests/pve_small_write_stall.sh).  A leg that follows another
# leg's 25 GB of writes is measured on a slower disk, so each leg here first
# discards both disks in full (TRIM) and leaves them idle SETTLE_S seconds,
# and the legs alternate, so a drift over the run shows as two legs of the
# same storage disagreeing.
#
# Each leg: both storages torn down (scripts/pve_mxfs_spare_disk.sh off,
# scripts/pve_lvm_drbd_baseline.sh down), DISK discarded and wiped on both
# hosts, the leg's storage built (pve_mxfs_spare_disk.sh up, or
# pve_lvm_drbd_baseline.sh up), the builds run, and the build VMs this
# harness left stopped destroyed.  The pair's own MXFS mount (/mnt/shared)
# stays stopped throughout; scripts/pve_mxfs_spare_disk.sh down restores it.
#
# Usage: scripts/pve_build_compare.sh <outdir> [leg ...]
#   legs: mxfs | lvm   (default: mxfs lvm mxfs lvm)
# Env:   PVE_PAIR ("192.168.1.80 192.168.1.81")  DISK (/dev/sdb)
#        MODEL (SVP100S: the disk's model must contain it)  SETTLE_S (120)
#        COUNTS ("3 4")  and the builds' DEFINES / MKOS_FLAGS (defaults: the
#        AlmaLinux 9.7 vault ISO, installed from the hosts' iso storage)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
OUT=${1:?outdir}; shift
LEGS=${*:-mxfs lvm mxfs lvm}
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
DISK=${DISK:-/dev/sdb}; MODEL=${MODEL:-SVP100S}; SETTLE_S=${SETTLE_S:-120}
export COUNTS=${COUNTS:-3 4}
export DEFINES=${DEFINES:-iso_url=https://vault.almalinux.org/9.7/isos/x86_64/AlmaLinux-9.7-x86_64-dvd.iso}
export MKOS_FLAGS=${MKOS_FLAGS:---local}
mkdir -p "$OUT" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/compare.log"; }
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; return "${PIPESTATUS[0]}"; }
OWNED="$REPO/tests/evidence/pve_pair_builds/owned_vms"

reap() {        # the build VMs this harness created and left stopped
    local h id name cur
    while read -r h id name; do
        [ -n "$id" ] || continue
        cur=$(on "$h" "qm list 2>/dev/null | awk -v id=$id '\$1 == id {print \$2, \$3}'" 30)
        [ "$cur" = "$name stopped" ] || continue
        say "  $h: destroying leftover build VM $id ($name): $(on "$h" "qm destroy $id --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1; echo rc=\$?" 120)"
    done < "$OWNED"
}
wipe() {        # both storages down, DISK discarded and wiped on both hosts
    MODEL=$MODEL "$REPO/scripts/pve_mxfs_spare_disk.sh" off >> "$OUT/compare.log" 2>&1
    "$REPO/scripts/pve_lvm_drbd_baseline.sh" down >> "$OUT/compare.log" 2>&1
    local h out
    for h in "${PAIR[@]}"; do
        out=$(on "$h" "set -u
            m=\$(cat /sys/block/$(basename "$DISK")/device/model)
            case \"\$m\" in *$MODEL*) ;; *) echo \"REFUSE: $DISK model is \$m\"; exit 1 ;; esac
            rd=\$(lsblk -nrso NAME,TYPE \$(findmnt -n -o SOURCE /) | awk '\$2==\"disk\" {print \$1}')
            [ \"/dev/\$rd\" != $DISK ] || { echo 'REFUSE: $DISK holds the root filesystem'; exit 1; }
            lsblk -nro MOUNTPOINT $DISK | grep -q . && { echo 'REFUSE: something on $DISK is mounted'; exit 1; }
            drbdsetup show 2>/dev/null | grep -q '\"$DISK\"' && { echo 'REFUSE: a DRBD resource still uses $DISK'; exit 1; }
            blkdiscard -f $DISK && wipefs -a -q $DISK && echo \"DISCARD_OK \$(hostname)\"" 300)
        say "  $h: $out"
        [[ "$out" == *DISCARD_OK* ]] || return 1
    done
    say "  idle ${SETTLE_S}s"
    sleep "$SETTLE_S"
}

say "legs: $LEGS on $DISK of ${PAIR[*]}, builds ${COUNTS// /+}"
i=0
for leg in $LEGS; do
    i=$(( i + 1 ))
    say "leg $i: $leg"
    reap
    wipe || { say "leg $i: the disks could not be reset; stopping"; break; }
    case "$leg" in
        mxfs) MODEL=$MODEL timeout 480 "$REPO/scripts/pve_mxfs_spare_disk.sh" up > "$OUT/leg$i-up.log" 2>&1; store=mxfssdb ;;
        lvm)  MODEL=$MODEL timeout 400 "$REPO/scripts/pve_lvm_drbd_baseline.sh" up > "$OUT/leg$i-up.log" 2>&1; store=drbdlvm ;;
        *) say "unknown leg $leg"; continue ;;
    esac
    rc=$?
    say "  $leg up rc=$rc: $(grep -E 'unit=active|Primary/Primary|active' "$OUT/leg$i-up.log" | tail -2 | tr -s ' ' | tr '\n' ' ')"
    [ "$rc" = 0 ] || { say "leg $i: $leg did not come up; stopping"; break; }
    STOP_INSTALLED=1 STORAGE=$store EVID="$OUT/leg$i-$leg" "$REPO/scripts/pve_pair_builds.sh" > "$OUT/leg$i-builds.log" 2>&1
    say "  builds rc=$?"
    grep -E 'installed after|never answered|its VM never started' "$OUT/leg$i-$leg/summary.txt" | sed 's/^/  /' | tee -a "$OUT/compare.log"
done
reap
MODEL=$MODEL "$REPO/scripts/pve_mxfs_spare_disk.sh" off >> "$OUT/compare.log" 2>&1
"$REPO/scripts/pve_lvm_drbd_baseline.sh" down >> "$OUT/compare.log" 2>&1
say "done; the spare disks are free and /mnt/shared is still stopped (scripts/pve_mxfs_spare_disk.sh down restores it)"
