#!/bin/bash
# pve_pair_guests.sh — take the owner's guests out of the way of a destructive
# test on the physical Proxmox pair, and put them back exactly as they were.
#
#   park     every VM on either host is shut down cleanly (qm shutdown, then
#            waits), and every disk of theirs on the shared MXFS storage is
#            moved to that host's own LOCAL storage (qm disk move --delete), so
#            /mnt/shared can be reformatted or both hosts reset without losing
#            a guest or its disk.  What was moved and which VMs were running is
#            written to STATE, which a second park refuses to overwrite.
#   unpark   every disk park moved goes back to the shared storage (raw), and
#            every VM that was running is started again.  STATE is removed only
#            when all of it went back.
#   status   what STATE holds, and each VM's state and disks now.
#
# Usage: scripts/pve_pair_guests.sh park|unpark|status
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), SHARED (default
#        shared), LOCAL (default local: a directory storage, so the copy is a
#        sparse file holding only the guest's data; local-lvm is the thin pool
#        that also holds DRBD's backing volume, and a copy that wrote a disk's
#        full size into it could fill the pool under DRBD), STATE (default
#        tests/evidence/pve_pair_guests/state), SHUTDOWN_S (a guest's clean
#        shutdown bound, default 180), MOVE_S (one disk's move, default 1200:
#        16 GiB through DRBD at the ~35-60 MB/s this pair writes, twice that)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
SHARED=${SHARED:-shared}
LOCAL=${LOCAL:-local}
STATE=${STATE:-$REPO/tests/evidence/pve_pair_guests/state}
SHUTDOWN_S=${SHUTDOWN_S:-180}
MOVE_S=${MOVE_S:-1200}
mkdir -p "$(dirname "$STATE")" || exit 1
LOG="$(dirname "$STATE")/log"
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
# One line per VM on <host>: <vmid> <status> <disk>=<volume> ...
LIST="for id in \$(qm list 2>/dev/null | awk 'NR > 1 {print \$1}'); do
    echo \"\$id \$(qm status \$id | awk '{print \$2}') \$(qm config \$id | awk -F': ' '/^(virtio|scsi|sata|ide|efidisk|tpmstate)[0-9]+: / && \$2 !~ /media=cdrom/ {split(\$2, v, \",\"); printf \"%s=%s \", \$1, v[1]}')\"
done"

case "${1:-}" in
park)
    [ -e "$STATE" ] && { say "REFUSED: $STATE exists — an earlier park was never undone (unpark first)"; exit 1; }
    : > "$STATE.new"; : > "$STATE.new.vms"
    for h in "${PAIR[@]}"; do
        while read -r id st disks; do
            [ -n "$id" ] || continue
            echo "$h $id $st" >> "$STATE.new.vms"
            for d in $disks; do
                case "$d" in *"=$SHARED:"*) echo "$h $id ${d%%=*} ${d#*=}" >> "$STATE.new" ;; esac
            done
        done < <(on "$h" "$LIST" 60)
    done
    say "VMs: $(tr '\n' ';' < "$STATE.new.vms" 2>/dev/null)"
    say "disks on $SHARED: $(tr '\n' ';' < "$STATE.new")"
    # shut every running VM down cleanly, both hosts at once
    while read -r h id st; do
        [ "$st" = running ] || continue
        say "$h: shutting down VM $id"
        on "$h" "qm shutdown $id --timeout $SHUTDOWN_S && echo DOWN" $(( SHUTDOWN_S + 30 )) | grep -q DOWN \
            || { say "FAIL: VM $id on $h did not shut down within ${SHUTDOWN_S}s"; exit 1; }
    done < "$STATE.new.vms"
    while read -r h id disk vol; do
        say "$h: moving VM $id $disk ($vol) to $LOCAL"
        on "$h" "qm disk move $id $disk $LOCAL --delete 1 > /dev/null 2>&1 && qm config $id | grep -E '^$disk: ' && echo MOVED" "$MOVE_S" | tee -a "$LOG" | grep -q MOVED \
            || { say "FAIL: could not move VM $id $disk off $SHARED"; exit 1; }
    done < "$STATE.new"
    { echo "# moved: <host> <vmid> <disk> <old volume>"; cat "$STATE.new"; echo "# vms: <host> <vmid> <status before park>"; sed 's/^/vm /' "$STATE.new.vms"; } > "$STATE"
    rm -f "$STATE.new" "$STATE.new.vms"
    say "parked: nothing of a guest is left on $SHARED"
    ;;
unpark)
    [ -e "$STATE" ] || { say "nothing parked ($STATE absent)"; exit 0; }
    fail=0
    while read -r h id disk vol; do
        case "$h" in "#"*|vm) continue ;; esac
        say "$h: moving VM $id $disk back to $SHARED"
        on "$h" "qm disk move $id $disk $SHARED --format raw --delete 1 > /dev/null 2>&1 && qm config $id | grep -E '^$disk: $SHARED:' && echo MOVED" "$MOVE_S" | tee -a "$LOG" | grep -q MOVED \
            || { say "FAIL: could not move VM $id $disk back to $SHARED"; fail=1; }
    done < "$STATE"
    while read -r tag h id st; do
        [ "$tag" = vm ] && [ "$st" = running ] || continue
        say "$h: starting VM $id"
        on "$h" "qm start $id && echo STARTED" 120 | grep -q STARTED || { say "FAIL: VM $id on $h did not start"; fail=1; }
    done < "$STATE"
    [ "$fail" = 0 ] || { say "unpark incomplete; $STATE kept"; exit 1; }
    mv "$STATE" "$STATE.done.$(date -u +%Y%m%dT%H%M%SZ)"
    say "unparked"
    ;;
status)
    [ -e "$STATE" ] && { say "parked:"; sed 's/^/  /' "$STATE"; } || say "nothing parked"
    for h in "${PAIR[@]}"; do on "$h" "$LIST" 60 | sed "s|^|  $h: |"; done
    ;;
*)
    echo "usage: $0 park|unpark|status"; exit 2 ;;
esac
