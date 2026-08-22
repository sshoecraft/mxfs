#!/bin/bash
# clyde_crash_latch.sh — after a host crash, stop the rig from silently
# restarting into the same crash, and keep the crash record as evidence.
#
# WHY
# ---
# `kernel.panic_on_oops=1` + `kernel.panic=30` turn an oops into a clean panic
# and an automatic reboot, which is what a remote operator needs: on
# 2026-08-21 the host oopsed and then sat unkillable until someone could reach
# it.  But an automatic reboot without a latch is a reboot LOOP waiting to
# happen — the harness comes back, drives the same workload, hits the same
# bug, panics again, and the only evidence is whatever survived the last pass.
#
# This runs once per boot, after systemd-pstore has drained /sys/fs/pstore
# into /var/lib/systemd/pstore/<id>/.  Any record it has not seen before means
# "this host crashed": it copies the record into .evidence/ and halts the rig.
#
# Clearing the halt is deliberate, the same as for the kmsg guard:
#   tools/clyde_kmsg_guard.sh clear
#
# Usage: tools/clyde_crash_latch.sh check     (systemd calls this at boot)
set -u

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
HALT="${MXFS_RIG_HALT:-$REPO/.rig_halt}"
HALT_LOCAL=/var/lib/mxfs/rig_halt
EVID="${MXFS_EVIDENCE_DIR:-$REPO/.evidence}"
SEEN="${MXFS_CRASH_SEEN:-$REPO/.crash_seen}"
PSTORE_ARCHIVE=/var/lib/systemd/pstore
PSTORE_LIVE=/sys/fs/pstore

now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# The halt must land even if /src (NFS) is unavailable at boot, so write both a
# repo-side flag (survives a host reset, which is where the harness looks) and
# a host-local one.  clyde_preflight.sh checks both.
write_halt() {
    local body="$1"
    printf '%s' "$body" > "$HALT" 2>/dev/null
    mkdir -p "$(dirname "$HALT_LOCAL")" 2>/dev/null
    printf '%s' "$body" > "$HALT_LOCAL" 2>/dev/null
    logger -t mxfs-crash-latch "RIG HALTED: host crash record found on boot" 2>/dev/null
}

check() {
    local found=() id dir dest body

    # Records systemd-pstore has archived, plus anything still sitting in
    # /sys/fs/pstore (systemd-pstore disabled, or a backend it did not drain).
    for dir in "$PSTORE_ARCHIVE"/*; do
        [ -d "$dir" ] || continue
        id=$(basename "$dir")
        grep -qxF "$id" "$SEEN" 2>/dev/null && continue
        found+=("$dir")
    done
    if [ -d "$PSTORE_LIVE" ] && [ -n "$(ls -A "$PSTORE_LIVE" 2>/dev/null)" ]; then
        found+=("$PSTORE_LIVE")
    fi

    if [ "${#found[@]}" -eq 0 ]; then
        echo "clyde_crash_latch: no new crash records"
        return 0
    fi

    mkdir -p "$EVID" 2>/dev/null
    dest="$EVID/crash_$(date -u '+%Y%m%d_%H%M%S')"
    mkdir -p "$dest" 2>/dev/null
    for dir in "${found[@]}"; do
        cp -a "$dir" "$dest/" 2>/dev/null
        id=$(basename "$dir")
        [ "$dir" = "$PSTORE_LIVE" ] || echo "$id" >> "$SEEN" 2>/dev/null
    done

    body="RIG HALTED $(now)
reason:   HOST CRASH (pstore record present at boot)
trigger:  ${found[*]}
evidence: $dest

This host panicked or oopsed.  kernel.panic_on_oops=1 stopped it and it
rebooted; the crash record is preserved above.  Read it before running
anything: a host that crashed once under this workload will crash again.
RULE 2: only the user reboots clyde.
Clear deliberately with: tools/clyde_kmsg_guard.sh clear
"
    write_halt "$body"
    echo "clyde_crash_latch: HALTED — crash record(s) archived to $dest"
    return 1
}

case "${1:-check}" in
check) check ;;
*) echo "usage: $0 check" >&2; exit 2 ;;
esac
