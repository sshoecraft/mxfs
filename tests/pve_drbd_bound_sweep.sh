#!/bin/bash
# pve_drbd_bound_sweep.sh — what each value of the DRBD write bound costs a
# lone writer, and what it buys the coordination writes under heavy load.
#
# The bound (drbd_inflight_kb / drbd_inflight_reqs, pal/linux/drbd.c) keeps a
# host's bulk writes in flight on DRBD under a limit so its heartbeat and
# register writes do not queue behind seconds of data.  Its 4096 KiB / 64
# default was set against eight VM installs on the physical pair; measured
# 2026-10-08 on that pair, it also holds one buffered sequential writer to
# 19-20 MB/s against 68-74 MB/s unbounded and 29-37 MB/s for XFS on a scratch
# DRBD resource on the same disks.
#
# For each value in BOUNDS (KiB; the request bound scales with it, 64 per
# 4 MiB): on participant 0 alone, one buffered 1 GiB dd with fsync (the lone
# writer); then tests/pve_pair_write_bound.sh at that bound (both hosts'
# direct and buffered writers at once, every coordination swap timed, every
# block verified).  The module's own values are put back at the end.
#
# Output: one line per bound: lone-writer MB/s, the write-bound verdict and
# its swap latency distribution line(s).
#
# Usage: tests/pve_drbd_bound_sweep.sh
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), BOUNDS (default
#        "4096 8192 16384 32768"), and the write-bound test's own variables.
# Budget: per bound ~70 s lone write + the write-bound test's LOAD_S (300) +
# ~60 s checks; the outer timeout is that times the number of bounds.
#
# Evidence: tests/evidence/pve_drbd_bound_sweep/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
BOUNDS=${BOUNDS:-4096 8192 16384 32768}
EVID="$REPO/tests/evidence/pve_drbd_bound_sweep/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
P=/sys/module/mxfs/parameters
orig=$(on "${H[0]}" "echo \$(cat $P/drbd_inflight_kb) \$(cat $P/drbd_inflight_reqs)" 20)
say "module values before: $orig"
setb() {  # <kb> <reqs>
    local h
    for h in "${H[@]}"; do
        on "$h" "echo $1 > $P/drbd_inflight_kb && echo $2 > $P/drbd_inflight_reqs && echo OK" 20 | grep -q OK \
            || say "$h: could not set the bound to $1 KiB / $2"
    done
}

for kb in $BOUNDS; do
    reqs=$(( kb / 64 )); [ "$reqs" -ge 64 ] || reqs=64
    setb "$kb" "$reqs"
    lone=$(on "${H[0]}" "dd if=/dev/zero of=/mnt/shared/bound-sweep bs=1M count=1024 conv=fsync 2>&1 | tail -1; rm -f /mnt/shared/bound-sweep; sync" 300)
    say "bound=${kb}KiB/${reqs} lone: $lone"
    PVE_PAIR="${H[*]}" BOUND_KB=$kb BOUND_REQS=$reqs timeout 900 "$REPO/tests/pve_pair_write_bound.sh" > "$EVID/write_bound-$kb.log" 2>&1
    rc=$?
    say "bound=${kb}KiB/${reqs} write_bound rc=$rc"
    grep -aE 'RESULT|swap|cas|reg_put|max|p99|MB/s|STALL|AUTH-CLOSED|REFUSED' "$EVID/write_bound-$kb.log" | tail -12 | cut -c1-220 | sed 's/^/    /' | tee -a "$EVID/log"
done

# shellcheck disable=SC2086
setb $orig
say "module values after: $(on "${H[0]}" "echo \$(cat $P/drbd_inflight_kb) \$(cat $P/drbd_inflight_reqs)" 20)"
say "evidence $EVID"
