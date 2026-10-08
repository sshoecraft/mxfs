#!/bin/bash
# pve_drbd_window_ab.sh — the DRBD write window against the fixed bound: what a
# lone writer gets, and what the coordination swaps pay, with one host writing
# and with both writing flat out.
#
# Arms (ARMS, each "<max_kib>:<target_ms>"): max_kib at the floor
# (drbd_inflight_kb, 4096) is the fixed bound; above it the window adapts
# (pal/linux/drbd.c, drbd_inflight_max_kb / drbd_inflight_target_ms).  Arms
# alternate LAPS times, so a drift in the pair's state cannot favour one.
#
# Per arm and lap:
#   lone   tests/pve_pair_write_bound.sh FIO=0 (every swap and register write
#          timed on both hosts, nothing else written) while participant 0
#          alone writes LONE_MB buffered with fsync: its rate, and the swaps;
#   flood  tests/pve_pair_write_bound.sh with both hosts' direct and buffered
#          writers at once (FILE_MB / BUF_MB / BUF_LOOPS sized so ~2 GiB in
#          all finishes inside LOAD_S on this pair's ~35 MB/s), every block
#          verified: its verdict and the swaps.
# The module's values are put back at the end.
#
# Usage: tests/pve_drbd_window_ab.sh
# Env:   PVE_PAIR (default "192.168.1.80 192.168.1.81"), ARMS (default
#        "4096:500 32768:500"), LAPS (2), LONE_MB (2048), LOAD_S (240),
#        FILE_MB (128), BUF_MB (256), BUF_LOOPS (2)
# Budget per arm and lap: lone ~LONE_MB / 20 MB/s + 30 s, flood LOAD_S + ~90
# s of checks; the outer timeout is their sum over arms and laps.
#
# Evidence: tests/evidence/pve_drbd_window_ab/<UTC stamp>/
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a H <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
ARMS=${ARMS:-4096:500 32768:500}
LAPS=${LAPS:-2}
LONE_MB=${LONE_MB:-2048}
LOAD_S=${LOAD_S:-240}
FILE_MB=${FILE_MB:-128}
BUF_MB=${BUF_MB:-256}
BUF_LOOPS=${BUF_LOOPS:-2}
EVID="$REPO/tests/evidence/pve_drbd_window_ab/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVID" || exit 2
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$EVID/log"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}
P=/sys/module/mxfs/parameters
orig=$(on "${H[0]}" "echo \$(cat $P/drbd_inflight_max_kb):\$(cat $P/drbd_inflight_target_ms)" 20)
say "module values before: $orig"
setw() {  # <max_kib> <target_ms>
    local h
    for h in "${H[@]}"; do
        on "$h" "echo $1 > $P/drbd_inflight_max_kb && echo $2 > $P/drbd_inflight_target_ms && echo OK" 20 | grep -q OK \
            || say "$h: could not set the window to $1 KiB / $2 ms"
    done
}
swaps() {  # <write_bound log>
    grep -aE 'cas_emulate|RESULT|FAIL' "$1" | cut -c1-200 | sed 's/^/    /' | tee -a "$EVID/log"
}

for lap in $(seq 1 "$LAPS"); do
    for arm in $ARMS; do
        kb=${arm%%:*}; ms=${arm##*:}
        setw "$kb" "$ms"
        tag="lap$lap-$kb-$ms"
        PVE_PAIR="${H[*]}" FIO=0 LOAD_S=$(( LONE_MB / 20 + 40 )) timeout 900 "$REPO/tests/pve_pair_write_bound.sh" > "$EVID/lone-$tag.log" 2>&1 &
        tracer=$!
        sleep 15
        lone=$(on "${H[0]}" "dd if=/dev/zero of=/mnt/shared/window-ab bs=1M count=$LONE_MB conv=fsync 2>&1 | tail -1; rm -f /mnt/shared/window-ab" 900)
        wait "$tracer"
        say "$tag lone: $lone"
        swaps "$EVID/lone-$tag.log"
        PVE_PAIR="${H[*]}" LOAD_S=$LOAD_S FILE_MB=$FILE_MB BUF_MB=$BUF_MB BUF_LOOPS=$BUF_LOOPS timeout 900 \
            "$REPO/tests/pve_pair_write_bound.sh" > "$EVID/flood-$tag.log" 2>&1
        say "$tag flood rc=$?"
        swaps "$EVID/flood-$tag.log"
    done
done

setw "${orig%%:*}" "${orig##*:}"
say "module values after: $(on "${H[0]}" "echo \$(cat $P/drbd_inflight_max_kb):\$(cat $P/drbd_inflight_target_ms)" 20)"
say "evidence $EVID"
