#!/bin/bash
# tests/dirent_durability_loop.sh <label> [laps]
#
# Repeats the dirent_durability suite test on 2/tcp until it fails, a node
# loses its mount, or a revocation-reference probe fires, then collects the
# evidence.  Built to reproduce D-TCP-INCARN-REVOKE-WORKER-IRELE-HITS-IPUT-BUG-
# NODE-PANIC (a kernel BUG in iput from mxfs_incarn_revoke_work_fn, seen once
# at round ~20 of a dirent_durability run) and, after a fix, to show it gone.
#
# Two sources, because neither sees everything.  A panic is read from the
# netconsole capture, the only record that survives the node's reboot — but
# netconsole carries almost nothing else from these nodes (measured s165a:
# 22 lines in a 15-minute loop, no mxfs lines).  The probes
# (P-REVOKE-EVICT-EARLY, P-REVOKE-REF-LOST) and the poison count are read from
# each node's own kernel log after every lap.
#
# POISON COUNT FIRST.  The revocation worker only runs on a poisoned shell;
# dirent_durability alone produced ZERO poisonings in 10 laps (s165a), so a
# clean lap with poison_n=0 proves nothing about the race.  Set POISON_NTH to
# arm the module's synthetic poison (dbg_poison_nth) on both nodes.
#
# derived time budgets: prep 400 s (tests/lu_reset_bystander_eh.sh's bound for
# the same 2/tcp prep); each lap is run.sh, which enforces dirent_durability's
# own 240 s budget from tests/suite/manifest (measured PASS 61-62 s).
# Exit 0 all laps clean, 1 a lap failed or a probe fired, 2 ABORT.
set -u
cd /src/mxfs || exit 2
LABEL=${1:?label}
LAPS=${2:-10}
NC=tests/evidence/netconsole.log
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ddloop_$LABEL
mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh
nc_mark=$(wc -l < "$NC" 2>/dev/null || echo 0)
echo "=== ddloop $LABEL START $(date -u +%FT%TZ) VERSION=$(cat VERSION) sv=$(modinfo -F srcversion mxfs.ko) laps=$LAPS out=$OUT netconsole_from_line=$nc_mark ==="

timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }

for n in test1 test2; do
    timeout 20 "$SSH" "$n" "echo ${POISON_NTH:-0} > /sys/module/mxfs/parameters/dbg_poison_nth" >/dev/null 2>&1
done
echo "dbg_poison_nth=${POISON_NTH:-0} on both nodes"

fails=0
for l in $(seq 1 "$LAPS"); do
    T0=$(date +%s)
    ./run.sh 2 tcp dirent_durability > "$OUT/lap$l.log" 2>&1
    v=$(grep -a '^  \(PASS\|FAIL\)  dirent_durability' "$OUT/lap$l.log" | tail -1 | cut -c1-200)
    panics=$(tail -n +"$((nc_mark + 1))" "$NC" | grep -ac 'invalid opcode\|Kernel panic')
    mounted=0; probes=0; poison=0; unins=0
    for n in test1 test2; do
        o=$(timeout 40 "$SSH" "$n" "grep -c ' /mnt/shared mxfs ' /proc/mounts; dmesg | grep -ac 'P-REVOKE-EVICT-EARLY\|P-REVOKE-REF-LOST\|P-REVOKE-DIRECT-FREE'; dmesg | grep -ac P566-POISON-N; dmesg | grep -ac P-POISON-UNINSERTED" 2>/dev/null | tail -4 | tr '\n' ' ')
        set -- $o
        [ "${1:-0}" = 1 ] && mounted=$((mounted + 1))
        probes=$((probes + ${2:-0})); poison=$((poison + ${3:-0}))
        unins=$((unins + ${4:-0}))
    done
    echo "LAP $l wall=$(( $(date +%s) - T0 ))s mounted=$mounted/2 poison_n_total=$poison uninserted_total=$unins probes=$probes panics=$panics $v"
    if ! echo "$v" | grep -q PASS || [ "$probes" -gt 0 ] || [ "$panics" -gt 0 ] || [ "$mounted" -lt 2 ]; then
        fails=1
        break
    fi
done

tail -n +"$((nc_mark + 1))" "$NC" > "$OUT/netconsole_window.txt"
grep -an 'P-REVOKE-EVICT-EARLY\|P-REVOKE-REF-LOST\|P-REVOKE-DIRECT-FREE\|invalid opcode\|Kernel panic\|RIP:' \
    "$OUT/netconsole_window.txt" | head -40 > "$OUT/probe_lines.txt"
echo "probe lines: $(wc -l < "$OUT/probe_lines.txt") (first 20 below)"
head -20 "$OUT/probe_lines.txt" | cut -c1-220
for n in test1 test2; do
    timeout 20 "$SSH" "$n" "echo 0 > /sys/module/mxfs/parameters/dbg_poison_nth" >/dev/null 2>&1
    timeout 40 "$SSH" "$n" "dmesg" 2>/dev/null | grep -a -A30 'P-REVOKE-EVICT-EARLY\|P-REVOKE-REF-LOST\|P-REVOKE-DIRECT-FREE\|P-POISON-UNINSERTED' > "$OUT/probe_$n.txt"
done
if [ "$fails" = 0 ] && [ "${poison:-0}" = 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL laps=$LAPS poison_n=0 — no shell was poisoned, the revocation never ran; this proves nothing evidence=$OUT"
    exit 1
fi
[ "$fails" = 0 ] && echo "RESULT: PASS label=$LABEL laps=$LAPS evidence=$OUT" \
                 || echo "RESULT: FAIL label=$LABEL evidence=$OUT"
[ "$fails" = 0 ]
