#!/bin/bash
# incident474_load_kill.sh — multi-victim kill UNDER REAL WRITE LOAD, bypassing
# run.sh's MQTT barrier (which hangs all nodes if a victim dies before every
# node reaches the barrier, producing a vacuous no-load kill).
#
# Drives the rsync_paired write pattern standalone on all N nodes via ssh:
# each node loops "build src tree -> rsync into its shared subdir -> remove
# dest" for DURATION seconds.  Once writes are CONFIRMED appearing in the
# shared fs, the named victims are virsh-destroyed VICTIM_GAP seconds apart.
# Survivor loops keep running through the fence/recovery window (their cycles
# may stall on victim-held grants — that is the point) and end on their own.
#
# Usage: tests/incident474_load_kill.sh <N> <victim1,victim2,...> [duration]
#   N        node count (test1..testN)
#   victims  comma-separated hostnames to virsh destroy (must be within test1..testN)
#   duration seconds of load-loop per node (default 180; must exceed
#            HB-timeout + fence + replay + purge, ~120s at 32 nodes)
#
# The script does NOT judge recovery itself — it prints the kill timestamps
# and exits after the load window so the caller can grep survivor journals.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:?usage: incident474_load_kill.sh <N> <victims_csv> [duration]}"
VICTIMS_CSV="${2:?usage: incident474_load_kill.sh <N> <victims_csv> [duration]}"
DURATION="${3:-180}"
VICTIM_GAP="${VICTIM_GAP:-2}"
MNT=/mnt/shared
LOADDIR="$MNT/.load474"

IFS=',' read -r -a VICTIMS <<< "$VICTIMS_CSV"

echo "=== incident474_load_kill: N=$N victims=${VICTIMS[*]} duration=${DURATION}s ==="
date -u +%FT%TZ

# 1. Start the load loop on every node in parallel.  The remote loop is
#    self-contained and time-bounded; a destroyed VM just takes its loop with it.
for i in $(seq 1 "$N"); do
    h="test$i"
    "$SSH" "$h" "nohup bash -c '
        SRC=/tmp/load474src
        D=$LOADDIR/node$i
        rm -rf \"\$SRC\"; mkdir -p \"\$SRC\" \"\$D\"
        for d in 1 2 3 4 5 6 7 8 9 10; do
            mkdir -p \"\$SRC/d\$d\"
            for f in \$(seq 1 40); do
                printf \"node$i-d%s-f%s-payload-%s\n\" \"\$d\" \"\$f\" \"\$(seq 1 20)\" > \"\$SRC/d\$d/file\$f\"
            done
        done
        end=\$((SECONDS + $DURATION))
        cyc=0
        while [ \$SECONDS -lt \$end ]; do
            cyc=\$((cyc+1))
            rsync -a --no-compress \"\$SRC/\" \"\$D/\" >/dev/null 2>&1
            sync
            rm -rf \"\$D\"
        done
        echo \"node$i cycles=\$cyc\" > /tmp/load474.done
    ' >/tmp/load474.log 2>&1 &" &
done
wait
echo "load dispatched to $N nodes @ $(date -u +%FT%TZ)"

# 2. Confirm load is really landing in the shared fs (from a survivor's view).
probe="test1"
for t in $(seq 1 30); do
    cnt=$("$SSH" "$probe" "find $LOADDIR -type f 2>/dev/null | wc -l" 2>/dev/null | tail -1 | tr -d '[:space:]')
    [ -n "$cnt" ] && [ "$cnt" -gt 100 ] && break
    sleep 1
done
if [ -z "${cnt:-}" ] || [ "${cnt:-0}" -le 100 ]; then
    echo "FAIL: load never appeared in $LOADDIR (cnt=${cnt:-?}) — aborting, no kills issued"
    exit 1
fi
echo "load CONFIRMED: $cnt files visible in $LOADDIR @ $(date -u +%FT%TZ)"

# 3. Kill the victims mid-load, VICTIM_GAP apart.
for v in "${VICTIMS[@]}"; do
    date -u "+KILL $v @ %FT%TZ"
    sudo virsh -c qemu:///system destroy "$v"
    sleep "$VICTIM_GAP"
done

# 4. Sit out the remaining load window + recovery slack, then report.
echo "waiting out load window (${DURATION}s) + 60s recovery slack..."
sleep "$DURATION"
sleep 60
echo "=== load window over @ $(date -u +%FT%TZ) ==="
"$SSH" "$probe" "cat /tmp/load474.done 2>/dev/null; find $LOADDIR -type f 2>/dev/null | wc -l" 2>/dev/null | tail -2
exit 0
