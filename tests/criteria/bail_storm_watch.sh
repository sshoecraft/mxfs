#!/bin/bash
# bail_storm_watch.sh — sess42 diagnostic: catch the "DLM reload BAIL
# (i_lock contended)" storm live and identify the i_lock HOLDER.
#
# The posix_semantics(16) probe showed one node's barrier signal absent
# for all observers (incl. itself) while its dmesg streamed reload BAILs
# on the barrier-dir inode at 2/s for 120s+ — i.e. some task held the
# dir's ILOCK rwsem the whole time.  down_write_trylock can't tell us
# who; a D-state stack dump during the storm can.
#
# Usage: bail_storm_watch.sh <num_nodes> <out_log> [poll_secs]
# Run on the host alongside a test run; Ctrl-C / kill to stop.
set -u
N="${1:?num nodes}"
OUT="${2:?output log}"
POLL="${3:-8}"
SSH_TOOL="${MXFS_SSH_TOOL:-/home/steve/src/mxfs/tools/mxfs_sshpass.sh}"
PASS_FILE="${MXFS_PASS_FILE:-/tmp/.mxfs_pass}"

declare -A last_cap
echo "=== bail_storm_watch start $(date -u +%F' '%T) nodes=1..$N poll=${POLL}s ===" >>"$OUT"
while :; do
    for i in $(seq 1 "$N"); do
        host="test$i"
        # recent BAIL count + uptime, one ssh
        info=$("$SSH_TOOL" "$host" "$PASS_FILE" '
            up=$(cut -d. -f1 /proc/uptime)
            recent=$(dmesg | grep "DLM reload BAIL" | tail -40 | awk -F"[][ .]+" -v up="$up" "\$2+0 > up-12" | wc -l)
            ino=$(dmesg | grep "DLM reload BAIL" | tail -1 | grep -oE "ino=[0-9]+")
            echo "R=$recent U=$up $ino"' 2>/dev/null | tail -1)
        recent=$(echo "$info" | grep -oE 'R=[0-9]+' | cut -d= -f2)
        [ -z "${recent:-}" ] && continue
        if [ "$recent" -ge 8 ]; then
            now=$(date +%s)
            prev=${last_cap[$host]:-0}
            # capture at most once per 60s per node
            if [ $((now - prev)) -ge 60 ]; then
                last_cap[$host]=$now
                {
                    echo "=== STORM on $host $(date -u +%T) $info ==="
                    "$SSH_TOOL" "$host" "$PASS_FILE" '
                        echo "--- D-state tasks ---"
                        ps -eo pid,stat,wchan:40,comm | awk "\$2 ~ /D/"
                        for p in $(ps -eo pid,stat | awk "\$2 ~ /D/ {print \$1}"); do
                            echo "--- stack pid=$p ($(cat /proc/$p/comm 2>/dev/null)) ---"
                            cat /proc/$p/stack 2>/dev/null
                        done
                        echo "--- mxfs_test/touch/find procs (any state) ---"
                        for p in $(pgrep -f "touch|find /mnt|mxfs_test" 2>/dev/null); do
                            echo "--- stack pid=$p ($(cat /proc/$p/comm 2>/dev/null) stat=$(awk "{print \$3}" /proc/$p/stat 2>/dev/null)) ---"
                            cat /proc/$p/stack 2>/dev/null
                        done
                        echo "--- last BAIL lines ---"
                        dmesg | grep "DLM reload BAIL" | tail -3' 2>/dev/null
                    echo "=== END STORM $host ==="
                } >>"$OUT"
            fi
        fi
    done
    sleep "$POLL"
done
