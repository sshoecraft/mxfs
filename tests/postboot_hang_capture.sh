#!/bin/bash
#
# postboot_hang_capture.sh — run a platform's packaged round with several
# whole-set reboot laps and, if a node's mount after a reboot does not return,
# keep what says where it waited: the kernel stack of every mount task and of
# every task in uninterruptible sleep on each node, and the end of each node's
# kernel log (the round keeps only the failing node's log, and nothing of the
# node that formed the cluster).
#
# Usage: tests/postboot_hang_capture.sh PLATFORM VERSION [LAPS] [CONFIG]
#   LAPS    (default 6)  POSTBOOT_LAPS for tests/packaged_round.sh
#   CONFIG  (default 2/net/mesh/direct)
#
# Output: tests/evidence/postboot_hang_<PLATFORM>_<VERSION>.out; its last line
# is POSTBOOT_CAPTURE_DONE.  The round enforces its own per-step bounds.
#
# Launch it detached (nohup setsid ... &): a run started as a tool's
# background task dies with the session that started it.
#
set -u
P="${1:?usage: tests/postboot_hang_capture.sh PLATFORM VERSION [LAPS] [CONFIG]}"
V="${2:?version}"
LAPS="${3:-6}"
CFG="${4:-2/net/mesh/direct}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
O="tests/evidence/postboot_hang_${P}_${V}.out"
{
    echo "=== $(date -u +%FT%TZ) postboot_hang_capture $P $V laps=$LAPS $CFG ==="
    scripts/lab_power.sh up "$P"
    # the round's storage is a pool LUN borrowed for this platform's set and
    # held by this shell, named in a lab file of its own (as tests/full_verify.sh
    # does for its platform steps)
    . tools/mxfs_lab.sh
    nodes=$(lab_nodes "$P") && portal=$(lab_need storage portal) \
        && line=$(tools/lun_pool.sh alloc --owner $$ --what "postboot_hang_capture $V $P" $nodes) \
        || { echo "no pool LUN for $P"; echo "POSTBOOT_CAPTURE_DONE $(date -u +%FT%TZ)"; exit 2; }
    echo "$line"
    LAB="$HOME/.config/mxfslab/lab.$P"
    { grep -E '^#|^addr|^qemu|^paths' "$MXFS_LAB"
      echo "storage portal=$portal target=$(sed -n 's/.* target=\([^ ]*\).*/\1/p' <<<"$line") lun=$(sed -n 's/.* dev=\([^ ]*\).*/\1/p' <<<"$line")"
      echo "nodes $P=$(echo $nodes | tr ' ' ',')"; } > "$LAB"
    MXFS_LAB=$LAB CONFIG=$CFG POSTBOOT_LAPS=$LAPS tests/packaged_round.sh "$P" "$V"
    echo "ROUND_RC=$?"
} >> "$O" 2>&1
if grep -aq 'FAIL: postboot' "$O"; then
    for h in $(tools/mxfs_lab.sh nodes "$P"); do
        echo "=== $h" >> "$O"
        timeout 60 tools/mxfs_sshpass.sh "$h" '
            date -u; echo mounts=$(grep -c " mxfs " /proc/mounts)
            for s in /proc/[0-9]*/stat; do
                d=${s%/stat}
                c=$(cat $d/comm 2>/dev/null)
                st=$(sed "s/.*) //" $s 2>/dev/null | cut -d" " -f1)
                if [ "$c" = mount ] || [ "$st" = D ]; then
                    echo "TASK pid=${d#/proc/} comm=$c state=$st"
                    cat $d/stack 2>/dev/null
                fi
            done
            echo "--- kernel log, mxfs lines, last 200"
            dmesg -T | grep -a -i "mxfs" | tail -200 | cut -c1-400' >> "$O" 2>&1
    done
fi
echo "POSTBOOT_CAPTURE_DONE $(date -u +%FT%TZ)" >> "$O"
