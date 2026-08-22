#!/bin/bash
# Collect wall-clock-aligned kernel logs from a set of nodes for incident
# forensics. Uses journalctl -k with an explicit UTC --since so cross-node
# ordering is real (dmesg's seconds-since-boot differ per node uptime).
#
# Usage: collect_incident_dmesg.sh <outdir> <since-utc "YYYY-MM-DD HH:MM:SS"> <node>...
set -u
cd "$(dirname "$0")/.."
OUT=$1; SINCE=$2; shift 2
mkdir -p "$OUT"
for n in "$@"; do
    (
        timeout 60 tools/mxfs_sshpass.sh "$n" \
            "journalctl -k --utc --since '$SINCE' -o short-iso --no-pager" \
            > "$OUT/$n.klog" 2>"$OUT/$n.err"
        echo "$n: $(wc -l < "$OUT/$n.klog") lines"
    ) &
done
wait
echo "collected into $OUT"
