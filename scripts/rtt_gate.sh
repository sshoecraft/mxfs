#!/bin/bash
# rtt_gate.sh — objective quiet-window gate for storm-sensitive matrix cells
# (dlm_scaling, dir_reuse_coherency at N>=16).
#
# Measures raw shared-LUN round-trip latency from inside a guest with dd
# direct reads — mxfs is NOT in the path, so the number isolates the
# host-side transport (qemu/loopback-iSCSI/SCST) service latency that the
# metadata-storm tests amplify (~6 sync round trips per create+stat+unlink).
#
# Derivation (2026-07-25, v0.11.81 32/cawp forensics): healthy band 48-58
# ops/s needs <= ~3.3ms storm RTT; idle-fleet RTT on a healthy host is
# ~1.8-2.0ms.  Gate: p50 <= 2500us AND 1-min loadavg <= 12 -> storm cells
# have their 7/20-era margin.  Neighbor workloads (game servers, vLLM) or
# a prior chunk's load decay push RTT above the gate; wait, don't run.
#
# Usage: scripts/rtt_gate.sh [node] [n_samples]   (default test1, 100)
# Exit 0 = gate open (quiet), 1 = gate closed.  Prints the measurements.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
NODE="${1:-test1}"
NS="${2:-100}"
LOAD1=$(awk '{print int($1)}' /proc/loadavg)
P50=$(timeout 90 "$SSH" "$NODE" "$PASS" '
    rm -f /tmp/rttg.log
    for i in $(seq 1 '"$NS"'); do
        t0=$(date +%s%N)
        dd if=/dev/sda of=/dev/null bs=4096 count=1 iflag=direct skip=$(( (RANDOM*7) % 100000 )) 2>/dev/null
        t1=$(date +%s%N)
        echo $(( (t1-t0)/1000 )) >> /tmp/rttg.log
    done
    sort -n /tmp/rttg.log | awk "{a[NR]=\$1} END{print a[int(NR*0.5)]}"' 2>/dev/null | tail -1)
P50=${P50:-999999}
echo "rtt_gate: node=$NODE p50=${P50}us load1=$LOAD1 (gate: p50<=2500 && load1<=12)"
[ "$P50" -le 2500 ] && [ "$LOAD1" -le 12 ]
