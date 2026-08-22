#!/bin/bash
# drc_synth_sync.sh — NULL-MXFS reproduction probe for the D-503 residual
# presync degradation.  Mimics dir_reuse_coherency's per-round harness IO
# pattern with ZERO mxfs operations: each "round", write a 16.9MB file to
# the node's ROOT fs (like the drc_create_r*.dmesg snapshot) and time
# sync(1), on a fixed cadence so all 32 nodes burst together like the
# barrier-locked test does.  If the fleet-simultaneous sync cost shows the
# same 0.6s -> ~3s step at round ~4 and back-to-back persistence as the
# real test, the presync slowdown is host-side (qcow2/virtio-flush/ext4
# journal contention from harness diagnostic IO), not mxfs.
# Results to kmsg as mxfs-SYNSYNC marks + OUT file.
# Usage (on node): drc_synth_sync.sh <out_file> <run_tag> [rounds] [cadence_s] [start_epoch]
OUT="${1:?out}"; TAG="${2:?tag}"; N="${3:-8}"; CAD="${4:-13}"; T0="${5:-$(date +%s)}"
: >> "$OUT"
# wait for the fleet-aligned start
while [ "$(date +%s)" -lt "$T0" ]; do sleep 0.2; done
for r in $(seq 1 "$N"); do
    RS=$(( T0 + (r - 1) * CAD ))
    while [ "$(date +%s)" -lt "$RS" ]; do sleep 0.2; done
    dd if=/dev/urandom of="/root/synth_${TAG}_r${r}.dat" bs=1M count=17 2>/dev/null
    t0=$(date +%s%N)
    sync
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    echo "mxfs-SYNSYNC tag=${TAG} r=${r} sync_ms=${ms}" > /dev/kmsg 2>/dev/null
    echo "tag=${TAG} r=${r} ts=$(date +%s) sync_ms=${ms}" >> "$OUT"
done
