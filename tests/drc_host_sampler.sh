#!/bin/bash
# drc_host_sampler.sh — sample CLYDE-side (host) state every INTERVAL seconds
# during a dir_reuse_coherency b2b pair: dirty/writeback pages, NVMe block
# stats (the single disk hosting BOTH the VM root qcow2s and the SCST LUN
# backing files), and a timed write+fdatasync probe that experiences the same
# throttling qemu's virtio-flush fdatasync does.  D-503 residual: node presync
# `sync` cost is suspected to be host-side qcow2 fdatasync backlog from the
# harness's 16.9MB/node/round dmesg snapshots (540MB/round fleet-wide).
# Usage: drc_host_sampler.sh <out_file> [interval_s] [duration_s]
OUT="${1:?out file}"; INT="${2:-2}"; DUR="${3:-1500}"
PROBE=$(mktemp /tmp/drc_host_probe.XXXXXX)
END=$(( $(date +%s) + DUR ))
: > "$OUT"
while [ "$(date +%s)" -lt "$END" ]; do
    {
        printf 'ts=%s ' "$(date -u +%s)"
        awk '$1=="Dirty:"{printf "dirty_kb=%s ", $2} $1=="Writeback:"{printf "wb_kb=%s ", $2}' /proc/meminfo
        # nvme0n1 full stat: rd_ios rd_merge rd_sec rd_ticks wr_ios wr_merge
        # wr_sec wr_ticks inflight io_ticks time_in_queue (+discard/flush)
        awk '{printf "nvme=%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s ", $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11}' /sys/block/nvme0n1/stat 2>/dev/null
        # 64KB write + fdatasync on / — same path/throttle as qemu qcow2 flush
        t0=$(date +%s%N)
        dd if=/dev/zero of="$PROBE" bs=65536 count=1 conv=fdatasync 2>/dev/null
        t1=$(date +%s%N)
        printf 'fsync_us=%s ' $(( (t1 - t0) / 1000 ))
        printf 'load=%s\n' "$(cut -d" " -f1 /proc/loadavg)"
    } >> "$OUT"
    sleep "$INT"
done
rm -f "$PROBE"
