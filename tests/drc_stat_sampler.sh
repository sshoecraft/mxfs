#!/bin/bash
# drc_stat_sampler.sh — sample /proc/fs/mxfs/stat + dirty/writeback + loadavg
# on THIS node every INTERVAL seconds, one JSON-ish line per sample, to OUT.
# Used to attribute dir_reuse_coherency round-pace degradation (D-503 residual)
# to a specific counter family (push_ail, log, ig, buf, icluster).
# Usage: drc_stat_sampler.sh <out_file> [interval_s] [duration_s]
OUT="${1:?out file}"; INT="${2:-5}"; DUR="${3:-400}"
END=$(( $(date +%s) + DUR ))
: > "$OUT"
while [ "$(date +%s)" -lt "$END" ]; do
    {
        printf 'ts=%s ' "$(date -u +%s)"
        awk '$1=="push_ail"{printf "ail=%s,%s,%s,%s,%s,%s,%s,%s,%s,%s ", $2,$3,$4,$5,$6,$7,$8,$9,$10,$11}
             $1=="log"{printf "log=%s,%s,%s,%s,%s ", $2,$3,$4,$5,$6}
             $1=="ig"{printf "ig=%s,%s,%s,%s,%s,%s,%s ", $2,$3,$4,$5,$6,$7,$8}
             $1=="icluster"{printf "icl=%s,%s,%s ", $2,$3,$4}
             $1=="buf"{printf "buf=%s,%s,%s ", $2,$3,$4}
             $1=="dir"{printf "dir=%s,%s,%s,%s ", $2,$3,$4,$5}
             $1=="trans"{printf "trans=%s,%s,%s ", $2,$3,$4}
             $1=="xpc"{printf "xpc=%s,%s,%s ", $2,$3,$4}
             $1=="vnodes"{printf "vn=%s,%s ", $5,$8}' /proc/fs/mxfs/stat 2>/dev/null
        # AIL depth: log head/tail LSN (cycle:block) — depth = head-tail blocks.
        # grant heads (bytes) show outstanding log-space reservations.
        for L in /sys/fs/mxfs/*/log; do
            [ -e "$L/log_head_lsn" ] || continue
            printf 'lsn_head=%s lsn_tail=%s grant_r=%s grant_w=%s ' \
                "$(cat "$L/log_head_lsn")" "$(cat "$L/log_tail_lsn")" \
                "$(cat "$L/reserve_grant_head_bytes")" "$(cat "$L/write_grant_head_bytes")"
            break
        done
        awk '$1=="Dirty:"{printf "dirty_kb=%s ", $2} $1=="Writeback:"{printf "wb_kb=%s ", $2}' /proc/meminfo
        # raw block-layer accumulators for the shared LUN (sda): deltas give
        # r_await/w_await through the FULL iSCSI+SCST+backing path (SG_IO
        # passthrough like CAW/FUA is NOT accounted here).
        awk '{printf "sda=%s,%s,%s,%s,%s,%s,%s ", $1,$4,$5,$8,$9,$10,$11}' /sys/block/sda/stat 2>/dev/null
        # raw-path latency probes: timed 4k O_DIRECT read. sdb = idle LUN on
        # the same iSCSI session/SCST target (pure transport+backing latency,
        # no mxfs traffic); sda = shared LUN (adds its queue).
        for d in sdb sda; do
            t0=$(date +%s%N)
            dd if=/dev/$d of=/dev/null bs=4096 count=1 skip=262144 iflag=direct 2>/dev/null
            t1=$(date +%s%N)
            printf 'probe_%s_us=%s ' "$d" $(( (t1 - t0) / 1000 ))
        done
        printf 'load=%s\n' "$(cut -d" " -f1 /proc/loadavg)"
    } >> "$OUT"
    sleep "$INT"
done
