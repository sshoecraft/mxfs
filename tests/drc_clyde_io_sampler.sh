#!/bin/bash
# drc_clyde_io_sampler.sh — clyde-host-side IO sampler for D-503 residual work.
# Samples iostat -x for DEV each INTERVAL, appending host Dirty (kB) as a
# trailing column. Field map of the OUTPUT (after the timestamp + device):
#   f3=r/s f4=rkB/s f7=r_await f9=w/s f10=wkB/s f13=w_await
#   f21=f/s f22=f_await f23=aqu-sz f24=%util f25=dirty_kb
# Usage: drc_clyde_io_sampler.sh <out_file> [dev] [interval_s] [duration_s]
OUT="${1:?out file}"; DEV="${2:-nvme0n1}"; INT="${3:-5}"; DUR="${4:-600}"
END=$(( $(date +%s) + DUR ))
: > "$OUT"
iostat -x "$INT" -d "$DEV" | while read -r line; do
    case "$line" in
        "$DEV"*)
            d=$(awk '$1=="Dirty:"{print $2}' /proc/meminfo)
            printf '%s %s %s\n' "$(date -u +%H:%M:%S)" "$line" "$d" >> "$OUT"
            [ "$(date +%s)" -ge "$END" ] && pkill -P $$ iostat && break
            ;;
    esac
done
