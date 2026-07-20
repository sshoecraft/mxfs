#!/bin/bash
# ddwatch.sh — run ON a test node.  Samples every second; when ANY task is in
# D state on two consecutive samples (a real stall, not transient IO), dumps
# its kernel stack each sample until it leaves D.
# Output: /root/ddwatch.log with uptime timestamps for dmesg joins.
#
# sess6 (ccloop a16ec5f2): built to catch the 25s single-create stall in
# dir_reuse_coherency round 6/9 (test6 f14: no P36-RETRY, no AGWAIT, dir EX
# held cached the whole time — stall point invisible in dmesg).
# sess1 (ccloop a9a03929): generalized from dd/md5sum/rm/sync to ALL tasks —
# the run45 120s wedge stalled bash creators and possibly kworkers, which the
# old name filter missed entirely.
set -u
OUT=/root/ddwatch.log
: > "$OUT"
declare -A prevD
while :; do
    declare -A nowD=()
    while read -r st p comm; do
        [ "$st" = "D" ] || continue
        nowD[$p]=1
        if [ -n "${prevD[$p]:-}" ]; then
            {
                echo "=== up=$(cut -d' ' -f1 /proc/uptime) pid=$p comm=$comm D-repeat=${prevD[$p]}"
                cat /proc/$p/stack 2>/dev/null
            } >> "$OUT"
        fi
        prevD[$p]=$(( ${prevD[$p]:-0} + 1 ))
    done < <(ps -eo state=,pid=,comm= 2>/dev/null)
    for p in "${!prevD[@]}"; do
        [ -n "${nowD[$p]:-}" ] || unset "prevD[$p]" 2>/dev/null || true
    done
    sleep 1
done
