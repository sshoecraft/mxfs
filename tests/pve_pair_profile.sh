#!/bin/bash
# pve_pair_profile.sh — where the time goes on an MXFS-on-DRBD Proxmox pair
# under a real workload (VM installs, a copy, a backup).  On both hosts ftrace's
# function profiler counts every call of a chosen set of MXFS functions and
# adds up the wall time each one spent, time asleep included, so a slow
# workload can be put on the operation that costs it (a log force, a cluster
# lock acquire, the DRBD write bound, a coordination swap) instead of guessed.
# Nothing is written to the kernel log.
#
# Alongside, function_graph with a duration threshold keeps every call of those
# functions that took SLOW_MS or longer, with its CPU and the time it returned.
# Both use the global tracer: nothing else on these hosts traces, and the
# script puts every setting back when it ends.
#
# The profile is read every INTERVAL_S seconds (the counters run on; each
# snapshot holds the totals since the start), so a run that changes character
# part way can be read interval by interval.
#
# Usage: tests/pve_pair_profile.sh [seconds]
#        Without seconds it runs until the local file STOP_FILE exists.
# Env:
#   PVE_PAIR    "<addr> <addr>" (default "192.168.1.80 192.168.1.81")
#   FNS         the functions (default below: the write and read entry points,
#               fsync and the log force, direct-write allocation and unwritten
#               conversion, transaction alloc/commit, the cluster inode and AG
#               lock acquires, the BAST workers, the DRBD write bound and the
#               DRBD compare-and-swap)
#   SLOW_MS     a call this long or longer is kept with its timestamp (default 1000)
#   INTERVAL_S  seconds between profile snapshots (default 300)
#   STOP_FILE   default $EVID/stop
#   EVID        default tests/evidence/pve_pair_profile/<UTC stamp>
#
# Output: $EVID/<host>.profile.<n> (each snapshot, every CPU's table), the
# summed table per host in $EVID/summary.txt, and $EVID/<host>.slow (the calls
# past SLOW_MS).  It grades nothing; it is an instrument.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
[ "${#PAIR[@]}" = 2 ] || { echo "pve_pair_profile: PVE_PAIR must name two hosts"; exit 2; }
RUN_S=${1:-}
FNS=${FNS:-xfs_file_write_iter xfs_file_read_iter xfs_file_fsync xfs_log_force_seq xfs_log_force xfs_log_force_inode xlog_cil_force_seq xlog_wait_on_iclog xfs_iomap_write_direct xfs_iomap_write_unwritten xfs_dio_write_end_io xfs_bmapi_write xfs_trans_alloc xfs_trans_commit mxfs_ilock_fallible mxfs_ag_dlm_lock mxfs_ag_dlm_unlock mxfs_trans_preacquire_inode_ags mxfs_dlm_ag_bast_work_fn mxfs_dlm_bast_work_fn mxfs_pal_ioq_admit mxfs_ioq_admit_one mxfs_pal_drbd_cas_emulate mxfs_drbd_reg_put xfs_create xfs_remove xfs_setattr_size xfs_alloc_vextent_start_ag xfs_alloc_vextent_near_bno}
SLOW_MS=${SLOW_MS:-1000}
INTERVAL_S=${INTERVAL_S:-300}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EVID=${EVID:-$REPO/tests/evidence/pve_pair_profile/$STAMP}
STOP_FILE=${STOP_FILE:-$EVID/stop}
mkdir -p "$EVID" || exit 1
SUM="$EVID/summary.txt"
T=/sys/kernel/tracing

say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUM"; }
on() {  # <host> <cmd> [timeout]
    timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you|^$'
    return "${PIPESTATUS[0]}"
}

declare -A NAME
for h in "${PAIR[@]}"; do
    s=$(on "$h" "echo \"name=\$(hostname) build=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) ver=\$(cat /sys/module/mxfs/version 2>/dev/null) tracer=\$(cat $T/current_tracer) profile=\$(cat $T/function_profile_enabled) thresh=\$(cat $T/tracing_thresh)\"" 20)
    say "$h $s"
    case "$s" in
        *"tracer=nop profile=0 thresh=0"*) ;;
        *) say "ABORT: $h's tracer is in use or was left set: $s"; exit 1 ;;
    esac
    NAME[$h]=$(sed -n 's/^name=\([^ ]*\).*/\1/p' <<<"$s")
done

restore() {
    local h
    for h in "${PAIR[@]}"; do
        on "$h" "echo 0 > $T/function_profile_enabled; echo 0 > $T/tracing_on; echo nop > $T/current_tracer; echo 0 > $T/tracing_thresh; echo > $T/set_ftrace_filter; echo 1 > $T/tracing_on; echo RESTORED" 30 | grep -q RESTORED \
            || say "WARNING: $h: could not put its tracer back"
    done
}
trap restore EXIT

slow_us=$(( SLOW_MS * 1000 ))
# The functions are selected by their line in available_filter_functions: a
# name written to set_ftrace_filter is matched against every traceable
# function in the kernel, which measured 7 s a name on pve1 (29 names, 196 s),
# while an index is taken as it is.  Run on each host with the names and the
# slow-call threshold as $1 and $2.
SETUP=$(cat <<'EOF'
T=/sys/kernel/tracing
echo 0 > $T/tracing_on
echo > $T/trace
idx=$(awk -v want="$1" 'BEGIN {n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i] " [mxfs]"] = 1} ($0 in w) {print NR}' $T/available_filter_functions | tr '\n' ' ')
[ -n "$idx" ] || { echo "NO_FUNCTION_FOUND"; exit 1; }
echo $idx > $T/set_ftrace_filter || { echo "FILTER_WRITE_FAILED"; exit 1; }
echo 4096 > $T/buffer_size_kb
echo "$2" > $T/tracing_thresh
echo function_graph > $T/current_tracer || { echo "TRACER_FAILED"; exit 1; }
echo funcgraph-abstime > $T/trace_options
echo funcgraph-proc > $T/trace_options
echo 1 > $T/function_profile_enabled && echo 1 > $T/tracing_on && echo "PROFILE_ON $(wc -l < $T/set_ftrace_filter)"
cat $T/set_ftrace_filter
EOF
)
SETUP64=$(base64 -w0 <<<"$SETUP")
for h in "${PAIR[@]}"; do
    # bounded on the host as well: ssh's own timeout here ends only the client,
    # and a setup left running there switched the tracer on after this script
    # had given up and put it back (pve1, 2026-10-06)
    out=$(on "$h" "echo $SETUP64 | base64 -d | timeout 45 bash -s -- '$FNS' $slow_us" 60)
    echo "$out" > "$EVID/${NAME[$h]}.filter"
    case "$out" in
        *PROFILE_ON*) say "$h ${NAME[$h]}: profiling $(sed -n 's/.*PROFILE_ON \([0-9]*\).*/\1/p' <<<"$out") of $(wc -w <<<"$FNS") functions, calls of ${SLOW_MS} ms or more kept" ;;
        *) say "ABORT: $h could not start the profile: $(tr '\n' ' ' <<<"$out" | cut -c1-300)"; exit 1 ;;
    esac
done

# The profile table leaves out every function whose mean is below tracing_thresh
# at the time it is read, so each snapshot pauses the slow-call trace, reads
# the table with the threshold at 0, and puts both back.
snap() {  # <n>
    local h
    for h in "${PAIR[@]}"; do
        on "$h" "echo 0 > $T/tracing_on; echo 0 > $T/tracing_thresh
            for f in $T/trace_stat/function[0-9]*; do echo \"== \$f\"; cat \$f; done
            echo $slow_us > $T/tracing_thresh; echo 1 > $T/tracing_on" 60 > "$EVID/${NAME[$h]}.profile.$1"
    done
}
T0=$(date +%s)
n=0
if [ -n "$RUN_S" ]; then until_what="${RUN_S}s have passed"; else until_what="$STOP_FILE exists"; fi
say "profiling until $until_what; a snapshot every ${INTERVAL_S}s"
last=$T0
while :; do
    now=$(date +%s)
    if [ -n "$RUN_S" ]; then [ $(( now - T0 )) -ge "$RUN_S" ] && break
    else [ -e "$STOP_FILE" ] && break
    fi
    if [ $(( now - last )) -ge "$INTERVAL_S" ]; then
        n=$(( n + 1 )); snap "$n"; last=$now
    fi
    sleep 5
done
n=$(( n + 1 )); snap "$n"
for h in "${PAIR[@]}"; do
    on "$h" "echo 0 > $T/tracing_on; cat $T/trace" 120 > "$EVID/${NAME[$h]}.slow"
done
say "profiled for $(( $(date +%s) - T0 ))s, $n snapshots"

python3 -I - "$EVID" "$n" "${NAME[${PAIR[0]}]}" "${NAME[${PAIR[1]}]}" <<'PY' | tee -a "$SUM"
import collections, re, sys
evid, last, names = sys.argv[1], sys.argv[2], sys.argv[3:]
unit = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1e3}
row = re.compile(r"^\s*(\S+)\s+(\d+)\s+([\d.]+)\s+(ns|us|ms|s)\b")
for n in names:
    hits, tot = collections.Counter(), collections.Counter()
    for line in open(f"{evid}/{n}.profile.{last}", errors="replace"):
        m = row.match(line)
        if not m or m.group(1) == "Function":
            continue
        hits[m.group(1)] += int(m.group(2))
        tot[m.group(1)] += float(m.group(3)) * unit[m.group(4)]
    print(f"{n}: function, calls, total wall s, mean ms (summed over CPUs; sleep and callees included)")
    for fn in sorted(tot, key=lambda f: -tot[f]):
        print(f"  {fn:36s} {hits[fn]:10d} {tot[fn] / 1000:12.1f} {tot[fn] / max(hits[fn], 1):10.2f}")
    slow = collections.Counter()
    for line in open(f"{evid}/{n}.slow", errors="replace"):
        m = re.search(r"\}\s+/\*\s+(\S+)", line)
        if m:
            slow[m.group(1)] += 1
    print(f"{n}: calls past the slow threshold: " + (", ".join(f"{f} {c}" for f, c in slow.most_common()) or "none"))
PY
