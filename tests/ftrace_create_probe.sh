#!/bin/bash
# ftrace_create_probe.sh — name the millisecond-scale callees of a small-file
# create on one mounted node (D-0349 instrument step 2 instrument).
#
# On <node>: arm function_graph on the open/write/close syscall entry points
# with a bounded depth, run <count> creates of 4 KiB files in a fresh private
# directory under /mnt/shared, stop tracing, and print (a) strace -T per
# syscall walls for a second, smaller loop and (b) every traced function
# whose duration carried the >= 1 ms ('#'), >= 10 ms ('*') or >= 100 ms
# ('@') function_graph marker, with a count per function name.
#
# budget: <count> creates at the measured ~10 ms each = count/100 s; the ssh
# bound below is 60 s for the default 50.  A timeout is a FAIL.
#
# Usage: tests/ftrace_create_probe.sh <node> [count=50] [depth=6] [graph-roots]
#   graph-roots: space-separated set_graph_function list (default: the three
#   syscall entry points; pass e.g. 'xfs_vn_create' to descend into one).
set -u
NODE=${1:?node}
COUNT=${2:-50}
DEPTH=${3:-6}
ROOTS=${4:-do_sys_openat2 ksys_write __x64_sys_close}
# MARKERS: function_graph duration markers to report ('!' >=100 us, '#' >=1 ms,
# '*' >=10 ms, '@' >=100 ms, '$' >=1 s); default = 1 ms and up.
MARKERS=${MARKERS:-#*@\$}
# PREFILL: create this many files untraced first, so the traced creates land
# in a directory of that size (block/leaf format instead of shortform).
PREFILL=${PREFILL:-0}
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ftrace_create_$NODE
mkdir -p "$OUT"
echo "=== ftrace_create_probe node=$NODE count=$COUNT depth=$DEPTH roots='$ROOTS' out=$OUT $(date -u +%FT%TZ) ==="

timeout 60 "$SSH" "$NODE" "T=/sys/kernel/tracing; [ -d \$T ] || T=/sys/kernel/debug/tracing; [ -f \$T/trace ] || { echo NO_TRACEFS; exit 3; };
d=$MNT/ftrace_probe_\$(date +%s); mkdir -p \$d && cd \$d || exit 4;
if [ $PREFILL -gt 0 ]; then p0=\$(date +%s%3N); for i in \$(seq 1 $PREFILL); do : > p\$i; done; p1=\$(date +%s%3N); echo \"PREFILL count=$PREFILL ms=\$((p1-p0))\"; fi;
echo 0 > \$T/tracing_on; echo nop > \$T/current_tracer; echo > \$T/set_graph_function; echo > \$T/trace;
echo function_graph > \$T/current_tracer; echo funcgraph-tail > \$T/trace_options; echo $DEPTH > \$T/max_graph_depth;
echo '$ROOTS' > \$T/set_graph_function;
echo 32768 > \$T/buffer_size_kb;
echo 1 > \$T/tracing_on; t0=\$(date +%s%3N);
for i in \$(seq 1 $COUNT); do head -c 4096 /dev/urandom > f\$i; done;
t1=\$(date +%s%3N); echo 0 > \$T/tracing_on;
echo \"CREATE_LOOP count=$COUNT ms=\$((t1-t0)) per_ms=\$(( (t1-t0) / $COUNT ))\";
cp \$T/trace /tmp/ftrace_create_probe.trace; wc -l /tmp/ftrace_create_probe.trace;
echo '--- functions with [$MARKERS] markers (count name), top 40 ---';
grep -E '^ *[0-9]+\) +[$MARKERS] ' /tmp/ftrace_create_probe.trace | sed -E 's/.*\| +//; s/^\} \/\* //; s/ \*\/$//; s/\(\);?$//; s/ \{$//' | sort | uniq -c | sort -rn | head -40;
echo '--- first 60 marked lines verbatim ---';
grep -E '^ *[0-9]+\) +[$MARKERS] ' /tmp/ftrace_create_probe.trace | head -60;
echo '--- strace -T of 10 more creates (open/write/close walls > 1 ms) ---';
for i in \$(seq 1 10); do strace -f -T -e trace=openat,write,close -o /tmp/ftrace_probe_strace.\$i sh -c \"head -c 4096 /dev/urandom > s\$i\"; done 2>/dev/null;
cat /tmp/ftrace_probe_strace.* | grep -E '<[0-9]+\.[0-9]+>' | awk -F'<' '{split(\$NF,a,\">\"); if (a[1]+0 >= 0.001) print}' | head -40;
echo nop > \$T/current_tracer; echo > \$T/set_graph_function; echo > \$T/trace;
cd / && rm -rf \$d /tmp/ftrace_probe_strace.*; echo PROBE_DONE" 2>&1 | grep -av '^Unauthorized\|^Warning\|^If you\|^$' | tee "$OUT/probe.txt"
rc=${PIPESTATUS[0]}
echo "=== ftrace_create_probe rc=$rc out=$OUT/probe.txt $(date -u +%FT%TZ) ==="
exit $rc
