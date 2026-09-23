#!/bin/bash
# tmpfile_churn_ftrace.sh — per-callee wall-time breakdown of ONE node's
# O_TMPFILE churn loop (D-TMPFILE-CHURN-the budget rule-PERF-400) with the kernel's
# function_graph tracer.  No rebuild, no probe printk: the tracer times every
# non-inlined function under the four syscall entry points of one churn
# iteration —
#     xfs_vn_tmpfile      (open O_TMPFILE -> xfs_create_tmpfile -> dialloc)
#     xfs_vn_link         (linkat AT_EMPTY_PATH -> xfs_link -> iunlink_remove)
#     xfs_vn_unlink       (unlink -> xfs_remove -> iunlink)
#     xfs_fs_destroy_inode (close -> evict -> xfs_inode_mark_reclaimable ->
#                          SYNC xfs_inactive -> xfs_inactive_ifree -> difree)
# — down to DEPTH levels, for the churn task only (set_ftrace_pid + the
# function-fork option, because `timeout` forks python as a child — without
# function-fork the first run traced nothing; pinned to one CPU so entry/return
# pairs stay on one per-CPU stack).
#
# Instrumented: this is the instrumentation step for the sess400 finding that the
# close->inactivate->ifree leg is 56% of a 7.5 ms median iteration whose
# native-XFS equivalent is ~0.1 ms, with 150-640 ms stalls in the tail.  The
# tracer names the callee that carries the time; only then is a fix designed.
# budget: iteration budget is derived on the spot (2 x native + ssh), not
# padded; the ftrace run itself is a measurement, not a pass/fail gate.
# the unkillable-wedge rule: one bounded ssh per phase; the python loop runs under `timeout`.
# the source-tree rule: lives in tests/.
#
# Usage: tests/tmpfile_churn_ftrace.sh <node-number> [iters=100] [depth=4]
# Env:   MXFS_MNT (default /mnt/shared)  FTR_OUT (dir for trace+summary)
#        TMPC_MODE=pernode|shared (default pernode: private dir per node)
#        FTR_FUNCS="f1 f2 ..." overrides the graph roots (second pass: point it
#        at the heavy callees the first pass named, with a smaller DEPTH)
# Out:   $FTR_OUT/trace.txt.gz   raw function_graph trace (node-side copy
#                                /root/tmpc_ftrace.txt is overwritten each run)
#        $FTR_OUT/summary.txt    per-function inclusive wall: count/total/
#                                avg/p50/p90/max, top-level ops first, then
#                                the 40 heaviest callees by total time
#        $FTR_OUT/churn.txt      the loop's own wall=/errs=/done= line
# Exit:  0 if the trace was captured and summarised, 2 on usage/tracer error.

NODE=${1:?node number}
ITERS=${2:-100}
DEPTH=${3:-4}
MNT=${MXFS_MNT:-/mnt/shared}
MODE=${TMPC_MODE:-pernode}
OUT=${FTR_OUT:-$(mktemp -d)}
cd "$(dirname "$0")/.." || exit 2
mkdir -p "$OUT"
SSH=tools/mxfs_sshpass.sh

DIR=$MNT/tmpfile_churn
[ "$MODE" = pernode ] && DIR=$MNT/tmpfile_churn/test$NODE

# Same loop as tests/tmpfile_churn.sh (linkat via ctypes: CPython os.link
# never follows the /proc/self/fd magic link -> EXDEV everywhere).
PY='import os,sys,time,ctypes
d=sys.argv[1]; iters=int(sys.argv[2]); tag=sys.argv[3]
libc=ctypes.CDLL(None, use_errno=True); AT_FDCWD=-100; AT_EMPTY_PATH=0x1000
os.makedirs(d, exist_ok=True)
errs=0; t0=time.time(); maxit=0.0; done=0; its=[]
for i in range(iters):
    ti=time.time()
    try:
        fd=os.open(d, os.O_TMPFILE|os.O_RDWR, 0o644)
    except OSError as e:
        errs+=1; print("ERR open_tmpfile", e, file=sys.stderr, flush=True); continue
    try:
        os.write(fd, b"x"*4096)
        if i % 4 != 3:
            name=os.path.join(d, "%s.%d" % (tag, i))
            if libc.linkat(fd, b"", AT_FDCWD, name.encode(), AT_EMPTY_PATH):
                e=ctypes.get_errno(); raise OSError(e, "linkat: "+os.strerror(e))
            os.unlink(name)
    except OSError as e:
        errs+=1; print("ERR", e, file=sys.stderr, flush=True)
    os.close(fd)
    done+=1; dt=time.time()-ti; its.append(dt); maxit=max(maxit, dt)
its.sort()
p=lambda q: its[min(len(its)-1, int(q*len(its)))] if its else 0
print("wall=%.3f errs=%d done=%d maxit=%.3f p50=%.4f p90=%.4f" % (time.time()-t0, errs, done, maxit, p(0.5), p(0.9)), flush=True)'

# Node-side summariser for function_graph output (funcgraph-tail + abstime on).
SUMPY='import re,sys,collections
f=sys.argv[1]
dur=re.compile(r"([0-9]+\.[0-9]+) us")
stacks=collections.defaultdict(list)     # cpu -> [name,...]
times=collections.defaultdict(list)      # name -> [us,...]
depth0=collections.defaultdict(list)     # top-level name -> [us,...]
nlines=0
for L in open(f, errors="replace"):
    nlines+=1
    if "|" not in L: continue
    parts=L.split("|")
    if len(parts)<3: continue
    cpu=parts[1].strip().split(")")[0].strip()
    fn=parts[2].rstrip("\n")
    s=fn.strip()
    m=dur.search(parts[1])
    if s.endswith("{"):
        name=s[:s.index("(")].strip()
        stacks[cpu].append(name)
    elif s.startswith("}"):
        if not stacks[cpu]: continue
        name=stacks[cpu].pop()
        if m:
            us=float(m.group(1))
            times[name].append(us)
            if not stacks[cpu]: depth0[name].append(us)
    elif s.endswith(";"):
        name=s[:s.index("(")].strip()
        if m:
            us=float(m.group(1)); times[name].append(us)
            if not stacks[cpu]: depth0[name].append(us)
def st(v):
    v=sorted(v); n=len(v)
    q=lambda x: v[min(n-1,int(x*n))]
    return n, sum(v), sum(v)/n, q(0.5), q(0.9), v[-1]
print("lines=%d functions=%d" % (nlines, len(times)))
print("\n== top-level entry points (inclusive wall, us) ==")
print("%-36s %6s %12s %10s %10s %10s %10s" % ("function","n","total","avg","p50","p90","max"))
for name,v in sorted(depth0.items(), key=lambda kv:-sum(kv[1])):
    n,t,a,p50,p90,mx=st(v)
    print("%-36s %6d %12.1f %10.1f %10.1f %10.1f %10.1f" % (name,n,t,a,p50,p90,mx))
print("\n== heaviest 40 functions by total inclusive wall (us) ==")
print("%-44s %6s %12s %10s %10s %10s %10s" % ("function","n","total","avg","p50","p90","max"))
for name,v in sorted(times.items(), key=lambda kv:-sum(kv[1]))[:40]:
    n,t,a,p50,p90,mx=st(v)
    print("%-44s %6d %12.1f %10.1f %10.1f %10.1f %10.1f" % (name,n,t,a,p50,p90,mx))'

echo "=== tmpfile_churn_ftrace test$NODE iters=$ITERS depth=$DEPTH mode=$MODE dir=$DIR out=$OUT ==="

# Phase 1: native baseline (derives the churn budget) + tracer availability.
# The two python programs travel base64-encoded: no quoting layer to fight.
PYB=$(printf '%s' "$PY" | base64 -w0)
SUMB=$(printf '%s' "$SUMPY" | base64 -w0)
nat=$(timeout 120 $SSH test$NODE \
	"echo $PYB | base64 -d > /root/tmpc_churn.py; echo $SUMB | base64 -d > /root/tmpc_ftrace_sum.py; D=\$(mktemp -d); python3 /root/tmpc_churn.py \$D $ITERS n 2>&1 | tail -1; rm -rf \$D; grep -c function_graph /sys/kernel/tracing/available_tracers" 2>/dev/null |
	grep -av '^Unauthorized\|^Warning:\|^If you')
natw=$(echo "$nat" | grep -o 'wall=[0-9.]*' | cut -d= -f2); natw=${natw:-0}
fg=$(echo "$nat" | tail -1)
echo "native: $(echo "$nat" | grep wall=)"
if [ "$fg" != 1 ]; then
	echo "FAIL: function_graph tracer not available on test$NODE (got '$fg')" >&2
	exit 2
fi
# mxfs churn budget: 2x native + 5 s launch, then x3 headroom for the tracer's
# own overhead (function_graph at DEPTH 4 adds per-call cost; the factor is an
# assumption that only bounds the run — a loop that hits it truncates done=).
# A MEASUREMENT bound, not a pass/fail budget.
budget=$(python3 -c "print(int((2*$natw+5)*3+0.999))")

# Phase 2: traced churn on mxfs.  All tracer state is reset first and last.
T=/sys/kernel/tracing
res=$(timeout $((budget + 40)) $SSH test$NODE "
set -u
T=$T
echo 0 > \$T/tracing_on
echo nop > \$T/current_tracer
echo > \$T/set_ftrace_pid
echo > \$T/set_graph_function
echo 65536 > \$T/buffer_size_kb
echo $DEPTH > \$T/max_graph_depth
echo '${FTR_FUNCS:-xfs_vn_tmpfile xfs_vn_link xfs_vn_unlink xfs_fs_destroy_inode}' > \$T/set_graph_function
echo function_graph > \$T/current_tracer
echo 1 > \$T/options/funcgraph-tail
echo 1 > \$T/options/funcgraph-abstime
echo 1 > \$T/options/function-fork
echo > \$T/trace
taskset -c 1 sh -c 'echo \$\$ > $T/set_ftrace_pid; echo 1 > $T/tracing_on; exec timeout $budget python3 /root/tmpc_churn.py $DIR $ITERS test$NODE' 2>&1 | tail -3
echo rc=\${PIPESTATUS[0]}
echo 0 > \$T/tracing_on
cat \$T/trace > /root/tmpc_ftrace.txt
echo nop > \$T/current_tracer
echo > \$T/set_ftrace_pid
echo > \$T/set_graph_function
echo 0 > \$T/max_graph_depth
echo 0 > \$T/options/function-fork
echo 1 > \$T/tracing_on
echo trace_lines=\$(wc -l < /root/tmpc_ftrace.txt) trace_bytes=\$(stat -c %s /root/tmpc_ftrace.txt)
python3 /root/tmpc_ftrace_sum.py /root/tmpc_ftrace.txt > /root/tmpc_ftrace_summary.txt 2>&1; echo sum_rc=\$?
" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you')
echo "$res" | grep -E 'wall=|rc=|trace_lines=|sum_rc=|ERR' | tee "$OUT/churn.txt"

# Phase 3: pull the summary and the compressed raw trace.
timeout 60 $SSH test$NODE "cat /root/tmpc_ftrace_summary.txt" 2>/dev/null | grep -av '^Unauthorized\|^Warning:\|^If you' > "$OUT/summary.txt"
timeout 120 $SSH test$NODE "gzip -c /root/tmpc_ftrace.txt" 2>/dev/null > "$OUT/trace.txt.gz"
echo "--- summary ($OUT/summary.txt) ---"
head -60 "$OUT/summary.txt"
echo "raw trace: $OUT/trace.txt.gz ($(stat -c %s "$OUT/trace.txt.gz" 2>/dev/null) bytes)"
grep -q 'top-level entry points' "$OUT/summary.txt" || { echo "FAIL: no summary produced" >&2; exit 2; }
exit 0
