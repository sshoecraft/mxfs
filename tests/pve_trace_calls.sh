#!/bin/bash
# pve_trace_calls.sh — count the calls of chosen mxfs functions on one host for
# a while, and who made them, without touching the global tracer (a profile may
# be running there) and without a line in the kernel log.  A private ftrace
# instance runs the function tracer filtered to those functions only; each
# call is one entry line, so the counts are exact unless the buffer overran
# (reported).
#
# Usage: tests/pve_trace_calls.sh <host> <seconds> <function> [function ...]
#        functions must be in the mxfs module (named as in
#        available_filter_functions without the " [mxfs]")
# Output: per function, calls and calls per second; then the top callers (comm)
#         per function; the raw trace is kept in $EVID/<host>.trace.
# Env:    EVID  default tests/evidence/pve_trace_calls/<UTC stamp>
#         STACK=1  also record each call's kernel stack (func_stack_trace) and
#                  print the distinct stacks, most frequent first: which path
#                  reaches a function, not only its immediate caller
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
HOST=${1:?usage: tests/pve_trace_calls.sh <host> <seconds> <function> [function ...]}
SECS=${2:?seconds}
shift 2
[ $# -ge 1 ] || { echo "pve_trace_calls: name at least one function"; exit 2; }
FNS="$*"
EVID=${EVID:-$REPO/tests/evidence/pve_trace_calls/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$EVID" || exit 1

# Run on the host with the function names and seconds as $1 and $2.  Functions
# are selected by line index in available_filter_functions: a name written to
# set_ftrace_filter is matched against every traceable function, seconds per
# name on these hosts, while an index is taken as it is.
PROBE=$(cat <<'EOF'
I=/sys/kernel/tracing/instances/mxfs_calls_$$
mkdir $I || { echo "NO_INSTANCE"; exit 1; }
trap 'echo 0 > $I/tracing_on; echo nop > $I/current_tracer; rmdir $I' EXIT
idx=$(awk -v want="$1" 'BEGIN {n = split(want, a, " "); for (i = 1; i <= n; i++) w[a[i] " [mxfs]"] = 1} ($0 in w) {print NR}' /sys/kernel/tracing/available_filter_functions | tr '\n' ' ')
[ -n "$idx" ] || { echo "NO_FUNCTION_FOUND"; exit 1; }
echo $idx > $I/set_ftrace_filter || { echo "FILTER_WRITE_FAILED"; exit 1; }
echo 16384 > $I/buffer_size_kb
echo function > $I/current_tracer || { echo "TRACER_FAILED"; exit 1; }
[ "$3" = 1 ] && { echo 1 > $I/options/func_stack_trace || { echo "STACK_OPTION_FAILED"; exit 1; }; }
echo 1 > $I/tracing_on
sleep "$2"
echo 0 > $I/tracing_on
echo 0 > $I/options/func_stack_trace
echo "OVERRUN $(awk '/^overrun:/ {s += $2} END {print s + 0}' $I/per_cpu/cpu*/stats)"
echo "FILTER $(tr '\n' ' ' < $I/set_ftrace_filter)"
grep -v '^#' $I/trace
EOF
)
P64=$(base64 -w0 <<<"$PROBE")
timeout $(( SECS + 90 )) "$SSHP" "$HOST" "echo $P64 | base64 -d | timeout $(( SECS + 60 )) bash -s -- '$FNS' $SECS ${STACK:-0}" </dev/null 2>&1 \
    | grep -avE '^Warning:|^Unauthorized|^If you|^$' > "$EVID/$HOST.trace"
grep -q -E '^(NO_INSTANCE|NO_FUNCTION_FOUND|FILTER_WRITE_FAILED|TRACER_FAILED|STACK_OPTION_FAILED)' "$EVID/$HOST.trace" \
    && { echo "pve_trace_calls: $HOST: $(head -1 "$EVID/$HOST.trace")"; exit 1; }
grep -E '^(OVERRUN|FILTER) ' "$EVID/$HOST.trace"
python3 -I - "$EVID/$HOST.trace" "$SECS" $FNS <<'PY'
import collections, re, sys
path, secs, fns = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
# "  <comm>-<pid> [cpu] flags ts: fn <-caller"
row = re.compile(r"^\s*(.+?)-(\d+)\s+\[\d+\]\s+\S+\s+[\d.]+:\s+(\S+)\s+<-(\S+)")
calls, who, callers = collections.Counter(), collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
stacks = collections.defaultdict(collections.Counter)
cur, frames = None, []
def close():
    if cur and frames:
        stacks[cur][" < ".join(frames[1:13])] += 1
for line in open(path, errors="replace"):
    if line.lstrip().startswith("=>"):
        frames.append(re.sub(r"\+0x[0-9a-f/]+|\s*\[mxfs\]", "", line.split("=>", 1)[1].strip()))
        continue
    m = row.match(line)
    if not m:
        continue
    if "<stack trace>" in line:
        continue
    close()
    cur, frames = m.group(3), []
    comm, fn, caller = re.sub(r"\d+$", "", m.group(1)), m.group(3), m.group(4)
    calls[fn] += 1
    who[fn][comm] += 1
    callers[fn][caller] += 1
close()
for fn in fns:
    print(f"{fn}: {calls[fn]} calls in {secs} s ({calls[fn] / secs:.1f}/s)")
    if calls[fn]:
        print("   by: " + ", ".join(f"{c} {n}" for c, n in who[fn].most_common(6)))
        print("   from: " + ", ".join(f"{c} {n}" for c, n in callers[fn].most_common(4)))
    for st, c in stacks[fn].most_common(8):
        print(f"   {c}x {st}")
PY
