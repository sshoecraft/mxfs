#!/bin/bash
# create_stall_stacks.sh [files_per_node] [participants]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess24)
# ----------------------------------------
# tests/create_scale_curve.sh measured, on the live cluster, per-create latency
# vs number of participants:
#
#   P            1     2     4     8    16    32
#   private p50  5     6     7     8    12    11   ms   <- unchanged by N
#   private mean 5.2   9.2  10.8  26.0  71.7 191.8 ms   <- 37x by N
#   shared  mean 5.9  13.1  29.6  61.2 108.2 247.9 ms
#
# p50 is FLAT in N.  The mean explodes purely from a tail (mean/p50 = 17-25x at
# P=32), and it does so even with PRIVATE per-node directories, so it is not
# dirent/leaf serialisation.  Each node spends ~2.2s on 8 creates of which only
# ~88ms is fast-path work: every node hits roughly ONE multi-second stall per 8
# creates, and the stall rate grows with node count.
#
# Guessing which lock that is would violate RULE 4.  This harness instead reads
# the answer off the kernel: while the 32-way create workload runs, a sampler on
# each node polls /proc/<writer>/stack + wchan at 50ms and records every sample
# where the writer is blocked.  The resulting histogram of blocking call sites IS
# the diagnosis -- no hypothesis required to collect it.
#
# Output: top blocking stack frames ranked by sample count, plus the per-sample
# state, so a 2s stall inside (say) mxfs_ag_dlm_lock is distinguishable from one
# inside xfs_log_force or xfs_buf_iowait.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
F="${1:-8}"
P="${2:-32}"
MNT=/mnt/shared
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)

# Worker + in-node sampler in one payload so the sampler knows the writer's PID
# exactly (no pgrep races against 32 concurrent nodes).  The sampler writes
# "SAMPLE <state> <wchan> || <frame> | <frame> | ..." lines only while the
# writer is NOT in R state, so a fast create contributes nothing.
PAYLOAD=$(cat <<'EOS'
set -u
D="$1"; F="$2"; R="$3"
mkdir -p "$D" 2>/dev/null
line="CSS r$R"$'\n'
s="$line"; while [ "${#s}" -lt 4096 ]; do s="$s$s"; done
pat="${s:0:4096}"

# The writer runs in a subshell whose PID we know.  It signals each create's
# latency so slow creates can be correlated with the samples by timestamp.
(
  prev=$(date +%s%N)
  for i in $(seq 1 "$F"); do
      printf '%s' "$pat" > "$D/n${R}_css_$i"
      now=$(date +%s%N)
      echo "OP $i $(( (now - prev) / 1000000 )) at $(( now / 1000000 ))"
      prev=$now
  done
  echo WRITER_DONE
) &
wpid=$!

# Sample the writer subshell.  printf-redirect creates happen in THIS shell, so
# the blocking task is $wpid itself.
while kill -0 "$wpid" 2>/dev/null; do
    st=$(cut -d' ' -f3 "/proc/$wpid/stat" 2>/dev/null)
    case "$st" in
        R|"") : ;;
        *)
            wc=$(cat "/proc/$wpid/wchan" 2>/dev/null)
            frames=$(sed -n 's/^\[<[0-9a-fx]*>\] //p; s/^ *//p' "/proc/$wpid/stack" 2>/dev/null \
                     | tr -d '\r' | paste -sd'|' -)
            [ -n "$frames" ] && echo "SAMPLE $st [$wc] || $frames at $(( $(date +%s%N) / 1000000 ))"
            ;;
    esac
    sleep 0.05
done
wait "$wpid" 2>/dev/null
echo SAMPLER_DONE
EOS
)

echo "=== create_stall_stacks: P=$P F=$F stamp=$STAMP ==="
DIRB="$MNT/.css_${STAMP}"
"$SSH" test1 "mkdir -p '$DIRB'" >/dev/null 2>&1
for i in $(seq 1 "$P"); do
    ( "$SSH" "test$i" "bash -s '$DIRB/r$i' '$F' '$i'" <<< "$PAYLOAD" \
        > "$OUT/n$i.txt" 2>&1 ) &
done
wait

python3 - "$OUT" "$P" <<'PY'
import sys, os, re, glob, statistics
from collections import Counter
out, P = sys.argv[1], int(sys.argv[2])

samples, ops, nodes = [], [], 0
for p in sorted(glob.glob(os.path.join(out, "n*.txt"))):
    seen = False
    for ln in open(p, errors='replace'):
        if ln.startswith('SAMPLE '):
            m = re.match(r'SAMPLE (\S+) \[([^\]]*)\] \|\| (.*) at (\d+)', ln.strip())
            if m:
                samples.append((m.group(1), m.group(2), m.group(3).split('|'), int(m.group(4))))
                seen = True
        elif ln.startswith('OP '):
            f = ln.split()
            if len(f) >= 3:
                ops.append(int(f[2])); seen = True
    nodes += 1 if seen else 0

print(f"nodes reporting={nodes}  creates={len(ops)}  blocked samples={len(samples)}")
if ops:
    ops.sort()
    print(f"per-create ms: mean={statistics.fmean(ops):.1f} p50={ops[len(ops)//2]} "
          f"p95={ops[min(len(ops)-1,int(len(ops)*.95))]} max={max(ops)}")
if not samples:
    print("\nNO BLOCKED SAMPLES -- either /proc/<pid>/stack is unreadable (needs "
          "CONFIG_STACKTRACE + root) or the stall is not in this task's context.")
    sys.exit(2)

print(f"\n=== task state while blocked ({len(samples)} samples) ===")
for st, c in Counter(s[0] for s in samples).most_common():
    print(f"  {st:4s} {c:6d}  {100.0*c/len(samples):5.1f}%")

print(f"\n=== wchan ===")
for wc, c in Counter(s[1] for s in samples).most_common(12):
    print(f"  {c:6d} {100.0*c/len(samples):5.1f}%  {wc}")

# The MXFS/XFS frame nearest the top of stack is the actual blocking site; frames
# above it are generic scheduler/wait plumbing that tell us nothing.
GENERIC = re.compile(r'^(__schedule|schedule|schedule_timeout|schedule_preempt_disabled'
                     r'|io_schedule|__wait_on_|wait_for_completion|__mutex_lock'
                     r'|mutex_lock|rwsem_down|down_read|down_write|__down|msleep'
                     r'|usleep_range|hrtimer|schedule_hrtimeout|bit_wait|out_of_line_wait'
                     r'|__lock_|percpu_|_raw_|do_syscall|entry_SYSCALL|__x64_sys)')
print(f"\n=== nearest non-generic blocking frame ===")
site = Counter()
for st, wc, frames, ts in samples:
    pick = None
    for f in frames:
        f = f.strip()
        if not f or GENERIC.match(f):
            continue
        pick = f.split('+')[0]
        break
    site[pick or ('?generic:' + (frames[0].strip().split('+')[0] if frames else '?'))] += 1
for f, c in site.most_common(20):
    print(f"  {c:6d} {100.0*c/len(samples):5.1f}%  {f}")

print(f"\n=== full stack of the 3 most common blocked signatures ===")
sigs = Counter(' | '.join(f.strip().split('+')[0] for f in s[2][:14]) for s in samples)
for sg, c in sigs.most_common(3):
    print(f"\n  [{c} samples, {100.0*c/len(samples):.1f}%]")
    for f in sg.split(' | '):
        print(f"      {f}")
PY
rc=$?
echo "=== cleanup ==="
"$SSH" test1 "rm -rf '$DIRB'" >/dev/null 2>&1
echo "=== raw samples in $OUT ==="
exit $rc
