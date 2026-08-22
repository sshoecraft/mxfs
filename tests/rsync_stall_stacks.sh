#!/bin/bash
# rsync_stall_stacks.sh [participants] [sample_s]
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess388)
# ----------------------------------------
# rsync_paired lap 1 runs ~14s on every node; lap 2+ (rename-over-existing
# delta) has a straggler tail of 27-55s that fails the done-barrier for all 32
# nodes.  Probe COUNTS inside the precise window were inconclusive (inode-DLM
# waits summed to ~1s/node; the AG-wait probe is capped), so — exactly like
# tests/create_stall_stacks.sh — this harness reads the straggler's wall off the
# kernel instead of guessing: a detached sampler on every node polls the kernel
# stack of every rsync/sync task at 10 Hz for the whole run, and the histogram
# of blocking call sites per node IS the anatomy.
#
# It runs the REAL criterion (./run.sh N caw rsync_paired) on whatever FS state
# the cluster is in (age it with prior laps first), so the result it annotates
# is the board's own FAIL/PASS line.
#
# Output: per-node sample counts, elapsed, and the top blocking edges (first
# mxfs/xfs frame below the scheduler prelude), plus a fleet-wide histogram.
set -u
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"
P="${1:-32}"
DUR="${2:-150}"
STAMP=$(date -u +%H%M%S)
OUT=$(mktemp -d)
LOG="/tmp/rss_${STAMP}.log"

# Detached in-node sampler.  pgrep -x matches comm only (safe per RULE 2c).
SAMPLER=$(cat <<EOS
nohup setsid bash -c '
end=\$(( \$(date +%s) + $DUR ))
while [ \$(date +%s) -lt \$end ]; do
  for p in \$(pgrep -x rsync; pgrep -x sync); do
    st=\$(cut -d" " -f3 /proc/\$p/stat 2>/dev/null)
    case "\$st" in R|"") : ;; *)
      wc=\$(cat /proc/\$p/wchan 2>/dev/null)
      fr=\$(sed -n "s/^\[<[0-9a-fx]*>\] //p; s/^ *//p" /proc/\$p/stack 2>/dev/null | tr -d "\r" | head -14 | paste -sd"|" -)
      [ -n "\$fr" ] && echo "SAMPLE \$p \$st [\$wc] || \$fr at \$(( \$(date +%s%N) / 1000000 ))"
    ;; esac
  done
  sleep 0.1
done
echo SAMPLER_DONE' > $LOG 2>&1 < /dev/null &
echo armed
EOS
)

echo "=== rsync_stall_stacks: P=$P dur=${DUR}s stamp=$STAMP out=$OUT ==="
armed=0
for i in $(seq 1 "$P"); do
    ( timeout 20 "$SSH" "test$i" "$SAMPLER" 2>/dev/null | grep -q armed && echo ok > "$OUT/arm$i" ) &
done
wait
for i in $(seq 1 "$P"); do [ -f "$OUT/arm$i" ] && armed=$((armed+1)); done
echo "samplers armed: $armed/$P"

t0=$(date +%s)
( cd "$REPO" && timeout 200 ./run.sh "$P" caw rsync_paired ) > "$OUT/run.log" 2>&1
echo "run rc=$? wall=$(( $(date +%s) - t0 ))s"
grep -E "  (PASS|FAIL)  rsync_paired" "$OUT/run.log" | head -2
RD=$(ls -dt /tmp/run_rsync_paired_* 2>/dev/null | head -1)
echo "run dir: $RD"

# Let the samplers expire, then pull.
left=$(( DUR - ( $(date +%s) - t0 ) + 2 ))
[ "$left" -gt 0 ] && sleep "$left"
for i in $(seq 1 "$P"); do
    ( timeout 30 "$SSH" "test$i" "cat $LOG" 2>/dev/null | grep -v Warning > "$OUT/n$i.txt" ) &
done
wait

python3 - "$OUT" "$P" "$RD" <<'PY'
import sys, os, re, glob
from collections import Counter, defaultdict
out, P, rd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
prelude = re.compile(r'^(__schedule|schedule|schedule_timeout|schedule_preempt|_raw_spin|mutex_lock|__mutex|rwsem|down_|__down|up_|wait_|prepare_to_wait|io_schedule|finish_wait|msleep|schedule_hrtimeout|do_nanosleep|hrtimer|__x64|do_syscall|entry_SYSCALL|ret_from|kthread|__wait|bit_wait|out_of_line|__flush_work|flush_work|wait_for_completion|__wait_for_common|__lock_page|folio_wait|wake_up|__cond_resched|preempt|__mxfs_pal_cond|mxfs_pal_cond_timedwait|mxfs_pal_cond_wait|blk_|submit_bio|__submit|wbt_|rq_qos|io_|try_to_wake|mxfs_pal_msleep|usleep|__schedule_timeout|common_nsleep|do_select|poll_|__x64_sys_(select|poll|read|write|wait))')
def edge(frames):
    fr = [f.split('+')[0] for f in frames.split('|') if f]
    core = [f for f in fr if not prelude.match(f)]
    if not core:
        return '|'.join(fr[:2]) or '?'
    return '|'.join(core[:3])
fleet = Counter(); pernode = {}
elapsed = {}
for i in range(1, P+1):
    raw = os.path.join(rd, f"test{i}.raw") if rd else ''
    if raw and os.path.exists(raw):
        m = re.search(r'elapsed=([0-9.]+)', open(raw, errors='replace').read())
        elapsed[i] = float(m.group(1)) if m else None
    c = Counter(); n = 0; blocked = 0; comms = Counter()
    for line in open(os.path.join(out, f"n{i}.txt"), errors='replace'):
        if not line.startswith('SAMPLE'): continue
        n += 1
        try:
            head, rest = line.split('||', 1)
            frames = rest.rsplit(' at ', 1)[0].strip()
        except ValueError:
            continue
        st = head.split()[2]
        blocked += 1
        e = edge(frames)
        c[e] += 1; fleet[e] += 1
    pernode[i] = (n, blocked, c)
order = sorted(pernode, key=lambda i: -(elapsed.get(i) or 0))
print("\n=== per node (sorted by elapsed) ===")
for i in order:
    n, b, c = pernode[i]
    top = ', '.join(f"{k}={v}" for k, v in c.most_common(4))
    print(f"test{i:<3} elapsed={elapsed.get(i)} samples={n} :: {top}")
print("\n=== fleet blocking-edge histogram (top 25) ===")
tot = sum(fleet.values()) or 1
for k, v in fleet.most_common(25):
    print(f"{v:6d} {100*v/tot:5.1f}%  {k}")
# stragglers vs fast: edges over-represented in nodes with elapsed > 25s
slow = [i for i in order if (elapsed.get(i) or 0) > 25]
fast = [i for i in order if 0 < (elapsed.get(i) or 0) <= 20]
def agg(ids):
    c = Counter()
    for i in ids: c.update(pernode[i][2])
    return c
cs, cf = agg(slow), agg(fast)
print(f"\n=== slow ({len(slow)} nodes) vs fast ({len(fast)} nodes): top slow edges with fast share ===")
ts, tf = sum(cs.values()) or 1, sum(cf.values()) or 1
for k, v in cs.most_common(15):
    print(f"slow {v:5d} ({100*v/ts:4.1f}%)  fast {cf.get(k,0):5d} ({100*cf.get(k,0)/tf:4.1f}%)  {k}")
PY
echo "raw samples: $OUT"
