#!/bin/bash
# tests/kmsg_visibility_latency.sh — how long after a kernel message is STAMPED
# does it become visible to `dmesg`?
#
# WHY THIS EXISTS (sess79)
#   Twice in one session a grep for a P236 marker returned nothing, and a later
#   grep found the same line carrying a printk timestamp EARLIER than the failed
#   grep.  If kmsg visibility can lag its own timestamp, then every harness in
#   this tree that does "reproduce, then snapshot dmesg once" can record a FALSE
#   NEGATIVE — the evidence exists, the snapshot just ran too early.  That is an
#   evidence-integrity bug in the measurement apparatus, not in the filesystem,
#   and it silently converts real failures into PASSes and real fixes into
#   "no evidence" (sess27 found three of this family).
#
# THE MEASUREMENT
#   Emit a unique marker to /dev/kmsg, then poll `dmesg` for it as fast as the
#   node will answer, over a single SSH session (so per-poll SSH setup cost is
#   not charged to the latency).  Report, for each of N trials:
#     stamp_s   printk timestamp the marker carries
#     seen_s    node-local monotonic clock when dmesg first returned it
#     lag_ms    (seen_s - stamp_s) — the window in which a snapshot lies
#
# Both clocks are read ON THE NODE from the same source family
# (/proc/uptime vs printk's monotonic stamp), never from the caller's clock.
#
# usage: kmsg_visibility_latency.sh [node=test2] [trials=10]
set -u
NODE="${1:-test2}"
TRIALS="${2:-10}"
SSH=tools/mxfs_sshpass.sh

echo "kmsg visibility latency: node=$NODE trials=$TRIALS"

$SSH "$NODE" "TRIALS=$TRIALS python3 - <<'PYEOF'
import os, re, subprocess, time

TRIALS = int(os.environ['TRIALS'])

def uptime():
    with open('/proc/uptime') as f:
        return float(f.read().split()[0])

def dmesg():
    return subprocess.run(['dmesg'], capture_output=True, text=True,
                          errors='replace').stdout

worst = 0.0
misses = 0
print('%-6s %-12s %-12s %-9s %s' % ('trial','stamp_s','seen_s','lag_ms','polls'))
for i in range(TRIALS):
    mark = 'KMSGLAT-%d-%d' % (os.getpid(), i)
    with open('/dev/kmsg', 'w') as k:
        k.write(mark + '\n')
    t_emit = uptime()
    polls = 0
    stamp = None
    # 10 s ceiling: any lag beyond that is already catastrophic for a harness
    while uptime() - t_emit < 10.0:
        polls += 1
        out = dmesg()
        m = re.search(r'^\[\s*([0-9.]+)\] .*' + re.escape(mark), out, re.M)
        if m:
            stamp = float(m.group(1))
            break
    seen = uptime()
    if stamp is None:
        misses += 1
        print('%-6d %-12s %-12.3f %-9s %d  <-- NEVER VISIBLE within 10s'
              % (i, 'n/a', seen, 'n/a', polls))
        continue
    lag = (seen - stamp) * 1000.0
    worst = max(worst, lag)
    print('%-6d %-12.3f %-12.3f %-9.1f %d' % (i, stamp, seen, lag, polls))

print()
print('worst observed lag: %.1f ms   never-visible trials: %d/%d'
      % (worst, misses, TRIALS))
if misses:
    print('VERDICT: kmsg can be INVISIBLE to dmesg long after it is stamped —'
          ' single-snapshot harnesses are unsound.')
elif worst > 500.0:
    print('VERDICT: kmsg visibility LAGS its timestamp by up to %.0f ms —'
          ' a harness must poll until the marker appears, not snapshot once.'
          % worst)
else:
    print('VERDICT: kmsg is visible essentially immediately (worst %.1f ms).'
          '  A single snapshot is sound for this node; a missed marker means'
          ' the message was NOT emitted, or the reader looked at the wrong'
          ' node/boot.' % worst)
PYEOF"
