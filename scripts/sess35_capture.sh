#!/bin/bash
# sess35: full-capture wrapper for sess34_repro.sh.
# Starts a `dmesg -W` follower on each node BEFORE the test runs, so
# the ring buffer doesn't wrap during the test (test1 generates ~1024
# log lines/sec under multi-node — the default 256KB ring buffer wraps
# in ~150s). Captures full chronology including pre-test mount + iget +
# first-acquire of every inode.
#
# Per RULE 3: persistent script lives in source tree.
#
# Usage: sess35_capture.sh <N>   — defaults to N=2.
# Output: /src/mxfs/notes/sess35_dmesg/test{N}.log on the dev host
# (collected at end via scp/ssh).

set -u
N="${1:-2}"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
OUT=/src/mxfs/notes/sess35_dmesg
mkdir -p "$OUT"

echo "=== Phase 1: cluster reset + prep + mkfs + mount ==="
/src/mxfs/scripts/cluster_reset_n.sh "$N"
/src/mxfs/scripts/cluster_mkfs_mount.sh "$N"

# Start follower BEFORE the test using /dev/kmsg which streams unbuffered.
# (dmesg -W to a pipe is block-buffered and yielded an empty file.)
echo "=== Phase 2: clear dmesg + start /dev/kmsg follower per node ==="
for n in $(seq 1 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  $SSH "$ip" "$PF" 'sudo dmesg -C; sudo bash -c "nohup cat /dev/kmsg > /tmp/sess35-dmesg.log 2>&1 < /dev/null &"; sleep 0.3; pgrep -af "/dev/kmsg"' \
    2>&1 | grep -vE 'Unauthorized|disconnect|Warning' | sed "s/^/test${n}: /"
done

echo "=== Phase 3: run test_concurrent_mkdir ==="
/src/mxfs/scripts/run_concurrent_mkdir.sh "$N" || true

# Brief settle for the follower to flush.
sleep 2

echo "=== Phase 4: stop followers + collect logs ==="
for n in $(seq 1 "$N"); do
  ip=$(getent hosts test$n.vm.localdomain | awk '{print $1}')
  $SSH "$ip" "$PF" 'sudo pkill -f "cat /dev/kmsg" 2>/dev/null; sleep 0.5; sudo chmod 644 /tmp/sess35-dmesg.log' \
    > /dev/null 2>&1
  sshpass -f "$PF" scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@${ip}:/tmp/sess35-dmesg.log" "$OUT/test${n}.log" 2>&1 \
    | grep -vE 'Unauthorized|disconnect|Warning|^$' || true
  echo "test${n}: $(wc -l < "$OUT/test${n}.log" 2>/dev/null || echo 0) lines captured to $OUT/test${n}.log"
done
