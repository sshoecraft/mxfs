#!/bin/bash
# clyde_wedge_diag.sh — RULE-2c-safe triage of a wedged clyde.
#
# Reads ONLY the /proc files that are safe on a wedged host:
#   /proc/<pid>/stat, /proc/<pid>/comm, /proc/<pid>/task/*/stat,
#   /proc/<pid>/task/*/stack
# NEVER touches /proc/<pid>/cmdline or /proc/<pid>/maps, and never runs
# `pgrep -f` / `ps aux` — each of those takes every process's mmap_lock, and one
# task wedged holding its own mmap_lock hangs them forever, adding unkillable
# tasks to a host that already has too many (memory
# `never-pgrep-f-on-clyde-mmap-lock-wedge`).
#
# Per RULE 2 this script NEVER reboots, shuts down or sysrqs the host.  It only
# reports.  Host recovery is the user's call.
#
# Usage: sudo tools/clyde_wedge_diag.sh [max_stacks]
set -u
MAX_STACKS="${1:-40}"

echo "=== $(date) ==="
echo "--- loadavg (1m 5m 15m running/total lastpid) ---"
cat /proc/loadavg
echo
echo "--- memory ---"
grep -E '^(MemAvailable|Dirty|Writeback):' /proc/meminfo
echo
echo "--- nvme progress over 10s (idle disk + many D tasks = deadlock, not slowness) ---"
python3 - <<'PY'
import time
def snap():
    for L in open('/proc/diskstats'):
        f = L.split()
        if f[2] == 'nvme0n1':
            return (int(f[5]), int(f[9]), int(f[12]))
    return (0, 0, 0)
a = snap(); time.sleep(10); b = snap()
print("  sectors_read/10s=%d sectors_written/10s=%d io_ticks_ms/10s=%d (of 10000)"
      % (b[0]-a[0], b[1]-a[1], b[2]-a[2]))
PY
echo
echo "--- D-state threads by comm, and by owning process ---"
python3 - "$MAX_STACKS" <<'PY'
import os, sys, collections
maxst = int(sys.argv[1])
by_comm = collections.Counter()
by_proc = collections.Counter()
sigs = collections.Counter()
total = d = 0
for p in os.listdir('/proc'):
    if not p.isdigit():
        continue
    td = '/proc/%s/task' % p
    try:
        tids = os.listdir(td)
    except OSError:
        continue
    try:
        pcomm = open('/proc/%s/comm' % p).read().strip()
    except OSError:
        pcomm = '?'
    for t in tids:
        try:
            st = open('%s/%s/stat' % (td, t)).read()
            state = st[st.rindex(')') + 2]
        except (OSError, ValueError):
            continue
        total += 1
        if state != 'D':
            continue
        d += 1
        try:
            comm = open('%s/%s/comm' % (td, t)).read().strip()
        except OSError:
            comm = '?'
        by_comm[comm] += 1
        by_proc[(p, pcomm)] += 1
        if len(sigs) < 4096 and sum(sigs.values()) < maxst:
            try:
                stk = open('%s/%s/stack' % (td, t)).read()
            except OSError:
                continue
            sigs[' <- '.join(l.split(']')[-1].strip()
                             for l in stk.splitlines()[:5])] += 1
print("  total threads=%d  D-state=%d" % (total, d))
print("  by comm:")
for k, v in by_comm.most_common(10):
    print("    %6d  %s" % (v, k))
print("  by owning process (pid, comm):")
for k, v in by_proc.most_common(8):
    print("    %6d  pid=%s %s" % (v, k[0], k[1]))
print("  stack signatures (sampled, need root):")
for k, v in sigs.most_common(6):
    print("    %6d  %s" % (v, k))
PY
echo
echo "--- SCST target device state ---"
for f in block active exported; do
    v=$(cat "/sys/kernel/scst_tgt/devices/mxfs/$f" 2>/dev/null) &&
        echo "  mxfs/$f = $v"
done
echo "  recent SCST blocking/mgmt lines:"
dmesg 2>/dev/null | grep -aE 'check_blocked_dev|scst_rx_mgmt_fn|TM ' | tail -5 |
    sed 's/^/    /'
echo
echo "--- ext4 / jbd2 health ---"
dmesg 2>/dev/null |
    grep -aiE 'EXT4-fs error|remount-ro|journal aborted|I/O error|hung task' |
    tail -8 | sed 's/^/  /'
echo "  filesystem fill (a >90% ext4 allocates slowly):"
df -h / /home /var/log 2>/dev/null | tail -n +2 | sed 's/^/  /'
echo
echo "NOTE: if the disk is idle, memory is free, and hundreds of threads sit in"
echo "ext4_buffered_write_iter, that is a LOCK deadlock on the host filesystem."
echo "Per RULE 2 a host reset is the USER'S call — document and report, never act."
