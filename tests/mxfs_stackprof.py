#!/usr/bin/python3
"""mxfs_stackprof.py — poor-man's wall-clock kernel profiler for a rig node.

WHY: probe COUNTS (P50-RD 5646, P68-EVDECIDE 12069, ...) tell you what the
code did, not where the wall went.  RULE 4 needs wall time tied to a NAMED
wait.  This samples /proc/<pid>/stack of the workload tasks at a fixed rate
and histograms the blocking stack, which is exactly that: a task found in
stack S on f% of ticks spent f% of its wall blocked in S.

Runs ON a node (deployed by tests/cc_stackprof.sh).  Output is a plain-text
histogram written to OUT so the harvester can just cat it.

usage: mxfs_stackprof.py <duration_s> <out_path> [hz]
"""
import os
import sys
import time
from collections import Counter

# Task comms the crash_consistency / dirent workloads run under.  D-state
# tasks are ALWAYS sampled regardless of comm (that catches kworkers doing
# the DLM drain, xfsaild, and anything else blocked in the FS).
WORKLOAD_COMMS = {
    "dd", "md5sum", "sync", "bash", "sh", "cat", "stat", "touch", "rm",
    "cp", "rsync", "ls", "mkdir", "dirent_durability", "fio",
}
# Frames that carry no attribution — every blocked stack ends in these.
BORING_PREFIXES = (
    "__schedule", "schedule", "schedule_timeout", "schedule_preempt_disabled",
    "io_schedule", "context_switch", "__switch_to", "ret_from_fork",
    "entry_SYSCALL", "do_syscall_64", "x64_sys_call", "__x64_sys_",
    "kthread", "worker_thread", "process_one_work", "rest_init",
    "arch_call_rest_init", "start_kernel", "secondary_startup",
)
# sess127: stacks containing any of these get their own tick-occupancy
# section — the DLM release (holder) side of an inode handoff.
FOCUS = ("mxfs_dlm_bast", "mxfs_drain_ilock_read", "mxfs_dlm_ilock_drain")


def frames(pid, tid):
    try:
        with open("/proc/%s/task/%s/stack" % (pid, tid), "rb") as f:
            raw = f.read()
    except OSError:
        return None
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        # "[<0>] func+0x12/0x34"
        line = line.strip()
        if not line.startswith("[<"):
            continue
        sym = line.split("]", 1)[-1].strip()
        sym = sym.split("+", 1)[0]
        out.append(sym)
    return out


def signature(fr):
    """Deepest -> shallowest, dropping scheduler/syscall boilerplate.

    Returns (top_wait, short_sig).  top_wait is the single most specific
    blocking function; short_sig is up to 4 informative frames, which is
    what distinguishes 'blocked in xfs_dialloc' from 'blocked in xfs_create'.
    """
    keep = [s for s in fr if not s.startswith(BORING_PREFIXES)]
    if not keep:
        return None, None
    return keep[0], " < ".join(keep[:5])


def main():
    dur = float(sys.argv[1])
    out = sys.argv[2]
    hz = float(sys.argv[3]) if len(sys.argv) > 3 else 20.0
    period = 1.0 / hz

    top = Counter()
    sig = Counter()
    percomm = Counter()
    # sess127: the release (holder) side, not the requester side.  sess126
    # proved ~100% of workload blocking wall is caw_wait_for_grant on the
    # mount root, and the open question is WHY the PR holders do not release
    # under the EX BAST.  A tick-level occupancy of the BAST worker answers
    # it directly: if the worker is blocked in mxfs_drain_ilock_read on a
    # large fraction of ticks the drain is the blocker; if it is absent, the
    # holders are not stalled in the release pipeline at all and the defect
    # is elsewhere (never-BAST'd, or release/re-acquire churn).
    focus = Counter()
    focus_top = Counter()
    focus_ticks = 0
    ticks = 0
    sampled = 0
    deadline = time.time() + dur

    while time.time() < deadline:
        t0 = time.time()
        ticks += 1
        tick_focus = False
        try:
            pids = [d for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            break
        for pid in pids:
            try:
                with open("/proc/%s/stat" % pid, "rb") as f:
                    st = f.read().decode("utf-8", "replace")
            except OSError:
                continue
            # comm is parenthesized and may contain spaces/parens
            rp = st.rfind(")")
            if rp < 0:
                continue
            comm = st[st.find("(") + 1:rp]
            state = st[rp + 2:rp + 3]
            if state != "D" and comm not in WORKLOAD_COMMS:
                continue
            try:
                tids = os.listdir("/proc/%s/task" % pid)
            except OSError:
                continue
            for tid in tids:
                fr = frames(pid, tid)
                if not fr:
                    continue
                t, s = signature(fr)
                if t is None:
                    continue
                sampled += 1
                top[t] += 1
                sig[s] += 1
                percomm["%s|%s" % (comm, t)] += 1
                if any(f.startswith(FOCUS) for f in fr):
                    focus[" < ".join(
                        x for x in fr if not x.startswith(BORING_PREFIXES))] += 1
                    focus_top[t] += 1
                    tick_focus = True
        if tick_focus:
            focus_ticks += 1
        dt = time.time() - t0
        if dt < period:
            time.sleep(period - dt)

    with open(out, "w") as f:
        f.write("# mxfs_stackprof ticks=%d samples=%d dur=%.1f hz=%.1f\n"
                % (ticks, sampled, dur, hz))
        f.write("## TOP-WAIT\n")
        for k, v in top.most_common(40):
            f.write("%8d  %s\n" % (v, k))
        f.write("## SIGNATURE\n")
        for k, v in sig.most_common(40):
            f.write("%8d  %s\n" % (v, k))
        f.write("## PER-COMM\n")
        for k, v in percomm.most_common(40):
            f.write("%8d  %s\n" % (v, k))
        f.write("## FOCUS %s ticks=%d of %d (%.2f%%)\n"
                % ("/".join(FOCUS), focus_ticks, ticks,
                   100.0 * focus_ticks / max(ticks, 1)))
        for k, v in focus_top.most_common(20):
            f.write("%8d  TOPWAIT %s\n" % (v, k))
        for k, v in focus.most_common(20):
            f.write("%8d  FULL %s\n" % (v, k))


if __name__ == "__main__":
    main()
