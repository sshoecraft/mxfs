---
name: AAA-ccloopcc87-sess6-ringbuf-INSUFFICIENT-worse-hang-need-tripwire
description: sess6: ring-buffer P135 fix (0.10.87) validated INSUFFICIENT — catches short cycles fast but node still wedges harder (800s+, new SSH sessions hang).…
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, build-0.10.87, RULE4]
---

## Result of validating 0.10.87 (ring-buffer P135-PRSWEEP-CYCLE, 32-entry hist) at 2/caw

Repro: `MXFS_DEV=/dev/mapper/mpatha ./run.sh 2 caw dir_reuse_coherency fence_during_write fault_netpartition`
with live per-node `dmesg -T -w` streaming (test1+test2). dir_reuse_coherency PASS, fence_during_write PASS,
fault_netpartition FAILED (timed out, nodes_pass=0/2).

**The ring buffer bailout itself works exactly as designed**: P135-PRSWEEP-CYCLE fired 5 times on test2,
each with `visited=2` or `visited=3` (near-instant detection — proves the ring catches SHORT cycles fast,
unlike v1's single-pointer check). Comms varied (kworker/u10:9, u12:27, u9:24, u11:30 x2) — sequential
pr_sweep re-triggers, not concurrent overlap (pr_sweep is one `work_struct` per mount).

**But the underlying hang is WORSE, not fixed.** Last P135 bailout: 02:59:39 (visited=3, ino=2097412).
NO further mxfs: log lines AT ALL after that — for 800+ seconds and counting (watchdog kept reporting
`CPU#1 stuck` for bash:9039 in `drop_pagecache_sb -> _raw_spin_lock` on `sb->s_inode_list_lock`, climbing
26s -> 830s+ across the whole poll window). RIP oscillates within `_raw_spin_lock+0x17/0x60` (0xe/0x19/0x21
seen too) across samples — genuinely actively spinning, not frozen on one instruction.

**New, worse symptom this session that wasn't reported in sess5**: a FRESH ssh login to test2 (separate
from the pre-existing live dmesg -T -w stream, which kept flowing fine) now HANGS too — TCP/sshd banner
exchange succeeds instantly (`nc test2 22` returns the banner immediately) but the authenticated interactive
session never completes even with ServerAliveInterval=3/CountMax=2 (~6s bound) — "Timeout, server test2 not
responding." This means the wedge is no longer confined to "one CPU spinning" — something about NEW session
setup (new process/shell) is ALSO now stuck, i.e. it's cascading/worsening over time, not a stable contained
failure. Node was still nominally "running" per `virsh domstate` and the EXISTING ssh stream kept receiving
data throughout, so this isn't a full guest freeze — just node getting less and less usable over time.

## Why this rules out "just shrink history / grow the ring buffer more"
Confirmed via code read: `xfs/xfs_mxfs_dlm.c` is the ONLY mxfs file that touches `s_inode_list_lock` or
`sb->s_inodes` (grep across xfs/*.c, pal/linux/*.c, mxfs_clayer/*.c — only hits are inside
`mxfs_dlm_pr_sweep_work_fn` itself). Traced every exit path of that function by hand: all lock/unlock pairs
are balanced, no path holds the lock indefinitely by construction. Ring buffer catches any cycle of length
<=32 (proven mathematically: for a periodic walk with period L, ring-of-32 only detects the repeat if L<=32,
since it needs node(N)==node(N-k) for k in [1,32], and node(N)==node(N-L) always by periodicity — so L>32
NEVER gets caught by a fixed-size trailing-window ring, regardless of ring size choice, unless ring size
exceeds the actual (unknown, possibly-huge or unbounded) cycle length). This means the fixed-ring approach is
structurally the wrong tool even before considering kernel-stack-size limits on a bigger array (a few KB max
on an 8-16KB kernel stack, so "just make it 4096" isn't viable anyway).

**Correct algorithm for this class of problem is Floyd's cycle detection (tortoise-and-hare)** — O(1) memory,
detects a cycle of ANY length in O(chain-length + cycle-length) steps. NOT yet implemented — flagged as the
right next mechanical fix IF the tripwire proves this really is a simple self-referencing cycle. Requires
rewriting the loop from `list_for_each_entry` macro to manual two-cursor pointer chasing (fast cursor advances
2 list-entries per step, checking `&fast->i_sb_list == head` at each step for proper termination, checking
`slow == fast` after fast has moved for cycle detection) — a bigger, more invasive rewrite of a delicate
lock-holding loop, hence NOT done reflexively; should follow proof, not precede it.

## Also: stock kernel code is UNPROTECTED regardless of what mxfs does to pr_sweep
`drop_pagecache_sb` (called from `drop_caches_sysctl_handler` -> `iterate_supers`) is 100% stock upstream
kernel code (fs/*.c, not part of the forked xfs/ tree) — it walks the SAME `sb->s_inodes` under the SAME
`s_inode_list_lock` with ZERO cycle protection and no cap. If the true bug is corruption of the shared list
structure itself (not just a bug local to pr_sweep's OWN traversal logic), fixing pr_sweep alone can NEVER
fully solve this — ANY consumer of `sb->s_inodes` (this drop_caches path, but also stock `evict_inodes`,
`invalidate_inodes`, shrinkers, `sync_filesystem`, etc.) is equally exposed. This is strong evidence the real
fix has to be at the SOURCE of the corruption (the over-release), not at any individual consumer.

## Next step (GPT's decisive experiment, from sess5's consult, not yet implemented)
Implement the "sweep-pin tripwire": track which inode `mxfs_dlm_pr_sweep_work_fn` currently holds pinned via
`igrab()` (the `toput` variable's live window, from `toput = inode` after a successful igrab, until the NEXT
`iput(toput)` call — this window can span MANY loop iterations, not just one). Store this in a new
`struct xfs_mount` field (alongside `m_mxfs_pr_sweep_work`, see xfs_mount.h). At the EXISTING
`P25-INSTR sync-inactive` hook (`xfs/xfs_icache.c:3314`, fires when an inode enters real xfs_inactive/eviction),
check whether `ip == ` that pinned pointer. If it EVER matches: direct proof pr_sweep's `igrab()`'d reference
was over-released by something ELSE (since a legitimate igrab reference should make real eviction impossible
until iput'd) — log full context (comm/pid/ino/stack via dump_stack()) to pinpoint the actual offending call
site. This is the same general bug FAMILY as BUG3 (raw ihold instead of igrab causing a phantom
resurrect/over-release) but a DIFFERENT specific site — BUG3's 3 fixes are confirmed unrelated (see
`AAA-ccloopcc87-sess5-BUG3-ROOT-CAUSE-PROVEN-FIXED-ilock_end-raw-ihold`, validated clean separately).

## Process hygiene note (unrelated to the bug, but cost real time this session)
Session 5 left FOUR separate nohup'd `run.sh` + matching `dmesg -T -w` process trees running, undetected,
for hours after relay (they got stuck on dead SSH connections once this session's `cluster_reset_n.sh`
power-cycled test1/test2 out from under them — no `ServerAliveInterval` on the ssh invocations in
`mxfs_sshpass.sh`, so a half-dead TCP connection to a destroyed VM hangs forever with no built-in liveness
check). Found via `ps -eo pid,ppid,lstart,cmd | grep -E "run\.sh|dmesg -T -w|mxfs_sshpass"` and cross-checking
lstart against the current session's own start time; had to kill ~97 stale PIDs across two passes (first
grep pattern missed the actual `sshpass -f ... ssh ... root@testN <cmd>` grandchild processes since their
cmdline doesn't contain the wrapper script's own name). **Future sessions: always check for and kill orphaned
run.sh/dmesg -T -w/ssh-root@test* processes with lstart BEFORE your own session's cluster_reset at the START
of any live-capture work** — they silently eat resources AND can run `fuser -k -m /mnt/shared` against your
live test at exactly the wrong moment (this exact cleanup command appears in fault_netpartition's own timeout
handler). Consider adding `-o ServerAliveInterval=5 -o ServerAliveCountMax=3` to `mxfs_sshpass.sh` as a
permanent fix so future dead-VM sessions self-terminate instead of hanging forever — not yet done this
session, worth doing before the next live-capture-heavy session.

## Cluster state when this was written
test2 was left in the wedged state (CPU#1 still spinning per last check, new SSH sessions timing out) —
about to be recovered via `cluster_reset_n.sh 2` (RULE 2 permits power-cycling test VMs, host itself untouched).
Once recovered, implement the tripwire, rebuild (bump to 0.10.88), redeploy, re-run the SAME repro, capture
the tripwire firing (or ruling it out) with live dmesg streaming again.
