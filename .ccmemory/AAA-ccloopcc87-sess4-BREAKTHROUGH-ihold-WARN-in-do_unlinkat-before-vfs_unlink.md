---
name: AAA-ccloopcc87-sess4-BREAKTHROUGH-ihold-WARN-in-do_unlinkat-before-vfs_unlink
description: sess4 BREAKTHROUGH: live capture proves i_count already 0 BEFORE do_unlinkat's own protective ihold() runs — over-release predates vfs_unlink entirel…
metadata:
  type: project
---

## THE key new finding this session (read this section first if resuming)

Live-captured a 3rd instance of BUG3 (test3, PID 9226, comm=rm, same
`kernel BUG at fs/inode.c:1798`/`iput+0x1c5/0x250` signature) with full pid=/comm=/ip=
instrumentation active. The dmesg sequence (chronological, all same wall-clock second):

```
------------[ cut here ]------------
WARNING: CPU: 2 PID: 9226 at fs/inode.c:451 ihold+0x28/0x40
Call Trace: do_unlinkat+0x272/0x320 -> __x64_sys_unlinkat -> ...
[... P13-SFRM ino=2099074(dir) name=[n3_10] comm=rm ...]
[... P82-ADD ino=10487777 ... P25-INSTR sync-inactive ino=0xa007e1(=10487777) ip=ffff8e238338e400 pid=9226 comm=rm ...]
[... P19-B3DEC ino=10487777 ... will_skip=0 (genuinely proceeds to free — gen matched, no B1-B5 fired) ...]
[... P9-INSTR ifree DONE ... P25-INSTR sync-inactive-DONE ino=0xa007e1 rc=0 ip=ffff8e238338e400 pid=9226 comm=rm ...]
------------[ cut here ]------------
kernel BUG at fs/inode.c:1798!
RIP: iput+0x1c5/0x250, Comm: rm, PID 9226
Call Trace: do_unlinkat+0x2d1/0x320 -> __x64_sys_unlinkat -> ...
```

**This is decisive.** `ihold()`'s own kernel-internal assertion is
`WARN_ON(atomic_inc_return(&inode->i_count) < 2)` — firing means the NEW post-increment
count was 0 or 1, i.e. i_count was ALREADY ≤0 the instant BEFORE `do_unlinkat` took its
own protective hold. Two different offsets within the SAME `do_unlinkat` frame
(`+0x272` for the ihold WARN, `+0x2d1` for the later iput/crash) match stock Linux
`do_unlinkat()`'s well-known structure: `ihold(inode)` BEFORE calling `vfs_unlink()`
(so it can still safely reference `inode` afterward for `fsnotify_unlink()`), then
`iput(inode)` AFTER, to drop that same temporary hold. fs/namei.c is generic VFS code —
MXFS does not (and should not) patch it.

**The implication: the over-release has ALREADY happened before `do_unlinkat` even calls
`vfs_unlink()`** — i.e., before ANY of the mxfs_inactive/B1-B5/sync-inactive machinery this
session spent most of its time on even runs for THIS unlink call. All of that machinery
(P25-INSTR, P19-B3DEC, P2L-INACT-LEAK, xfs_inactive's B1-B5 gate) is DOWNSTREAM, entered
later in the SAME do_unlinkat call (via vfs_unlink -> ... -> eventually the LATER iput at
+0x2d1 driving the actual eviction) — it is NOT where the bug lives, just where its
consequences get logged. Whatever zeroed i_count already happened by the time
`do_unlinkat` reaches `+0x272`, i.e. essentially immediately after path lookup
(`user_path_at`), before `vfs_unlink` starts.

Given the crashing task's OWN PID (9226) is confirmed as the one hitting the WARN (not a
foreign thread) — the leading hypothesis going into next session: **this exact inode
number was very recently freed+reused within rm's OWN shell loop** (this stress workload
unlinks many files in a tight loop from one shell script), and `do_unlinkat`'s path lookup
for the NEXT filename resolved to a dentry/inode whose refcount bookkeeping was ALREADY
broken by a PRIOR iteration's cleanup in this same process, OR — more likely given
everything else learned this session — some MXFS-side path (still unidentified) drops an
extra reference on this inode asynchronously (a kworker, bast/reclaim path, NOT
necessarily synchronous within rm's call chain) in the narrow window between rm's
`user_path_at` lookup and its `ihold()` call, i.e. a genuine cross-thread race after all —
just happening EARLIER (at lookup-to-ihold time) than anything previously suspected
(bast_notify, bast_process, trans_drain_inode_unlocks were all suspected as running LATER,
downstream of vfs_unlink, which per this finding is already too late — the damage is done
by then).

## What to check next (in priority order)

1. **Confirm do_unlinkat's actual structure** — I ran out of turn budget verifying this
   directly against `/src/linux/fs/namei.c` (grep for `do_unlinkat` returned nothing,
   possibly a stale grep or the file needs a different read approach — try `Read` directly
   on `/src/linux/fs/namei.c` and search, or check Ubuntu 6.8's actual source if available
   via `apt-get source` — NO, that would violate RULE 1's "never download kernel source";
   instead reason from the offsets/WARN semantics alone, which already strongly support
   the ihold-before/iput-after structure without needing the exact source).
2. **This completely reframes where to look**: stop auditing bast_notify/bast_process/
   bast_dwork_fn/trans_drain_inode_unlocks as the FIRST place to look (a background
   subagent already exhaustively, script-verified audited bast_notify's ~15 exit paths
   this session and found NO over-release there — only a separate, wrong-polarity
   reference LEAK bug at 4 sites, worth fixing later but not urgent/not BUG3). Instead:
   figure out what runs BETWEEN "rm's path lookup resolves the dentry" and "do_unlinkat's
   own ihold() call at +0x272" for THIS inode number, on a live 8-node cluster, that could
   drop a reference. This is a much narrower window than previously assumed.
3. **Best diagnostic next step**: since the bug manifests as i_count being wrong AT THE
   VERY MOMENT do_unlinkat looks up the dentry, consider instrumenting XFS's own
   dentry-to-inode lookup path (`xfs_iget`/`xfs_lookup`) or watching i_count immediately
   after lookup, for the SPECIFIC inode about to be unlinked, cross-referenced against ALL
   ihold/iget/irele/iput call sites cluster-wide for that ino in a tight time window before
   the crash — not just the mxfs-side "release" machinery already instrumented.
4. Consider whether this is actually a **cross-NODE** race (a peer's concurrent action on
   the SAME just-recycled inode number) rather than same-node — given the extreme
   inode-number reuse rate under this specific $HOT-directory workload (16 names per rank,
   8 nodes, continuous create+unlink+recreate), and given this codebase's EXTENSIVE prior
   history of exactly this hazard class (see `caw-sess5-STALER-identified-reload-inode-and
   -levers-tried` and related memories), a peer node reusing the SAME inode number and some
   BAST/reload interaction touching THIS node's cached dentry/inode before rm's own lookup
   completes is a strong candidate — but this time the timing window is BEFORE vfs_unlink,
   not during xfs_inactive as previously assumed.

## State of the tree (as of this write)

- VERSION unchanged: 0.10.84. Latest srcversion: 2AE187BE67804705D03578C — diagnostic-only,
  matches convention (bump VERSION only when an actual proven fix lands).
- The unsafe B2 "fix" from earlier this session was FULLY REVERTED (see sibling memory
  `AAA-ccloopcc87-sess4-BUG3-B2fix-REJECTED-topologyA-confirmed` for full detail) — do NOT
  re-apply it; both GPT-5.6 and Fable independently confirmed it trades a crash for silent
  disk corruption.
- Diagnostics live in tree (all safe, capped, no behavior change): P126-DEMOTE-RACE (fires
  often, NOT correlated to BUG3, separate issue), P2L-EX-GENMIS (forensic-only tripwire,
  not yet observed firing), P127-TRANSDRAIN (not yet observed), ip=/pid=/comm= on
  P25-INSTR/P19-B3DEC/P2L-INACT-LEAK/INACT-SKIP-STALE (VERY useful — this is what cracked
  open the finding above; keep these).
- A background subagent exhaustively (script-verified, not eyeballed) audited ALL ~15 exit
  paths of `mxfs_dlm_bast_notify` (xfs_mxfs_dlm.c ~14871-15659) — confirmed NO over-release
  there. DID find a real but wrong-polarity reference LEAK at 4 sites
  (~15361-15365/15494-15498/15556-15561/15640-15644: `queue_work()`-already-pending false
  branches missing an `xfs_irele(ip)`, unlike 3 sibling sites that get it right) — worth
  fixing eventually (resource exhaustion under sustained load) but does NOT cause BUG3
  (a leak keeps i_count artificially HIGH, opposite of what a premature-eviction crash
  needs). Its recommendation to look at `mxfs_dlm_bast_process` (~10974, ~3000 lines) next
  is SUPERSEDED by this session's later finding above — the bug is earlier than any of
  that machinery, so don't spend the next session's budget there first.
- Full-combo (`dir_reuse_coherency`+`fence_during_write`@8/caw) repro count this session:
  10 iterations run, 3 hit BUG3 (iters 1, 2, and this last one on test3), 1 hit a SEPARATE
  softlockup (bast_notify's xfs_irele/iput/evict contending with umount's evict_inodes,
  not yet investigated further — may or may not share a root cause with BUG3), 6 clean.
  ~30% hit rate this session, consistent with historical ~20-25% estimate.
- Live per-node `dmesg -T -w` streaming (via `mxfs_sshpass.sh test$n /tmp/.mxfs_pass
  "dmesg -T -w" > logfile &`, one per node, killed+relaunched fresh before each iteration)
  is the technique that made all of this possible — the host-side serial console log
  (`/var/log/libvirt/qemu/test<N>-serial.log`) is loglevel-filtered and MISSES all
  `pr_warn`-level diagnostics entirely, only showing the bare crash trace. Keep using live
  `dmesg -T -w` capture for any further hunting.
- criteria.json / matrix_check.py's "100% PASS" surface reading is STALE and not to be
  trusted (see sibling memory for detail) — do not use it as evidence of criteria
  satisfaction. task #5 (full fresh 1/2/4/8/16/32 sweep) cannot proceed until BUG3 has an
  ACTUAL PROVEN fix, validated across many more clean iterations than achieved so far
  (0 clean iterations of any actual fix — the only fix attempted this session was
  reverted).
