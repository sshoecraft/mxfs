---
name: AAA-ccloopcc87-sess6-fable-consult-recycle-race-hypothesis
description: sess6: Fable consult on P135 list-corruption root cause. Hypothesis: xfs_iget_recycle vs background xfs_reclaim_inode race via sess40's IRECLAIM wind…
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, build-0.10.90, RULE4, RULE5-fable]
---

## Context
Continuation of sess6's RULE-4 hunt for the P135-PRSWEEP-CYCLE root cause (self-referential `sb->s_inodes`
entry). Prior steps this session: ring-buffer mitigation (0.10.87, works but insufficient — same corruption
ALSO hangs stock kernel `drop_pagecache_sb` with zero protection, proven via live capture, see sibling memory
`AAA-ccloopcc87-sess6-ringbuf-INSUFFICIENT-worse-hang-need-tripwire`); sweep-pin tripwire (0.10.88, fired ZERO
times — refutes "pr_sweep's own pinned inode gets evicted from under it", see sibling memory
`AAA-ccloopcc87-sess6-tripwire-REFUTED-adding-heartbeat`); heartbeat instrumentation (0.10.89) proved pr_sweep
itself is NOT the long-running lock holder during the hang (goes silent 27s+ before hang starts, never
retriggers during it) — the true holder must be stock kernel code hitting the SAME corruption.

## Fable consult (RULE 5, first qualifying consult this session — bar met: complete instrumented proof,
two distinct approaches tried+refuted, architectural question)
Gave Fable the full evidence trail (P135 signature, drop_pagecache_sb impact, tripwire negative result, ruled
out direct i_sb_list manipulation and inode_init_always touching i_sb_list, only ONE inode_sb_list_del call
site in stock fs/inode.c (inside evict())). Fable's key insight:

**The self-loop signature (X self-linked + an EARLIER list node still pointing at X) can ONLY arise from
`inode_sb_list_add()` being called TWICE on the same inode without an intervening delete — NOT from a bad
evict.** Double-evict is a no-op (list_del_init on an already-self-linked node does nothing). The pointer
algebra only works if X was linked, then linked AGAIN at a new position (overwriting X's own next/prev to the
new spot, but stranding the OLD position's neighbors pointing at X) — one later evict heals the SECOND
position and self-links X, leaving the FIRST position's dangling predecessor exactly matching the observed
`visited=2..3` signature (walker steps predecessor -> X -> orbits immediately).

Fable's mechanism hypothesis: `xfs_iget_cache_hit`'s "sess40" block (xfs_icache.c ~1127-1184) sets
`XFS_IRECLAIM` (meant to be a strict test-and-set exclusivity token gating the background
`xfs_reclaim_igrab`/`xfs_reclaim_inode` walker) around a call to `mxfs_dlm_reload_inode()` (can sleep on
DLM/disk I/O during a netpartition, which is why the bug needs fault injection to reproduce), then clears it
and returns -EAGAIN for the caller to retry — enabling a second, concurrent recycle/reclaim to slip in.

## My own follow-up code read (BEFORE building/testing) partially refines Fable's exact mechanism
Read the sess40 block precisely: `XFS_IRECLAIM` set (line ~1135) and clear (line ~1181) ARE both under the
SAME continuous `i_flags_lock` hold, and `IRECLAIM` stays SET for the entire `mxfs_dlm_reload_inode()` call —
so `xfs_reclaim_igrab` (xfs_icache.c ~1914, checks `IRECLAIMABLE && !IRECLAIM` under the same lock) correctly
CANNOT win against sess40 DURING the reload itself. Fable's literal "blind set while B already owns it" framing
doesn't hold up against the actual code (Fable was reasoning from my prose description, not the source).

**Refined hypothesis**: sess40 does NOT clear `XFS_ICI_RECLAIM_TAG` (the per-AG radix-tree reclaim-candidate
tag) — unlike the real `xfs_iget_recycle` path, which does (line ~636-637). So immediately AFTER sess40
clears `IRECLAIM` and returns -EAGAIN (telling its caller "content refreshed, retry the lookup"), the inode is:
IRECLAIMABLE=true, IRECLAIM=false, tag=still-set, content=freshly-reloaded — exposed to the background
`xfs_reclaim_inode` walker for a genuine window BEFORE the caller's retry re-establishes any protection. If
the walker wins that race, it fully reclaims (frees) the inode for real while the retrying caller still
believes it's dealing with a live, cached, about-to-be-recycled inode — a race between "real reclaim" and
"someone about to recycle the same object," which is the class of bug that produces the double-link signature.

## Instrumentation added this session in response (build 0.10.90, srcversion D74F78B94E1873B2C9E1648)
Both edits in xfs/xfs_icache.c (mxfs's own forked file — could NOT hook stock `inode_sb_list_add` directly,
it's `EXPORT_SYMBOL_GPL` but only called from un-forked fs/inode.c internals):
- **P139-RECYCLE-UNLINKED** (`xfs_iget_recycle` entry, before `xfs_reinit_inode` runs): `pr_warn` + `dump_stack()`
  if `list_empty(&inode->i_sb_list)` — direct proof "we're about to recycle an inode that's ALREADY been fully
  evicted/unlinked by someone else," with a stack trace of the losing caller.
- **P140-RECLAIM-COMMIT** (`xfs_reclaim_inode`'s `reclaim:` label, right before `mxfs_dlm_evict(ip)`):
  unconditional `pr_warn` with ino/ptr/pid/comm for EVERY real eviction commit — an audit trail to
  cross-reference against P135 (pr_sweep's cycle detector) and P139 reports after the fact (which specific
  ino/ptr got reclaimed, by whom, exactly when, relative to when a corruption was later discovered).

## Next step
Re-run the identical repro (`MXFS_DEV=/dev/mapper/mpatha ./run.sh 2 caw dir_reuse_coherency fence_during_write
fault_netpartition`, live dmesg -T -w both nodes) on 0.10.90. Read results in this priority order:
1. Does P139-RECYCLE-UNLINKED fire? If yes: mechanism CONFIRMED (recycle-vs-reclaim race), stack trace shows
   the exact caller/path — proceed to design the real fix (likely: sess40 must clear XFS_ICI_RECLAIM_TAG too,
   OR must not release IRECLAIM protection until the caller has safely re-validated the inode, OR needs its
   own dedicated synchronization primitive rather than relying on the ambient IRECLAIM/tag state before retry).
2. If P139 does NOT fire but P140-RECLAIM-COMMIT shows a reclaim landing suspiciously close (same ino, small
   time delta) to a LATER P135/P139-would-be corruption window: still strong circumstantial support, refine
   further (e.g. the double-add might route through xfs_iget_cache_MISS's iget_locked path creating a SECOND
   struct inode object for the same ino, rather than xfs_iget_recycle re-touching the SAME object as P139
   checks for — would need a parallel check in the cache-miss path too).
3. If NEITHER fires and the hang still reproduces: this specific hypothesis (sess40/IRECLAIM-tag-window) is
   refuted too; the double-add must be happening via a still-undiscovered THIRD mechanism — consider Fable's
   ranked alternative (IRECLAIM ownership assertions with an owner field, ranked #2 in its response) or
   escalate to GPT per RULE 5's chain (Fable did not resolve it).

## Reusable repro + cleanup reminders (re-confirmed painfully this session, see also sibling memories)
- ALWAYS `rm -f /tmp/mxfs_run.lock` before a fresh `cluster_reset_n.sh`/`run.sh` sequence.
- ALWAYS grep for AND kill orphaned `run.sh`/`dmesg -T -w`/bare `ssh ... root@testN <cmd>` processes (lstart
  before your own session's cluster_reset) before starting a new live-capture — the bare `ssh` grandchild
  processes (spawned by mxfs_sshpass.sh's non-exec'd final command) do NOT show up if you only grep for the
  wrapper script name; grep `"ssh .*root@test|sshpass.*root@test"` instead and filter by lstart.
- Once the hang reproduces, a NEW ssh session into the wedged node will NOT complete (sshd banner responds
  instantly, authenticated session times out even with short ServerAlive bounds) — you get exactly ONE shot
  per repro via whatever dmesg -T -w stream was already running before the hang started. Any new diagnostic
  must be pre-instrumented in the kernel and rebuilt/redeployed BEFORE the next repro attempt.
- After extracting what you need from a hung node, recover it with `cluster_reset_n.sh 2` (RULE 2 permits
  power-cycling test VMs) rather than waiting — this specific corrupted-list walk in stock
  `drop_pagecache_sb` has no natural termination (list_next_entry on a self-referential node always returns
  itself), so it will NOT resolve on its own.

## Cluster state
test1+test2 freshly reset and on 0.10.90 (ALL_OK) as of this checkpoint, about to re-run the repro.
