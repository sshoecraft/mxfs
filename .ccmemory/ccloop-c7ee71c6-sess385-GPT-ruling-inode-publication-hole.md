---
name: ccloop-c7ee71c6-sess385-GPT-ruling-inode-publication-hole
description: sess385 RULE-5 ruling: AG release has NO inode-log-item→home-block conversion stage; a log force is not an inode flush. Fix = quiesce/flush/pointee-f…
metadata:
  type: project
tags: [agi, unlinked, rule5, defect-361, dlm-release, invariant-1, drain]
---

## What was measured first (sess385, 32/caw, build 9FF47B72D59E6DCE4C8ECA9)

`mxfs_dlm_ag_drain_inode_buffers` never received the three hardenings the
AG-META drain got years ago after two separate corruption bugs:

| hardening | meta drain | inode drain |
|---|---|---|
| no `_XBF_DELWRI_Q` skip (v0.3.31) | yes | **NO** |
| blocking `xfs_buf_lock`, not trylock (v0.3.27) | yes | **NO** |
| pinned / BLI-attached fallthrough on empty `b_li_list` (sess77, 4dd7-sess4) | yes | **NO** |

**HOLE 1, MEASURED.** One healthy 5-test lap, 32 nodes, board all-PASS:
34 dirty inode-cluster buffers skipped at AG release (15 `_XBF_DELWRI_Q`,
19 failed trylock); of the 23 that could be FUA-read back, **10 differed from
in-core at the instant of release**, covering 13 dinodes. Architectural
Invariant 1 is violated on a green board.

Probe: `P85-INODE-DRAIN-CENSUS` / `-SPLIT`, param `mxfs.inode_drain_probe`.
NOTE: the first P85 build used a trylock in the post-walk check and got
`checked=0` on every TRYLOCK_SKIP — it could not see the case it existed to
measure. A blocking lock (same argument as v0.3.27) made all 23 checkable and
no deadlock occurred across 32 nodes.

## HOLE 2 — the deeper one, CONFIRMED by the ruling

The two halves of `xfs_iunlink` reach the medium by DIFFERENT mechanisms:

- `agi_unlinked[bucket]` and the victim's `di_next_unlinked` are **buffer-logged**
  → covered by the existing drains.
- the victim's `di_nlink = 0` comes from `xfs_droplink`, which dirties the
  **INODE LOG ITEM** (`XFS_ILOG_CORE`). It reaches the cluster buffer only when
  `xfs_iflush` runs — normally from xfsaild, asynchronously.

**A log force is not an inode home-block flush.** `xfs_log_force(SYNC)` at AG
release makes the inode item durable in OUR journal, which no peer ever replays.
Nothing in the AG release path forces the AG's dirty in-core inodes into their
cluster buffers. If xfsaild has not pushed yet, the cluster buffer is *not dirty
at all* — a "clean skip" whose in-core image and the medium agree and BOTH say
LINKED. So we publish an AGI whose unlinked head points at a home dinode reading
`nlink != 0` = the acquirer's `xfs_iunlink_reload_next` -EFSCORRUPTED inside a
dirty rename transaction.

This is **not another skipped-buffer bug — it is an omitted inode-to-buffer
conversion stage**, and HOLE-1 instrumentation is structurally blind to it.

### The hazard is far broader than di_nlink
Any field carried by the inode log item is journal-only at unlock: `di_mode`,
uid/gid/projid, `di_size`, timestamps, `di_nblocks`, extent counts, inode flags,
`di_gen`, `di_forkoff`, fork formats, local data/attr fork contents, embedded
extent records, embedded btree roots. External fork/btree blocks are separate
buffers and are fine; inode-resident state is not.

## The fix (ruling)

**HOLE 1** — harden `drain_inode_buffers` to match the meta drain: no
`b_li_list`-empty-alone skip, no `_XBF_DELWRI_Q` skip, take a ref, blocking
`xfs_buf_lock`, synchronous write, **propagate every write error, and do NOT
unlock the AG after any failure**. Re-evaluate buffer state under its lock.
Guarantee no new AG mutation can relog an inode after the drain's coverage
point, or the scan is only a moving snapshot.

**HOLE 2 — option (c), a real AG inode-publication/quiescence stage:**
1. stop admitting new local ops that can modify this AG
2. wait for existing local AG users that can hold/relog inodes to leave
3. force the log so committed inode items are unpinned
4. **flush every inode log item dirtied under that AG grant into its cluster buffer**
5. synchronously write those inode buffers
6. write dependent AG metadata
7. final cache flush
8. verify no new dirty generation appeared
9. only then release the grant

The reason both previous AIL-push attempts deadlocked was NOT "AG vs global":
the release worker took inode locks while threads that could hold those locks
were blocked behind the release itself. **If a thread can hold ILOCK_EXCL while
waiting for the BAST worker, the protocol is deadlockable no matter how narrow
the inode scan is.** Requires per-AG per-grant-epoch tracking of dirtied inodes
with stable lifetime, relog-during-flush handling, an epoch proving full
coverage, and reclaim/shutdown handling.

### Option (b) — buffer-log di_nlink in xfs_iunlink — REJECTED as the fix
Not for the reason I proposed (a later iflush of a stale in-core copy — A's
in-core nlink is already 0, so that is not the main objection). Rejected for:
dual logging authority over the same inode-core bytes; buffer-log range
granularity can replay neighbouring stale inode-core bytes; unproven replay
ordering vs earlier/later inode relogs and inode free/reuse stale-item
processing; v3 CRC/LSN rules make "store zero + xfs_trans_log_buf" insufficient;
and it fixes ONE field for ONE transition while every other inode-log-item field
stays journal-only. `di_next_unlinked`'s direct buffer management is a
deliberate unlinked-list exception, not a licence to dual-log arbitrary fields.
And never modify `di_nlink` in the buffer *without* logging it — that makes
normal writeback appear to fix it while violating recovery semantics.

### Option (a) — walk the AGI unlinked buckets — containment only
Acceptable as a narrow measure for this signature, but: locking those inodes
reproduces the same ILOCK deadlock; the AGI/chain are themselves in transition;
an inode can be added after the walk unless the AG is quiesced; and it fixes
only unlinked-list dereferences, not stale size/mode/gen/forks/reuse state.

## Ordering — pointee before pointer

Current order **maximizes** the bad crash window: it persists and flushes the
AGI (the pointer) BEFORE the inode-buffer drain (the pointee). Correct order:
inode items → inode buffers (sync) → barrier → AG metadata → final flush →
unlock.

In a purely cooperative handoff with full quiescence and no force-preemption,
intermediate order is not externally observable. It matters for crash/forced
takeover — but ordering alone can never make a multi-block XFS transaction
atomic. Crash takeover requires journal replay of the failed owner, or fencing
plus recovery, or refusal to grant until the previous owner's publication is
known complete. A peer must never force-preempt and immediately trust home
blocks.

Moving the inode drain earlier is insufficient on its own: drain → another local
op relogs an inode → second meta drain writes new AGI → unlock recreates the
split. Needs quiescence or an epoch protocol proving no post-drain mutation.

## Hazards to instrument on the blocking lock (2b)
23 successful waits prove the ordinary "xfsaild is mid-submit" case, they do NOT
disprove a DLM/local-user lock inversion. Watch for: buffer owner waiting on the
AG DLM handoff; owner holding an inode/transaction lock waiting on work that
needs this worker to return; I/O completion work on the same ordered workqueue
with all workers blocked; shutdown paths leaving a waiter on a completion that
never fires; local AG ops not actually quiesced. Under Invariant 1 a timeout may
diagnose/shutdown/fence but may NEVER be followed by unlock.

## `_XBF_MXFS_ALLOC_QUEUED` (2c)
`_XBF_DELWRI_Q` says "on some delwri protocol", not which list or owner. The
alloc queue must be drained/transferred through its own path before the generic
inode drain meets the buffer; the inode drain must not submit a partially
initialized fresh allocation buffer; one `b_list` linkage must never be treated
as belonging to both the MXFS list and xfsaild's. Assert the property via
`_XBF_MXFS_ALLOC_QUEUED` — do not infer it from `_XBF_DELWRI_Q`.
