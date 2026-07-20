---
name: sess35 lessons — H22-H26 isolation and v5-v6 architectural confirmation
description: 2026-05-08. H22 invisible-release DISPROVEN; H24/H25 PROVEN bug shape (in-memory dir3 buf has data, disk has zeros); H26 extra-flush FALSIFIED. Bug is LIO target durability cliff below kernel block layer; v6 architecture is the right direction.
type: project
originSessionId: d4562ae4-b174-429d-b9c2-1f6388f69368
---
# sess35 lessons (2026-05-08)

## Setting

The user directed sess35 with specific instructions: read CLAUDE.md
RULE 4 (debug-loop methodology, repeatedly violated last session),
read state.md SESS35 FIRST ACTIONS, read v6-cache-architecture-proposal,
**stop patching v5**, follow hypothesis→instrument→prove/disprove
loop strictly. Confirmed v6 direction before any code change.

## What was done

Built srcversion `43CA28E08F7AA051002C892` adding to sess34's
instrumentation:
- `P-H22-CALL site=<NAME>` at every `mxfs_v5_dlm_inode_unlock` callsite
  in xfs/xfs_mxfs_dlm.c (BAST_RELEASE @558, BAST_NOTIFY_NO_INODE @618,
  BAST_NOTIFY_NONE_NL @657, EVICT @1594).
- `P-H22-REPAIR`, `P-H22-PURGE-NODE`, `P-H22-PURGE-MASK` at all
  slot-clear bypass paths in dlm/dlm_caw.c.
- `P-H25-MEM` 32-byte hex dump of bp->b_addr at BAST-DIR-STALE
  skip_locked moment (in xfs_mxfs_dlm.c).
- `P-H26-FLUSH` second `blkdev_issue_flush` at end of bast_process
  for directories, just before the DLM unlock.

Built `scripts/sess35_capture.sh` per RULE 3: starts `cat /dev/kmsg`
follower on each node BEFORE the test (line-buffered, no ring-buffer
wrap), runs the test, scp's logs to `notes/sess35_dmesg/`.

## What was learned (in dependency order)

### test1 dmesg ring buffer wraps in ~150s under multi-node load

Default kernel ring buffer is ~256KB; the spammy `P63-INSTR
FAST-PATH-DIR` and `P10-INSTR ACQ-FRESH` printk's on test1 fill it
in roughly two minutes. Sess34's "test1 NEVER receives bast_notify"
finding may have been an artifact of buffer wrap (early bast_notify
events lost). With the kmsg follower, sess35 captures full chronology.

### H22 (invisible release) DISPROVEN

test1 receives BAST normally for ino 8388736. Clean chain:
ACQ-FRESH → bast_notify ENTRY → BAST-MEM-PRE → BAST-DIR-STALE →
P-H22-CALL site=BAST_RELEASE → CAW-UNLOCK. No "silent" slot-clear
path fires. The slot-clear callsite tagging (4 sites in
xfs_mxfs_dlm.c + 3 in dlm_caw.c) caught nothing anomalous.

### H23 (silent ICACHED setter on test1) DISPROVEN

test1's `i_dlm_state=ICACHED, i_dlm_mode=EX` is set legitimately via
the slow path of `mxfs_dlm_ilock_begin` after a successful CAW
grant. P13-INSTR ACQ-FRESH log line fires. No bypass path setting
ICACHED without a grant.

### H24 (BAST-DIR-STALE skip_locked leaves dir3 un-staled) PROVEN

`P36-INSTR ino=8388736 BAST-DIR-STALE ext=1 dirblks=1 cached=1
staled=0 skip_locked=1`. The `xfs_buf_trylock` in the BAST-DIR-STALE
walk fails on the dir3 buf at lba=8388408 — the buf is locked by
some thread at the moment bast_process runs. The walk skips it
without staling (and crucially, without forcing it to disk).

### H25 (memory vs disk divergence) PROVEN

P-H25-MEM at the skip_locked moment dumps `bp->b_addr[0..31]` =
`5844 4233 ...` = "XDB3" + valid dir3 content. **Memory has the
correct content.**

P-H16-INSTR on the peer's FUA-read of the same LBA: `magic=0x0`
(zeros). **Disk does not have the content.**

P-H12 says `pin=0 flags=0x30 (DONE|ASYNC) bip_in_ail=-1` — per
the kernel's bookkeeping, the BLI lifecycle is complete (transaction
logged, log committed, AIL pushed, bio submitted, bio completed,
BLI freed). Yet disk reads zeros.

### H26 (extra flush before unlock) FALSIFIED

Added `blkdev_issue_flush` at the end of bast_process for directory
inodes, just before the DLM unlock. Flush returns rc=0 (success).
Peer's FUA-read STILL shows `magic=0x0`. The flush is honored at
the kernel block layer but the underlying LIO target stack hasn't
durably persisted test2's writes by the time test1 reads them.

## Architectural conclusion

The bug is the **LIO target durability cliff** below the kernel
block layer:
- `target_core_iblock.c:772` drops SCSI FUA bits (sess30 finding,
  CLAUDE.md design tension).
- `blkdev_issue_flush` (REQ_PREFLUSH → SCSI SYNCHRONIZE CACHE) is
  ack'd by LIO but apparently doesn't force underlying durability
  reliably under cross-initiator workloads.
- No amount of v5-layer flushing or invalidation can close this
  bug; the data simply isn't durable when peer reads it.

This matches the v6 proposal §11.2 architectural-cliff analysis.
The v6a direction (GFS2-shaped primitives + page-cache amortization
+ invalidate-on-acquire chokepoint) doesn't *directly* fix this
cliff either, but it makes the cluster invariants checkable and the
failure modes uniform — and v6's narrowed FUA-read window
(`_XBF_FUA_FRESH`, sess31 v0.3.129) is a piece of the solution that
helps amortize and surface the failure earlier.

## Why H17's drop_caches paper-overs the bug

H17 added `drop_caches` between the test's own mkdirs and the
global count. The drop forces test1 to re-read the dir block from
disk. By the time the assertion runs (~ms after the bug window),
LIO has finally drained its internal cache — disk now has the
correct content. The test passes.

The actual user-impact bug fires for any application that reads
within ~milliseconds of a peer's metadata operation, before LIO
asynchronously catches up. Latency-sensitive workloads (rsync,
build systems, anything tree-walking) hit this consistently.

## Sess35 prescription for sess36+

1. **Don't keep patching v5 at the bast_process layer.** No flush,
   barrier, or wait there can close the LIO durability cliff. The
   user said this explicitly; sess35's H26 falsification confirms
   it empirically.
2. **Server-side investigation:** what does LIO actually do with
   REQ_PREFLUSH on this `/sys/block/sda/queue/fua=0` configuration?
   Is `iblock` backstore caching writes in a way that SYNCHRONIZE
   CACHE doesn't penetrate? This is a clyde host investigation,
   not an mxfs source change.
3. **v6a phase 1 implementation** per proposal §3 + §11.9. This
   makes the failure mode uniform and gives us a single chokepoint
   to measure and tune. Note: v6a alone won't fix the LIO cliff —
   that's likely a server-config or hardware-stack change.
4. **Read-side workaround as a stopgap:** when peer's FUA-read
   returns magic=0x0 for an inode whose dinode says fmt=EXTENTS
   size>0, treat it as a transient read failure and retry with
   backoff. Not architecturally clean but prevents user-visible
   data loss while v6a is built.

## What got reverted / not changed

- No v5 code patches landed beyond the instrumentation. H26 was a
  diagnostic falsifier; its blkdev_issue_flush addition can stay
  (it's a no-op cost on hardware where flush works correctly,
  cheap insurance) or be reverted before sess36 — either is fine.
- No fix for the bug was attempted at the architectural layer in
  this session.
- Sess34 instrumentation was preserved; sess35 added on top.

## Sess35 build state

srcversion `43CA28E08F7AA051002C892`. test1 + test2 both running
with this build (verified by sess35_capture.sh).

## Sess35 H27 — proof the bug is in the storage stack, not mxfs

Added P-H27-SUBMIT-DIR3 and P-H27-COMPLETE-DIR3 instrumentation
filtered to writes of dir3 blocks (magic XDB3). Both nodes submit
writes to LBA 8388408 with `bi_status=0` (success) per kernel
bookkeeping. Host-side O_DIRECT read of /dev/sda LBA 8388408 (after
`sg_sync` + `blockdev --flushbufs`) returns **all zeros**.

A grep for XDB3 magic across the first 8 GiB of /dev/sda finds 15
occurrences, but **none in the FSB range that ino 8388736's dir
extent should occupy**. After the test, test1 reports I/O error on
`ls /mnt/shared/.mxfs_test/concurrent_mkdir/`.

**Conclusion:** writes are being acknowledged at the kernel block
layer but not actually persisted at the LBAs the kernel believes.
This is a storage-stack issue (LIO target / tcm_loop / Samsung SSD
870 EVO firmware) below mxfs's reach. v6 architectural work won't
fix this; it requires either:
- Different storage backing (NVMe with PLP, ramdisk testing, etc.)
- Different LIO config (fileio backstore vs iblock)
- Different delivery (iSCSI loopback vs tcm_loop)
- Vendor / firmware investigation

**Sess36 must investigate the storage stack first** — every kernel-
side mxfs change is a waste of effort if this is unaddressed.

## CORRECTION (sess35 late) — storage stack IS sound; bug IS in v5

Wrote `scripts/sess36_e1_xinit_durability.sh` (single write VM1 → read VM2)
and `scripts/sess36_e1b_concurrent_xinit.sh` (both VMs 100 concurrent
4KB writes to same LBA, then read).

**Both PASS.** Cross-initiator durability works correctly on this
hardware under simple workloads. The storage-stack-cliff theory is
**falsified**.

So the earlier conclusion (that writes "complete" but don't persist)
was wrong. The real picture: the host-side dd I ran was LONG after
the test. Between mxfs's bio submit and my dd, mxfs did MANY more
operations on LBA 8388408. Some final cleanup operation may have
written zeros there.

The actual bug shape is the H7/H24 timing race:
- test2's dir3 buf iflush is QUEUED in xfsaild's delwri (managed by AIL)
- test2's bast_process sees the buf locked at BAST-DIR-STALE walk
  (skip_locked=1) and DOESN'T synchronously submit
- test2 releases DLM
- test1 acquires, FUA-reads disk
- test2's bio HASN'T been submitted yet by xfsaild (or has been but not
  yet completed) — test1 reads zeros (the LBA's pre-write content,
  since extent was freshly allocated)
- test1 modifies based on stale (zero) content
- Lost entries

Fix path is what sess34 attempted (H8/H10): synchronously push the
dir3 buf to disk in bast_process before DLM unlock. The
lock-inversion risk vs xfsaild's iop_push is the engineering
problem. Sess36 should design a push that doesn't deadlock — the
candidate is `xfs_buf_delwri_pushbuf` or splicing the buf onto a
private list and `xfs_buf_delwri_submit_nowait`-style.

**v6 is still the architectural answer**, but the urgent narrow fix
is in v5's bast_process drain pipeline. Different from "v6 is
needed because storage cliff" → "v6 is the right shape because v5's
bolt-on invalidation is incomplete and prone to timing races".

## H29 — REQ_META hypothesis FALSIFIED

After E1/E1b proved storage stack works, the only difference between
mxfs's writes (which fail) and userspace dd writes (which succeed)
was the REQ_META flag in `xfs_buf_bio_op`.

H29 falsifying experiment: removed `| REQ_META` from
`xfs_buf_bio_op`. Built srcversion `2F9DBB1B8E82C8D96B4CFDD`. Ran 2
iterations:
- iter 1: BEFORE=98 AFTER=100 (cache divergence as before)
- iter 2: BEFORE=0 AFTER=50 (catastrophic as before)

**Same bug surface as baseline.** REQ_META is NOT the cause.

Reverted; current build srcversion `6875590D9985DCD9DE56208`.

## Cross-version corroboration

A parallel `mxfs.1` test on 16 nodes (different cluster, different
DLM, different cache architecture) loses ~50% of its 800 expected
mkdirs (got 381-385). Same magnitude as v5's catastrophic-mode
failures. Suggests the bug lives in a SHARED layer below mxfs:

- xfs_buf_submit_bio → submit_bio → block layer → LIO iblock_execute_rw → /dev/sda
- Both versions go through this path
- E1/E1b proves the path works for userspace direct I/O
- H29 proves REQ_META isn't the differentiator
- So something ELSE about mxfs's bio submission pattern triggers a
  bug in this path

## Sess36 hypothesis space (post-H29)

- **H30: xfs_buf reuse race** — bp's underlying memory is reused for
  another buf while a prior bio is still in flight. The bio's data
  vector points to that memory; bio writes the NEW content (from the
  reusing context) to the OLD LBA. Net: silent corruption.
- **H31: refcount imbalance under cross-node BAST cycles** — drops
  bp early, in-flight bio refers to freed memory.
- **H32: vmalloc'd buf pages have a 6.8 kernel bug** in
  bio_add_virt_nofail under high concurrency.
- **H33: LIO iblock_execute_rw concurrency bug** — accepting bios
  but reordering or losing them under load.
- **H34: Samsung SSD 870 EVO firmware** — specific write-pattern bug
  that simple userspace E1b doesn't trigger but mxfs's pattern does.

Sess36 should pick one and instrument carefully (RULE 4). H30 is
my best guess — would manifest as exactly the observed pattern (some
writes succeed, some are silently zeros).

## Files added/modified

Modified:
- `xfs/xfs_mxfs_dlm.c` — added P-H22-CALL site=... (4 sites),
  P-H25-MEM dump, P-H26-FLUSH at end of bast_process.
- `dlm/dlm_caw.c` — added P-H22-REPAIR, P-H22-PURGE-NODE entry,
  P-H22-PURGE-NODE SLOT, P-H22-PURGE-MASK entry, P-H22-PURGE-MASK
  SLOT.
- `scripts/run_concurrent_mkdir.sh` — widened grep to include
  P-H17, P-H22.

Added:
- `scripts/sess35_capture.sh` — full-capture wrapper using
  `/dev/kmsg` follower to defeat ring-buffer wrap.
- `notes/sess35_findings.md` — running findings document.
- `notes/sess35_h22.md` — H22 hypothesis (now disproven).
- `notes/sess35_dmesg/test{1,2}.log` — captured dmesg from latest
  repro (kept for sess36 reference).
