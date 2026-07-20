---
name: sess101_lessons
description: sess101 — unlink_visibility FIXED (286311EE): acquire-side drain_evict was SKIPPING in-AIL/dirty dir blocks → stale-base durable clobber. Now evict a…
metadata:
  type: project
---

# sess101 (2026-06-06, ccloop run 29df431e) — unlink_visibility FIXED

## BUILD `286311EE` (KEEP) — unlink_visibility PASS (rc=0, 36s, 4 nodes)
The last failing cache_coherency subtest. ONE-LINE root + fix below.

## ROOT (PROVEN via RULE-4 write-trace + Gemini RULE-5 reconcile)
Acquire-side `mxfs_dir_drain_evict_data_blocks` (xfs/xfs_mxfs_dlm.c ~L766) gated its
clear-XBF_DONE evict on `DONE && !dirty && !in_ail && !pinned && !delwri`. The
`!in_ail` guard was the LOST-UPDATE SOURCE: a node acquiring dir EX during the
concurrent create/delete storm kept its OWN in-AIL cached dir block (committed but
log-tail-pending) and RMW'd that STALE base, durably DROPPING a peer's just-committed
dirents. Manifested as a node's own `rm` returning ENOENT on a CONTIGUOUS RANGE of
files IT created ("rm: cannot remove node3_file2..19: No such file or directory"), no
I/O error — a peer had clobbered them from a stale base; other nodes then saw them as
survivors.

## FIX: evict (clear XBF_DONE only — NOT xfs_buf_stale) ALL non-pinned dir blocks
Changed the gate to `(DONE && !pinned)`. in-AIL/dirty/delwri are now evicted too;
only PINNED stays a hard skip (clearing DONE on pinned corrupts, sess64; the bounded
drain loop above already log_force+waits the pin tail). Leaf/node/freeindex blocks are
covered automatically — the loop iterates EVERY block in the dir data-fork extent map.

## WHY SAFE NOW (the sess96/99-vs-sess69 contradiction, RESOLVED by Gemini)
sess99 found "aggressive acquire cold-read returns stale SCST content" and reverted —
but that PREDATED publish-before-notify (sess97). Pre-publish, the releaser unlocked
before its data fenced to SCST media, so a cold-read raced an unflushed write. NOW
publish-before-notify (log_force SYNC + xfs_bwrite each dir block + blkdev_issue_flush,
EX held, post-commit) fences every committed dir change to the LUN before any peer is
told ⇒ a plain cold-read reliably sees the durable image (sess69 PROVED raw O_DIRECT
byte-identical across initiators = transport coherent). Clearing XBF_DONE on a
clean-but-in-AIL buf is SAFE: BLI stays attached, AIL keeps old (already-durable) LSN,
next read cold-fetches, next modify re-logs. xfs_buf_stale is DANGEROUS here
(drops rhashtable entry while AIL refs it → ghost/duplicate buf cache corruption).

## DECISIVE INSTRUMENT that cracked it (reuse this)
P-DIRWR write-trace (pal/linux/xfs_buf.c:2003) logs every dir-block write {node,daddr,
active=count-stale,comm,realns}. KEY: SYNC the 4 nodes' wall clocks first
(`date -u -s` to a common second on all nodes — they drift ~1.5s/node, breaking any
realns merge), then merge all 4 nodes' P-DIRWR by realns into one timeline per daddr.
Result: DELETE-phase writes MONOTONIC (no delete clobber) ⇒ the clobber is CREATE-phase
acquire-stale-base. comm=xfsaild also writes dir blocks (intermediate, benign). Capture
note: kernel ring overflows during the create burst — the create-phase writes were lost
to the ring; the rm-ENOENT signature was what nailed create-phase.

## ALSO this session (minor, keep)
- Re-enabled the fast-path EX `dir_ex_stale_refresh` evict (P101-FASTEX-EVICT, ~L3290):
  it NEVER fires (fast-path stale_base=0 always — a node holding EX cached means no peer
  modified, confirmed) so it's harmless/defensive. The REAL fix was slow-path drain_evict.

## NEXT (next session — criteria NOT yet met, marker NOT written)
1. `virsh destroy/start test1-4` clean reboot → `reset4.sh 4` deploys 286311EE.
2. Re-verify rename_visibility STILL PASS + cross_visibility + cross_write_read (the
   drain_evict change could affect them). Then full `tests/criteria/cache_coherency.sh
   --nodes 4` must be 4/4. The read-path twin `mxfs_dir_evict_data_blocks` (L379) STILL
   has the old `!in_ail` skip — if a survivor/visibility (not rm-ENOENT) residual shows,
   apply the SAME in-AIL-safe evict there (clear DONE on non-pinned).
3. Then `tests/criteria/verify_ship.sh` end-to-end — all 12 criteria in ONE run.
4. Watch: intermittent bnobt double-free shutdown (~1/2 runs, separate blocker).
Related: [[sess98_gpt_fix_design]] [[sess97_lessons]] [[sess69-ondisk-proof-durable-lostupdate]]
