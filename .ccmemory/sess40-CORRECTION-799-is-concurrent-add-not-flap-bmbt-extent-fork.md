---
name: sess40-CORRECTION-799-is-concurrent-add-not-flap-bmbt-extent-fork
description: sess40 CORRECTION: the readdir=799 loss is NOT the TCP flap (flap-prevention build still loses it with ZERO flap events). It's a concurrent-add lost-…
metadata:
  type: project
---

## sess40 (ccloop 4cb2d0a2) — CRITICAL CORRECTION to [[sess40-REFRAME-799-is-tcp-flap-not-buffer-barrier-noop]].

### The flap is NOT the cause of readdir=799 (it was coincidental correlation)
On the flap-prevention build (`A985424B`, `dlm/peer.c` send no longer tears down on transient timeout), 8/tcp dir_reuse STILL FAILED with readdir=799 at ROUND 1 — and the failure-moment dmesg on ALL nodes had **ZERO flap events**: no "deferring death", no "reconnected — flap absorbed", no "did not reconnect", no "timed out (slow peer under load)" (my new flap-prevention log), no "communication with node lost". So there was NO transport disruption whatsoever, yet one dirent was durably lost. The earlier sess40 finding (test7 flap ↔ node7_f1 loss) was COINCIDENTAL — under the 8-node storm a flap often co-occurs but does NOT cause the dirent loss.

### What the 799 loss actually is (re-confirmed)
A concurrent multi-node dir-block lost-update — the 130-session core bug. Durable, all nodes agree, LOOKUP_ENOENT REREAD_MISS, happens even at round 1 on a FRESH dir (so NOT cross-tenure/daddr-reuse). Sub-modes seen: single dirent (readdir=799, data-block content) AND whole-block (~49 entries, e.g. node5_f*.md5). Cascades to `DABUF_MAP_HOLE` (xfs_da_btree.c:2876 — the dir's in-core extent map has no mapping for a logical block the leaf references).

### KEY UNEXPLORED LEAD (next session, RULE 4): the dir INODE / bmbt EXTENT FORK
`dataclobber` (write-chokepoint detector) and `dir_relverify` (release probe) are BOTH SILENT on this loss — but they ONLY inspect dir3 DATA/LEAF block CONTENT. They do NOT cover:
- the dir INODE buffer write (di_size / di_nextents / inline extent records), or
- bmbt (dir data-fork btree) block writes.
The DABUF_MAP_HOLE cascade = a dir logical block became UNMAPPED → its whole extent record was lost. A concurrent dir-GROWTH race (node A allocates a new dir data block + adds extent record N to the inode fork; node B's stale inode/bmbt write reverts extent N) would: (a) lose all entries in block N (the ~49-entry whole-block loss), (b) leave the leaf hash pointing into the now-unmapped block → DABUF_MAP_HOLE, (c) be INVISIBLE to dataclobber. The single-dirent (799) sub-mode may be the data-block-content variant of the same race. **NEXT: add a write-chokepoint detector for the dir INODE extent fork + bmbt blocks (compare in-core extent records / di_nextents vs disk at submit, owner=shared dir), analogous to dataclobber but for the bmbt/inode fork. PROVE whether an extent-map clobber is the root.** Also check `mxfs_submit_partial_inode_write` for the shared dir inode (false-sharing logic may interact). Reference: P60-BMBTWRITE probe already exists (xfs_mxfs_dlm.c ~982); mxfs_dir_bmbt_scan in the durable check.

### Kept fixes this session (build now `5A98FD22`)
- sess39 v2 `dir_refresh_inplace` → default 0 (was catastrophic).
- `dir_wr_barrier` → default 0 (no-op).
- TCP flap-prevention (`dlm/peer.c` + `kern.c`): transient send timeout no longer tears down socket; `mxfs_pal_tcp_send` now returns -EAGAIN (nothing sent, safe to keep+retry) vs -ECONNRESET (partial sent → desync → must reset). Helps the MASS-FAIL (membership-flap) mode; does NOT fix the 799. 8/tcp 3/6→6/8. 2/tcp 3/3 (no regression). KEEP (correctness improvement) but it is NOT the 799 fix.

### Status
8/tcp dir_reuse NOT 100% (the concurrent-add/extent-fork lost-update remains). 1/2/4 tcp not re-verified on 5A98FD22 this session (2/tcp was 3/3 on A985424B). The GPT reliability-layer roadmap ([[sess40-FIX-tcp-flap-prevention-send-no-teardown]]) addresses the flap/mass-fail mode, NOT the 799. The 799 is the dir-block/extent-fork lost-update — attack the inode/bmbt extent fork next.
