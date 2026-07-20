---
name: sess69-ROOT-xfsaild-reflush-stale-dir-buffer-behind-disk
description: sess69 ROOT (precise): 4/tcp dir_reuse single-dirent loss = xfsaild flush of a dir DATA buffer 1-entry BEHIND durable disk (current-tenure stamped, s…
metadata:
  type: project
---

## sess69 PRECISE ROOT (dataclobber=1 DETECT mode, RULE 4) — write-side stale re-flush

Ran 4/tcp dir_reuse with `dataclobber=1` (detect-only; compares the dir buffer about to be written vs the CURRENT on-disk block content for EVERY multinode dir data/leaf write — covers leaf-format too, unlike P-WRACT which only fingerprints block-0/daddr=120). `P-DATACLOBBER-SKIP` fires 280× over 20 rounds. Categorized by comm/kind/stale/delta(disk_cnt-buf_cnt):

- **`xfsaild/sda kind=data stale=0 delta=1` (13×)** ← THE single-dirent-loss clobber. xfsaild background-flushes a dir DATA buffer with ONE FEWER entry than the durable on-disk block, reverting disk and durably dropping a peer's entry (the readdir=399/400 loss). `stale=0` = bufgen==dirgen (CURRENT-tenure stamp), so the sess41 `dc_stale` (bufgen<dirgen) enforce gate MISSES it → why enforce=2 didn't fix it.
- `rm kind=data stale=0 delta=1` (177×) ← LEGIT: rank1's rm-rf removing entries one at a time (buffer = disk-1 is correct).
- `*/leaf stale=0 delta=0` (75×) ← leaf rewrites, equal count, hash differs (mostly legit leaf reorg).
- `dd/bash kind=leaf stale=1 delta=275-281` (4×) ← fresh (bufgen=0) leaf clobber (leaf-hash hole vector; enforce CATCHES these via dc_stale).

### Mechanism
The clobbering buffer is a DIRTY/in-AIL dir DATA buffer holding this node's committed content that is BEHIND the durable disk image by 1 entry (disk has a peer's entry the buffer lacks). The acquire-side evict (mxfs_dir_drain_evict_data_blocks) KEEPS dirty/in-AIL buffers (undurable → not evicted) AND only CLEARS XBF_DONE on clean ones — but **clearing XBF_DONE does NOT stop xfsaild from flushing the stale b_addr content**; it only forces the next READ to re-fetch. So a lingering dirty BLI whose b_addr is behind disk gets flushed by xfsaild over the peer's newer block. This is the sess16 "lingering-BLI stale xfsaild re-flush" — confirmed, but the buffer is current-tenure-stamped (stale=0) so every bufgen/tenure-based write guard misses it.

### Why this is HARD to fix (the central trap)
The count signal `disk_cnt > buf_cnt` is AMBIGUOUS:
- legit removal (rm): buffer = disk - {name being removed by THIS txn} → would be wrongly suppressed (resurrection — this is what blanket enforce=2 did → readdir=0/400 empty dir).
- stale clobber (xfsaild): buffer = disk - {a peer's entry this node never touched}.
Count/subset comparison alone CANNOT distinguish them. The reliable discriminator is TRANSACTION INTENT (is the dropped name one this node's active txn means to remove?) — not available at the buf-write chokepoint.

### Candidate fixes (next session — pick one, INSTRUMENT before enforce)
1. **Strengthen release Invariant 1 to drain the LOG/AIL, not just bwrite the buffer**: at dir EX release, ensure NO dir BLI lingers in the AIL (log tail advanced past it) so xfsaild can never flush a post-release stale dir buffer. The sess97 fence does xfs_log_force(SYNC)+ail_push_ag_sync+xfs_bwrite but a BLI can still linger / the buffer can be re-dirtied. Verify with a probe: count dir BLIs in AIL after the release fence completes.
2. **Name-aware suppression**: suppress the xfsaild flush ONLY when comm is a background flusher (xfsaild) AND the buffer's entry-set is a strict SUBSET of disk's (disk has every buffer name plus more) — a legit rm is an active-txn write (not xfsaild) so it's exempt. Risk: an active-txn removal whose buffer xfsaild later flushes. Needs care.
3. **On acquire-evict, for a dirty/in-AIL dir buffer that is BEHIND disk (disk superset), do NOT keep-and-let-xfsaild-flush it — instead drain it to the log FIRST (checkpoint) then re-read disk and re-merge** (GPT-5.5: treat dirty/in-AIL after handoff as a protocol issue, wait clean + reload, don't skip).

### Tooling: `dataclobber=1` (detect) is the RIGHT diagnostic — keep using it. P-WRACT cap raised to 2M (build 1B683F47) but it only covers block-0 (daddr=120, block-format) so dataclobber=1 is better for leaf-format. NEVER enforce (dataclobber>=2 / dirskip=1) — over-suppresses legit removals → empty dir.

Cluster: build 1B683F47 (= baseline + P-WRACT cap bump only; functionally baseline). Marker NOT written. See [[sess69-REFUTED-dataclobber-enforce-makes-it-catastrophic]], [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]], [[sess69-DECISIVE-loss-invisible-to-detectors-double-grant-remaster]].</body>
