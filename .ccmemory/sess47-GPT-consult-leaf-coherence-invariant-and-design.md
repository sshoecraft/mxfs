---
name: sess47-GPT-consult-leaf-coherence-invariant-and-design
description: sess47(ccloop) GPT-5.5 architectural design for the reused-dir LEAF-vs-data durable tear: release-side force-complete ALL dir-fork buffers (incl leaf…
metadata:
  type: project
---

## sess47 — GPT-5.5 consult: fix for the reused-dir LEAF-vs-data durable TEAR

PROVEN failure: on-disk TORN dir — leaf hash index references data bno=1 which the
(current, loaded_gen==dir_gen) extent map has as a HOLE -> xfs_dabuf_map !HOLE_OK ->
EFSCORRUPTED -> xfs_create trans_cancel -> shutdown. Root = a node modifies/destages a
STALE cached LEAF over a peer's durable leaf+free update.

### GPT-5.5 core invariant (the thing to enforce):
"At the instant a node releases dir EX, stable storage holds a SELF-CONSISTENT image of
the directory's data fork + LEAF/NODE index + inode extent map + alloc metadata through
the releasing tenure's final LSN; and the releasing node has NO remaining buffer / log
item / AIL item / delayed write that can modify any block of that dir after unlock."

### Concrete mechanism (priority order):
1. **Release-side: expand the flush from "dir DATA blocks" to the ENTIRE data fork —
   include LEAF/NODE/dabtree/free index blocks.** Force-COMPLETE them: write+wait, let
   NORMAL iodone retire the BLI (NOT force-abort/ail_delete — that's the refuted-harmful
   path). xfs_log_force alone is NOT enough (it makes the log durable but leaves a
   write-eligible buffer that xfsaild can destage stale AFTER unlock). Must push/wait AIL
   for ALL dir-fork buffers until clean+non-write-eligible, THEN blkdev flush, THEN unlock.
2. **Write-fence (safety belt) at xfs_buf_submit / mxfs write wrapper**: refuse to write a
   dir-fork metadata buffer unless the submitting node still holds the matching EX tenure
   (grant_seq + incarnation match). Else xfs_force_shutdown (better than corrupting shared
   LUN). Makes the stale-leaf-overwrite physically impossible.
3. **Acquire-side: invalidate ALL clean dir-fork buffers (incl LEAF/NODE, bno>=leafblk),
   not just blocks in the extent map.** Stamp every dir buffer with
   owner_ino+incarnation+dir_gen+grant_seq; refuse to dirty/write an old-tenure buffer.
4. **Once-per-handoff (NOT per-op) leaf validation**: on first LEAF read after a handoff,
   check each leaf entry's data-block ptr against the current bmap; if it points to a HOLE,
   rebuild the dir index from DATA blocks under EX (log+flush) and retry — else the
   xfs_dabuf_map hole becomes a clean rebuild instead of a shutdown. This is a GUARDRAIL;
   if #1+#2 hold it stays silent.

### Why prior attempts failed (GPT framing): postread_reread = per-op leaf reread (too
slow). The release drain currently flushes DATA blocks but the LEAF prior-tenure skip is
EXCLUDED ("never LEAF — leaf skip desyncs hashes"), so a stale/lingering-BLI leaf survives
the handoff and is destaged. The leaf is a DERIVED index: authoritative ONLY within a
tenure; across handoff it must come from stable storage after the prev holder's release
barrier OR be validated/rebuilt for the current grant — never be a casually-writable
local cache.

### GFS2/OCFS2: dirty metadata belongs to a cluster-lock tenure; demoting drains/invalidates
it; NO metadata writeback after the lock tenure ends. They do NOT rebuild the dir index per
handoff — they rely on the drain-before-demote + invalidate-on-acquire discipline.

### NEXT (RULE 4): VERIFY whether mxfs_dir_flush_data_blocks_relsafe / flush_one_daddr
actually force-completes (xfs_bwrite+wait, BLI retired) the LEAF/NODE blocks at release, or
skips/keeps them. If leaf isn't force-completed -> that's the gap -> implement #1 for leaf.
Then #2 write-fence as the belt. Keep build with the 3 sess47 wedge fixes (05BC5765-line).
See [[sess47-BREAKTHROUGH-3-wedge-fixes-8tcp-passes-sometimes-final-blocker-p13-collide]].
</body>
