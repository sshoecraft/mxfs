---
name: sess33-PROVEN-clean-inAIL-stale-reflush-not-ghost
description: sess33 DECISIVE: P-WGHOST=0 refutes mechanism B (no duplicate buffer). dir_reuse loss = CLEAN(dirty=0) in_ail=1 canonical dir buffer reflushed by xfs…
metadata:
  type: project
---

## sess33 — DECISIVE: mechanism B (ghost buffer) REFUTED; loss = clean in-AIL stale reflush

### Probe (build C0F7D69E, dir_writeprobe=1 dirwr=1): added P-WGHOST at the dir-DATA write chokepoint (pal/linux/xfs_buf.c, inside P-WMERGE block). `mxfs_dir_canonical_buf_ptr()` does an RCU-only rhashtable lookup (no lock/hold, pointer compare) → logs if the bp being destaged != the canonical rhashtable buffer for that daddr.

### RESULT on a LOSING iter (readdir 799/800, rounds 4 & 10, all 8 nodes):
- **P-WGHOST = 0 on ALL 8 nodes.** P-WMERGE fires 2-7×/node. => the destaged bp IS the canonical rhashtable buffer. **Mechanism B (duplicate/ghost xfs_buf per daddr) is REFUTED** — sess32's "8 different bp pointers in 100ms" was a HEAVY-PROBE ARTIFACT (different buffers across TIME/rounds, never two simultaneously for one daddr).
- Every P-WMERGE loss line: `owner=131 disk_extra=1 incore_extra=1 held_mode=5(EX) in_ail=1 dirty=0 pin=0 lseq=7 wseq=7 bgen=0 kind=data — MERGE-NEEDED`.

### MECHANISM (now clean, RULE 4 proven):
The loss-causing write is a **CLEAN (dirty=0), in-AIL (in_ail=1), NON-pinned canonical dir-DATA buffer reflushed by xfsaild while we hold EX**, whose content has gone STALE (disk has a peer's dirent we lack = disk_extra=1; we have our dirent disk lacks = incore_extra=1). Sequence: tenure N we addname (POST-RMW superset, durable at release) → BLI written (wseq=lseq=7) but LINGERS in AIL clean → peer acquires EX, adds its dirent to disk, releases → we re-acquire EX (held_mode=5) → xfsaild reflushes our lingering STALE clean buffer → clobbers peer's durable dirent. Mutual/symmetric across nodes = ping-pong, last writer wins, the other's dirent = durable 799.

### KEY: ALL bad writes are dirty=0 (clean). The release fence's data_durable check waits for durability/!pin/!dirty but does NOT RETIRE a clean already-written BLI from the AIL → it lingers and gets reflushed after a peer supersedes the block.

### FIX OPTIONS (next): (A) release-side AIL-retire — at EX release after data_durable, REMOVE every dir data/leaf BLI for the inode from the AIL so it can't be reflushed (GPT-endorsed, sess32-DECISIVE). (B) chokepoint suppress+invalidate of CLEAN(dirty=0) divergent dir-buffer reflushes, SYMMETRIC on all nodes (each node's active-tenure release already made ITS dirent durable; suppressing all clean stale reflushes keeps both durable → 800). NOTE sess32 "suppress relocates loss" — verify it wasn't asymmetric / didn't suppress active dirty writes. (C) merge/graft union at write (dir_write_merge exists, default 0; historically DLM-timeout). Prefer A or B (B avoids release-path deadlock risk). [[sess32-DECISIVE-A-vs-B-late-destage-toctou]] [[sess26-FINAL-root-aba-buffer-stale-bli-fua-skip-and-exact-fix]] [[sess32-HEAD-handoff]]
