---
name: ccloop-c7ee71c6-sess47-TAIL7-ROOT-SHAPE-merge-misses-iunlink
description: sess47 FINAL DECODE: fossil producer root shape = mxfs_buf_coherent_reread_verify's per-slot merge preserves only ATTACHED-inode-item slots — committ…
metadata:
  type: project
---

# FOSSIL PRODUCER ROOT SHAPE (sess47 final finding) — pal/linux/xfs_buf.c mxfs_buf_coherent_reread_verify (~1176)

The helper reads the platter (plain/FUA per mxfs_fua_disable) into a bounce buffer and installs it over b_addr, WITH an existing per-slot merge (sess7 "P150 sibling"): it preserves slots that have ATTACHED INODE LOG ITEMS (last-iflush images this node owns).

## The hole (fits every observation)
An iunlink di_next_unlinked write is a **buffer-log** change (xfs_trans_log_buf via the iunlink item precommit), not an inode-item attachment. After checkpoint the buffer bli detaches/cleans; and for a DEFER-REAPED ZOMBIE the in-core inode was RECLAIMED — its slot has NO attached item. The merge therefore preserves nothing for that slot and the platter's PRE-clear image (old di_next_unlinked) is installed → fossil under a current-gen core (later inode flushes rewrite core but preserve next_unlinked by design). Explains:
- victims are always zombies/chain members whose shells were reclaimed;
- P-PINNED-REREAD (read_map site) silent — this path bypasses read_map;
- inocl fence flushes don't help — if the DELWRI writeback hadn't landed, the platter is legitimately old and flush doesn't push delwri;
- dip_gen==i_gen (core laundered by later flushes);
- burst-conditioned (CRC-retry/coherent re-reads fire under torn-read storms — the 07-16 comment's exact trigger).

## Fix design space (GPT consult with this decode; precedents)
1. Extend the merge: also preserve di_next_unlinked (4 bytes/slot) for any slot whose ino has committed-undestaged changes per the P220 epoch ledger (pend>flush) — the ledger survives reclaim (per-ino, mount-level). Narrow, targeted.
2. Or: before installing the snapshot, if mxfs_buf_has_uncheckpointed_mods(bp) || buffer DELWRI → destage first (flush the buffer home), then re-read. Ordering-safe but heavier.
3. Or: preserve di_next_unlinked for ALL slots from current b_addr unconditionally when the current image passed its verifier previously — risky: a PEER's legitimate next_unlinked update to a coresident slot must not be clobbered by OUR stale copy (shared-grain! sess122 lesson) — option 1's ledger-scoped preservation avoids this (we only preserve slots WE have undestaged writes for).
Recommend: option 1 + a P-INOCL-RAWMERGE probe printing preserved slots. Verify with the aged soak (producer rate ~1/6 cycles) + the P53 falsifier.

## State
0.11.381 fleet; test2 withdrawn (cycle-6 ring saved: /root/cyc6_t2_*.dmesg); 5 clean cycles + 1 fatal. All sess47 threads in TAIL2-TAIL6 + END memories.
