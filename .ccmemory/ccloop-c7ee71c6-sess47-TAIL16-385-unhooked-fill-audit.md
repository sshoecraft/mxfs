---
name: ccloop-c7ee71c6-sess47-TAIL16-385-unhooked-fill-audit
description: sess47 last: 385 cycle-2 fatal (test2, store ACTIVE ov=3 skew=14) — an install path is still unhooked; NEXT: audit readahead/reverify branch + all cl…
metadata:
  type: project
---

# 385 cycle-2 fatal — overlay coverage audit is the next move

Ring test2:/root/c2_385_t2_*.dmesg: P53 ino=0x3c000cc old_ptr=0xcb (fossil shape), WITH the store demonstrably active this cycle (ov=3, skew=14 on test2 alone). Victim's fill left no probe trace ⇒ an install path bypasses BOTH overlay hooks.

## Audit list for the relay (in likelihood order)
1. **read_map "already read" branch** (pal/linux/xfs_buf.c ~1511): a buffer filled by READAHEAD (XBF_READ_AHEAD bio completes with no ops) is later verified via xfs_buf_reverify — NEVER passes the cold-fill overlay hook. Hook the reverify/ops-attach point for xfs_inode_buf_ops (overlay before first use), or hook readahead completion.
2. Any xfs_trans_read_buf / uncached / DIRECT slice readers of cluster daddrs (P34D src=plain reload reads dinodes RAW — audit whether that path feeds the BUFFER or only in-core; the P53 reads the buffer via imap_to_bp).
3. Overlay-vs-use race at the hooked sites (overlay runs after read completes but before caller sees it? verify lock/ordering — buffer lock held through both ⇒ should be race-free; confirm).
4. If all hooked and it still fires: the write side (target dropping FUA writes) → escalate to FUA cluster writes + verify-after-write policy.

## Score on 385 (v3): cycle1 CLEAN (ov=2 skew=13 fleet), cycle2 FATAL (test2). Store versions: v1 blind (retire hole), v2 blind (gendrop hole), v3 = two known holes closed, ≥1 fill path uncovered.
The A-prime machinery itself is proven sound (overlay specimens correcting exact fossil shapes); completeness of INSTALL-SITE coverage is the remaining engineering. All prior context: TAIL7-TAIL15 + END memories. Rig: test2 withdrawn (ring saved), 31 green on 385.
