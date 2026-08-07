---
name: ccloop-c7ee71c6-sess47-TAIL10-install-site-coldfill
description: sess47 closing datum: fossil install site = COLD read_map fill of a fresh cluster buffer (P-INOCL-COLDREAD same daddr 120ms pre-P53, agno16) — A-prim…
metadata:
  type: project
---

# Fossil install site pinned (382 ring, test2 t=1383)

Sequence: P-INOCL-COLDREAD agno=16 daddr=33492000 (fence=1, cold read_map fill of a FRESH buffer) at 1383.694 → first P53 ino=0x20001a4 old_ptr=0x1a2 at 1383.817 (same AG chunk; the fossil value 0x1a2 is a neighbor agino seen in adjacent P34D src=plain reloads). Fresh-buffer fill = zero local state = gate blind (refused=0) ✓.

## Therefore
- The A-prime overlay (typed-ledger authoritative next_unlinked) must run at the **cluster cold-fill completion in read_map** (site of the existing P-INOCL-COLDREAD probe, pal/linux/xfs_buf.c ~1516) AND in coherent_reread_verify — both install paths.
- The remaining why-is-platter-stale fork is discriminated BY the ledger at overlay time: pend>flush for the slot's ino ⇒ delta never went home (teardown-with-unwritten-committed-delta arm — then ALSO find who tore down that buffer: no P-BUF-FREE-WITH-ITEMS fired, so it was clean+detached at free; the delwri write may have been skipped/cancelled); ledger says flushed ⇒ target dropped the write (LIO durability precedent) ⇒ fence/FUA-write policy escalation.
- Implementation order stands per TAIL8/TAIL9: typed ledger records first; overlay at both installs; P53-to-zero = promotion signal.
