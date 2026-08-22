---
name: ccloop-c7ee71c6-sess241-aglock-orphan-ondisk-evidence-slotdump
description: sess241: built tools/caw_slotdump; ON-DISK proof: all 25 AGs EX-held no waiters, ag=N by bit N; test30 gets -EAGAIN on ITS OWN ag=13 bit — lost in-me…
metadata:
  type: project
---

# sess241 — AG-lock orphan livelock: on-disk evidence captured

New critical defect from sess240 (rsync_paired FAIL 0/32 on 0.11.488, test30 rsync livelocked in mxfs_ag_dlm_lock_bounded). NOT yet ledgered.

## Tool
`tools/caw_slotdump.c` (NEW): dumps the on-disk CAW slot table via SG_IO READ(16)+FUA (same transport semantics as kernel read_slot). Build by hand: `gcc -Wall -Wextra -O2 -I../include -o caw_slotdump caw_slotdump.c` (deliberately not added to Makefile). Usage: `caw_slotdump /dev/sdb --type ag`. Slot table = super->disklock_offset + 64*512; 65536×512B slots; prints HB table (bit→node_id) first.

## On-disk truth (captured live during the livelock)
- ALL 25 AGs held EX, `wmode=NL`, zero waiter bits (NOQUEUE trylock registers none).
- Affinity: ag=N held by node-bit N for N=1..24, except ag0→bit25, ag3→bit28, ag13→bit12.
- bit12 = node_id 4022113226 = **test30 itself**. test30 holds ag=12 AND ag=13 EX on disk.
- test30's P5G sweep skips ag=12 silently (in-mem tracked → fast path OK) but prints P5G "peer-held" for ag=13 — its OWN on-disk bit, with lmod refreshed continuously (something CASes that slot each cycle).
- Other AG slots' lmod ≈ 02:38–02:44Z (written during the rsync run by the CURRENT incarnation — not leftovers of the earlier failed clean-slate pass, though verify per-node mount times before fully ruling that out).
- fs 2% full → not space. Peers idle, P12-AGBAST-RX holders=0 cached=0.

## Hypothesis (open)
In-memory hold state (pag_dlm_* flags and/or caw ctx->held tracking) lost for on-disk-retained EX grants on ~26 nodes; CAW lock treats an UNTRACKED own bit as a peer's hold (fast paths that return success on own-bit require is_tracked_held) → -EAGAIN forever, self included. The sess20 mxfs_ag_strand_repair (called from the P12 orphan_nak branch, requires holders=0 && !cached && !bast_scheduled && pending>3s) exists for EXACTLY this state but did not fire/repair in 20+min of BASTs — prime open question; suspect bast_scheduled stuck true, or repair mis-detection.

## Key code
xfs_mxfs_dlm.c:36651 (bounded sweep/P5G), :35897 (__mxfs_ag_dlm_lock fast paths), :40960-41100 (P12 RX + orphan_nak + strand repair call); dlm_caw.c:3637 (caw_adopt_retained, mount-window only), :9584 (self_held_scan); v5_mount.c:5909/6018.

## State left
test30 STILL livelocked (PID 18371, unkillable) — kept for evidence. Cluster otherwise idle on 0.11.488. Next: ledger defect; peer dmesg (sched= in P12 prints, strand-repair prints); read mxfs_ag_strand_repair; then destroy/start test30 and finish board.
