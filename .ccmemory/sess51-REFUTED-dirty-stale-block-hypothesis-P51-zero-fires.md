---
name: sess51-REFUTED-dirty-stale-block-hypothesis-P51-zero-fires
description: sess51(ccloop) REFUTED the dirty+epoch-stale-block-kept hypothesis: P51-KEEPSTALE-DIRTY probe fired 0× at a single-dirent loss (round11). Base is NOT…
metadata:
  type: project
---

## sess51 (ccloop) — REFUTED: the divergent RMW base is NOT epoch-stale (P51-KEEPSTALE-DIRTY 0×)

### Test: build 65E74628 (probe-only, baseline behavior) added P51-KEEPSTALE-DIRTY firing inside mxfs_dir_evict_data_blocks when a dir DATA block at modify-evict is BOTH `dirty` (kept by the undurable guard) AND epoch-stale (`b_mxfs_dir_epoch != 0 && b_mxfs_dir_epoch < cur_mep`). 8/tcp dir_reuse, dirwr=1, clean reboot.
### Result: round 11 SINGLE-dirent loss (readdir=799/800) occurred, but P51-KEEPSTALE-DIRTY fired **0 times** (all 8 nodes / test1). (Run also then cascaded round12-14 readdir=0 = the flaky second mode again.)

### ⇒ REFUTED [[sess51-SHARPEST-mechanism-in-AIL-stale-block-needs-merge-or-drain-on-acquire]]: the clobber is NOT a dirty-AND-epoch-stale block kept by the evict guard. At RMW time the dir blocks are NOT epoch-stale (b_epoch == cur_mep — the per-block read gate IS refreshing them, or cur_mep tracks them fresh). This MATCHES sess50's "modify-base-stale REFUTED — relepoch == i_dlm_epoch at every read (base always fresh)".

### What this leaves (the hard core, unchanged since sess50): the count-preserving divergent RMW happens with a base that is FRESH by every local epoch/gen metric. Two nodes add different dirents to the same block such that one is durably lost, WITHOUT either node's local coherency signal (epoch, dir_gen, grant_gen, b_mxfs_dir_epoch) indicating staleness. The only model consistent with this + zero master double-grants + stable singular master + monotonic epoch is a TRUE PHANTOM: a node modifies under a cached EX whose grant the master has already moved to a peer, and the phantom's blocks are stamped at the phantom's own (stale-but-self-consistent) epoch so they look "fresh" locally. The local epoch machinery CANNOT detect this by construction (sess106 proved it for CAW via the on-disk slot bit; TCP has no equivalent — the held-check reads the same local mirror).

### THEREFORE the next real fix must be one of (none yet tried to completion):
1. **Master-authoritative held-check on the dir-EX fast-path for shared dirs (TCP):** add a DLM message type "do I hold EX at epoch E?" the modifying node sends to the master before/at a shared-dir RMW; if the master says no (it granted a peer), force slow-path re-acquire. This is the TCP analog of the CAW on-disk-slot check. Cost: 1 RPC per shared-dir EX op — gate to dir_gen>0 + throttle. This DIRECTLY kills the phantom.
2. **GPT's BAST-quiesce + active-user refcount (mechanism d):** ensure no local fast-path op admitted before a BAST keeps running after release. Verify the immediate (non-MHT) bast_notify→bast_process path waits for i_dlm_ex_holders==0 before releasing (the MHT dwork at :10488 does; check the immediate path).
3. Investigate WHY P-DOUBLEGRANT=0 yet two nodes modify: add a probe at the actual RMW that queries the master (not local mirror) whether we hold — if it logs held=0 at a loss, the phantom is confirmed and #1 is the fix.

### STATE: tree = clean baseline C69E3475 (byte-identical, ALL sess51 edits reverted: grant_gen, epoch-evict gate, P51 probe). Cluster may be wedged from killed repro8 — reboot+reprep next session. Marker NOT written (criteria NOT met). The flaky readdir=0 CASCADE mode (round12-14 here; also loop iters) needs separate attention — likely a node slow/wedged under storm load → transient divergence; correlate with the D-state mxfs-worker teardown wedge.
