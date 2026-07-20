---
name: sess41-DEFINITIVE-loss-is-insert-time-not-writeback-ring-proven
description: sess41 DEFINITIVE (ring count-trace): dir_reuse loss is INSERT-time (entry never durably added) — NOT clobber/reorder/writeback. No count regression…
metadata:
  type: project
---

## sess41 (ccloop 4cb2d0a2) — DEFINITIVE: the dir_reuse loss is an INSERT-TIME drop, not a writeback/clobber/reorder. Build `5E7CC562` (dirland/choke_merge default OFF → == keeper functionally).

### Three independent ring/merge measurements, all converging:
1. **merge inert (dko=0 always)** → in-core ⊇ disk at every dir-data write → NO stale-base / stale-cache RMW clobber.
2. **landing ring: NO cross-incarnation reorder** (only daddr=120/block0 has >1 incarnation, strictly forward round→round; all other daddrs single-incarnation) → NO older/stale write of a reused daddr winning.
3. **count-augmented ring: NO count regression during the CREATE phase** — every data block's active-dirent count is MONOTONIC up; the ONLY count drops are `comm=rm` (legit teardown). A non-rm small drop search returned EMPTY.

### CONCLUSION: the lost dirent is NEVER durably added to a data block.
The dir ends create-phase with 799 (one short), no block ever "had it then lost it". So it is dropped AT INSERT (concurrent addname / leaf-node split / data-block allocation during dir growth), NOT clobbered later. This RECONCILES + CONFIRMS sess17 (insert-time, P35E showed the entry absent from the EARLIEST captured block image) with hard ring evidence, and REFUTES sess40's writeback-overlap/reorder theory and sess41's own reuse-ordering hypothesis.
- Victims observed: node3_f46.md5, node6_f3.md5, node7_f20.md5, node7_f16.md5 (.md5 sidecars), and node5_f43 (a DATA file) — so it is NOT .md5-specific; any concurrently-added entry can be dropped. After the loss, rounds cascade to readdir=0 (DABUF_MAP_HOLE) — the known cascade.
- mht=1000 (long holds, few handoffs) STILL FAILED → not handoff-frequency.

### Serialization paradox (the crux for next session): EX is serialized (no double-grant), yet a committed add is dropped at insert. Possible mechanisms:
- A leaf/node SPLIT or block→leaf→node CONVERSION (triggered by dir growth during the create storm) drops an entry that another node added in the prior tenure — i.e. the splitting node's in-core structure or freeindex/bestfree is subtly inconsistent with the just-added entry, and the split/rebalance loses it. (sess22 leaf-hash family.)
- A data-block ALLOCATION during growth: the new block's content/freeindex races.
- The add is committed to the LOG but the buffer image written omits it (freescan/bestfree miscompute after a concurrent modify).

### NEXT (RULE 4): instrument the ADD path, not writeback.
- Tools ready (build 5E7CC562, all default-off): `mxfs.dirland=1` → in-kernel landing ring with per-block dirent COUNT, dumped on fail via `echo 1 > /sys/module/mxfs/parameters/dland_dump` (the test does this automatically on readdir-miss); `tests/drc_cap8.sh N "dirland=1"` saves per-node dumps to /src/mxfs/tests/tcp/drc_cap/dland_<host>.txt. Overhead-free (NOT DRC_STREAM, which is ~4min/round).
- Add an addname-path probe: in xfs_dir2_node_addname / xfs_dir2_leafn_add / xfs_da3 split, log when a specific just-added name's slot/hash is dropped or relocated during a concurrent split, gated by a light flag. OR: at the END of each node's create wave, before sync, have the node verify (in-core) that all its OWN just-created names are present (read-back) — if a node's own f43 is already gone in-core right after creating it, the loss is local-insert; if present in-core but gone after the peer's next tenure, it's cross-tenure split.
- Compare the dir FORMAT at the loss round (block vs leaf vs node) — the growth/conversion correlation suggests instrumenting the conversion boundary.
See [[sess41-DEFINITIVE...]] supersedes [[sess41-PROVEN-799-is-post-submit-writeorder-not-stalebase-merge-dead]] and [[sess41-landing-ring-no-reorder-loss-is-creator-entry-never-durable]]; cross-ref [[sess17-detector-refutes-enforce-and-cc-flaky-pass]] (insert-time), [[sess22-FIX-node-format-datascan-leafhash-heal]].
