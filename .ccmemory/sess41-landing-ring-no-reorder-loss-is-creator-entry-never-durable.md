---
name: sess41-landing-ring-no-reorder-loss-is-creator-entry-never-durable
description: sess41 landing-ring (overhead-free) result: NO cross-incarnation reorder + merge dko=0 → dir_reuse loss is NOT a clobber; the creator's entry never l…
metadata:
  type: project
---

## sess41 (ccloop 4cb2d0a2) — overhead-free in-kernel landing ring built + first capture analyzed. Build `4CC3447B` (dirland/choke_merge DEFAULT OFF → == keeper functionally, NO regression).

### TOOL (works, fast, rotation-immune): in-kernel P-DLAND landing ring
- `mxfs.dirland=1` → each dir3 data/leaf/block write COMPLETION records into a 4096-entry in-kernel ring (NO printk during run → no timing perturbation, unlike DRC_STREAM which was ~4min/round).
- The dir_reuse test (tests/suite/dir_reuse_coherency.sh) does `echo 1 > /sys/module/mxfs/parameters/dland_dump` the instant it detects a readdir miss → dumps the whole ring to dmesg → captured in drc_fail_rN snapshot.
- `tests/drc_cap8.sh` copies each node's P-DLAND dump to `/src/mxfs/tests/tcp/drc_cap/dland_<host>.txt` (NFS) for offline analysis. Entry fields: `d=daddr o=owner i=incarn(i_generation) s=sum(FNV of post-header) t=realns c=comm op=ops`.
- Run: `bash tests/drc_cap8.sh 4 "dirland=1"`. Merge nodes: `cat dland_test*.txt | grep 'P-DLAND d=' | sed ... | sort by daddr,realns`.

### FIRST CAPTURE RESULT (round 2 fail, lost `node7_f16.md5` — again a .md5 2nd-wave sidecar, all nodes agree, no flap)
- Merged all 8 nodes' rings by realns per daddr (owner=131). **ONLY daddr=120 (block 0) had >1 incarnation**, and its transition was strictly FORWARD (round1 incarn → round2 incarn, monotonic realns, the normal round boundary: round-N rm/data tail → round-(N+1) fresh block-format create). **NO backward / ABA landing** (no older incarnation or older sum landing after a newer one) on ANY daddr.
- => **The cross-incarnation reuse-REORDER hypothesis (an older prior-round write of a reused daddr winning) is REFUTED for the captured rounds.**

### COMBINED CONSTRAINT (very tight): the loss is NOT a clobbering write
- merge-inert proved `dko=0` always → in-core ⊇ disk at EVERY write (no writer lacks an on-disk name → no stale-base or stale-cache RMW clobber).
- landing-ring proved no reorder → no older image re-lands.
- Together these rule out ALL "a bad write overwrites the entry" mechanisms. The remaining possibility: **the creator's entry (node7_f16.md5) is NEVER durably written** — a lost/suppressed/never-submitted write, or an insert-time drop (reconciles toward sess17's INSERT-time finding). The consistent victim = a `.md5` 2nd-wave sidecar (added when the dir is already large/converting) across MANY captures (sess41: node6_f3.md5, node7_f20.md5, node7_f16.md5; sess40-cap: node3_f46.md5).

### NEXT (RULE 4) — decisive probe to find WHERE the entry vanishes:
1. Augment the ring entry with the block's ACTIVE-DIRENT-COUNT at write completion (cheap: count non-free dir2_data entries). Then for each daddr, watch its count over the round: if a block reaches count N then a later same-incarnation write has N-1 → the loss moment + which write dropped it. If NO block ever drops a count, the entry was never added to a durable block → pursue the INSERT path (xfs_dir2_node_addname / leaf split / data-block alloc during the .md5 wave) — instrument the addname of a .md5 sidecar into the large/converting dir.
2. Cross-ref: is the lost entry's data-block write present in the ring at all? If the creator's block-with-entry never appears as a landing → the write was suppressed/never submitted (check all default-on skip paths; or a freescan/format-conversion drop).
3. The .md5-wave + dir-growth correlation strongly suggests a data-block ALLOCATION-during-growth or leaf/node CONVERSION drop, not a handoff clobber.
- mht=1000 (long EX holds, few handoffs) STILL FAILED → handoff frequency is NOT the driver (refuted).
See [[sess41-PROVEN-799-is-post-submit-writeorder-not-stalebase-merge-dead]] [[sess40-PROVEN-799-is-release-drain-gap-async-writeback-overlap]].
