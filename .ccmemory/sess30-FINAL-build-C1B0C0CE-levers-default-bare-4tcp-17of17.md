---
name: sess30-FINAL-build-C1B0C0CE-levers-default-bare-4tcp-17of17
description: sess30(ccloop) FINAL: build C1B0C0CE (4 levers now DEFAULT-1). BARE ./run.sh 4 tcp = 17/17, 1/tcp = 16/16. crash_consistency+soak FIXED. SOLE blocker…
metadata:
  type: project
---

## sess30 FINAL HANDOFF

### Build **C1B0C0CE** — criteria-ready (the 4 winning levers are now MODULE DEFAULTS=1)
`dir_release_invalidate, dir_relinval_clean, dir_gen_per_handoff, dir_modify_extent_adopt` all default 1 (xfs/xfs_mxfs_dlm.c). So **bare `./run.sh N tcp` uses the validated config** — no MXFS_EXTRA_MODARGS needed.

### Criteria `./run.sh {1,2,4,8} tcp` 100% — status
- **1/tcp = 16/16 = 100% ✓** (single-node set, no dir_reuse)
- **4/tcp = 17/17 = 100% ✓ (verified BARE run.sh, build C1B0C0CE)**
- 2/tcp = 16/17 — ONLY dir_reuse_coherency
- 8/tcp = 11/17 — dir_reuse_coherency (+ zero_silent_loss flaky, passes most runs)

### THREE verified fixes this session
1. **crash_consistency ABBA hang** (the sess21/29 PRIMARY 8/tcp wall) — FIXED, PASS 8/8 in-suite on every run. `mxfs_dir_flush_data_blocks_relsafe` (snapshot daddrs under i_lock, drop i_lock, flush via i_lock-free `mxfs_dir_flush_one_daddr`). [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]]
2. **soak** (4/tcp blocker) — FIXED. `mxfs_buf_ops_from_magic()` in xfs_buf_verify_write re-derives the verifier from on-disk magic when b_ops==NULL on a CRC fs → stamps CRC, no dump_stack. [[sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover]]
3. Levers defaulted → bare-run.sh criteria-honest.

### SOLE remaining blocker: dir_reuse_coherency (FLAKY: passed 4-node twice, failed 2-node + 8-node)
PROVEN root (RULE 4, 2-node round-2 repro, cleanest ever): **durable single-dirent TOTAL loss** — `P21H-LEAFHOLE name="node1_f10.md5" hv_in_leaf=0` + `drc-CLASS LOOKUP_ENOENT REREAD_MISS` → node1's OWN just-created dirent gone from BOTH leaf-hash AND data blocks after sync+drop_caches+cold-read. **Refined hypothesis: Invariant-1 release-flush COMPLETENESS gap** — node1's EX-release dir-data flush doesn't always destage a just-added dirent's data block before handing EX to node2; node2 cold-reads a disk version missing it (acquire-evict DID invalidate, P-DE-BLK done=0), RMWs, dirent permanently lost. The undestaged-tracking (b_mxfs_logged_seq vs written_seq) likely mis-reports the f10.md5 block as already-destaged so the release-flush skips it. At 8 nodes the rm-rf mass-free also flakily hits AGI-CRC shutdown (Face A, NOT a no-buf-ops write — P30 never fired) and a progressive dir-missing face (Face B, readdir=0/stat ENOENT).

### NEXT SESSION (RULE 4): 
Use the FAST 2-node repro (`bash tests/tcp/full8.sh 2 ""` — fails ~round 2, node1_f10.md5). Instrument the release-flush undestaged decision for the storm-dir data block carrying the about-to-be-lost dirent: prove whether needs_flush=0 (skipped as "already destaged") for a block NOT actually on disk. Refuted levers (don't retry): dir_leaf_rebuild (bnobt double-free), dir_write_merge (cross-block dups), dir_flush_lockwait (breaks Inv1), dir_postread_reread (FUA leaf tears).
Backups: xfs_mxfs_dlm.c.backup-sess30. Build deployed via NFS (/src/mxfs/mxfs.ko). See [[sess30-SCOPING-1and4tcp-100pct-dir_reuse-sole-flaky-blocker]] [[sess30-dir_reuse-insuite-cascade-is-AGI-CRC-shutdown-not-dabuf]].
