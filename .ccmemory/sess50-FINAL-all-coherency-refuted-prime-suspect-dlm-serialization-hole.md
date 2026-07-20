---
name: sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole
description: sess50(ccloop) FINAL: ALL cache-coherency theories refuted (base always fresh, relepoch==i_dlm_epoch at every read). Prime suspect = DLM serializatio…
metadata:
  type: project
---

## sess50 (ccloop 4cb2d0a2) FINAL — every coherency-cache theory refuted; the loss is a DLM SERIALIZATION HOLE

### Build at relay: F6E61BD7-ish + relepoch_reread=0 (rebuilding to clean baseline). All sess50 changes are instrumentation + TWO dormant (default-OFF, refuted) modargs (dir_relepoch_skip, dir_relepoch_reread) + the b_mxfs_relepoch buffer field. Functionally == baseline 3B0EB406 (epoch_adopt=0). dir_reuse 8/tcp still flaky FAIL (~1 PASS/4).

### THE DECISIVE NEW EVIDENCE (P50-RD trace, build F6E61BD7, dirwr=1):
At EVERY dir-block read of inode 131: **b_mxfs_relepoch == dp->i_dlm_epoch** (would-reread count = 0 across thousands of reads). i_dlm_epoch DOES advance (1..14 over the run). So the in-core base is ALWAYS read under the CURRENT release-epoch — the existing unconditional acquire-evict (mxfs_dir_drain_evict_data_blocks, xfs_mxfs_dlm.c:15132) keeps it fresh. **The RMW base is NOT stale at modify** (confirms sess69 stale_base=0).

### COMPLETE REFUTATION MAP (this session + prior, all evidence-backed — do NOT retry):
- **stale READ** repopulating buffer: refuted (sess37 P28-PLATTER MATCH; reads coherent).
- **stale WRITEBACK reflush** (xfsaild flushes pre-release stale buffer): refuted — built the i_dlm_epoch writeback-skip gate (b_mxfs_relepoch < i_dlm_epoch, clean), reliability loop **PASS=0/FAIL=4**, and 2/4 losses had **0** skips.
- **stale MODIFY base** (GPT's modify-time stale-cache theory): refuted — relepoch==epoch at every read (base always fresh).
- **grant_gen writeback gate**: refuted (gg_mismatch=0 always; grant_gen often 0/inert).
- **content disk-superset suppression** (refresh_inplace/subset): refuted (whole-batch regression).
- **acquire LOCKED-SKIP hole** (dir_acq_lockwait=600): refuted (still 0/8).
- **Case A allocator-overwrites-live-dirent**: ruled out (xfs_dir2_data_check_free would EFSCORRUPT; loss is SILENT).
- **count-regression** (same-buffer wrote-fewer): P-COUNTREGRESS fires 0× (loss is count-PRESERVING content-divergence — one dirent replaced).

### ⇒ PRIME REMAINING SUSPECT: a DLM SERIALIZATION HOLE / PHANTOM-EX. With base-fresh + reads-coherent + EX-supposedly-serialized, the only consistent mechanism for a count-preserving single-dirent loss (varies by name = a RACE) is TWO nodes modifying the SAME dir block concurrently — i.e. the per-inode DLM EX does NOT actually serialize in some window. STRONG corroborating signal already captured (sess50 grant_gen probe + sess69): clobbers where **i_dlm_mode=EX (mode=5) but mxfs_dlm_grant_gen=0 / cur_grantgen=0** = the XFS layer holds a CACHED/PHANTOM EX not backed by a current LOCAL DLM grant (dlm/dlm.c:2406 scans local table, returns 0 = no granted lock owned by local_node). If a peer holds the real EX while this node modifies under phantom-EX → concurrent RMW → count-preserving clobber. (Note grant_gen=0 is AMBIGUOUS: phantom-EX OR a benign master self-grant that skipped dlm_next_gen — must disambiguate.)

### NEXT (RULE 4) — DECISIVE concurrent-modifier test (do this FIRST):
At the dir-modify chokepoint (xfs_dir2_data_use_free, or mxfs_dir_data_track which already runs at every dir-buffer log under EX), query the DLM MASTER's conflicting-grant view: does ANOTHER node currently hold EX/PR-conflicting on inode 131 while WE are modifying? Use/extend dlm/dlm.c count_conflicting_grants (line ~599, "the master has issued conflicting grants") or add mxfs_v5_dlm_inode_peer_holds_ex(ctx, ino). Log P51-CONCURRENT-MOD if a peer holds EX at our modify. If it fires → serialization hole PROVEN → fix the DLM (the phantom-EX: i_dlm_mode=EX while not actually granted — find why i_dlm_mode isn't downgraded when the grant is lost, OR why the master grants a peer while we hold; check the BAST/MHT paths and the fast-path EX serve at xfs_mxfs_dlm.c:14380+ which serves cached EX without re-validating the grant). If it does NOT fire → serialization is sound and the loss is elsewhere (commit/log-replay ordering; re-examine).
- GPT-5.5's owner-cookie variant (consulted 2× this session): on EX acquire write {node,epoch} to a debug sector w/ FUA; in every dir-modify primitive read+verify it's us; on release clear. Overlapping cookies across nodes = hole. More work but bulletproof cross-node proof.

### Tools added this session (all in tree): tests/drc_grantgen_probe.sh, tests/drc_timeline.sh (P50-RD/P50-WR content trace), tests/drc_reliability_relepoch.sh (8-run pass/fail loop), P50B-TENURE/xnode + P50-RD epoch fields (dirwr-gated). Storage CONFIRMED LIO-ORG, write-through, FUA reads required+on.

See [[sess50-relepoch-writeback-gate-REFUTED-loss-is-at-modify-not-writeback]] [[sess50-REFUTED-grantgen-and-tenure-counters-unreliable-handoff-underfires]] [[sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted]].</body>
