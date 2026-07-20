---
name: sess28-HANDOFF-head-build-C1B4BFC0-next-step-3way-merge
description: sess28(ccloop) HANDOFF HEAD: keeper build C1B4BFC0 (all levers off == prior 164A6D5D). Loss=WRITE-SIDE confirmed. Next: NFS-stream P-WMERGE+mode to p…
metadata:
  type: project
---

## sess28 HANDOFF HEAD — where the next session starts

### CRITERIA: 1/2/4/8 tcp dlm 100%. NOT MET. Sole blocker = 8/tcp dir_reuse_coherency durable dirent loss (readdir<800). 1/2/4 tcp green.

### Keeper: build **C1B4BFC0** (deployed via NFS /src/mxfs/mxfs.ko). ALL sess28 levers DEFAULT OFF -> behaviorally == prior keeper 164A6D5D. Working modargs (NOT default): `dir_gen_per_handoff=1 dir_modify_extent_adopt=1`. Cluster CLEAN, 8 nodes up.

### THE decisive sess28 finding (RULE 4, clean cluster): the loss is WRITE-SIDE; the read is fully coherent.
- diff1=0 over 300 samples (in-core dir block == platter at addname), p28c=0, rdmiss=1, corrupt=0. Read-side fix (dir_addname_coherent) is a DEAD END. See [[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]].
- P-WMERGE classifier (dir_writeprobe=1): clobbering dir-data writes are MOSTLY **pure-stale** (incore_extra=0, disk_extra>0 — test1 daddr=120 disk_extra=153 = reverting 153 peer entries) + a few **MERGE-NEEDED** (incore_extra>0 AND disk_extra>0). See [[sess28-FINAL-writeside-suppression-all-variants-fail-merge-needed]].
- ALL drop-suppression FAILS: full subset_guard -> readdir=316 (drops legit merge-needed); pure-stale-only (incore_extra==0) -> SHUTDOWN (structurally unsafe; a legit REMOVE also looks pure-stale). See [[sess28-REFUTED-subset-guard-overfires-catastrophic-readdir316]].

### NEXT STEP (RULE 4, two phases):
1. **DIAGNOSE EX-vs-NL** (build C1B4BFC0 already has it): the P-WMERGE probe now logs `held_mode` (mxfs_v5_dlm_inode_held_rawmode) + in_ail + dirty + bgen for each clobbering write. BUT the dmesg ring ROTATES under the 498s run (messages lost before grep). MUST stream to NFS like sess27's drc_catch3 (DRC_STREAM=1 -> /src/mxfs/tests/tcp/drc_cap/stream_rankN.log). Add an NFS-stream wrapper to drc_one.sh OR reuse drc_catch3. Then read held_mode for the pure-stale writes:
   - held_mode==EX -> the EX HOLDER is destaging a base that went stale AFTER its addname (a peer added between our addname and our destage). Fix = capture the RMW base per dir-data buffer (b_mxfs base snapshot) and do a 3-WAY MERGE (base, ours, disk) at the write chokepoint: graft disk dirents NOT in base (peer adds) into ours, do NOT re-graft base dirents we removed. This resolves the remove-vs-peer-add ambiguity that breaks naive union.
   - held_mode==NL/0 -> a released-tenure stale write; the EXISTING P16/P17 mxfs_buf_xfsaild_skip_dir_write (default on) should suppress it but doesn't -> find the predicate gap (it samples mode at queue time, re-check at submit like the P61 bmbt chokepoint already does).
2. **IMPLEMENT** the chosen fix. The 3-way merge needs a per-dir-data-buffer base snapshot (taken at first modify of the tenure, like the shortform reload base). sess21 union-merge offset-collision caution: rebuild bestfree (xfs_dir2_data_freescan) + place grafted dirents in genuinely-free space + fix block-format leaf-entry array.

### Tooling (tests/tcp/): drc_one.sh (single run, EXTRA=modargs, captures p28c/p26/p12/rdmiss/corrupt/P-WMERGE-merge-vs-stale), drc_diag.sh (multi-run), drc_platter.sh. ALL need NFS-streaming added to beat dmesg ring rotation on long runs.
### INFRA: a background driver SURVIVES `pkill -f <name>` and keeps spawning run.sh -> contaminates concurrent runs (TWO drivers mkfs the same LUN = false read-divergence, false 0/8 cascades). ALWAYS `ps -eo pid,etime,cmd|grep -E 'drc_|run.sh 8 tcp'`, kill driver PID explicitly, verify 0 before trusting an 8-node result. This cost hours in sess28 (the early P28W "read-side" REAL hits were contamination artifacts).
