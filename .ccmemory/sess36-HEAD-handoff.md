---
name: sess36-HEAD-handoff
description: sess36 HEAD: build CF57F8AB=keeper-equiv. Loss PROVEN = stale WRITE (release-drain/AIL-push of content-stale block), base missing a peer entry that I…
metadata:
  type: project
---

## sess36 HEAD — read first. CRITERIA NOT MET (1/2/4 tcp pass on keeper; 8/tcp blocked by dir_reuse readdir=799 single-dirent durable loss).

### BUILD on disk = CF57F8AB = keeper 4703FA18 + 2 A/B levers BOTH DEFAULT 0 (== keeper): dir_grant_evict (sess10/61 grant-gen modify-evict) + dir_conv_genbump (refuted). SAFE, no regression.

### IN FLIGHT at relay: a single capture `cap.sh "dir_release_fua_write=1" 24` is RUNNING → result in scratchpad/cap_fw.log (check it FIRST next session). `dir_release_fua_write` (xfs_mxfs_dlm.c:3539, default 0) = after the release-drain xfs_bwrite, re-issue each dir block as an EXPLICIT SCSI WRITE(16)+FUA (mxfs_pal_scsi_write_fua_bdev) to force the PLATTER before DLM unlock. This is the WRITER-SIDE platter-durability fix and is STRONGER than the flaky dir_modify_target_flush (which used bio-level blkdev_issue_flush that LIO drops). NOTE explicit SCSI FUA commands WORK on LIO even though bio REQ_FUA is dropped (per the read-FUA workaround).

### THE PROVEN DIAGNOSIS (this session, RULE 4, dataclobber=1 + grant_evict capture, REPRODUCED):
1. Loss = a stale WRITE (NOT a stale base — grant_evict gives a FRESH base, loss persists). The clobber writes a dir block whose RMW base was missing a PEER's entry that IS on disk at write time (P-DATACLOBBER-SKIP: disk_cnt > buf_cnt OR leaf hash-divergent; real_mode=5 EX, in_txn=0, comm=dd/rm, in_ail=1, bdirty=0, stale=0 GEN-BLIND, SAME incarnation).
2. The mechanism is **PLATTER-LAG**: the EX-handoff serializes (A releases before B acquires), so B's reread SHOULD see A's drained entry — but A's release-drain blkdev_flush does NOT reach the LIO platter, and B's FUA read pierces to the (stale) platter. So B RMWs a base missing A's entry → writes it back → A's entry durably lost on ALL nodes. (Lost files this session: node2_f49, node8_f40.md5, node5_f3 — all on REUSED daddrs/inodes across rm-rf rounds.)

### REFUTED this session (do NOT retry): dir_conv_genbump (796); dir_drain_merge (CATASTROPHIC 471+dup+shutdown); dir_grant_evict ALONE (safe, fresh base, loss persists); dir_modify_target_flush (flaky — bio blkdev_flush LIO-dropped); dir_ail_defer (DEADLOCK — it defers the AIL push that dd needs for log-space progress → 184s starvation shutdown; combo grant_evict+ail_defer = 2/3 PASS but the SHUTDOWN disqualifies + passes were luck); dir_zombie_retire (!DONE-gated, the loss-write block is DONE=1); dir_tenure_evict/dir_evict_prior_tenure (sess30/32 refuted).

### NEXT (in priority order):
1. **Read cap_fw.log** (dir_release_fua_write=1 single run). If PASS + within RULE-0 budget (~480s; FUA-writes may be slow — check `time`): run a 5-6 batch (scratchpad/batch.sh "dir_release_fua_write=1" 6). If reliably PASS, that's the fix → default it ON, rebuild, run FULL 1/2/4/8 tcp.
2. If FUA-write too slow: scope it to ONLY the blocks that matter, or combine with grant_evict (base fresh + platter durable).
3. If FUA-write does NOT fix: platter-lag refuted → the peer entry is genuinely not on disk at B's reread (a release-drain completeness bug — A didn't drain its entry). Instrument A's release-drain coverage for the lost daddr.

### Harness: scratchpad/{cap.sh,batch.sh} "<MODARGS>" [N] = reboot+run drc 8/tcp + dmesg capture. Stream logs tests/tcp/drc_cap/stream_rank*.log (OVERWRITTEN each run — mine immediately after a FAIL: grep RDMISS for the lost name, P11-DATALOG for its daddr, P-DATACLOBBER-SKIP/P-RELFLUSH for the clobber). See [[sess36-PROMISING-grant_evict-plus-ail_defer-combo]] [[sess36-grant-evict-insufficient-loss-is-platter-lag-reread]] [[sess33-HEAD-handoff]].
