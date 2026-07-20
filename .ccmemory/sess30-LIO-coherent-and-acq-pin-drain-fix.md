---
name: sess30-LIO-coherent-and-acq-pin-drain-fix
description: sess30: 2/tcp cluster target is LIO fileio write-thru (cold-reads COHERENT, not SCST); dir_reuse fix = strengthen acquire pin-drain w/ periodic log_f…
metadata:
  type: project
---

## sess30 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp

### Criterion = ./run.sh 2 tcp 100% pass. ONLY dir_reuse_coherency fails (16/17 pass).

### DECISIVE infra finding (resolves a long-standing contradiction)
The 2-node TCP test cluster's iSCSI target is **LIO fileio backstore `/home/steve/disk.img`, "write-thru activated"** (confirmed: `/dev/sda` vendor=`LIO-ORG`, targetcli on clyde shows fileio mxfs write-thru; NO SCST anywhere). So **plain-bio cold-reads ARE coherent** — a written block is immediately visible to all initiators (write-through = no target write-cache). `mxfs_fua_disable=1` (default) is therefore SAFE here. The `project_test_cluster_scst` memory is STALE/wrong for THIS cluster (that's the v5/.1 SCST cluster). ⇒ evict+cold-read IS a valid refresh mechanism; the SCST "stale-reread" failure mode (sess96/99 reverts) does NOT apply here.

### Baseline (build AB435ACC) exact signature
`./run.sh 2 tcp dir_reuse_coherency` → FAIL 0/2. Round 15/24: **readdir=186/200, lookup_fail=0**, missing = `node1_f1..node1_f14` (a contiguous create-order range = ONE dir DATA block) — durably gone from BOTH nodes. **No shutdown, no rc=-110, no P35F/P99-STALE-SKIP** (release flush→stale loop is NOT leaking). test1 had 334 P21S-EVICTSKIP-LEAF (leaf left stale at acquire) but lookup_fail=0 (read-time leaf heal covers it). ⇒ pure DATA-face stale-base clobber, NOT the leaf face.

### Root mechanism (matches sess29 PROVEN)
A re-acquiring node keeps a PIN-ONLY stale dir DATA block (pinned, !dirty, !in_ail, DONE; content already PUBLISHED to disk via publish-before-notify, but CIL-pin-tailed). `mxfs_dir_drain_evict_data_blocks` (acquire-side, called at slow-path L8687 + fast-path L8249 when dir_gen>loaded_gen) does ONE pre-loop `xfs_log_force` then a 50-iter (~100ms) PASSIVE msleep wait; if still pinned it GIVES UP (P-ACQ-DRAIN-SKIP) → block stays stale → RMW onto stale base → durable dirent drop. The single force misses a block re-pinned by publish-before-notify's own re-log or pinned after the pre-scan; passive msleep can't unpin without a force.

### FIX (build 72676B77, sess30) — UNVALIDATED at write time
In the per-block pin-wait loop (`mxfs_dir_drain_evict_data_blocks`, ~L3302): extend bound 50→`MXFS_DIR_ACQ_PIN_WAIT`=2000 (~4s, wedge backstop << 120s DLM timeout) AND re-issue `xfs_log_force(SYNC)` at w==50 (~100ms) then every 250 iters (~500ms). Gentle cadence avoids the sess97 log-force-storm (force/32ms → 5.5x unlink slowdown, reverted). SAFE: runs post-grant, NO ILOCK, NO peer blocked (peer just released to us) → only delays OUR RMW, not a peer → no merge-class -110 timeout. A pin-only block is our own already-published work; forcing just completes its CIL checkpoint, then unpin→evict→cold-read peer's durable image.

### Secondary lead (NOT yet pursued)
`i_mxfs_self_created` gate (xfs_inode.c:1221 set on create; cleared on peer BAST @dlm.c:5482) skips the fast-path stale refresh for a self-created dir — but it clears as soon as the peer contends, so likely not primary. Revisit if the pin-drain fix is insufficient.

### Next
If 72676B77 makes dir_reuse 2/2: run FULL `./run.sh 2 tcp` (all 17 tests) to confirm 100% + no regression, THEN write criteria-met. Reboot/clean cluster before runs. See [[sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX]], [[sess29-GPT-design-tenure-local-poison-purge-at-NL]].
