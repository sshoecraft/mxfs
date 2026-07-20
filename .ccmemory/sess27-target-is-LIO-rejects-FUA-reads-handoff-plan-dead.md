---
name: sess27-target-is-LIO-rejects-FUA-reads-handoff-plan-dead
description: sess27 CRITICAL: test cluster target is LIO-ORG (NOT SCST) and REJECTS SCSI READ(16)+FUA (asc=0x24). FUA reads fall back to plain bio. sess26 fua_dis…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — DECISIVE INFRA CORRECTION (supersedes sess26 FUA framing)

### The target REJECTS FUA reads
test2 boot dmesg (build C99F988B, 2026-06-19):
```
scsi 0:0:0:0: Direct-Access LIO-ORG  mxfs  4.0
mxfs: SCSI READ(16)+FUA rejected by target (ILLEGAL REQUEST asc=0x24) — falling back to plain bio reads (write-through backstore assumed)
```
- Target identifies as **LIO-ORG** (the Linux LIO/tgt target), NOT SCST. The memory `project_test_cluster_scst` ("SCST iSCSI — CAW works") is WRONG for the current 2/tcp cluster, OR the target was swapped. Trust the boot log.
- `mxfs_pal_scsi_read_fua_bdev` → SCSI READ(16) w/ FUA → target returns ILLEGAL REQUEST asc=0x24 (INVALID FIELD IN CDB) → mxfs falls back to **plain bio reads** for ALL metadata. The `_XBF_FUA_FRESH` / `mxfs_buf_read_fua` path CANNOT pierce any cache here — FUA simply doesn't work.

### Why this KILLS the sess26 handoff plan
sess26's "EXACT NEXT FIX" was: detach BLI + xfs_buf_stale the ABA dir buf, **run with fua_disable=0** so "the post-stale fresh read needs FUA to pierce SCST." On THIS target FUA is rejected → fua_disable=0 changes nothing for reads (FUA attempted, -EOPNOTSUPP, plain bio fallback). The "dir_merge raw FUA read returned fresh inum B" almost certainly worked NOT because of FUA but because it forced an ACTUAL device read (bypassing the in-core xfs_buf cache) and the LIO backstore is write-through/coherent.

### Reframed root (consistent with all evidence)
- Coherency mechanism on this cluster = **plain-bio reads hit the COHERENT write-through LIO backstore** (sess122's assertion, pal/linux/xfs_buf.c:3700). Other 15+ 2/tcp tests PASS on this.
- `dir_reuse_coherency` fails because node1's cold read of the dir DATA block holding node2's entries serves node1's **STALE in-core xfs_buf (XBF_DONE set, NO bio issued)** — the evict (mxfs_dir_evict_data_blocks via consumer_refresh, force_evict=1) is failing to invalidate that specific block. readdir lists correct NAMES (same every round) so readdir count=200 passes, but the inums are prior-round → iget -ENOENT → lookup_fail.
- So the fix is **in-core buffer invalidation on the reuse/ABA read path**, NOT FUA. Next: instrument with dirwr=1 to see whether the node2-block is P-EVICT-SKIP (undurable→skipped) vs P-EVICT-DONE (cleared but re-read stale). Default fua_disable=1 is CORRECT for this target; do NOT chase fua_disable=0.

### Infra gotcha: test nodes AUTO-MOUNT mxfs on boot
After `virsh destroy+start`, test2 (and test1) auto-mount mxfs ~20s into boot (LIO LUN appears → module loads → mount at /mnt/shared). Source NOT yet found (no fstab/systemd/cron/rc.local/modules-load). This auto-mount races manual prep and can leave a STALE-FS / split-brain mount. `umount -l` on it leaves refcnt=1 (won't rmmod = wedged). Use run.sh's robust prep_cluster (parallel fuser -k + umount + rmmod retries BEFORE mkfs) which is the PROVEN path, or virsh-reboot then re-prep. Build is C99F988B (clean, .ko newer than src).
</body>
