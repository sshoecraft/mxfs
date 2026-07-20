---
name: sess49-ROOT-cache_coherency-uv-is-P43-fmtrevert-guard-misfire
description: sess49 FIXED 90-session cache_coherency blocker + got FULL 2/tcp suite 17/17: P43-DIR-FMTREVERT guard misfired on legit peer block→shortform shrink.…
metadata:
  type: project
---

## sess49 (ccloop 8ddb16a2) — cache_coherency uv FIXED; FULL 2/tcp suite 17/17 (build DBA88871)

### RESULT: `./run.sh 2 tcp` = **17/17 PASS** (clean reboot, run_id 212642Z). cache_coherency
standalone **10/10**. dir_reuse_coherency 2/2 (NO regression). Reliability re-runs in progress.

### sess48's "SCST per-initiator read cache" conclusion was WRONG (false premise)
Storage = **LIO fileio over /home/steve/disk.img, ONE instance on clyde, virtio-scsi to both
VMs = ONE coherent host page cache** (emulate_write_cache=0). NO per-initiator cache. See
[[storage-backend-is-lio-fileio-not-scst]]. Never chase SCST/FUA for coherency on this rig.

### PROVEN ROOT (RULE 4, raw-disk + dmesg): 100% READ-SIDE guard misfire
uv fail = test1 (reader) sees node2's LAST 10 deletes (node2_file21..30); test2 correct.
- DISCRIMINATOR (tests/uv_disktruth2.sh + drop_caches): test1 dir count=10 size=4096(BLOCK);
  test2 count=0 size=6(SHORTFORM). **test1 `echo 3 > drop_caches` → 0** ⇒ LUN is the correct
  shortform, test1's in-core BLOCK inode is STALE. Pure read-side.
- dmesg: eviction ring fired + reload armed, but **`P43-DIR-FMTREVERT-SKIP`** (xfs_mxfs_dlm.c
  ~6837 + P43B snapshot ~7112) REFUSED node2's durable block→shortform image. sess43 built that
  guard for dir_reuse (CREATE-only, dirs only grow); its assumption "a genuine peer removal holds
  EX, BASTs us to NL, so we re-read at NL with no in-core block fork to lose" is FALSE for the
  unlink/delete path — node2 empties the dir → block→shortform → destages + bumps our gen, but
  test1 holds a CLEAN, stale BLOCK fork at PR and the guard pins it FOREVER.

### FIX (KEEP, DBA88871): SOUNDNESS GATE on P43 + P43B (mirrors P33/P116)
Keep the in-core block ONLY when authoritative: `dfr_dirty` (pincount>0||ili_fields||IN_AIL) OR
`dfr_grant_held = (i_dlm_mode == MXFS_LOCK_EX)`. Else FALL THROUGH → adopt disk shortform
(P43-ADOPT-PEER-SHRINK).
- **Why EX-only, not mode!=NL**: the FAILING reload is the ACQUIRE path, which sets
  i_dlm_mode=target(PR=3) BEFORE the reload (line ~9380→reload), so v1 `mode!=NL` still flagged a
  PR *reader* authoritative (`P43-DIR-FMTREVERT-SKIP ... dirty=0 held=1(mode=3)`) → ~15% flake.
  A PR holder CANNOT have unshared writes (writes need EX) ⇒ a PR copy differing from durable disk
  is STALE → must adopt. EX-gate = IDENTICAL behavior to old guard for EX holders (dir_reuse
  creators KEEP, no regression), only changes PR/NL-clean to adopt (uv readers). mode: 0=NL 3=PR 5=EX.

### VALIDATION METHOD (carry forward)
- cache_coherency uv flake was ~15%; needs 10× to trust. uv_disktruth2.sh reproduces divergence in
  ~1 iter (faster than full cache_coherency). drop_caches on the outlier = the read-side oracle.
- Full suite ~20-25 min (soak capped at TEST_TIMEOUT=300). Trust per-run log (ran=N pending=0), not
  accumulated showstat. virsh destroy+start BOTH between full runs.
Related: [[sess46-CRITICAL-suite-is-broadly-flaky-never-17of17-clean]] [[sess43-suite-failures-are-largely-contamination-not-real]] [[sess48-uv-writeside-FIXED-readside-inode-cluster-stale]]
