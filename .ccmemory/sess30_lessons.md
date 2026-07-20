---
name: sess30_lessons
description: Sess30 (2026-05-07) — Path A (manual-bio CAW submission) shipped v0.3.128. Partial fix at small scale; residual at 15× scale. caw_verify retry compounds with caller retries — DO NOT USE.
type: project
originSessionId: 7229d9d0-b519-4889-a60f-2f0fe50bd187
---
# Sess30 — Path A (manual-bio CAW) implementation

## Headline result

**Path 1 (manual-bio submission) is now the v0.3.128 default.** It improves
CAW reliability at 5×256 cross-node stress (from sess26's ~50% baseline
to **80% PASS** across 5 mount-verified samples × 5 iters = 20/25 at
sess30 end).  Adding `mxfs.caw_flush=1` (post-CAS blkdev_issue_flush)
brings it to **84%** — marginal improvement.  At 15× scale (15×256,
15×512), the underlying SCSI non-persist bug **still fires** — single
sample fails at iter 1-9 with bnobt LEFT/RIGHT-FAIL.

Final srcversion: `A492B1861C46A46C2EFBE7D` (path 1 default,
caw_verify=0, caw_flush=0, caw_gen_verify=0 default; bio->bi_bdev
set to part0 to match sg.c's blk_rq_map_bio_alloc).

## Sess30 final A/B comparison (mount-verified, 5×256, 5 samples each)

| Config                                      | Pass rate    | Notes                          |
|---------------------------------------------|--------------|--------------------------------|
| caw_path=1 default                          | 20/25 = 80%  | Baseline path A                |
| caw_path=1 + caw_flush=1                    | 21/25 = 84%  | Marginal vs baseline           |
| caw_path=1 + caw_gen_verify=1               | 22/25 = 88%  | Marginal; P72=0 (no detection) |
| caw_path=1 + caw_verify=1 (poll-persist)    | 0/25 = 0%    | Latency exhausts DLM grant     |

The marginal improvements from `caw_flush` and `caw_gen_verify` are
within sample variance.  None of the at-PAL or at-caller verification
mechanisms reliably catches the bug because **the device's write-cache
returns most-recent-written data on FUA-read** — verify reads see the
write that's still in cache, not on media.  The cross-init coherency
issue manifests when peer's later FUA-read hits the device after the
write-cache entry has been evicted (rather than committed) — this is
not visible to the originating node at all.

## Storage-side root cause investigation (sess30 finding)

`/dev/sda` on T1/T2 is virtio-scsi passthrough of host's `/dev/sdc`,
which is a tcm_loop loopback to LIO's `block` backstore exporting
host's `/dev/sda` (Samsung 870 EVO 2TB SSD).

**The Samsung 870 EVO does not support SCSI FUA:**
- `/sys/block/sda/queue/fua = 0` on the host.
- `sg_modes -p 0x08 /dev/sda` reports `DpoFua=0`.
- `sg_vpd -p bdc /dev/sda` reports `FUAB=0`.

**LIO target's `tcm_iblock` drops initiator FUA bit silently.**
`drivers/target/target_core_iblock.c:772`:
```c
if (bdev_fua(ib_dev->ibd_bd)) {        // FALSE on Samsung 870
    if (cmd->se_cmd_flags & SCF_FUA)
        opf |= REQ_FUA;
    ...
}
```
So our CAW writes (CDB cdb[1]=0x08 FUA bit set) reach LIO with SCF_FUA,
but the outgoing bio to `/dev/sda` does NOT get REQ_FUA.  Writes hit
the SSD's write-back cache, get ACKed, persist to NAND eventually.
LIO's `emulate_write_cache=0` further means initiators don't know
there's a cache and don't auto-flush.

**However**, adding `blkdev_issue_flush` after every CAS-success only
brought 80% → 84%.  So FUA-on-write-side isn't the entire story.
Possibilities for sess31:
1. The flush isn't reaching the underlying device fast enough under
   stress (blkdev_issue_flush completes when queue says so, may not
   wait for actual NAND commit).
2. There's a separate cross-init-read coherency issue: even after our
   write+flush, peer's FUA-read may hit cached/stale data due to
   read-cache, multipath, or scsi-mq dispatch ordering.
3. The actual bug is in the kernel scsi_execute_cmd dispatch path
   (sess26 P49 hypothesis) and FUA dropping is only ONE contributing
   factor.

**Sess31 should consider:**
- Set `emulate_write_cache=1` on LIO target so initiators auto-flush.
- Replace Samsung 870 with an enterprise SSD that supports FUA.
- Or implement Path C cluster-coherency layer (mxfs_clayer) above
  the DLM to detect and recover from non-persist via slot-generation
  semantics.

## Critical gotcha: silent single-node fake-success

The `mxfs_cluster_reset.sh` test harness can silently fail T1's
mkfs/mount (e.g., `mkfs.mxfs: zero_region verify FAIL @67118080 byte
1024 = 0x4b — storage silently dropped writes`).  When this happens,
the script keeps going, T2 mounts onto the prior session's filesystem
in single-node mode, and stress runs T2-only.  All "T1+T2 dd+rm OK"
markers in the harness PASS because T1's dd writes silently land on
local ext4 instead of /dev/sda.  **Always verify** both nodes mount
post-reset:

```bash
M1=$(ssh T1 'mount | grep -c mnt/shared')
M2=$(ssh T2 'mount | grep -c mnt/shared')
[ "$M1" -eq 1 ] && [ "$M2" -eq 1 ] || abort
```

Earlier sess30 results may have been single-node fakes.  All sess30
final-state numbers below are mount-verified.

## What was implemented (kept in tree)

`pal/linux/kern.c::caw_manual_bio()` — mirrors `drivers/scsi/sg.c`'s
`sg_start_req` data path: fresh `alloc_page()` per submission, copy
compare/write into it, `bio_alloc(NULL, 1, REQ_OP_DRV_OUT, GFP_KERNEL)`,
`bio_add_page(bio, page, 1024, 0)`, `blk_rq_append_bio`, manual scmd
setup with `scmd->allowed=0` (matching SG_DEFAULT_RETRIES), no
`RQF_QUIET`, `blk_execute_rq(req, true)`.  Avoids
`bio_add_virt_nofail` → `virt_to_page(caller_buf)` aliasing that
`scsi_execute_cmd`'s `bio_map_kern` does.

Module params (both `0644`, runtime-writable):
- `mxfs.caw_path` — default 1 (manual-bio).  0 = legacy `scsi_execute_cmd`.
- `mxfs.caw_verify` — default 0 (off).  1 = post-CAS FUA-readback verify
  with bounded retry (DO NOT USE — see below).

VERSION 0.3.128, srcversion `EE4C29D1F2511EB80FB51A1`.

## What did NOT work — DO NOT REPEAT

### `caw_verify=1` (post-CAS FUA-readback verify-and-retry at PAL layer)

**Compounds with caller retries → ETIMEDOUT.**

Mechanism: when verify-read sees content ≠ write_buf, the PAL retries
the CAS with same compare/write.  The retry can hit MISCOMPARE
(because peer raced in OR our previous CAS finally persisted), which
returns -EAGAIN to the caller.  Caller (`caw_lock`/`caw_unlock`) has
its own MXFS_CAW_MAX_RETRIES=100 loop, which compounds: 100 × 5 ×
(CAS + verify + msleep) easily exceeds the 60s DLM grant timeout.

In a sess30 test with `caw_verify=1` at 15×256:
- T2 hit `caw_unlock: unlock exhausted 100 retries for ino=0 type=3` 
- Followed by `DLM inode lock failed: ino=128 mode=5 rc=-110`
- `Corruption of in-memory data (0x8) detected` shutdown

P71-INSTR fired thousands of times on same lba (e.g. lba=182186 had
11+ rapid-fire mismatches).  Detection IS correct (sess26 P49 root
cause #2 is real) but compounding makes it worse than no-verify.

**Sess31: if doing verify-and-retry, do it at the CALLER layer
(`caw_lock` / `caw_unlock` in dlm_caw.c), with intent-aware logic
that uses the slot's `generation` field to distinguish:**
- "our CAS persisted, peer overwrote with later generation" (success)
- "our CAS didn't persist, generation unchanged" (retry)

### `caw_path=1` from insmod with non-fresh disk state

When the cluster is reset onto a disk that has stale CAW slot state
from prior runs (sess26 noted mkfs's pwrite-O_SYNC zero isn't durable
on LIO), iter 1 can fail immediately with ETIMEDOUT regardless of path.
Always run `/tmp/mxfs_cluster_reset.sh` to fresh-mkfs before stress.

## Investigation findings (for sess31)

### iSCSI initiator-side device characteristics

```
/sys/block/sda/queue/fua = 1
/sys/block/sda/queue/write_cache = "write back"
sg_vpd -p bdc /dev/sda:
  WABEREQ=0  WACEREQ=0  ZONED=0  RBWZ=0  BOCS=0  FUAB=0
sg_inq /dev/sda:
  version=0x06 [SPC-4]  CmdQue=1  TPGS=3  3PC=1  Protect=0
```

`FUAB=0` in Block Device Characteristics VPD page is suspicious — needs
sess31 follow-up to determine whether the LIO target's underlying block
device honors FUA on writes (see `drivers/target/target_core_iblock.c`
line 772: tcm_iblock only sets `REQ_FUA` on its outgoing bio if
`bdev_fua(ib_dev->ibd_bd)` returns true on the server-side bdev).

### Path A doesn't fully fix because

The bug isn't (only) in `bio_map_kern`'s data-aliasing path — sg.c
userspace path uses functionally identical bio construction to my
`caw_manual_bio`.  Both go through `scsi_alloc_request` →
`blk_rq_append_bio` → `blk_execute_rq(_nowait)`.  The remaining
non-persist must be either:
1. iSCSI server-side LIO/iblock cache coherency under stress.
2. A scsi-mq dispatch path issue specific to high-rate concurrent CAW.
3. The actual `tcm_iblock` -> bio submit path on the server doesn't
   honor FUA when the underlying device's `bdev_fua` is false.

## Sess30 paths to investigate next (Path B and C from state.md)

- **Path B (kernel patch):** instrument `scsi_execute_cmd` and
  `bio_map_kern` on the initiator AND `target_core_sbc::compare_and_write_post`
  + `tcm_iblock::iblock_execute_rw` on the server.  Confirm where the
  non-persist actually happens (initiator-side dispatch lie, or
  server-side write-cache vs FUA flag).
- **Path C (mxfs_clayer cluster-coherency):** add a layer above DLM
  that detects bnobt invariant violations and triggers fresh-acquire
  retry with cache invalidation.  Spec Phase 4 D6 + Phase 7.
  Mid-multi-session work.

## Sess30 final state

Tree: v0.3.128, srcversion `EE4C29D1F2511EB80FB51A1`.  Default config
ships with `caw_path=1, caw_verify=0`.  Cluster on T1+T2, mounted, last
test 5×256 = 5/5 PASS.

P-INSTR additions kept in tree:
- P71-INSTR: caw verify-mismatch (only fires when `caw_verify=1`).
- mxfs_caw_verify_{ok,mismatch,exhausted} atomic64 counters (no sysfs
  exposure yet; check via crash analysis or expose in sess31).
