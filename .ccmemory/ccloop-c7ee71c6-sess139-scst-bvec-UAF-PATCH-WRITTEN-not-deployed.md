---
name: ccloop-c7ee71c6-sess139-scst-bvec-UAF-PATCH-WRITTEN-not-deployed
description: sess139: the SCST fileio bvec-UAF patch is WRITTEN and builds clean (+caw-abort-reclaim.2), GPT-reviewed with 3 extra fixes folded in. NOT deployed.
metadata:
  type: project
tags: [scst, vdisk_fileio, use-after-free, infra, next-step, D-PR-FENCE-PREEMPT-WITHOUT-ABORT]
---

# sess139 — SCST bvec-UAF patch WRITTEN, builds clean, NOT YET DEPLOYED

Running module is still the buggy `+caw-abort-reclaim.1`. The tree now builds
`+caw-abort-reclaim.2`. **Nothing has been deployed; the rig is untouched and
healthy** (0 D-state, 32 VMs up, 64 production sessions).

## What landed in /src/scst (3 files)

1. `scst/include/scst_const.h:61` — suffix `+caw-abort-reclaim.1` -> `.2`.
2. `scst/include/backport.h` (tail) — `kiocb_start_write()`/`kiocb_end_write()`
   compat for `< 6.5`, with the `__sb_writers_release/acquired` lockdep handoff.
3. `scst/src/dev_handlers/scst_vdisk.c` — `fileio_async_complete()` +
   `fileio_exec_async()`.

Build: `cd /src/scst/scst && make` — CC+LD clean, zero warnings.
NOT installed: `sudo make install` has NOT been run.

## The five changes in scst_vdisk.c

- **THE FIX.** `kfree(p->async.bvec)` removed from `fileio_exec_async()` after
  submit; moved to the top of `fileio_async_complete()` with
  `p->async.bvec = p->async.small_bvec`. Exactly-once by the kiocb contract
  (fs calls ki_complete after -EIOCBQUEUED, else the submitter calls it).
  Also fixes a *second* UAF the old code had: on the queued route the
  completion can free `p` before the submitter reached its `kfree(p->...)`.
- **Retry.** `iov_iter_bvec()` + kiocb init moved INSIDE the loop (a rejected
  attempt can advance both the iter and `ki_pos`). Loop restated as
  `if (nowait && (ret == -EAGAIN || ret == -EOPNOTSUPP)) { ...; continue; } break;`
- **kiocb.** `init_sync_kiocb(iocb, fd)` replaces the zeroed compound literal,
  then `ki_flags &= ~(IOCB_APPEND|IOCB_NOWAIT|IOCB_DIRECT)` so device config,
  not open flags, is authoritative.
- **`ssize_t ret`** (was `int`; `call_*_iter` return `ssize_t`).
- **`nr_bvecs = bvec - p->async.bvec`** replaces `sg_cnt` in `iov_iter_bvec()`.
- **Freeze protection** (new, GPT-required): `kiocb_start_write()` + set
  IOCB_WRITE before `call_write_iter`, iff `dir == WRITE && S_ISREG(backing)`;
  `kiocb_end_write()` at the top of the completion and before a retry.
  Mirrors `fs/aio.c aio_write`/`aio_complete_rw` exactly.

## Audits closed this session (do not redo)

- `bio_iov_bvec_set()` at `/src/linux/block/bio.c:1177-1186` does
  `bio->bi_io_vec = (struct bio_vec *)iter->bvec` — **aliased, not copied**.
  Confirms the UAF by code, matching sess138's live-memory forensics.
- **bvec count is exact on >= 5.1**: `vdisk_map_pages_to_bvec()` emits exactly
  ONE bvec per SG entry (the multi-page loop is `#if < 5.1`), and
  `scst_get_buf_count()` returns `cmd->sg_cnt`. No overflow. The pointer-derived
  count also fixes a latent OOB on the `< 5.1` branch, where the helper emits
  page-count bvecs but `sg_cnt` counted SG entries.
- **IOCB_WRITE alone was the wrong call.** Kernel-wide grep: consumed only by
  `fs/aio.c`, `fs/backing-file.c`, `fs/cachefiles/io.c`. It is *bookkeeping for a
  freeze reference*, not a direction flag (direction comes from
  `iov_iter_rw()`). GPT agreed: setting it without taking the reference would be
  wrong — so take the reference too.
- 6.8's `kiocb_start_write()` does NOT set IOCB_WRITE, and `kiocb_end_write()`
  does NOT check it. The caller must track the pairing (GPT's claim that
  end_write self-guards is **wrong for 6.8/6.19** — do not follow it).
- `vdev_open_fd()` never sets O_DIRECT or O_APPEND; O_DSYNC iff
  `wt_flag && !nv_cache`, the same condition under which the code sets
  IOCB_DSYNC. So `init_sync_kiocb` changes no behaviour on this rig.

## Blast radius of the bug (established, sess137+139)

`/sys/kernel/scst_tgt/devices/mxfs` = `vdisk_fileio`, `/home/steve/disk.img`,
**`async=1 o_direct=1`** — the exact configuration with the UAF. That combo comes
from `scripts/scst_setup.sh:54` (`MXFS_SCST_DEVPARAMS`) and is described there as
"the sess26 proven combo", so the whole 32-node CAW campaign has run on it.
Trigger is >4 bvec segments. Per the sess137 GPT ruling, timing/perf and
error-rate evidence from before the fix is SUSPECT and a clean run does not
establish absence.

## NEXT STEPS, in order

1. `cd /src/scst/scst && sudo make install`. (Reload drops the 32-node LUN.)
2. Destroy the test VMs (disposable), then `rmmod iscsi_scst scst_vdisk scst`.
3. Rebuild the rig — the path is in [[rig-recovery-after-clyde-reboot-scst-mpath]]:
   `sudo bash scripts/scst_setup.sh setup` (~2s), then
   `sudo -E bash scripts/mpath_up.sh up 32` (~100s), then
   `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` (~76s).
   **Do NOT use `systemctl start scst`** — `/etc/scst.conf` is stale and names
   deleted images. The live config as of sess139 is captured at
   `scripts/scst_rig/scst-live-sess139.conf` for reference.
   Confirm `cat /sys/module/scst/version` shows `...+caw-abort-reclaim.2`.
4. RULE-4 verification: re-run the stage-(ii) loop+dm-delay reproducer
   (`tests/fence_inflight/stack.sh`) that GPF'd `dma_direct_map_sg` in
   sess136/137 — it is the deterministic trigger. Assert no GPF, no leaked
   loop0 in-flight requests, no D-state. Repeat several laps.
   `scripts/loop_unwedge/` clears it without a host reboot if it wedges again.
5. Then rebaseline the full 32/caw board on the fixed target.

GPT also suggested (not yet done, optional): runtime KFENCE via
`/sys/module/kfence/parameters/sample_interval`, and qualification-only atomic
counters asserting `dynamic bvec allocs == frees` and
`queued submissions == async callbacks`.
