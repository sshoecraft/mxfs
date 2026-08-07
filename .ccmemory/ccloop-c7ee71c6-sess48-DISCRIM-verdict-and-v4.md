---
name: ccloop-c7ee71c6-sess48-DISCRIM-verdict-and-v4
description: sess48: P-IUNL-DISCRIM verdict = WRITE-NOWHERE-IN-TARGET w/ wr_epoch STAMPED ⇒ fossil-carrying home write wrongly retired records; v4 shipped (0.11.3…
metadata:
  type: project
---

# sess48: media-vs-transit DECIDED + A-prime v4

## The experiment (TAIL18) ran and returned a verdict
Built in-kernel discriminator `mxfs_iunl_discrim` (xfs_mxfs_dlm.c, next to the store): at first overlay mismatch per call, after the store spinlock drops, A/B-read the cluster sectors — PLAIN bio (target-cache-coherent view) + SCSI FUA (media view) — decode the slot, print all four values + wr_epoch + flush_epoch. Cap 60/boot.

## Verdicts (387 c1: 2 specimens; 388 c1: 8)
ALL `WRITE-NOWHERE-IN-TARGET`: plain==fua==img(old), committed absent from cache AND media.
- **Transit/FUA-read-path theory DEAD** (fix F plain-bio-in-window would do nothing).
- 388 added wr_epoch: **STAMPED (6133 vs flush 6135; 6240 vs 6254)** ⇒ a covering cluster write COMPLETED after the record, yet neither cache nor media has the value ⇒ **the completed write itself carried the fossil** (in-core slot lost pre-submission — the known cold-DMA/reread clobber family). Target loss refuted (would need acked+flushed write loss).
- **Root of the 386 ~1/2-cycle fatal**: retire-on-mere-completion stamped wr_epoch for fossil-carrying writes → lazy drop (fe>wr_epoch) killed the protecting record → unguarded fossil → P53. NOT missing install hooks.

## v4 (0.11.389→390, fleet 390 deployed, guards clean)
1. **Install site 4 = WRITE side** (pal/linux/xfs_buf.c, xfs_buf_submit, right before xfs_buf_verify_write, mirrors mxfs_dir3_data_writemerge precedent): overlay live committed values onto OUTGOING inode-cluster payload (multi-node, single-map). Print P-IUNLSTORE-WRSITE w/ pin/delwri/bli/in_ail/lseq/wseq/comm — the state snapshot names the in-core clobber pipeline when it fires.
2. **Payload-verified retire** (mxfs_iunl_store_retire_range now takes base/len = completed b_addr): stamp wr_epoch ONLY if written slot matches. 389-c1 refinement: gen/magic MISMATCH also stamps (dead-incarnation records — free-time gen bump or reuse; once any different-gen image lands+flushes, no pre-commit same-gen image can be served again; 38 benign all-gen-mismatch FOSSILWR in 389-c1, values all equal). Only SAME-GEN value mismatch = true fossil write ⇒ record kept + P-IUNLSTORE-FOSSILWR alarm (should be impossible with site 4 — firing = regression alarm).

## Soak protocol (unchanged)
cycle = `timeout 160 ./run.sh 32 caw rsync_paired` + `timeout 280 mxfs_sshpass test1 sleep 250` + lap again; sweep 32 nodes for Shutting down/P53/OVERLAY/WRSITE/FOSSILWR; matrix `timeout 480 tests/openunlink_matrix.sh test1 test2 test3` every ~2 cycles + reap repro guard at deploy. Promotion bar: multi-cycle P53-zero with same-gen FOSSILWR=0.

## Standing
0.11.390 fleet-wide, 32/32 green. 11 defects OPEN of 39 (4 critical). If P53 recurs on 390: WRSITE/FOSSILWR/OVERLAY counts at the fatal decode which leg leaked; ring saved per protocol. History: TAIL7-TAIL18 (sess47) + this.
