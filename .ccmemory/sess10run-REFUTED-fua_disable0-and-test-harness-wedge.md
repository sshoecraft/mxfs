---
name: sess10run-REFUTED-fua_disable0-and-test-harness-wedge
description: sess10(ccloop): fua_disable=0 REFUTED for 4/tcp dir_reuse (storage cache coherent). IMPORTANT harness fact: a dir_reuse FAIL leaves a node wedged (rm…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — two more findings

### fua_disable=0 REFUTED
`MXFS_EXTRA_MODARGS='fua_disable=0' ./run.sh 4 tcp dir_reuse_coherency` → FAIL 0/4. So forcing FUA reads (pierce per-initiator cache to platter) does NOT fix it → storage/SCST cache IS coherent (confirms sess69); the durable loss is NOT a read-cache-staleness issue. (Note: cluster is SCST not LIO so FUA is available, but it doesn't help.) Don't re-try fua_disable/fua_always.

### CRITICAL test-harness fact (affects ALL future validation)
After a dir_reuse_coherency FAIL at 4-node, a node is left **WEDGED**: mxfs won't rmmod (D-state mxfs-ino-bast/flush kworker holding the LUN), so the NEXT run's `mkfs_mxfs -f /dev/sda` returns 1 (FS_PREP_FAIL / PREP FAIL (mkfs)). Consequence: **running `./run.sh 4 tcp dir_reuse_coherency` N times in a row gives only ONE valid result (the first, post-reset); runs 2..N PREP-FAIL on the wedge.** ALL my earlier "Nx flake-rate" batches were partly invalid for this reason. To validate a fix you MUST `virsh -c qemu:///system destroy+start test1..test4` (wait for boot) BEFORE EACH run. The wedge itself is a real teardown bug (a release/drain kworker never completes after the heavy concurrent storm) and may share a root with the durable loss.

### Net refutation list this session (do NOT re-try as the fix)
dir_epoch_adopt, fast-path grant_gen-change (inert), fast-path handoff bool (under-fires), level epoch (constant in tenure), dirskip enforce, non-owner xfsaild flush, fua_disable=0/fua_always. Writer durability (P-DSIG flush=1) works; slow-path acquire cold-read+evict works; clobber holds real EX and is stale_base=0.

### Remaining direction (unchanged): release→grant ordering / release-drain coverage hole (GPT Rank1/2). Decisive next experiment = compare P106-EXREL (release-done realns, xfs_mxfs_dlm.c:6709, gated dirwr/instr) vs the next owner's P-DIRRD (cold-read realns+crc) for the lost block, with a per-run virsh reset. See [[sess10run-HANDOFF-do-release-grant-timing-probe-next]].

### Status: criterion NOT met. Tree DE3A7E21 baseline. Cluster reset (test1-4 booting).
