---
name: sess46-REFRAME-8tcp-dominant-failure-is-node-isolation-wedge-not-doublegrow
description: sess46(ccloop): 8/tcp dir_reuse MULTI-MODAL — ~equal MASS/node-isolation(>40s unreachable→dead→work lost) + SINGLE intra-block. Host NOT oversubscrib…
metadata:
  type: project
---

## sess46 (ccloop 4cb2d0a2) — 8/tcp dir_reuse failure REFRAMED + characterized

Build on disk: **A00D8CFE** = sess45 keeper FB296422 + PROBE-ONLY (no behavior
change → keeper-equivalent). Probes: P13-COLLIDE extended (buf dirty/inail/pin/
done/bufgen + disk dmagic/downer/ourdir); **P46-GROW** (xfs_dir2_node.c
add_datablk, NON-perturbing, no I/O: newdbno, daddr, incore_nx, incore_sz,
dirgen, valid_epoch — every dir-grow for ino<=256).

### MODE DISTRIBUTION (drc_detail8.sh, 5 iters, 1 PASS / 4 FAIL = ~20-25% pass):
- **MASS / node-isolation (HALF the fails, loses MANY entries)**: a node goes
  UNREACHABLE >40s mid-create-wave → peers self-fence then "did not reconnect
  within 40000 ms — declaring dead, recovering locks" → its in-flight round work
  never publishes. Captured: round 24, node5 lost ~54 (all 50 .md5 + tail files
  f47-f50; f1-f46 present); another fail node6 lost ~22. Membership HAD fully
  formed (active_count=8) before the isolation.
- **SINGLE (other half, loses 1)**: node4_f27, node7_f1 (node7_f1 = classic
  FIRST-dirent loss, sess62 family) — the intra-block / grow path.

### KEY CORRECTIONS to sess45's model (all RULE-4 grounded):
1. **Host NOT oversubscribed**: clyde 56 CPUs (load ~4.5), 70GB free, 8 VMs use
   32 vcpu/32GB → the >40s unreachability is a **WEDGE** (unbounded sync drain /
   DLM-EX starvation), NOT CPU starvation. sess45's "host-load FLAP" assumption
   is WEAK. Bumping tcp_death_grace MASKS, doesn't fix.
2. **Release DOES drain the dir inode**: dir-EX release calls
   `mxfs_ail_drain_inode_sync(ip)` (xfs_mxfs_dlm.c ~8724) waiting
   `!in_ail && pincount==0` = checkpointed AND written-home → write-through LIO
   → A's dinode (extent map/di_size) IS durable at release. So the SINGLE is NOT
   a release-side inode gap.
3. **LIO target WRITE-THROUGH + REJECTS FUA passthrough** (kern.c:502-514):
   `mxfs_pal_scsi_read_fua_bdev`/`mxfs_pal_bdev_read_plain_bdev` = plain bio read
   into a DISCARDED kmalloc temp (no buffer-cache effect) → causally INERT except
   LATENCY. ∴ sess45 `dir_release_fua_write` likely redundant; any "FUA read
   fixes it" = TIMING-MASKING (RULE-0 debt).
4. **P13-COLLIDE off=64 = FALSE POSITIVE** (ourdir=0 = garbage disk bytes).
   **P46-GROW ourdir=1 = ABA reuse** (daddr held a PRIOR round's dir block,
   owner=131 because the dir inode is reused) — NOT a same-round double-grow.
   So "double-grow" is NOT proven; the SINGLE is the older intra-block/first-
   dirent family.

### MASKING EXPERIMENT (why FUA-read "fixes" are fake): a FUA/bio read at the
dir-grow raised pass rate (keeper ~4-7/8 → +1 grow read ~6/8 → +2 reads ~5/5),
but read+discard → only latency → masks the SINGLE (tight grow-latency race).
Removing the reads (non-perturbing build) → failure rate back to ~75%.

### NEXT (RULE 4) — attack the DOMINANT isolation/wedge mode:
A node disconnects only on a HARD recv/send error (peer.c:104,140; transient
-EAGAIN loops). BASTs ARE queued to m_mxfs_inode_bast_wq (not drained inline in
the recv thread), so recv-thread-inline-drain is weakened. The dead node's dmesg
is wiped on reboot → need a LIVE per-node watchdog/beacon capturing WHAT a node
is blocked in (D-state stack / current op) when its peer declares it dead.
Also: self-fence + memb_settle(20s) + grace(40s) may AMPLIFY a brief wedge into
a cluster-wide EX-freeze cascade — consider a survivor-side "last-heard-op" log
and/or a less aggressive fence. Map node-id→testN via active_count beacon
(local=<id>). Harnesses: tests/drc_detail8.sh (captures [FAILROUND]+per-node
failing-round P46-GROW grows+[MEMBERSHIP]+[DEATH/FLAP], no early break),
tests/drc_batch8.sh. See [[sess45-WINNING-config-and-remaining-work]].
</body>
