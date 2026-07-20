---
name: sess16run-mht50-dirreuse-loss-durable-survives-forcecoherent
description: sess16(ccloop): dir_reuse 8/tcp mht=50 loss (node1_f1/node5_f40) is DURABLE — survives force_coherent=1 AND postread_reread=1 → NOT read-staleness; =…
metadata:
  type: project
---

## sess16 (ccloop 4cb2d0a2) — dir_reuse 8/tcp @ mht=50 loss is DURABLE, not read-staleness

Build BAB5566E (= 48C6A95E + P32F-NXSHRINK-FENCE, inert). The 8/tcp criterion blocker reduces to the mht tension ([[sess15run-MHT-tradeoff-tcpdlm-wants-low-dirreuse-wants-high]]): mht=300 → dir_reuse PASS / tcp_dlm_scaling FAIL(slow); mht=50 → tcp_dlm PASS / dir_reuse FAIL. Window empty. So the ONLY convergent path is: fix dir_reuse so it's correct at LOW mht, then set mht low for both.

### What the mht=50 dir_reuse failure ACTUALLY is (measured, 8 nodes, clean reboot each run)
Failrounds identical every run: **round 1, readdir=751/800, lookup_fail=2, missing=[node1_f1.md5 node5_f40.md5]** on the PEERS (test2..8). The OWNER (test1) shows `P21H-LEAFHOLE dir_ino=131 name=node1_f1 hv_in_leaf=0 ... sameincarn=1` + `P33-DSCAN-ONDISK incore==disk` (incore_nx=2 disk_nx=2 size=4096 gen match) — i.e. the loss is DURABLE on disk (leaf hash hole for a name still in the data block), not a stale in-core copy.

### RULE-4 discriminators run THIS session (all DISPROVE read-staleness)
1. **postread_reread=1** (FIX3 reliable grant-gen leaf/data re-read, default OFF): P67 fired 26-29×/node, leafhole detector quiet, but **SAME loss** (node1_f1/node5_f40). → confirms sess67 "P67 never fired on the clobber; loss is not gen-stale read."
2. **force_coherent=1** (clears XBF_DONE on EVERY dir read → FUA re-read always, no cache hit) + postread_reread=1: **SAME durable loss**. → the loss is NOT a cache-hit stale read. Even with every read coherent, the peer's durable image is missing node1_f1.
3. Prior [[sess52]]: ex_pop=1 (single EX holder) → NOT a literal concurrent double-grant (but verify on THIS 8-node-TCP build; sess49 still claims "TCP double-grant").

### Leading hypothesis for NEXT session (release-durability gap)
node1_f1 is created by rank1 under EX, released; a peer then acquires EX, FUA-reads the dir data/leaf block, but gets a pre-f1 image (rank1's block write not yet DURABLE at release), adds its own entry, writes back → f1 durably clobbered. mht=300 masks it (long hold → writes complete before release); mht=50 exposes it (release before write completes). NEXT: verify Invariant-1 drain at EX release actually WAITS for dir DATA+LEAF block write completion + blkdev_flush BEFORE unlock — check whether dir leaf/data blocks are covered by drain_meta_buffers / the bast_process drain, or escape it. P21F-RELFLUSH-LEAF DOES fire at release (leaf flush issued) — question is whether it's WAITED on. Alternative: re-test concurrent-EX on TCP (instrument ex holders on ino=131 at the addname RMW).

### P32-NXSHRINK shutdown is a SEPARATE (secondary) failure
ONLY test1 shuts down via P32-IFLUSH-NXSHRINK (stale smaller dir extent map flushed under EX, dlm_mode=5, comm=rm). My P32F-NXSHRINK-FENCE (xfs_inode.c, param dir_nxshrink_fence default 1) targets it with discriminator `dir_epoch(ino) > i_dlm_dir_valid_epoch` — but **fence NEVER fired** (cur_ep ≤ valid_epoch at all 22 P32 events): the epoch is NOT advanced at the stale flush → discriminator WRONG. Fence is currently inert/harmless. test2-4 shut down with ZERO P32 events (different downstream cause = the leaf-vs-data tear from the loss above). The leaf-hash lost-update is the PRIMARY root; the shutdown is downstream of it. Fix the loss first.

### Levers/params (live, 0644): inode_mht_ms, dir_postread_reread(def 0), force_coherent(def 0), dir_epoch_adopt(def 1), dir_nxshrink_fence(def 1, new this sess). Repro: clean virsh destroy+start test1-8, then `MXFS_EXTRA_MODARGS='inode_mht_ms=50' TEST_TIMEOUT=240 ./run.sh 8 tcp dir_reuse_coherency`. A FAIL wedges the LUN → MUST virsh-reboot before next prep (mkfs 'device busy'). See [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]] [[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]].</body>
