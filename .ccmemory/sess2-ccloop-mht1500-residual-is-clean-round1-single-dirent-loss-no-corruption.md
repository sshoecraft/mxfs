---
name: sess2-ccloop-mht1500-residual-is-clean-round1-single-dirent-loss-no-corruption
description: sess2(ccloop) at inode_mht_ms=1500: 8/tcp dir_reuse = 4/5 (80%). Residual failure is a CLEAN round-1 single-dirent loss (799/800, all nodes agree, NO…
metadata:
  type: project
---

## sess2 — inode_mht_ms=1500 reliability + residual characterization

### Reliability: 4/5 PASS (80%) over 5 clean-reboot iters. Wall ≈ 535-585s/iter.
### Residual FAILURE signature (captured live on the still-booted cluster):
```
ALL 8 nodes: DABUF=0  shutdown=0  declared-dead=0
lastfail = round=1 rank=ALL readdir=799/800 lookup_fail=0 missing=[]
```
**→ The batching ELIMINATED every corruption path** (DABUF_MAP_HOLE=0, no FS shutdown, no node declared-dead/flap). What remains is a SINGLE clean dirent lost in **ROUND 1 ONLY**, durable + agreed by all nodes, no corruption. = the pure cross-node intra-block dir-data freespace DOUBLE-ALLOCATION / write-side lost-update (sess44/sess36 signature). Flaky (~1/5), confined to round-1.

### Why round-1: round 1 is the FIRST create wave into a freshly-FORMED cluster on a freshly-created dir (shortform→block→leaf grow under 8-way concurrency). Most handoff contention + format transitions happen here (sess35 "round-1 format-transition block-vs-data divergence"; sess22 "round-1 create-visibility miss" long-standing flaky residual). Later rounds (dir already leaf-format, cluster settled) pass.

### RULE 0 BLOCKER on mht=1500: wall≈540s/iter; workload (24 rounds) ≈440s ≈18s/round. Native single-node XFS equivalent (24×800 small-file create+md5+readdir+rm) ≈ 60-72s. So mht=1500 ≈ 6-7× native — FAILS the RULE-0 2× ceiling. **mht=1500 is a DIAGNOSTIC that confirms GPT's batching thesis, NOT a shippable solution.** The real fix must make each handoff CORRECT so a SMALL mht (low latency) reaches 100%.

### CONVERGED next-target (much narrower than before):
Eliminate the **round-1 single-dirent write-side lost-update** during the concurrent shortform→leaf grow. Two complementary angles:
1. STRUCTURAL (preferred, GPT design [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]]): make the dir-EX handoff a correct whole-inode checkpoint+invalidate so the acquiring node's free-slot search reflects ALL committed adds (no double-alloc) — then drop mht back toward default for RULE-0.
2. The loss is the bestfree/free-slot search picking a slot a peer already used, on a base that doesn't reflect the peer's add. mht reduces handoffs but a residual handoff still has a stale base. The existing addname epoch-refresh (mxfs_dir_addname_epoch_refresh=1) + read-path gates miss this case (b_epoch==valid_epoch on the stale block, OR the round-1/format-transition path). Instrument the round-1 loss specifically: P13-COLLIDE / P-STALEBASE-MODIFY at the losing addname; check if it's a shortform-rebase or block→leaf transition base.

### Test infra added: tests/tcp/drc_mht_reliab.sh (N MHT batch+timing), tests/tcp/drc_mht_capfail.sh (single iter + live failure-signature dump). 
### Current state: build EA485CE6 unchanged (mht via modarg only). Criterion NOT met (80%, and RULE-0 slow). Marker NOT written.
See [[sess2-ccloop-BREAKTHROUGH-inode-mht-1500-8tcp-dirreuse-PASS]] [[sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents]] [[sess35-ROOT-round1-format-transition-block-vs-data-divergence]]
