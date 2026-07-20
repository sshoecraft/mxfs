---
name: sess2-ccloop-FINAL-epoch-fixes-banked-corruption-gone-residual-is-writeside
description: sess2(ccloop) FINAL build 5240351B (KEEP): leaf/block addname DATA + LEAF-HASH epoch-refresh. At DEFAULT mht=300 ELIMINATES all corruption (DABUF/shu…
metadata:
  type: project
---

## sess2 (ccloop) FINAL — build 5240351B. KEEP (strictly better than EA485CE6). Criterion NOT met; marker NOT written.

### What 5240351B adds (2 evidence-based fixes + 1 probe), vs EA485CE6:
1. **DATA-block epoch refresh** in `mxfs_dir_addname_coherent_refresh` (xfs_dir2_data.c): port node-format's master-handoff-epoch gate to leaf/block addname (b_mxfs_dir_epoch < master_ep → cold re-read the data block before free-slot search). Closes most intra-block free-slot double-alloc.
2. **LEAF-HASH-block epoch refresh** in xfs_dir2_leaf_addname (xfs_dir2_leaf.c, after xfs_dir3_leaf_read): same idiom on the LEAF index buffer before the hash insert. Closes most leaf-hash holes.
3. P2-EPOCHPLACE + P2-LEAF-EPOCHSTALE + P2-LEAFHASH-EPOCHSTALE always-on probes (regression detectors; must trend to 0).
All gated mxfs_dir_addname_epoch_refresh (default 1). CLEAN-only (own dirty/in-AIL-undestaged/pinned never dropped).

### MEASURED EFFECT (default mht=300, where baseline EA485CE6 = 0/8 DETERMINISTIC DABUF_MAP_HOLE+shutdown):
- **ALL corruption ELIMINATED**: DABUF=0, shutdown=0 across runs (HUGE — first corruption-free 8/tcp at DEFAULT mht, no slow batching).
- Reliability ~2/3-ish (flaky). Residual = CLEAN single-dirent loss (799/800, e.g. round-17), no corruption. Both epoch probes FIRE (P2-LEAF-EPOCHSTALE ×3-4, P2-LEAFHASH ×2) → the refreshes work but a residual loss slips through.

### CONCLUSION (consistent with sess36): the epoch READ-refreshes are NECESSARY but NOT SUFFICIENT. The residual 799/800 is a **WRITE-side lost-update** — a node's destage/insert reverts a peer's add even with a coherent read base (two EX tenures on the same dir block interleave). Read-coherency cannot fix a write-side TOCTOU; only true serialization (no overlapping EX modification of the same dir block) can. = GPT's whole-inode coherent ACK-based handoff [[sess2-ccloop-GPT55-design-whole-inode-EX-handoff-ack-based]].

### State of the two knobs:
- **mht=1500** (batching): 0%→80% by reducing handoff COUNT (fewer overlap windows). RULE-0-SLOW (~540s, ~6× native). Diagnostic, not shippable.
- **epoch fixes (5240351B)**: eliminate corruption + most loss at LOW mht (RULE-0-OK ~450s). Residual write-side loss.
- Likely **mht=1500 + 5240351B together** → highest reliability (untested ≥3×; do this next as a stopgap measure while building the real fix).

### NEXT SESSION (clear path):
1. Confirm 5240351B is a clean KEEP: run ./run.sh {1,2,4} tcp + other 8/tcp tests — ensure the leaf/data epoch re-reads don't regress (they're CLEAN-only + gated, low risk).
2. Implement the WRITE-side serialization (the real fix): GPT whole-inode ACK-based handoff — on genuine EX handoff, release=checkpoint WHOLE dir + invalidate, acquire=invalidate WHOLE inode + reread, gate dir-modify on explicit EX epoch token. This closes the residual write-side lost-update so a LOW mht reaches 100% (correct AND RULE-0-fast).
3. Validate ≥10 clean runs (bug ~20-40% flaky) at default mht, P2-* probes → 0, then full suite {1,2,4,8} tcp.

### Test infra (RULE 3): tests/tcp/drc_mht_reliab.sh, drc_mht_capfail.sh, drc_modarg_reliab.sh. Build 5240351B on /src/mxfs/mxfs.ko (deployed via NFS).
See [[sess2-ccloop-leaf-DATA-epoch-fix-works-residual-now-leaf-HASH-hole]] [[sess2-ccloop-ROOT-PROVEN-leaf-block-addname-missing-epoch-refresh]] [[sess2-ccloop-BREAKTHROUGH-inode-mht-1500-8tcp-dirreuse-PASS]] [[sess36-FACE...]]
