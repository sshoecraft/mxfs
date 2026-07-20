---
name: sess17run-GPT-design-incarnation-stamp-dirbuf-plus-digen-reload
description: sess17(ccloop) GPT-5.5 convergent design for round-5 reuse-churn first-dirent loss: di_gen-level reload at post-EX + per-daddr dir-buffer incarnation…
metadata:
  type: project
---

## sess17 (ccloop) GPT-5.5 design — reuse-churn (round-5+) first-dirent loss

Context: my fast-path handoff-adopt fix (post_release=dir_ex_handoff on grant_gen/epoch handoff, build 9AF854E6) moved dir_reuse 8/tcp failure round 1→5. Round-5 residual = INODE INCARNATION mismatch: a node holds PREVIOUS incarnation in-core (i_generation=1902947330) while disk di_gen=2928081416 (after rm-rf+recreate), RMW/converts off the stale incarnation, drops the first dirent. See [[sess17run-ROOT-round1-firstdirent-loss-convert-gate-inert]].

### GPT verdict: TWO parts, both required (neither alone suffices)
1. **Post-EX / pre-local-ILOCK reload keyed on LEVEL-TRIGGERED di_gen** (not grant_gen edges, which under-fire ~80% on TCP). At the xfs_ilock DLM-EX hook (where my fix lives), if `in-core i_generation != authoritative di_gen` (from grant payload or disk dinode) → force `mxfs_dlm_reload_inode(post_release=true)` = DISCARD old incarnation fork + ADOPT disk. di_gen is level-triggered, returned on every grant. Do NOT gate on size==0 (the existing P103 reuse-adopt does — that's why it fired 0×). Generation mismatch ⇒ discard/adopt, NEVER merge (so no resurrection — old incarnation dirents are logically dead, must not be flushed or used as RMW base).
2. **Per-daddr dir-buffer INCARNATION STAMP checked at buffer lookup.** The buffer cache is daddr-keyed; the XFS dir verifier only proves "block belongs to inode 131", NOT "belongs to incarnation 2928081416 of 131". So a stale prev-incarnation XBF_DONE buffer at a reused daddr passes the verifier and becomes a stale RMW base. Stamp each dir DATA/LEAF/NODE/FREE buffer with {ino, di_gen, dir_epoch, kind} at coherent read; at EVERY dir buffer lookup, if XBF_DONE && stamp doesn't match current {ino, i_generation, epoch} → clear DONE, cold reread, verify, restamp. A dirty stale-incarnation buffer = corruption (don't flush). Cover dir block/data/leaf/node/free read helpers AND the sf→block / block→leaf conversion read paths.

### Why both: reload alone leaves a stale daddr XBF_DONE buffer reusable after the fork is fixed; buffer-stamp alone doesn't fix a stale in-core shortform conversion base frozen before any external block read.

### Cheap on common path: grant says same di_gen + no epoch advance → no reread; stamp matches → accept cached. Cold reread only on coherence miss (incarnation change / epoch advance / unstamped buffer).

### MXFS already has: `bp->b_mxfs_dir_incarn`, `bp->b_mxfs_dir_gen`, `ip->i_dlm_dir_evicted_incarn`, `new_incarn=(evicted_incarn!=i_generation)` in modify_refresh. So machinery partially exists — wire the stamp-REJECT at dir buffer read (xfs_da_read_buf) and the di_gen-level reload at the post-EX fast path. NEXT: implement, test round-5+ at 8/tcp. Criterion NOT met.</body>
