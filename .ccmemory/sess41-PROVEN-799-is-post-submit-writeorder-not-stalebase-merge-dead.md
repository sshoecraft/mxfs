---
name: sess41-PROVEN-799-is-post-submit-writeorder-not-stalebase-merge-dead
description: sess41 DECISIVE: dir_reuse 799 loss is POST-SUBMIT writeback/reuse ORDERING (in-core ⊇ disk at every write; content-merge proven INERT). GPT plan + P…
metadata:
  type: project
---

## sess41 (ccloop 4cb2d0a2) — DECISIVE redirection of dir_reuse readdir=799/794 root. Current build **0B73D70B** = keeper B17141DA FUNCTIONALLY (ALL new params default-off → NO regression, still ~6/8). New (all OFF): choke_merge infra, REACH probes, P-DLAND landing trace, dirland flag.

### DECISIVE NEGATIVE #1 (RULE 4): the loss is NOT a stale-base RMW
Added a removed-set-disambiguated content-merge at the UNIVERSAL dir-data write chokepoint (xfs_buf_submit→mxfs_dir3_data_writemerge, pre-CRC; gated dir_choke_merge). Probes (8/tcp): P-WMR-REACH FIRES (disk differs from in-core) but **disamb=0 ALWAYS, dko=0 ALWAYS** on passing AND failing runs → **in-core ⊇ disk at EVERY dir-data write** → merge structurally INERT. `dir_choke_merge` DEFAULT 0. Supersedes [[sess41-FIX-chokepoint-disambiguated-dir-merge]].

### THEREFORE: POST-SUBMIT writeback/REUSE ORDERING (an older write of a reused daddr wins on media)
Dirent written correctly (in-core complete) but durably reverted by an older/stale image of the (reused) physical daddr. Fits all evidence (all nodes agree, LOOKUP_ENOENT, no flap, no double-grant, count-preserving, correlates with rm-rf+recreate reuse every round). Reconciles sess17(insert-time)+sess40(handoff). GPT-5.5 confirmed.

### GPT-5.5 RANKED FIX PLAN (invariant = PHYSICAL-block/owner-incarnation, not inode/extent)
1. written_seq at COMPLETION not SUBMIT (+b_mxfs_io_inflight). Likely PARTIAL (current-extent in-flight already ~caught by in_ail + xfs_bwrite buffer-lock; same reason mount-wide m_mxfs_dir_wr_inflight barrier was a no-op).
2. **Drain by OWNER/INCARNATION incl FREED/converted/leaf blocks, NOT current extent map** — release fence walks current extents, misses freed blocks = THE KEY GAP.
3. **Cluster physical-daddr REVOKE/quarantine before reuse** (or local per-inode freed-daddr ring drained at free, since the freeing node holds EX + peers already synced).
4. Remove acquire-side bounded "wait-then-keep-stale" fallback (mxfs_dir_drain_evict_data_blocks LOCKED-SKIP).
5. Per-daddr single-in-flight-write serialization.

### TOOLING + the trace-overhead trap (IMPORTANT for next session)
- `mxfs.dirland=1` → P-DLAND at I/O COMPLETION: `daddr/owner/incarn/sum(FNV of post-header)/realns/comm` for dir3 data/leaf/block writes. Merge nodes by realns per daddr → which content version lands LAST. NOTE owner is garbage for leaf blocks (header layout differs); valid for data/block.
- KERNEL RING ROTATES over 24 rounds → fail snapshot kept only ~40 P-DLAND/node (rounds 1-4); the lost .md5 sidecar write (comm≠dd) rotated out. Partial data showed per-daddr writes grouped CLEANLY by incarnation (NO reorder in window) and the CREATOR wrote the round-4 daddr LAST yet the entry is lost → the reverting write is NOT in the captured trace (rotated OR a b_ops P-DLAND doesn't cover).
- **DRC_STREAM=1 (via `MXFS_TEST_ENV='DRC_STREAM=1 DRC_ROUNDS=N'` — run.sh line 199 ALREADY forwards MXFS_TEST_ENV to each rank, no edit needed) writes full dmesg to /src/mxfs/tests/tcp/drc_cap/stream_rankN.log (NFS, rotation-immune) BUT IS TOO SLOW: dmesg --follow piping to NFS + dirland flood = ~4 min/ROUND (RULE-0 catastrophic, self-contaminating → masks the race).** DO NOT use DRC_STREAM+dirland together at full workload.
- BETTER next-session trace: an IN-KERNEL circular buffer for P-DLAND entries (fixed array, NO printk/NFS per line), dumped via debugfs or on-fail — avoids the printk/stream overhead entirely. OR dirland to ring + bump guest log_buf_len. OR reduce DRC_ROUNDS to ~6 AND DRC_NFILES enough to keep leaf/btree format, streaming only then.

### NEXT (RULE 4): prove the exact late/stale write (which node, EX/NL, incarn same-vs-prior, freed-block bio vs non-dir3 b_ops), THEN implement the matching piece of fix 2/3. If a light trace still shows no reorder for the lost daddr, the reverting write uses a b_ops P-DLAND misses (widen coverage) or it's the leaf index. See [[sess40-PROVEN-799-is-release-drain-gap-async-writeback-overlap]].
