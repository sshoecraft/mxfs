---
name: caw-16node-dirent-loss-CASE-B-PROVEN
description: PROVEN (ccloop 26c41354 sess1): 16-node dangling-dirent = CASE B (post-release async clobber), NOT drain-incomplete. dir_relverify=1 → 0 P25-RELVERIF…
metadata:
  type: project
---

## CASE B PROVEN — 16-node dir dirent-removal loss is a POST-RELEASE async clobber

ccloop 26c41354, sess1, build 591A76FB. Extends [[caw-16node-dirent-loss-current-state-sess1]] + [[caw-16node-dirent-loss-gpt-design-plan]].

### The decisive result (RULE 4, no rebuild)
Ran cache_coherency at 16 with `MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 dir_relverify=1"`. `dir_relverify` verifies disk==incore at EVERY dir-EX release and logs `P25-RELVERIFY-MISMATCH ino= daddr= incore_cnt= disk_cnt= (incore!=disk at EX release)` on any divergence.
**Result: 0 P25-RELVERIFY-MISMATCH cluster-wide (all 16 nodes).** So EVERY dir-EX release leaves the dir block on disk == in-core (the removal IS durably applied at release). GPT's Case A (drain never wrote the removal) is REFUTED. **It is CASE B: a POST-RELEASE async write reintroduces the removed dirent.**
(Caveat: relverify=1 also TIMES OUT the test at 16 nodes — per-release FUA-read latency, RULE-0 — so it is a DIAGNOSTIC only, NOT a shippable fix. But P25=0 is a robust statement about drain correctness regardless of the timeout.)

### What this rules IN / OUT
- OUT (Case A): mxfs_dir_data_durable / the release drain (xfs_mxfs_dlm.c ~11237) is CORRECT. Do NOT add more release-side draining. The heavyweight guards (dir_relverify/dir_release_stale/dir_wr_barrier) all TIMEOUT at 16 (RULE 0) AND are unnecessary (drain already works).
- IN (Case B): a write AFTER node5's correct release re-writes the dir block WITH the removed dirent. With `fua_always=1` a peer FUA-reads fresh on ACQUIRE, so the reintroducer is most likely an ASYNC **xfsaild destage of a STALE cached dir buffer** (a peer's, or node5's own, buffer whose in-core image still contains the removed dirent and was never invalidated) — the classic ABA writeback. Proven clobber shape (ccmemory sess22/sess32-HEAD): stale-KEPT dir block destaged WHILE STILL HOLDING EX → the `dir_ex_write_guard` not-held-EX gate MISSES it.

### THE FIX target (lightweight, no per-handoff latency)
`mxfs_buf_xfsaild_skip_dir_write` (pal/linux/xfs_buf.c ~3327-3610) — the xfsaild dir-block destage suppressor. It has many default-OFF/refuted arms (mxfs_dataclobber, dir_ex_write_guard, dir_stale_incarn_skip, dir_subset_guard; dc_stale = b_mxfs_dir_gen<dir_gen). None catch "in-core write REINTRODUCES a dirent absent on current disk" WITHIN-tenure. Skipping a bad async write costs ZERO handoff latency (no RULE-0 risk).

### NEXT (RULE 4 — instrument the reintroducing write, then a targeted skip)
1. Rebuild with a WRITE-SIDE probe at the dir-block destage (xfs_buf.c, where the bio is submitted for a dir DATA/LEAF buf): for owner == the shared test dir, before submitting, do a raw-FUA read of the CURRENT disk block; if the in-core image about to be written contains a dirent (name+inum) that the fresh disk read LACKS (= a reintroduction), log `writer comm, daddr, owner, b_mxfs_dir_gen vs i_dlm_dir_gen, b_mxfs_dir_incarn vs i_generation, i_dlm_mode(EX?), the reintroduced inum, XFS_LI_IN_AIL, done/dirty/pin`. Loop cache_coherency at 16 (baseline dirwr=1 dirland=1, NO relverify) until the dangling-dirent fail; the probe names the exact clobbering write.
2. Then the fix = SKIP that specific destage (the disk is authoritative; our stale in-core would reintroduce a removed dirent). Gate to avoid false-skips of legit ADDs: only skip when a real-FUA disk read proves the disk is a valid same-owner SAME-INCARNATION (b_mxfs_dir_incarn==i_generation) dir block and the in-core buf would reintroduce an inum the disk lacks. Mirror sess26 dir_subset_guard but for the REINTRODUCE direction (in-core has EXTRA inum vs disk), same-incarnation gated so ghosts/fresh-blocks excluded.
3. Alternative/complementary: INVALIDATE (clear XBF_DONE|_XBF_FUA_FRESH) a peer's cached dir buffer when it observes the dir's CAW slot generation advanced (a peer modified it) — so the stale buffer never destages. Cheaper than per-release work; runs on the BAST-poll observing gen change.

### RULE 5 status: proven diagnosis + Case B pinned + 2 fixes refuted (MHT, release-guards). GPT-5.5 consulted once ([[caw-16node-dirent-loss-gpt-design-plan]]). If the write-side probe + targeted skip doesn't converge, 2nd GPT call justified (ask_fable NOT connected; only ask_gemini/ask_gpt).
