---
name: sess30-refuted-prior-tenure-evict-levers-and-relay-boundary
description: sess30(ccloop) end: dir_evict_prior_tenure=1 + dir_tenure_evict=1 REFUTED (dir_reuse still 0/8 + dlm_scaling 7/8). Keeper build 37A37B10. Precise roo…
metadata:
  type: project
---

## sess30 relay-boundary note

### Refuted this turn: `dir_evict_prior_tenure=1 dir_tenure_evict=1` (epoch-based prior-tenure read-hook evict, was NOT in the winning config) — dir_reuse 8/tcp STILL 0/8, AND dlm_scaling dropped to 7/8 (extra eviction cost). Keep default-0.

### PRECISE ROOT nailed this session (best characterization yet)
The dir read-time gen/epoch-invalidation hook (`xfs_da_read_buf`, xfs_da_btree.c ~3232) **CANNOT invalidate an in_ail/pinned/UNDESTAGED stale dir buffer** (clearing XBF_DONE on it corrupts — sess64; and an undestaged buffer holds this node's un-written add A). So a dir MODIFY that reads a stale prior-tenure in_ail-undestaged block (bgen=0, base missing peer's add B) **RMWs the stale base** → destages base+A over disk base+B → durably drops B (the 399/400, P21H-LEAFHOLE). The read hook ALREADY handles the DESTAGED in_ail case (sess133 `mxfs_dir_buf_is_undestaged` discriminator). The residual is the UNDESTAGED conflict: our un-written A on a stale base missing B → **requires a transactional 3-way re-apply of A onto the freshly-read base+B** (can't evict=lose A, can't destage=lose B, can't byte-merge at bio chokepoint=cross-block dup/refuted). This is THE unavoidable fix and it's a major undertaking.

### KEEPER BUILD 37A37B10 (deployed): 4 dir levers default-1 + crashconsist ABBA fix + soak P30-ops-recover fix + (default-off/inert) dir_release_flush_all_done, agi_crc_probe. Behaviorally == C1B0C0CE for the validated config.

### VERIFIED criteria progress: 1/tcp=16/16 ✓, 4/tcp=17/17 ✓ (bare). 2/tcp & 8/tcp blocked ONLY by dir_reuse (flaky: single-dirent loss + rarer AGI-CRC shutdown 8-node). crash_consistency + soak FIXED.

### NEXT: implement the transactional in-AIL-delta re-apply at re-acquire (the only non-refuted path), OR find why the modify obtains a bgen=0 block via get-without-read instead of the gen-checking read (fix that get site so the modify never RMWs a stale base). Diagnostics in tree: P30-AGI-RDFAIL/WRITE (agi_crc_probe), P-WMERGE (dir_writeprobe), P-DE-BLK. See [[sess30-TRUE-HEAD-handoff-final-corrected]] [[sess30-LEAD-bgen0-clobber-block-origin-is-next-target]].
