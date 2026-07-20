---
name: sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX
description: sess16(ccloop) GPT-5.5 convergent design for the dir-EX-handoff lost-update: tie dir-buffer validity to CONTINUOUS DLM grant tenure. Primary=drain-th…
metadata:
  type: project
---

## sess16 (ccloop) GPT-5.5 design — tenure-scoped dir-buffer coherency (the convergent fix)

For the PROVEN root in [[sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate]] (a node RMWs a shared dir block from a stale cross-tenure base — peer wrote count=126, node later wrote count=77 — because the anti-resurrection keep-guard preserves the node's own now-stale buffer across an EX handoff).

### Core invariant GPT recommends
**A dir DATA/LEAF/NODE/FREE buffer is valid only while the node has CONTINUOUSLY held ≥PR since the buffer was loaded.** Dropping below PR ends the tenure; a peer may have written the LUN, so the cached payload is no longer a valid RMW base. This is the real coherence boundary.

### Precise non-resurrection predicate (the 90-session knot, resolved)
"Never drop un-drained local work; ALWAYS drop old-tenure clean/durable directory buffers." The key realization: at the demote/release point, AFTER Invariant-1's synchronous drain, the buffer is DURABLE on the LUN — so clearing XBF_DONE is NOT resurrection (the peer reads exactly what we drained; we reread the peer's newer image later). The payload-LSN "undestaged" heuristic gives FALSE POSITIVES and must NOT decide cross-node coherence — DLM tenure/epoch state dominates.

### Three-part design (do all three)
1. **PRIMARY — drain-then-invalidate at RELEASE, fenced.** On BAST/demote: set a REVOKING bit → block NEW local dir ops from starting (gate the create path BEFORE it begins the txn, not just before DLM acquire) → wait active_dir_ops==0 → drain (force log, wait unpin, push AIL/delwri, FUA-write home blocks, WAIT io) → verify clean quiescence (no dirty BLI/pin/delwri) → clear XBF_DONE + zero tenure/epoch stamps on ALL dir metadata buffers (DATA+LEAF+NODE+FREE, not just daddr=120) → drop grant to NL → clear REVOKING. **The REVOKING writer-fence is the correctness hinge** — it closes the "redirty after drain, before grant drop" window that sank sess96's naive force-evict-on-release.
2. **BACKSTOP — epoch-invalidate at REACQUIRE.** On grant acquire: bump local tenure_gen, record grant_epoch; if grant_epoch > i_dlm_dir_valid_epoch → assert no local dirty dir bufs, invalidate any remaining old-tenure/old-epoch dir buffers (OVERRIDE the payload-LSN keep-guard, justified because epoch-advance proves a peer wrote since our drain), set valid_epoch=grant_epoch. Epoch is the RELIABLE signal (sess64 level-triggered), NOT grant_gen (sess61: overfires, bumps every promotion).
3. **ENFORCE at USE.** Stamp each dir buf with (tenure_gen, epoch) at coherent read. Before RMW/write: require XBF_DONE && buf.tenure==ip.tenure && buf.epoch==ip.epoch && grant≥PR(read)/EX(write); else FUA-reread+restamp (or shutdown loud in debug). This alone would have caught test2's count=77 stale write.

### CONCRETE implementation plan (build on existing machinery — much of this EXISTS)
- FIX3 already adds `b_mxfs_grant_gen` (xfs_buf.h) + `i_dlm_cached_grant_gen` (xfs_inode.h) + a postread re-read in xfs_da_read_buf (param `dir_postread_reread`, currently default 0). It's ~the "enforce at use" piece but (a) EX-only, (b) still wrapped by the clean/undestaged keep-guard, (c) keyed on grant_gen (overfires) not epoch, (d) OFF.
- Minimal convergent change: re-key the postread re-read on the EPOCH (`i_dlm_dir_valid_epoch` vs `mxfs_v5_dlm_inode_dir_epoch(ino)`) and, WHEN epoch advanced, OVERRIDE the undestaged keep-guard (clear XBF_DONE even if the payload-LSN says undestaged) — because epoch-advance + we-dropped-below-PR proves it's stale, not un-drained. Keep the dirty/pinned/in_ail/delwri guards (those ARE genuine in-flight local work; epoch can't advance while WE hold EX continuously, so a dirty buf under our continuous EX is ours and kept).
- Add the release-side invalidate in the BAST/release drain path (after mxfs_dir_flush_data_blocks completes, before the EX→NL grant drop). The REVOKING fence: check whether mxfs already serializes bast_process vs active local txns via the ILOCK (bast_process Phase 2 takes ILOCK to drain; if a create holds ILOCK, bast_process blocks → that may already be the fence for single-txn; the gap is the cached-grant-between-txns window which the invalidate closes).

### VALIDATE
mht=50 (or 0) MUST become correct: P-DIRWR daddr count must be monotonic (no 126→77 regression). Then dir_reuse 8/tcp PASS at low mht AND tcp_dlm_scaling ≤60s → full 8/tcp 17/17 → 1/2/4. Canaries: unlink_visibility/rename_visibility/crash_consistency MUST stay PASS (resurrection regress = the keep-guard override was too broad). Instrument the 2 failure modes GPT flags: (1) dir buf dirtied during REVOKING (redirty-after-drain), (2) stale-tenure buffer used for RMW/write.

Build BAB5566E (baseline + inert P32F fence). The P32F-NXSHRINK-FENCE I added is a SECONDARY symptom guard with a wrong discriminator (never fires) — leave gated, revisit/remove. See [[sess69-FIX-caveat-evict-on-release-refuted-thread-the-needle]] (sess96 naive evict refuted — GPT's REVOKING fence is the missing piece).</body>
