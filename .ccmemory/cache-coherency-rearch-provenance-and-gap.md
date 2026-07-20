---
name: cache-coherency-rearch-provenance-and-gap
description: The cache_coherency re-architecture (fence-invariant design) = Grok+Gemini+Claude 2026-06-06 (NOT GPT). Done for DIR locks (worked); NEVER applied to…
metadata:
  type: project
---

# Cache-coherency re-architecture — provenance + the real gap (read before band-aiding)

## Provenance correction (user, 2026-06-07)
The cache_coherency **re-architecture** is the three-invariant FENCE design recorded in
[[sess96_gpt_fix_design]]. Its body attributes it to "GPT-5.5" — **that attribution is WRONG**.
The user produced it yesterday (2026-06-06) as a **Grok + Gemini + Claude** collaboration,
driven by the self-contained problem statement in `/src/mxfs/CACHE_COHERENCY_ISSUE.md`
(written for external architectural review). It is SEPARATE from `NEWARCH.md` (which only
re-architects the *notification transport* — TCP invalidation mesh — and whose Phase-0 gate
already returned Outcome 3 "cannot pass even fully synchronous", deferring the mesh).

## The design (three fence invariants)
- **Inv 1** — DLM EX release/demote = a real **checkpoint fence**: every buffer the lock
  protected must have reached the shared target AND be clean / non-pinned / **not left as an
  AIL obligation** before unlock. No timeout/best-effort; writeback fail → shutdown.
- **Inv 2** — slow-path EX acquire = an **invalidation fence**: bump gen, mark cached bufs
  stale, re-read from target before first use. Never write a stale buf on acquire.
- **Inv 3** — the "keep stale & continue" (DIR-STALE-SKIP) branch becomes **FATAL**.
- Footnote in the design (load-bearing): *"the same fence design applies to AG locks
  (AGF/AGI/AGFL/bnobt bufs)."*

## Did it work? Partially — and it RELOCATED the bug (the key finding)
1. Implemented for **dir/inode locks** across sess88→99→103→107 → **worked**: killed the dir
   data-coherency bugs (rename_visibility / unlink_visibility / cross_visibility now pass).
2. **Never applied to the AG/allocation locks.** That omission IS the **bnobt double-free**
   (durable: on-disk inode owns a block the bnobt lists free; P47 DISK-LIVE-same-gen / P81
   disk_claims_freed=1). The last ~dozen sessions (incl. ccloop sess19–22) band-aided it with
   WRITE-SIDE interlocks at xfs_buf_submit (P122 split-revert; P124 alloc-revert, proven this
   session) instead of fixing the lock-handoff layer. P124 = a last-instant degenerate Inv 1.
3. Applying Inv 1's **synchronous drain-before-release rigorously EXPOSED the §6 structural
   lock-inversion** → the symptom class shifted from DATA corruption to a **LIVENESS wedge**
   (sess109–113): drain runs in the BAST kworker but must flush buffers owned by XFS's own
   b_sema/ILOCK/xfsaild that the kworker can't reach → root-inode (ino=128) cluster buffer left
   locked + in-AIL + off-list → drain spins forever → peer EX times out → shutdown.
   (sess113 named the leaked-lock root via b_lock_ip tracking: merge_dirs forced-FU path.)

## What "get past this" actually means (CACHE_COHERENCY_ISSUE.md §10)
The recurring wall is the §6 lock-inversion. The architected answer is to change **WHERE the
release-path drain runs**, GFS2-glock-style (`inode_go_sync`/`inode_go_inval`):
either make the **DLM strictly outermost** (acquire DLM before any XFS buffer/ILOCK so the BAST
path never waits on a buffer a blocked local thread owns), OR **move the drain out of the BAST
kworker** into the context that already owns ILOCK. PLUS apply the fence to **AG locks** (fix the
frozen `pag_dlm_meta_gen` so Inv-2 acquire-invalidation actually fires for AG-meta — the
sess19b shared-epoch finding; AG analog of the dir SEQLOCK epoch [[sess97-gpt-dir-coherency-design]]).

## Directive
Write-side interlocks (P122/P124) are STOPGAPS that relocate the failure, not the fix. Don't
drift back into them. The real work is the GFS2-style drain relocation + AG-lock fence.
Related: [[sess96_lessons]] [[sess108_lessons]] (NEWARCH chokepoint, KEEP) [[sess112_lessons]]
[[sess113_lessons]] [[sess19b-shared-epoch-design]] [[sess121-bnobt-clobber-writeside-fix]]
