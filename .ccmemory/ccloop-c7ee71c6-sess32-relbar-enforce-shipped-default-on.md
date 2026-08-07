---
name: ccloop-c7ee71c6-sess32-relbar-enforce-shipped-default-on
description: 0.11.280: relbar_enforce default ON — anchored-unlock ledger close (2 durable passes else -ESTALE defer); A/B 10-12 leaks vs 0, 6/26551 defers, board…
metadata:
  type: project
---

# sess32 — relbar enforcement shipped (0.11.280, 699CEA74991DF48FE88B9B8)

## What ships
`mxfs.relbar_enforce=1` (default): in mxfs_dlm_bast_process's ANCHORED unlock
tail, before the wire unlock: if `i_mxfs_pub_pending_seq != durable_seq`, run
up to 2 in-place durable passes (`__mxfs_dlm_dir_inode_durable` for dirs /
`mxfs_inode_cluster_durable` for non-dirs — the wire grant is still ours, so
the writes are authorized); if the ledger still won't close, DEFER the wire
unlock by folding into the existing LIVE-SKIP `-ESTALE` path (stranded=true →
bast_pending re-arm → requeue). Counters `closed`/`deferred` in
P220-RELEASE-BARRIER-TOTAL; P228-RELBAR-DEFER (cap 400) prints each defer.
Wrapper scope closes with a `}	/* sess32 rb_defer scope */` before the
p15h_reap epilogue — mind it when editing that region.

## A/B (same build, 32/caw, dirent_durability producer + guard board)
- enforce=0: obligation=10 and 12 per lap at the wire unlock (typed: shared
  parent dirs, lastrel=1 — durable flush RAN, then a commit landed in the
  flush→unlock window; fmt=1 shortform; item clean at print).
- enforce=1 (3 laps + board): obligation=0, closed=0, **deferred=6/26551
  (0.02%)** — all 6 on ino 150/142 (criterion base dirs), every one
  pend-dur=+1 cls=UNCOPIED, i.e. an in-window recommit the 2 passes could
  not capture (likely mid-commit; the requeue lands it a cycle later).
  Thousands of unlocks of the same inos did NOT defer → transient, no
  starvation. Walls unchanged: dd 64/65/66s, cache 28s, crash 69s,
  dir_reuse 101s. Default flipped ON after this evidence.

## Measurement lessons
- The wire-unlock numerator is INTERMITTENT lap-to-lap (10, 12, 0…) — a
  single zero-exposure lap proves nothing; accumulate.
- relbar_check("anchored") runs INSIDE the non-deferred arm — a deferral
  skips it, so with enforce=1 `obligation` counts only post-enforce residue.
- `closed=0` does NOT mean the passes are useless: the observed opens are
  mid-commit windows; the value of the arm is the DEFER (never hand the
  grant away open), not synchronous closing.

## Remaining for D-RELEASE-BARRIER-OPEN (still OPEN)
1. noanchor unlock arm (second relbar_check site ~16504) unenforced.
2. GPT's admission interlock (RELFLUSH as a real gate: block new protected
   mutations during the closing drain) — removes the recommit window itself.
3. Certificate covers inode CORE only; dir DATA blocks need per-tenure
   buffer obligations (sess29 warning; GPT design in sess32 ruling memory).
4. Orphan/inodegc minority class (1/16 typed events, nlink=0) — GPT's
   authority-reacquiring inodegc design queued.
5. Closure per GPT: source-counters-zero + deterministic race injection +
   5-point fault matrix + extended stress; a finite zero count insufficient.
