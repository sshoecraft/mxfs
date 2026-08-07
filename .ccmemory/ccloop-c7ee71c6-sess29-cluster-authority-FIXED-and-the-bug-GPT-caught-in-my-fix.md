---
name: ccloop-c7ee71c6-sess29-cluster-authority-FIXED-and-the-bug-GPT-caught-in-my-fix
description: Cluster-authority fix (mxfs.cluster_passenger_skip) A/B'd at 8 and 32 nodes: divergence 3/10 -> 0. Plus the bug in my own fix that a GPT review caugh…
metadata:
  type: project
tags: [mxfs, D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, sess29, fixed, gpt-review]
---

# sess29 — inode-cluster write authority: fixed, A/B'd, and self-corrected

Build **0.11.258** (`A25A8EF99DD4821AD2D4CB6`).
Knob: `mxfs.cluster_passenger_skip` — bit0 = drop un-logged slots held only in
PR, bit1 = drop un-logged slots with no in-core inode, **ships 3**, 0 = pre-fix.

## The fix

Drop from the inode-cluster write every un-logged slot this node has no write
authority for. This is exactly what `P56-CORESIDENT-DIR-SKIP` already does for
an un-logged DIRECTORY slot; the non-dir case was never guarded, and that
unguarded `continue` (commented "held non-dir inode -> write it") was the defect.

**Lost-write safety is structural, not lucky.** `logged` is built by walking
`bp->b_li_list` — every inode log item attached to THIS BUFFER — and a logged or
buf-logged slot is never skipped. So a skipped slot provably has no log item for
the buffer's iodone to complete: no AIL item is wrongly removed and no dirty
state is wrongly cleared. That is the assertion GPT asked for, satisfied by
construction.

## A/B — same build, both arms fresh prep, identical workload, window re-marked

| nodes | arm | unauthorised slots WRITTEN | DIVERGENT |
|---|---|---|---|
| 32 | skip=0 | 2242 | **3** |
| 32 | skip=3 | 0 | **0** |
| 8 | skip=0 | 1446 | **10** |
| 8 | skip=3 | 0 | **0** |

Every arm passed `dir_reuse_coherency` and `dirent_durability` at both node
counts — **the control's corruption is silent to every criterion on the board**.
`crash_consistency` 65 s/90 s with the fix, identical to the pre-fix baseline.

## ⛔ THE BUG IN MY OWN FIX — caught by a GPT review, NOT by the A/B that passed

`nskip` counts only the OLD skip rules (free / NL / un-logged dir). I kept the
authority mask separate (`pr_skip`) and counted it in `n_pr_skip`. But the
early-out is:

```c
if (nskip == 0)
        return false;   /* "not a partial write" -> caller writes the WHOLE buffer */
```

So a buffer whose **only** skips were authority skips hit `nskip == 0`, returned
false, and the whole buffer went out — every unauthorised passenger included.
**The mask was computed and thrown away.**

Worse, the per-slot probe stamped `skipped=1` from the mask at the time the slot
was *considered*, so it reported INTENT, not OUTCOME. The A/B's "2241 slots
dropped" was an overstatement. After the fix (`nskip == 0 && n_pr_skip == 0`) the
same workload drops **6187** — the true exposure was ~2.8x what I measured.

Divergence still went 3->0 and 10->0 in the buggy build only because `nskip` is
usually nonzero (free/NL slots are common). **That is luck, not design** — and it
is exactly why an A/B that "passes" is not a substitute for a design review.

## GPT's remaining items, in its order (NOT yet done)

1. **Remove the `declined` fallback.** It currently reinstates the skipped slots
   when the mask would empty the write — i.e. "there was nothing legal to write,
   so write the illegal bytes anyway". Measured 0 so far, which does not make it
   safe. `dirty == 0` after the authority mask implies no logged items and no
   bli_dirty ranges, so refusing loses nothing; the helper already owns
   submission (`return true` = "I submitted it"), so refusal is expressible.
2. **Logged slots need an authority check too.** "Logged this round" proves a
   JOURNAL representation, not authority to publish to HOME. With
   D-RELEASE-BARRIER-OPEN open: A logs X under tenure, releases, B takes tenure
   and publishes X, then A writes its logged image and overwrites B. The
   DIRECTORY case is already guarded (`P56-NL-LOGGED-DIR-SKIP` refuses a logged
   dir slot at NL without a RELFLUSH token); the non-dir case is the same
   asymmetry one level up.
3. Verify storage-granule alignment / lower-layer RMW safety — per-inode v5 CRCs
   detect torn images but do NOT make concurrent sub-block writes safe (e.g.
   512-byte inode writes to a 4Kn device).
4. Audit every other path that publishes an inode-cluster buffer (log recovery,
   inode alloc/free, reclaim, unmount flush, error/retry) — a recovery path that
   reconstructs one inode and writes the whole cached cluster reproduces this.
5. Split-I/O error handling: if one flush becomes several range writes and one
   fails, decide what stays in the AIL.
6. Stale-READ mirror: the skipped bytes remain in the local cached buffer. A
   later DLM acquisition must not consume them as authoritative without reload —
   otherwise a stale-write bug becomes a stale-read bug.
