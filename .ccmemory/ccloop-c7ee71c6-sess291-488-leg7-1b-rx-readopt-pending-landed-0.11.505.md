---
name: ccloop-c7ee71c6-sess291-488-leg7-1b-rx-readopt-pending-landed-0.11.505
description: sess291: D-488 leg7 part 1b LANDED+BUILT 0.11.505 sv 7BFD835EDA68D87A5C6D621 — rx strand READOPT_PENDING + P295 worker mint + P243 reclaim guards; NO…
metadata:
  type: project
tags: [D-488, readopt-mint, rx-readopt-pending, P295, P243, 0.11.505]
---

# sess291 — D-488 leg 7 part 1b landed (0.11.505)

Implements the sess289 ruling part 1b on top of sess290's 1a. Clean
rebuild, links, no new warnings. NOT deployed — next step is 32/caw
deploy + fault-inject verification (strand inject knob
mxfs_ag_strand_inject_hit already exists in bast_work_fn).

## What changed
- `xfs_ag.h`: new `bool pag_dlm_readopt_pending` (set/cleared under
  pag_dlm_lock; single-flight via bast_scheduled latched in same crit
  section).
- rx strand detector (xfs_mxfs_dlm.c P5N-AG-ORPHAN-NAK branch): no
  longer sets `cached=true` — that fabricated a cached tenure with
  published epoch 0 which the cached fast-path reclaim adopted as
  WRITE authority (the epochless-writing-tenure window). Now sets
  readopt_pending + bast_scheduled + bast_pending and queues worker.
- New `mxfs_dlm_ag_rx_readopt_mint()` (above bast_work_fn), dispatched
  from Phase-1 !cached arm when readopt_pending && !demoting &&
  !release_pending: rereads slot via mxfs_v5_dlm_ag_held —
  bit gone → P295-RX-READOPT-GONE, clear pending;
  bit ours → mxfs_ag_dlm_lock (attested, published epoch 0 → 1a P294
  READOPT mint, epoch published by the normal acquire path) →
  P295-RX-READOPT-MINTED → clear scheduled latch, set bast_pending →
  mxfs_ag_dlm_unlock → last-holder transition reschedules worker →
  normal drain/COMMIT/release. Mint fail → P295-RX-READOPT-FAIL,
  nothing published, no requeue (rx watchdog re-arms on next BAST
  ~1/s — matches "rx readopt is the backstop" philosophy).
  readopt_pending cleared at: worker holders-bails (local acquire
  resolved it via attested fresh path), Phase-2 COMMIT, unmount flush,
  single→multi surrender.
- P243 extension (ruling: probe EVERY writable-tenure entry):
  cached-reclaim arms (fast path + slow recheck) FAIL CLOSED on CAW +
  epoch==0: drop the hint, fall through to fresh attested acquire
  (which re-mints via 1a) — P243-AGAUTH-UNBOUND src=cached-fast/-slow.
  release_pending reclaim arms: PROBE ONLY (src=relpend-fast/-slow).
  Reasoning: only setter of release_pending=true today is the unlock
  quarantine arm (P275-AGUNLK-QUARANTINE) which keeps demoting held so
  wait_demote blocks all acquirers — the arm is unreachable; a
  behavior change would interact with mxfs_dlm_ag_meta_iodone's
  deferred release (consults release_pending && holders==0 → platter
  unlock) and risks clearing a quarantine marker. Detect first (RULE 4).

## Key facts established (code audit)
- Normal cached retention (last-holder unlock, cached=true) KEEPS the
  published epoch; epoch zeroing sites are release-commit points that
  also clear cached in the same pag_dlm_lock section. So CAW
  cached=true + epoch 0 was exactly and only the rx-strand fabrication.
- gres from the 1a mint is proving (reaffirm=0, filled from NEW image)
  → __mxfs_ag_dlm_lock's publish block accepts it; no P243 fires.
- Strand state (holders=0, !cached, !dm, !rp checked under lock at rx)
  excludes any in-flight platter unlock, so the worker mint cannot race
  one; quarantine (dm held) is excluded in the worker dispatch check.

## Verification plan (next session)
Deploy 0.11.505 32/caw, board baseline, then strand-inject: assert
dmesg chain P5N → P295-RX-READOPT-MINTED + P294-READOPT-MINT
(Enew>Eold), bit never absent (caw slot dump), no Eold republish, and
the subsequent normal release. Then STILL_HELD inject for the 1a re-arm
(P275-AGUNLK-REARM should now show P294-READOPT-MINT underneath).
