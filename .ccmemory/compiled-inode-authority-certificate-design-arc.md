---
name: compiled-inode-authority-certificate-design-arc
description: Compiled: inode authority certificate sess95-101 — rulings (cert not cache, CAS out-param, release-begin chokepoint), landings 0.11.428-435, measurem…
metadata:
  type: project
tags: [compiled, authority-certificate, foreign-replay, step5.3, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# Inode authority certificate — design arc sess95→101 (step 5.3 of the foreign-replay campaign)

The producer half of per-INODE authority for buffer log images: how the design was forced
through three GPT rejections into the shipped shape, and what the first rig measurements
said. Continues [[compiled-foreign-replay-authority-tokens]] (steps 1-3); the release-side
wiring that follows this arc is sess104/sess162/sess163.

## Design rulings (each rejection names the load-bearing hazard)

**sess95 — both initial designs REJECTED** [[ccloop-c7ee71c6-sess95-GPT-ruling-step5.3-inode-authority]]:
buffer-stamp-at-modify is historical state (can claim epoch E after E released, peer modified,
we reacquired at E+N — a stamp is sound only with a pin, a checkable active flag, or a
mechanical no-release-between-stamp-and-format proof, and "normally ILOCKed" is not one);
`xfs_iget(INCORE)` in the CIL formatter is the right semantics but wrong mechanism (reclaim
races, per-AG locks, irele in formatter). Ruled shape: immutable per-grant certificate behind
ONE RCU pointer, published only after durable EX acquire, unpublished at FIRST release-begin,
NEVER reactivated (reacquire mints new). Owner derivation once per logical buffer item from
map 0 with hard validation (the bmbt trap: BLFT_BTREE is shared with AG btrees — only
`b_ops==xfs_bmbt_buf_ops && magic==BMA3` proves inode-owned long-format). Statuses must be
population-splitting (OWNER_UNKNOWN/AUTH_NOT_CACHED/AUTH_NOT_HELD/EPOCH_UNAVAIL/AUTH_RACED);
only VALID proves (`mxfs_auth_st_proves`). NO AG fallback ever. Epoch NAMESPACE blocker:
inode-slot vs iclus-slot epochs are incomparable → closed by MXFS_AUTH_CLASS_ICLUS carrying
the backing kind + exact resource on the wire (0.11.428)
[[ccloop-c7ee71c6-sess95-step5.3-wire-landed-cert-design]].

**sess96 — grant_meta hash-cache epoch source REJECTED** [[ccloop-c7ee71c6-sess96-GPT-ruling-step5.3-producer-REJECTS-cache]]:
needed property is "epoch from THIS EXACT grant operation", and `mode > i_dlm_mode` does not
protect a full EX→NL→EX cycle where the OLD acquire completion wins i_dlm_lock last
(delayed completion installs the NEW tenure's epoch off stale evidence). Ruled: thread an
immutable `{resource, epoch, kind, cookie}` OUT of the granting CAS; install validates under
i_dlm_lock via a gen-snapshot cookie, not a mode comparison. Revoke must hook release-BEGIN
(a centralized helper), not the mode=NL cleanup stores — NL is assigned after the slot is
marked releasing/handed off. Routing change IS a tenure transition (revoke, re-mint from the
new backing's own result; clearing alone leaves the inode forever non-proving). Blockers
still tracked from here: uint32 epoch wrap (ABA; ledger D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID),
transaction/CIL tenure crossing. Owner-derivation ladder + the line-verified site inventory
(3 disk-acquire EX stores, 2 local-grant, 3 mirror re-affirm raise-only, 11 mode=NL) landed
0.11.429 [[ccloop-c7ee71c6-sess96-owner-derivation-landed-and-site-inventory]].

## Landings (all build-clean; deployed only at sess100)

- **0.11.430** `struct mxfs_grant_result` threaded out of all 6 CAW grant paths; `valid`
  requires held∈{EX,PW} && nonzero epoch (zero = namespace restart, refused). The two
  already-held reaffirm fills are NOT the rejected cache: they read one slot image showing
  holder bit + epoch together — first-hand evidence, flagged distinct
  [[ccloop-c7ee71c6-sess97-grant-result-outparam-LANDED]].
- **0.11.431** the authority state machine: `i_mxfs_auth_state`
  {NONE, UNPUBLISHED_EX, DURABLE_EX, RELEASING} + gen + install/revoke/begin_release/
  note_unpublished helpers + 11 counters. THE structural fact: all 19 real `i_dlm_mode`
  stores sit in xfs_mxfs_dlm.c wrapped in the dtr_om/mxfs_dlmtr_rec idiom → the chokepoint
  sees every transition with old mode in hand → miss-proof lowering backstop. Gen bump in
  revoke is UNCONDITIONAL even at state NONE (a release inside the acquire window must
  invalidate the snapshot); install does NOT bump (gen counts relinquishments; concurrent
  same-tenure installs take MAX epoch). New blocker found: sticky RELEASING makes an ABORTED
  release (P15-REL-ABORT leaves mode==EX) permanently non-proving → re-affirm path required
  BEFORE begin_release wiring [[ccloop-c7ee71c6-sess98-authority-state-machine-LANDED]].
- **0.11.432** acquire half wired at the one chokepoint `mxfs_dlm_inode_lock_routed` (both
  arms): gen_snap sampled at ACQUIRING before descending into the DLM; routing-flip revoke
  absorbs only its OWN gen bump (`mine` test — re-snapshotting a third party's bump would
  erase evidence). ICLUS continuity: `ic->auth_epoch` set in the same ic->lock section as
  disk_mode raise, cleared at all 3 NL sites — `ic` IS the grant object, so one-lock-section
  reads are first-hand, unlike the rejected hash cache. Publish worker's pub_defer_claim
  installs from its own claim result (UNPUBLISHED_EX→DURABLE_EX)
  [[ccloop-c7ee71c6-sess99-authority-install-wired-acquire-half]].

## Measurements (0.11.434 deployed 32/caw; first numbers after 5 unmeasured sessions)

[[ccloop-c7ee71c6-sess100-authority-population-MEASURED-on-rig]]: rsync_paired PASS 32/32
at no measurable cost. installs 321 vs unpublished_noted 13153 — the created-file lifecycle
is `grant_local_new → UNPUBLISHED_EX → publish-as-DEMOTE → NL`: it never passes through a
durable tenure BY DESIGN (the routed publish path deliberately claims no cluster EX; sess5
measured that claim wedging the bast pipeline). Not a wiring bug; an architecture fact.
`release_begin==0, revoke==backstop` measured — confirming only the backstop revoked before
the sess162 wiring.

[[ccloop-c7ee71c6-sess101-GPT-ruling-AG-cert-rejected-plus-ownauth-instrument]]: broad
AG-class authority for inode images REJECTED (containment ≠ authority; 8 blockers, incl.
non-ABA identity ino+generation, birth-vs-later-update classification, turnover rule at AG
release). General invariant named: *a grant epoch must not go stale while replay-required
records depending solely on it are outstanding*. The ruled long-term shape for unpublished
children is an AG-MINTED DURABLE DELEGATION (batched claim {ino+gen, owner incarnation,
birth AG resource+epoch, scope}), not an authority-free exception. Also refuted the 97.6%
headline (unpublished_noted counts state entries, not images). P239-OWNAUTH instrument
landed+wired (owner-derivation finally called; RCU pag_ici_root lookup, 10-way outcome
histogram) to decide the fork: durable-dominates → wire the gate; unpub-dominates →
delegation required; uncached/stale-dominates → capture moves to the dirty seam. novalid
split measured: notvalid=100% — `caw_grant_result_fill` declines valid on cluster-routed
acquires (the ic->auth_epoch==0 lead sess102+ chased). Live tokclass: the non-AG population
is ~6.3% of images, 99% bmbt t4 (later-modification blocks — strong prior for delegation).

## Recurring lessons

- Provenance is an operation property, not a resource property: every rejected design
  (buffer stamp, iget-in-formatter, hash cache, AG containment) failed by substituting
  "some grant existed" for "THIS grant produced this".
- Ship counters before designs: unpublished_noted/novalid/P239 each redirected the next
  session's work; five build-clean-unmeasured sessions in a row was the anti-pattern.
- Fail closed at every unknown (epoch 0, TCP, no gres, unknown class/status), and never
  let a "bad ones" enumeration admit future statuses.
