# FREE-PUBLISH — the freed-dinode publication invariant

Status: LANDED sess427 (0.38.1), D-IFREE-DINODE-NEVER-PUBLISHED-INOBT-FREE-
VISIBLE-PEER-DOUBLE-ALLOC-SHUTDOWN-0351.  Design-consult rulings: `docs/rulings/free-publish-invariant-d0351.md`.

## The invariant

> A peer may select an inode as free under a newly acquired AG allocation
> grant only if the matching free dinode image (`di_mode == 0` at the freed
> incarnation's new generation) is already durable on the shared LUN.

Equivalently: *inobt-free visible to a peer ⇒ dinode-free already durable*.
The inobt/AGI buffers may physically reach the platter earlier (xfsaild
writes them whenever it likes) — that is tolerable only while this node still
holds the AG EX, because no peer can act on the free bit without the grant.
The AG-grant handoff is therefore the enforcement point.

## The defect (measured, s430 `tests/dir_recreate_estale.sh`, 2026-08-28)

test1 (`rm -rf D`) freed `D/test2` = ino 8388737, a directory whose per-inode
EX had just been stripped by a peer BAST; the inactivation held the cluster
EX (`i_dlm_mode` stayed 0), set `MXFS_IF_DLM_RELFLUSH`, committed the ifree
(inobt bit freed, `xfs_iunlink_remove` discharged the sess387 *unlink*
obligation) and ended with the item still pinned: `P128-INACT-DEFER` kept the
grant cached and **cleared RELFLUSH**.  11 ms later xfsaild's push discarded
the dinode flush (`P119-NONEX-FLUSH-SKIP`, no sanction) and in the same push
wrote the inobt free (`P144-WR inobt lsn=100000075`) and the inode cluster
with the OLD image (`P170-CLWR [8388737:40755:507]`).  86 ms later test2's
`mkdir -p D/test2` allocated 8388737 from the free bit, read the live platter
dinode, and MXFS's double-alloc gate (`P-CR63-DEFER-DISKLIVE`, `P-CR62
DISK-LIVE`) failed closed with `-EUCLEAN` after `dialloc` had dirtied the
transaction → dirty `xfs_trans_cancel` → filesystem shutdown → fenced.

Why nothing caught it: the eager per-ifree durability chain is off since
sess2 (`mxfs_ifree_eager_durable=0`, 17-33 ms/unlink) in favour of the AG
release's Phase-2 drain — but that drain only writes the cluster *buffer*;
the copy-in of `mode=0` into the buffer is `xfs_iflush`'s job and is gated by
the P119 sanction that the DEFER branch had removed.  The release audit
(sess387 P87) enforced *unlink* obligations only; the ifree discharged that
obligation and armed nothing.

## The fix — a FREE publication obligation (same machinery as sess387)

`struct mxfs_pubob` gains `kind` (UNLINK / FREE_PENDING / FREE), `gen` and
`epoch`.

1. **Continuous coverage.**  `xfs_inactive_ifree` marks the inode
   `i_mxfs_freeob = 1` before `xfs_ifree`; `mxfs_pubob_discharge` (called by
   `xfs_iunlink_remove` inside the ifree transaction) then *transitions* the
   entry to FREE_PENDING instead of dropping it (creating it if the unlink
   conversion had already landed).  After `xfs_trans_commit` the entry
   becomes FREE with `gen = i_generation` (the bumped value) and `epoch =
   pag_mxfs_grant_epoch` — the AG EX tenure held at that moment (holders > 0,
   so no release can begin in between).  Epoch 0 there is a protocol failure
   (`P-FREEOB-NOEPOCH`).  A failed ifree drops it (`mxfs_pubob_free_abort`).
2. **P55C in `xfs_iflush`** (before the P119 guard) for `i_mxfs_freeob == 2`:
   classify the platter image against `{gen, epoch}`:
   - `mode=0 && di_gen==gen` — already published: discharge, skip;
   - `mode!=0 && di_gen==gen-1` — the exact incarnation we freed: WRITE it,
     sanctioned by (a) the release audit's retiring token (`RELFLUSH` under
     `pag_dlm_demoting` with `pag_mxfs_rel_epoch` set, after the audit's own
     out-of-cache verify) or (b) the **publication-write gate** on the same
     uninterrupted tenure (`mxfs_ag_pubwrite_begin(pag, epoch)`: count up,
     re-check the epoch; the release COMMIT zeroes the epoch and then waits
     for the count to drain before its buffer drain — closing the TOCTOU a
     bare epoch read would have); otherwise the item is kept DIRTY
     (`-EAGAIN`, nothing consumed) — laundering it would let reclaim take the
     only copy of the free image — and a strike is counted;
   - any other `di_gen` — not our predecessor: never write, neutralize
     (`i_mxfs_dead_incarn_gen`), discharge, loud `P55C-FREE-FOREIGN`.
   The copy-in marks `MXFS_IF_PUBOB_FLUSHED` for a free only when the image
   written is the free image (`i_mode == 0`, committed).
3. **AG-release audit** (`mxfs_p86_agi_unlinked_publish_audit`, runs after
   the drains and before `mxfs_v5_dlm_ag_unlock`): FREE_PENDING → defer;
   FREE → FUA/plain read of the home dinode, same classification; the exact
   predecessor with a shell is published through `mxfs_iflush_agino_target`
   (its scoped RELFLUSH is P55C's retiring token) and re-verified
   (`P-FREEOB-PUBLISHED`); unpublishable frees count as `pag_mxfs_freeob_split`
   and the release worker defers the unlock in 2 s steps (up to 16 s beyond
   the P87 deferral) and then **fails closed** (`P-FREEOB-REFUSED`,
   shutdown) regardless of the P87 protest knob — our journal slice carries
   the committed free, so replay publishes it after a fence.
4. **Recovery worker** (`mxfs_freeob_recover_fn`, never in AIL/iflush
   context): after 8 P55C denials the mount's worker takes the AG EX afresh,
   reads the home dinode off the LUN and re-scopes the obligation to the new
   tenure (`P-FREEOB-RESCOPED`), discharges an already-published one, or
   neutralizes a foreign one — so a lost tenure (only reachable after a
   publish-under-protest) never pins the AIL tail indefinitely.

## 0.38.1 → 0.38.3: two defects in the first landing (sess428, proven by instrument)

The s431 32/caw board on 0.38.1 collapsed (cache_coherency 0/32, 14
criteria blocked) with 51 `P55C-FREE-FOREIGN` lines, all `disk_mode=00`,
and on test5/test1 each was followed by `P32D-DEADINCARN-SKIP` on a NEW
live file (`incore_mode=0100644`, EX held) that then never reached the
platter.

1. **Classification.**  `i_generation` is random at allocation
   (`xfs_init_new_inode`) and `++` at free, so a short-lived incarnation
   whose live image never reached the platter leaves `mode=0` at the
   PRE-allocation gen.  The invariant is about MODE: a free platter dinode
   satisfies FREE-PUBLISH at any gen (ours, an older free, or a peer's
   later free).  All three classifiers (P55C, the audit FREE branch, the
   recovery worker) now treat `mode==0` as published; `P55C-FREE-HOME`
   reports `disk_gen` and whether it is an older/other free image.
2. **Poison survives re-allocation.**  A FOREIGN verdict stamps the freed
   shell with `i_mxfs_dead_incarn_gen` (write-poison: never write this
   shell's core), and `xfs_iget_recycle` preserved it, so when THIS node
   re-allocated the number the new life inherited the poison.  The recycle
   path now clears it on a local create (`P-RECYCLE-DEADSTAMP-CLEAR`): the
   new incarnation is ours by construction (inobt under the AG EX; a
   deadshell create has passed the platter verdict).

Verification: `tests/sess428_chain.sh` — dre ×2 with the sess428-fixed
harness (zero `P55C-FREE-FOREIGN` with `disk_mode=00`, zero
`P32D-DEADINCARN-SKIP`) then the full 32/caw board.

## 0.38.3 → 0.38.4: the home-free discharge must SETTLE the ledger (sess429)

The s432 board on 0.38.3 (dre ×2 clean) collapsed at fio_perf: test1 shut
down via `P237-EVICT-OBLIGATION ino=133 pend=14 dur=0 nlink=0 imode=00`
six seconds after `P55C-FREE-HOME ino=133 disk_gen=0` discharged the FREE
obligation.  The discharge dropped the obligation but left the freed
incarnation's publication ledger open; `flush_out`'s abandoned-publication
chokepoint marked it fenced, and the only consumer of that mark is the
deferred-RELEASE worker — an unlinked inode gets no BAST and goes straight
to reclaim.  In 0.38.1 the same inode took the FOREIGN branch, whose
write-poison *exempted* P237: the tripwire was masked, never satisfied.

Design-consult ruling (ccmemory `ccloop-c7ee71c6-sess429-GPT-ruling-home-free-
ledger-settle`): a free image already at home satisfies the freed
incarnation's publication **by equivalence**, provided (a) the local
incarnation is terminal (in-core mode 0, nlink 0, a live committed FREE
obligation), (b) the ifree transaction is log-complete — the inode item is
unpinned (xfs_iflush_cluster never flushes a pinned inode; the recovery
worker checks explicitly), (c) the home dinode is mode 0 (gen irrelevant).
The recovery worker settles ONLY (no write, adopt or unlink-convert: a peer
may have allocated and freed the number in the lock gap; mode 0 now still
proves the requirement was met).  P237's evict-side last-chance publish
must never write an `ISTALE_CAW` shell.

Landed as `mxfs_pubob_settle_home_free()` (called before the discharge at
both home-free sites; stamps fepoch/wmb/durable/flush exactly like the
adopt-side discharge; `P55C-FREE-HOME-SETTLED`, or `-UNSETTLED` when a
predicate fails — the ledger then stays open and P237 stays fail-closed),
and the `!XFS_ISTALE_CAW` gate on the P237 last-chance publish.
Verification: `tests/sess429_chain.sh` (MARK-bounded sweeps count
settled / unsettled / P237), built as 0.39.0 together with the tauth
view-record step 1 (TCP-side, format/usermode only).

## 0.39.0 → 0.39.1: same-node CHAINS are not foreign (sess430)

The s433 32/caw board on 0.39.0 (clean: 0 FAIL, 0 shutdowns) still logged
164 `P55C-FREE-FOREIGN` on 63 inodes and 634 `P-FREEOB-FOREIGN` from the
release audit.  Classification (`tests/classify_free_foreign.py` over the
journald sweep): all regular files, **none** with `disk_gen == gen-1`, every
inode's activity on ONE node, and the per-inode signature
`P55C-FREE-FOREIGN → P-RECYCLE-DEADSTAMP-CLEAR → …` repeating up to 5 laps
on the same number.  Mechanism (instrumented, code): life 1 of ino X reaches the
platter live at gen G; `rm` arms FREE {G+1, epoch E}, unpublished; the
node's next create recycles the freed shell (`xfs_iget_recycle`, the
dominant reincarnation path under churn) — `XFS_IRECLAIM_RESET_FLAGS`
clears `MXFS_IF_PUBOB` on the shell but the store entry stays `kind=FREE`;
life 2 (random gen R) is never flushed; `rm` → FREE {R+1, E}; the flush
finds mode≠0 at gen G ≠ R and calls it FOREIGN: never write, neutralize,
discharge.  Net: inobt free, platter LIVE at G, nothing left to enforce —
the first peer to allocate X takes the DISK-LIVE shutdown (latent on the
board only because dialloc locality re-used the numbers on the same node).
Two further hazards of the same gap: the audit could poison a LIVE
recycled inode as foreign (s433: one `P32D-DEADINCARN-SKIP` on a live
file) or target-flush it and refuse the unlock.

Design-consult ruling (ccmemory `ccloop-c7ee71c6-sess430-GPT-ruling-free-foreign-
chain`): tenure continuity is the ownership proof but only with explicit
chain provenance, and a live inode must never be represented by an
actionable FREE entry.  Landed:

- `struct mxfs_pubob.chain` + kind `CHAIN_LIVE`.  `mxfs_pubob_recycle()`
  (called from `xfs_iget_recycle` on a local create): an open FREE /
  FREE_PENDING entry under the SAME tenure epoch becomes CHAIN_LIVE with
  `chain+1` (`P-FREEOB-CHAIN-LIVE`); a different tenure = the audit was
  bypassed → drop, loud `P-FREEOB-CHAIN-BROKEN`; any other kind →
  `P-FREEOB-RECYCLE-ANOMALY`.  The per-inode `i_mxfs_freeob`/strikes of the
  previous life are reset there (they are not iflags).
- `mxfs_pubob_arm` on a CHAIN_LIVE entry makes it UNLINK again (chain kept);
  FREE_PENDING/FREE carry the chain forward.
- Classifiers: P55C writes a chained free at ANY live gen under the same
  tenure sanction as the exact predecessor (`P55C-FREE-CHAIN`); no sanction
  → DENIED (worker), never FOREIGN.  The audit skips CHAIN_LIVE entries and
  publishes a chained FREE when `ob.epoch == pag_mxfs_rel_epoch`
  (`P-FREEOB-CHAIN`).  The recovery worker (fresh EX, tenure broken) keeps
  the FOREIGN verdict, now loud as a protocol failure.
- Neither FOREIGN branch write-poisons a shell whose in-core mode ≠ 0.

Verification: `tests/free_foreign_realloc_repro.sh` (same-node
dd+sync+rm+dd+rm chains, then a peer allocates in the same dir) via
`tests/sess430_chain.sh`: measured FAIL on 0.39.0 first, then PASS on
0.39.1 with `P-FREEOB-CHAIN-LIVE`/`P55C-FREE-CHAIN` present and zero
FOREIGN / DISK-LIVE, followed by dre ×2 and the 32/caw board with zero
`P55C-FREE-FOREIGN` and zero `P-FREEOB-FOREIGN` fleet-wide.

### 0.39.1 → 0.39.2: the deferred release path skipped the gate (sess430)

s435 (0.39.1, `tests/sess430_chain.sh`): reproducer PASS (chain depth 199,
`P55C-FREE-CHAIN` written, zero DISK-LIVE), dre ×2 clean, board 0 FAIL — but
the full journald sweep of the board window (`tests/evidence/
sess430_s435_boardfull/`) still held 32 `P55C-FREE-FOREIGN` (clusters of
2-5 on one number), 6 worker `P-FREEOB-FOREIGN`, 2 `P-FREEOB-CHAIN-BROKEN`
(`ob_epoch=31 epoch=33`: the AG EX tenure changed between a free and the
same node's re-allocation with the obligation open) and zero audit lines
(no PENDING/UNPUBLISHED/audit-FOREIGN).  Code: the publication gate (audit
+ bounded deferral + fail-closed) ran ONLY on `mxfs_dlm_ag_bast_work_fn`'s
inline unlock; the DEFERRED release (`mxfs_dlm_ag_release_work_fn`, taken
whenever AG-metadata writeback was still pending at the release COMMIT)
purged the iunlink store and unlocked without it.  Once a number's free
crosses a release unpublished, every later free of it on that node is
misread as FOREIGN against the node's own image — the self-perpetuating
clusters above.

Landed: the gate is `mxfs_ag_release_publish_gate(pag, path)` and runs on
both paths (a fail-closed shutdown on the deferred path leaves the AG
locked for the fence/replay, never handing the peer the free bit);
`mxfs_pubob_unlock_census(pag, path)` prints `P-FREEOB-XRELEASE` at EVERY
`mxfs_v5_dlm_ag_unlock` site (inline, deferred, iodone-fallback, unmount)
when a FREE/FREE_PENDING entry is still open as the grant leaves — the
instrumented instrument that names the path if any crossing remains.  A deadshell
create over a CHAIN_LIVE entry (our chained life freed by a peer) is
`P-FREEOB-CHAIN-SUPERSEDED`, not an anomaly (s435: 12).  `P-FREEOB-CHAIN-LIVE`
is printed 200× then every 500th (s435: ~4k per node per board).

### 0.39.2 → 0.39.3: the audit skipped its obligations with the head walk

s436 (0.39.2) board: 0 shutdowns, but 42 `P55C-FREE-FOREIGN`, 3
`P-FREEOB-CHAIN-BROKEN` and the new census fired 8× — every one
`path=bast-inline free=1`, i.e. a committed FREE obligation survived the
INLINE gate, 6 ms after a `P55C-FREE-DENIED` and with no audit line at all
(test1 ino 133, rel_epoch 43; re-allocated 0.26 s later under epoch 45).
`mxfs_p86_agi_unlinked_publish_audit` returned 0 before its obligation
section whenever the AGI buffer was not in core or its `XBF_TRYLOCK` lost a
race (or the P86 knob was off) — the head walk needs that snapshot, the
obligation enforcement never did.  Now only the head walk is skipped
(`P86-HEADWALK-SKIPPED ag= reason=`), the obligations run on every release.

## Containment (0.39.3, sess430) — two-phase candidate validation in dialloc

design-consult ruling (ccmemory `ccloop-c7ee71c6-sess430-GPT-ruling-d0351-dialloc-
containment-two-phase`): no platter I/O under the AGI/btree-cursor nesting
(Option A refused), a dedicated non-expiring per-AG quarantine, a clean
`-EUCLEAN` (never `ENOSPC`, never a dirty cancel) when nothing else is left.

`xfs/libxfs/xfs_ialloc.c`:
- `xfs_dialloc_ag(..., pick_only)`: phase 1 runs the existing candidate
  rotation (`mxfs_dialloc_pick_in_rec`: cooldown, probe budget, DLM
  try-reserve) and returns the reserved candidate with the trees UNTOUCHED.
- `mxfs_dialloc_two_phase()` (called from `xfs_dialloc_try_ag`, also after
  the grow-a-chunk retry): `xfs_trans_brelse` the AGI, validate, re-read the
  AGI, then phase 2 = `xfs_dialloc_ag` with `rs->validated` set: the cursor
  starts at the candidate's chunk record and `pick_in_rec` takes exactly
  that inode (no probe).  A phase-2 miss re-picks (`P-DIALLOC-VALIDATED-
  LOST`); never an unvalidated fallback.  Bounded: 64 restarts →
  `P-DIALLOC-DISKLIVE-STORM`, `-EUCLEAN`.
- `mxfs_dialloc_validate_candidate()`: the pubob store first (an open
  FREE / FREE_PENDING / CHAIN_LIVE entry = this node's own unpublished
  image, allowed — the chain case above); then
  `mxfs_dbg_disk_di_mode_coherent` (plain LUN read, no buffer cache);
  mode 0 → allocate; LIVE → `P-DIALLOC-DISKLIVE`, agino stored in
  `pag->pag_disklive_q` (xarray, exact membership, no expiry, never evicted
  for the mount), `-EUCLEAN` → re-pick; unreadable → one retry, then
  `P-DIALLOC-VALIDATE-EIO`, `-EIO` (clean).  The DLM reservation taken on a
  rejected candidate stays node-cached: harmless, and it keeps peers'
  try-reserve off the same number.
- `pick_in_rec` skips quarantined aginos (`rs->quarantined`); `xfs_dialloc`
  returns `-EUCLEAN` with `P-DIALLOC-ALL-QUARANTINED` instead of `-ENOSPC`
  when the only remaining free inodes are quarantine members.
- Only the finobt allocator is two-phased; every MXFS volume carries a
  finobt (mkfs writes it), so the inobt-only path is never taken in the
  cluster.  A freshly grown chunk is still validated (the pick may land on
  an older record).

### One inode-chunk carve per allocation

A create's transaction reserves space for exactly one inode chunk
(`XFS_IALLOC_SPACE_RES`); the rest of its reservation belongs to the
directory entry and parent pointer it still has to write, and the allocator
cannot see that split.  Upstream never carves twice in one `xfs_dialloc`
because after a carve the pick cannot fail; the refusals above can make it
fail, and `xfs_trans_roll` carries only the remainder of the reservation
forward, so a second carve spends blocks reserved for something else and
`xfs_trans_mod_sb` shuts the filesystem down when the count is exceeded.
The invariant is enforced by a credit, not by the refusal logic:

- **One carve per `xfs_dialloc` call, whatever the refusals do.**  Both
  carve arms (`pagi_freecount == 0`, and the `swept` retry) pass
  `mxfs_dialloc_carve_gate`; a second carve is refused
  (`P-DIALLOC-CARVE-BOUND`) and the AG handed back as `-EAGAIN`, which the
  sweep treats as any other transient refusal.  The credit is spent when
  `xfs_ialloc_ag_alloc` succeeds, before the roll: a carve that found no
  room leaves it for the next AG; a carve that landed is spent even if the
  roll then fails.  Callers that need two inodes in one transaction
  (`xfs_mxfs_dirshard.c`) call `xfs_dialloc` twice with a reservation sized
  for both; the credit is per call.
- **`swept` stays the vote "this lap found no usable candidate"**, cast by
  a full finobt lap that skipped every free inode (peer-held, or cooling
  after any refusal, ours included) and by the transient-refusal storm exit
  (`P946-DIALLOC-PUBPEND-STORM`).  It is reset at every AG visit, so one
  AG's vote never carves in the next.  The vote must stay: an AG whose only
  free number is refused for the life of the mount (a magic-less home that
  is not ours) has nothing usable, and the one carve is what gives the
  create fresh numbers.  Casting it only for peer contention was tried and
  hung the create instead: with the refused number the AG's sole free
  inode, nothing carved, and the sweep backed off forever with the parent
  directory locked, until the node had to be power-cycled.

What this leaves open, deliberately: after its one carve a create whose
every candidate — including the fresh chunk's — keeps being refused is a
bounded-rate back-off loop with no deadline, rather than a shutdown; and
the restart budget (64 per call, never reset) means every visit after the
first storm examines one candidate.  Both are liveness questions, separate
from the accounting invariant, and a deadline for the first must not be
added before the create's held state across the back-off (parent ILOCK,
log reservation, quota, AG grant) is audited.

Cost: one plain read (~0.3 ms on the rig LUN) + an AGI brelse/re-read
(cache hit) per allocation; the DLM reservation probe in the same loop
already costs the same order.  The board's sustained_load / dirent pace
rows are the budget check.

### Sparse records: the candidate walk masks the holes (0.85.3, D-0948)

A sparse inode record (`ir_count < 64`) is carved with `ir_free = ALL_FREE`
and the missing inodes described only by `ir_holemask` (one bit per four
inodes).  So every hole bit reads as a free inode in `ir_free`, and any walk
of the free mask that does not first AND it with
`xfs_inobt_irec_to_allocmask()` hands out a number whose home block was never
carved — it belongs to whatever owns that block.  Upstream's
`xfs_inobt_first_free_inode` masks; `mxfs_dialloc_pick_in_rec` did not, and
on s572 (0.75.118) took offset 0 of a record with holemask 0xff whose home
was a live directory data block: the create read XDD3 through
`xfs_imap_to_bp`, the transaction was already dirty, the node shut down
(the kernel's own `xfs_inobt_check_irec` had printed the corrupt record —
freemask 0x…fffe under holemask 0xff — 15 ms earlier).  The validator is a
second defence here, not the first: it reads the hole's block and can only
say "no magic" (refuse and re-pick, from 0.84.16) or, if the block happens to
hold an old free dinode image, "free" — and then the allocation lands in a
block the inobt does not own.

The rule: every MXFS walk of `ir_free` (the candidate pick, a re-pick after a
refusal, the chunk-free scan, a validator) masks the holes first.  Knobs and
counters: `dialloc_holemask_n` (picks that met holes below a free inode and
masked them), `dialloc_holepick_n` (candidates taken from inside a hole —
control arm only), `dbg_dialloc_pick_holes=1` (the pre-fix walk, A/B
control), `dbg_force_sparse_carve=1|2` (every carve sparse; 2 also requests
the upper half of the next chunk-aligned region exactly before the ordinary
near-bno search).  All test-only, 0 in production.  Measured on the rig: the
exact upper-half request is refused whenever the region above the hint is
not free, and the holes-below shape (holemask 0xff) is produced anyway by
the near-bno search under forced sparse carving, because a half-chunk free
extent whose region's lower half is occupied is an ordinary outcome of that
search -- it is the placement the incident's own carve took, with a
directory block in the lower half.

Verification: `tests/dialloc_disklive_inject.sh` (`tests/dinode_inject.py`
plants a LIVE image with a resealed crc under a number whose free image is
verified on the platter, then the node allocates in that directory) via
`tests/sess430_containment_chain.sh`: measured on 0.39.2 first (expected:
P-CR62 + shutdown), then PASS on 0.39.3 (P-DIALLOC-DISKLIVE for X, creates
succeed, X never handed out, no shutdown), then ffr/fhs/dre ×2/board.
A/B knob (0.39.4): `mxfs.dialloc_validate` (sysfs, default 1) — 0 restores
the pre-containment allocator for `tests/dialloc_disklive_inject.sh`'s
`MXFS_DIALLOC_VALIDATE=0` arm (expected: P-CR62 + shutdown of the node on
the cache-miss create).  Test aid only; never run a campaign with it off.
Also 0.39.4: a CHAIN_LIVE entry met by any local recycle is
`P-FREEOB-CHAIN-SUPERSEDED deadshell=<0|1>` (the peer freed our chained
life; s436 saw 16 such stale-linked-shell recycles), not an anomaly — a
free of our own live life always transitions the entry through arm →
FREE_PENDING → FREE, so CHAIN_LIVE at recycle can only be the peer case.

Not yet covered (ruling): queueing the observation to the release audit /
owner notification — the quarantine is per mount and clears only with the
mount; repair is `chk_mxfs`'s job.

## 0.39.4 → 0.39.5: the staged free image was restored away by the cluster merge (sess431)

The s437 board on 0.39.3 was clean by every verdict except the containment's
own count: 123 `P-DIALLOC-DISKLIVE` quarantines, 39 downstream FOREIGN.  The
per-inode timelines (`tests/evidence/sess430_s437_inos/`,
`scripts/analyze_p_diskslive_p55c.py`) named the producer for 56 of the 123:

    P55C-FREE-FLUSH ino=134217887 gen=…488 disk_gen=…487 disk_mode=040755 via=tenure
    P239-OVERLAY-ID ino=134217887 slot=31 arm=restore relflush=0 dlm_mode=0 flush=16 dur=14
    P-CLMERGE restored ino=134217887 slot=31 bmode=00 dmode=040755          (+0.5 ms, same bp)
    P56-NL-LOGGED-DIR-SKIP daddr=67780736 slot=31 ino=134217887             (the slot is a dir again)
    P-DIALLOC-DISKLIVE ino=134217887 disk_mode=040755 disk_gen=…487         (+35 s, same node)

`xfs_iflush` stages the free image at inode-NL under the AG pubwrite tenure,
but `mxfs_iflush_cluster_merge_dirs` decides which slots the buffer owns from
a different predicate — RELFLUSH, or EX with same-tenure dirty provenance, or
a PR directory in the AIL.  A committed free satisfies none of them, so the
sess62 rule ("a foreign slot's durable disk image is authoritative") put the
platter's pre-free LIVE image back over the staged free image.  For a
directory the partial-write mask then refused the (now live, NL) dir slot; for
a regular file it simply rewrote the live image.  Either way the free never
left the host, `PUBOB_FLUSHED` discharged the obligation on the live-image
write, and the AG release gate had nothing left to enforce.

Design-consult ruling (`docs/rulings/freepub-claim.md`):
do not infer publication authority from in-core state; mint an explicit
**FREE-publication claim** at the copy-in and have every downstream site
consult the same claim.

Landed:

- `struct xfs_inode`: `i_mxfs_freepub_{bp, epoch, seq, gen}` — the buffer
  the free image was staged into, the AG tenure epoch that sanctioned it,
  the `flush_seq` stamped for it and the image's `di_gen`.  Minted in
  `xfs_iflush` right after the stage stamp when P55C sanctioned the copy-in
  (`P-FREEPUB-CLAIM`).
- `mxfs_freepub_claim_valid(ip, bp, pag, img, &why)` (`xfs_mxfs_dlm.c`,
  non-blocking, safe under `pag_ici_lock`): buffer identity, `flush_seq`
  unchanged, obligation still open (`i_mxfs_freeob == 2` + `PUBOB`), the
  buffer image is mode 0 at the claimed gen, and the AG tenure is the claimed
  epoch (live grant, or the retiring token while `pag_dlm_demoting`).
- The merge keeps a valid claimed slot (`flushing|authorit`,
  `P-FREEPUB-KEEP`).  A claim on the same buffer that no longer validates is
  traced (`P-FREEPUB-CLAIM-STALE site=merge why=`) and falls through to the
  restore arms, whose ledger rollback now fails it closed (`P238 …
  cls=freepub-stale`: watermark rolled back, `PUB_SKIPPED` re-arm,
  `PUBOB_FLUSHED` dropped, claim retired) so the live-image write cannot
  discharge the obligation.
- The partial-write mask treats a valid claim as its own authority class at
  NL (`P-FREEPUB-WRITE`; not a `P219` no-authority publish, not a
  stale-stage skip candidate).
- Cleared (`P-FREEPUB-CLAIM-CLEAR why=`) at durable iodone, the
  `PUB_SKIPPED` re-arm, `xfs_iflush_abort`, obligation discharge and
  `mxfs_pubob_recycle`; initialised in `mxfs_dlm_inode_init`.

Measured on s439 (0.39.5, `tests/evidence/sess430_s439.log`, board 0 FAIL /
0 shutdowns): fleet-wide `fp_claim=2088 fp_keep=2157 fp_write=2082
fp_durable=1997 freepub_stale=0`; `P-CLMERGE restored bmode=00` after a P55C
line: 0 of 72 remaining quarantines (was 56 of 123).  `P-DIALLOC-DISKLIVE`
123 → 72, `P55C-FREE-FOREIGN` 39 → 41 — the residual is the FOREIGN family
(platter live at a gen this node never owned), traced below.

(The first "34 without any P55C" count compared raw `[ secs]` stamps across
nodes — each VM's own monotonic clock.  `scripts/analyze_p_diskslive_p55c.py`
now converts every node to wall-clock from its `realms=` lines; the
wall-clock count on s437 was 28.)

## 0.39.5 → 0.39.6: a stale skip verdict and a buffer-image "home" (sess431)

`scripts/freepub_claim_chain.py` over the s439 board journals: 84 of 2088
claims were kept and written but ended `why=pub-skipped`.  Specimen (test10
ino 67109002): 23 ms before the P55C round, `P235-EX-STALE-SKIP` masked the
same slot's re-logged, already-landed image and set `MXFS_IF_PUB_SKIPPED`
unconditionally; that round's completion skipped the item at the
`ili_last_fields` check (nothing had been flushed) and never cleared the
flag.  The P55C round's completion then found it, fired `P187-PUB-REARM`
(the sector had in fact been written) and did not advance `durable`.  The
next push read the buffer slot — this node's own staged free image — as
"free image already at home", settled the ledger by equivalence and
discharged the obligation.  In this specimen the bytes had landed; the
mechanism does not know that.

Two changes:

- The copy-in success path clears `MXFS_IF_PUB_SKIPPED` alongside
  `MXFS_IF_CLMERGE_HIT`: every skip verdict is taken at submit, after the
  copy-in, so only a skip of the bytes just staged may re-arm their
  completion.
- P55C classifies the home on the **platter** whenever this inode has an
  unlanded staged image (`flush_seq != durable_seq`): a coherent plain read
  (`mxfs_dbg_disk_di_mode_coherent`, the read the dialloc validation
  trusts) replaces the buffer slot's mode/gen; a differing image is traced
  (`P55C-HOME-PLATTER`), a failed read is DENIED with a strike
  (`P55C-HOME-READ-FAIL`), never a verdict.

## 0.39.6 → 0.39.7: chain provenance lost at an UNLINK discharge (sess431)

The s439 residual — 41 `P55C-FREE-FOREIGN`, 72 `P-DIALLOC-DISKLIVE` —
was one producer.  `tests/analysis/sess431_gen_trace.py` over the board
journals: for every one of the 41, the platter's live gen was a life **this
same node created** (`P165-AFFINE-STALE child_gen=` on the same node,
`P383 selfcr=1`), and that life's free (`gen_home+1`) never reached P55C on
any node (0 matches fleet-wide).  The dense window (test1 ino 134, the
iunlink-fossil test row: create/unlink chains under one AG tenure) shows the
mechanism directly — `P-FREEOB-CHAIN-LIVE chain=1 → 2 → 1`: the count was
**reset** between the 6th and 7th recycle, and the 7th life's free then
classified `FOREIGN` (`ochain == 0`) instead of `CHAIN`, leaving the
gen-2204568790 image live on the platter under a free inobt bit.

The reset: life 6 was a tmpfile (`P82-ADD vfs_nlink=0` at create) that was
linked (`P82-REM`) and then unlinked.  `xfs_iunlink_remove` at the link
discharges the UNLINK obligation (`mxfs_pubob_discharge(…, "removed")`);
with `i_mxfs_freeob != 1` the generic path **dropped the store entry** —
and its `chain`.  The unlink re-armed a fresh entry (`chain=0`), the ifree
made it `FREE chain=0`, and P55C had no provenance left.  The same drop
happens on `"flushed"` (the unlink conversion write of a chained life
landing before its ifree), which is the common shape on a board.

Fix (0.39.7): an UNLINK-obligation discharge of an entry that carries
`chain > 0` reverts it to `CHAIN_LIVE` (life continues, not actionable
until freed — exactly what the recycle minted) instead of dropping it
(`P-FREEOB-CHAIN-KEPT why=removed|flushed`).  `mxfs_pubob_arm` already
turns CHAIN_LIVE back into UNLINK on the next unlink, `free_pending` /
`free_commit` carry `chain` through, and the recycle's
`CHAIN_LIVE → SUPERSEDED` verdict (a peer freed our chained life) is
unchanged.  FREE-kind discharges (`home-free`, `foreign`, `superseded`)
still drop.

## 0.39.7 → 0.39.9: P55C always classifies from the platter; directed proof (sess431)

design-consult review of 0.39.6/0.39.7 (`docs/history/gpt-review-0396-0397-directed-test-required.md`): the
`PUB_SKIPPED` clear and the chain-kept transition are sound; the platter-read
home had two gaps.  (1) Its trigger, `flush_seq != durable_seq`, is not a
sufficient detector — every drop path rolls `flush_seq` back to `durable_seq`
while the buffer keeps the staged mode-0 bytes, so a dropped claimed write
followed by a re-push would still have read the buffer as "free at home".
(2) No board ever exercised the branch (`P55C-HOME-PLATTER=0`).

0.39.9: P55C **always** classifies the home from a raw platter read
(`mxfs_dbg_disk_di_mode_coherent`: private bounce buffer through
`mxfs_pal_bdev_read_plain_bdev`, never the xfs buffer cache; the cluster
buffer is locked, so no write of it is in flight; peers are excluded by the
AG tenure the obligation holds; failed/invalid read → DENIED + strike).
`xfs_buf_inode_iodone` also clears `PUB_SKIPPED` on its `!ili_last_fields`
early exit so the completion is self-contained.  The buffer image `dip` is
no longer evidence of anything in P55C.

Directed proof: `mxfs.freepub_drop_once=N` (fault injection, test aid only)
drops the next N claimed free-image sectors from their cluster write exactly
as a masked slot is dropped (`P-FREEPUB-INJECT-DROP`, watermark rolled back,
`PUB_SKIPPED` re-arm).  `tests/freepub_platter_home_inject.sh` (chain stage
`fph`) then requires, for the dropped inode X: `P187-PUB-REARM`,
`P55C-HOME-PLATTER ino=X buf_mode=00 platter_mode=0100644`, a re-push
`P55C-FREE-FLUSH`, `P-FREEPUB-WRITE`, `P-FREEPUB-CLAIM-CLEAR why=durable`,
no `P55C-FREE-HOME` for X before that, `P-FREEOB-XRELEASE=0`, and the
platter dinode X reading mode 0 (`tests/dinode_inject.py show`).

## Verification

Measured series (32/caw board + `sess430_containment_chain.sh` sweeps, raw
board journals under `tests/evidence/sess431_s4NN_inos`):

| lap | build | P-DIALLOC-DISKLIVE | P55C-FREE-FOREIGN | claim ends | notes |
|---|---|---|---|---|---|
| s437 | 0.39.3 | 123 | 39 | — | 56 of 123 = merge-restore chain |
| s439 | 0.39.5 | 72 | 41 | 1997 durable / 84 pub-skipped / 7 recycle | restore chain 0; stale PUB_SKIPPED found |
| s440 | 0.39.6 | 57 | 34 | 1959 durable / 18 recycle | pub-skipped 0; chain-provenance root found |
| s442 | 0.39.7 | **0** | **0** | 2101 durable / 6 recycle | all fail-closed tags 0, `freepub_stale=0`, `P-FREEOB-CHAIN-KEPT` engaging |
| s443 | 0.39.8 | **0** | **0** | 1960 durable / 5 other | full-journal counters (`disklive_raw`/`foreign_raw`) |
| s444 | 0.39.9 | **0** | **0** | 2090 durable / 6 other | + directed platter-truth test PASS (`20260828T185928Z_fph_s444`) |

**D-0351 disposition: FIXED AND VERIFIED (2026-08-28, sess431, 0.39.9).**
Every root cause above was proven by instrumentation before its patch
(instrumented); the reproducers and three consecutive 32/caw boards pass under
unchanged criteria with every fail-closed counter at zero; the containment
(two-phase dialloc validation + DISK-LIVE quarantine) stays as the
defence in depth.  Remaining, separately ledgered: D-401 (crash_consistency
at its 90 s budget), D-0352 (formation_test ramp deny).

`scripts/freepub_claim_chain.py` proves the per-claim chain (CLAIM → KEEP →
WRITE → CLEAR why=durable) on every lap from s439 on;
`scripts/analyze_p_diskslive_p55c.py` (wall-clock) classifies any residual
quarantine against the preceding P55C on any node.

`tests/dir_recreate_estale.sh` (4 nodes, now also asserts recreator rc and
per-node shutdown signatures) reproduced the defect on its first run on
0.37.0; the fix is verified when that reproducer passes with `P55C-FREE-FLUSH`
/ `P-FREEOB-PUBLISHED` lines present and zero `P-CR62 DISK-LIVE`,
`P-CR3-CANCEL`, `P-FREEOB-REFUSED`, `P-FREEOB-FOREIGN`, `P-FREEOB-NOSHELL`,
`P-FREEOB-NOEPOCH` lines fleet-wide, followed by the 32/caw board.

## 0.63.0 → 0.63.1: the entry is the authority (sess465, D-0524)

**The defect** (D-FREEOB-COMMIT-VS-FLUSHED-DISCHARGE-RACE-PENDING-STUCK-
FAILCLOSED-SHUTDOWN-0524, chain 88's 8/caw board, test1 fenced in
`dir_reuse_coherency` round 4).  Established to the line order of test1's
kernel log (`tests/evidence/sess464_8caw_dirreuse_fence_20260902T074512Z`):
xfsaild copied inode 327155847's UNLINK image into its cluster buffer
(`P240-COPYIN-ID`, `i_mxfs_freeob==0` so the copy-in set `PUBOB_FLUSHED`)
and submitted the write; the write's completion walked the buffer's inodes
(`P-FREEPUB-CLAIM-CLEAR why=durable` for the six siblings) *interleaved*
with rm's ifree of that inode (`P150-FREE-IBT off=7`, `P82-REM`).  The
completion's `mxfs_pubob_discharge("flushed")` read `i_mxfs_freeob==1` and
called `mxfs_pubob_free_pending` (kind=FREE_PENDING, byte=1); the commit's
`mxfs_pubob_free_commit` read the same byte and wrote (kind=FREE, byte=2).
Each function read the byte outside `m_mxfs_pubob_lock` and wrote the kind
inside it, so the committed FREE was overwritten by FREE_PENDING.  Nothing
ever advances a FREE_PENDING entry but the ifree itself, so the release
gate read "ifree in flight" (`P-FREEOB-PENDING` every 2 s) for its whole
20 s budget and executed `P-FREEOB-REFUSED` → `xfs_force_shutdown` →
withdraw → fenced by test8.  The mirror ordering (commit's byte=2 visible
first) sends the completion down the discharge arm and DROPS the committed
FREE obligation silently — the original D-0351 exposure.

**The rule now** (design-consult ruling, `docs/rulings/d0524-pubob-race-fix.md`): the store
entry is the single authority and every decision about it is taken under
`m_mxfs_pubob_lock`; `i_mxfs_freeob` is a mirror written under the same
lock, never a correctness input.

- **Pending at the ifree START.**  `xfs_inactive_ifree` calls
  `mxfs_pubob_free_pending(mp, ip, tenure_epoch)` before `xfs_ifree`
  (`__GFP_NOFAIL` entry — a free whose obligation is not recorded is the
  exposure itself).  The predecessor state (UNLINK / CHAIN_LIVE / none,
  with chain, gen and epoch) and the tenure epoch are recorded in the
  entry.
- **Commit is unconditional and total.**  `mxfs_pubob_free_commit` runs
  after every successful commit: FREE_PENDING→FREE, UNLINK→FREE
  (`P-FREEOB-COMMIT-NOPENDING`), absent→created (`P-FREEOB-COMMIT-CREATED`),
  FREE idempotent; a tenure skew between start and commit or any other kind
  is `P-FREEOB-COMMIT-PROTOCOL` + shutdown (fail closed).
- **Abort restores the predecessor exactly** (`mxfs_pubob_free_abort`,
  `P-FREEOB-ABORTED`), only for a clean cancel; under shutdown the outcome
  is unknowable and FREE_PENDING is kept.
- **The copy-in publishes a token; the completion consumes it.**
  `mxfs_pubob_stage_flush` (ILOCK shared + buffer locked) decides under the
  lock which image the write carries — UNLINK (entry UNLINK, nlink 0) or
  FREE (entry FREE, mode 0) — and stores it as the entry's `inflight`;
  `PUBOB_FLUSHED` is only the completion's cheap hint.  `mxfs_pubob_discharge
  ("flushed")` consumes the token under the lock and discharges only when
  it still matches the entry; otherwise `P-FREEOB-FLUSH-STALE` and nothing
  changes.  `xfs_iflush_abort` and the cluster-merge overlay consume the
  token (`mxfs_pubob_flush_abort`) without touching the entry.  Two images
  of one inode cannot be in flight together (one cluster buffer per inode,
  copy-in under its lock, completion consumed under it before unlock);
  `P-FREEOB-TOKEN-BUSY` reports the violation.
- **A FREE_PENDING entry at the release gate is failed bookkeeping, never
  in-flight work** — the ifree holds the AG EX, so the gate cannot run
  beside it.  Self-heal: if the in-core shell carries
  `MXFS_IF_FREE_COMMITTED` and the entry's pending tenure is the tenure the
  release retires, promote to FREE (`P-FREEOB-PENDING-COMMITTED`) and audit
  it as FREE in the same lap.  An orphan or a cross-tenure pending entry is
  `P-FREEOB-PENDING-FATAL` and the gate refuses at once
  (`pag_mxfs_freeob_fatal`, no 20 s defer).  Only an uncommitted pending
  entry keeps the bounded deferral, as insurance against a hole in the
  holder reasoning.
- **Instrument.**  `mxfs.freeob_commit_delay_ms` sleeps between the
  commit and `mxfs_pubob_free_commit`, widening the window so a completion
  lands inside it; `tests/d0524_freeob_sweep.sh` counts every marker per
  node; `tests/sess465_chain94_d0524_freeob_race.sh` is the verification
  chain (knob laps must show `P-FREEOB-FLUSH-STALE` > 0 with zero
  `P-FREEOB-PENDING*` / `P-FREEOB-REFUSED` / shutdowns, then the 32/caw
  board).

## The allocator's own-obligation arm, and the assertion that checks it

`mxfs_dialloc_validate_candidate` consults the obligation store before the
platter: a candidate with an open FREE / FREE_PENDING / CHAIN_LIVE entry of
this node's is REFUSED transiently (`P946-VALIDATE-PUBPEND`, the ordinary
reservation cooldown, an asynchronous publication kick, re-pick) — never
allowed on the inference that the live image at its home must be ours, and
never put in the mount-lifetime DISK-LIVE quarantine (D-0946, ruling
`docs/rulings/d0946-two-gates-reuse-authorization.md`).  The consequence the
rest of the system may rely on: **a number the allocator hands out has no open
FREE obligation, and since an obligation is retired only by the completion of
the write carrying the free image, its home dinode reads mode 0.**
`dialloc_pubpend_refuse=0` keeps the pre-fix arm as an A/B control; the exact
counters are `dialloc_pubpend_refused` / `dialloc_pubpend_allowed` (writing
resets).

Test aid, default off: `dbg_recycle_platter_assert=1` makes every create-path
recycle in `xfs_iget_recycle` read the recycled number's home with the same
coherent plain platter read (`mxfs_dbg_disk_di_read_coherent`, a private
bounce buffer, never the xfs buffer cache) and fail the recycle with
-EFSCORRUPTED when it is live (`P946-RECYCLE-ASSERT-DISKLIVE`), i.e. it takes
the deferred-deadshell verdict on every recycle instead of only on a shell that
still carries a mode or blocks.  Under the fixed allocator a fire is a crossed
FREE-PUBLISH invariant; under the control arm it reproduces the D-0946
shutdown on the first re-pick.  `dbg_recycle_platter_checked` /
`dbg_recycle_platter_live` count the checks (writing resets).  Harness:
`tests/d0946_recycle_platter_assert.sh` (arms `fix` and `control`; the control
arm destroys the mount by design).

Audit hook left for a later session (ruling S1-7): `P-FREEOB-FREE-DISCHARGED-BY`
counts FREE obligations ended by a caller's own home classification
("home-free", "foreign", "superseded") rather than by the FREE image's
completion; "superseded" (reload adopted a newer incarnation) still ends a
FREE entry on the reload's evidence alone.
