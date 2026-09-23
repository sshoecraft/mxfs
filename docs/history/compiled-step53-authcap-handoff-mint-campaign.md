<!-- sess102-110: step-5.3 authority-capture campaign — format-time to first-dirty capture, NONE-population root cause, direct-handoff epoch-mint fix chai… -->
# step-5.3 authority-capture campaign (sess102-110)

One continuous root-cause chain: move authority-token capture off CIL
format-time onto the first-protected-dirty seam, discover the resulting
telemetry proves the DLM's direct-EX-handoff optimization mints no grant
epoch at all, then close that root through 5 landed defects on `dlm_caw.c`
+ `v5_mount.c`. Versions run 0.11.435 → 0.11.440. All work happens on
ccloop run c7ee71c6.

## sess102 — the seam and the instrument, before any code `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

`xfs_trans_dirty_buf` (xfs/xfs_trans_buf.c:503) is the single point every
buffer passes through to become dirty — the correct capture seam, keyed on
transaction identity (`tp`) rather than the format-time BLFT lookup the
prior design used. Proposed sidecar `mxfs_bli_auth` on
`xfs_buf_log_item`, captured once per capture-window (first dirty only; a
re-log in the same window that resolves to a different resource/epoch
increments a mismatch counter instead of silently overwriting).

Instrument `P240-AUTHCAP` designed around the decisive cross-tab: outcome
× (dlm_mode ≥ PW) at capture time. `NONE + mode≥PW` = the authority
*recorder* is broken; `NONE + mode<PW` = a genuine unauthorized write (a
live coherency defect, worse than replay).

Two traps banked before landing: (1) the existing report modulus fires
every 8192 tokens, too coarse — an 8-criterion dir-heavy chunk advanced
only one node past the boundary, so a "1052-image" sample was one node's,
not the fleet's; drop to 1023. (2) counters are per-module-load — a deploy
resets them, so snapshot/diff with `tests/ownauth_counters.sh`, never
assume a zero base.

## sess103 — landed, unmeasured (0.11.436) `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

Capture keyed on `t_mxfs_capseq`, a lazily-assigned atomic64 field on
`xfs_trans`, **not** the `tp` pointer — transactions come from a slab and
addresses get reused, so a pointer key could alias a fresh transaction and
suppress recapture, exactly the stale-epoch-stamp bug the change exists to
prevent. Two field-layout facts that shaped the code: `__bli_format` is
authoritative for BLFT flags on every buffer including discontiguous ones,
but `blf_blkno` is only correct on map 0 for multi-map buffers — the
classifier must take flags from `__bli_format` and AG from
`bli_formats[0].blf_blkno`, never mix them. And: nothing tree-wide
*consumes* the captured token yet (`mxfs_auth_st_proves` has zero
callers) — this landing only changes what gets stamped, not any
apply/skip decision, so it's safe to ship ahead of the consumer work.

## sess104 — measured; two new defects found `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md` `docs/rulings/release-hook-and-install-retry.md`

0.11.436 deployed to 32/caw. Capture plumbing proven sound: `nocap=0`
(no dirty path bypasses the seam), `noblft=0` (the one unproven design
assumption — BLFT is always set before first dirty — holds over 112640
windows), `mismatch=0`. No RULE-0 regression despite adding a
perag_get+RCU lookup per re-log (250162 of them).

Decisive cross-tab, 220947 images: `durable` 96.01% (expected), `none`
3.78% (8346 images), `noowner` 0.22% (476, later shown vacuous —
`mxfs_buf_owner_authority` reports `dlm_mode=0` by construction for every
early-return arm before the mode-reading section, so `noowner`'s 0%-held
proves nothing). **Every single NONE image was dirtied while holding a
writing mode** — the authority *record* is incomplete, not the write
unauthorized. `NONE` decomposes exactly into directory-buffer BLFTs
(dir_block/dir_data/dir_leaf1); `noowner` is entirely dino (inode-cluster,
separate territory). One node (test1) carried 8170/8346 NONE images —
flagged as workload-weighted (one missed transition on one hot directory
can generate thousands of images), not yet node-specific.

Two new defects surfaced and ruled on by GPT:

- **Finding A — dead release hook.**
  `mxfs_inode_authority_begin_release_locked` has zero callers; every
  relinquishment goes through a diagnostic backstop that fires *after*
  `i_dlm_mode` is already lowered. Ruling: real defect.
  `i_dlm_mode` is a local summary, not the distributed release
  linearization point, and no memory-ordering trick on its store can
  repair ordering against a peer-visible disk update. Required order:
  close the local mutation gate → drain in-flight protected mutations
  (including their first-dirty capture) → set RELEASING under the
  authority serialization → only then any peer-visible
  publish/handoff/downgrade/route-change → lower `i_dlm_mode` last.
  Hooking too early is the opposite bug: an already-authorized in-flight
  mutation dirties after the clear and gets falsely stamped NONE. Site
  rule (don't enumerate functions): every operation that can make the
  current epoch unavailable to new local mutations, or make
  relinquishment externally observable, must funnel through one
  centralized release-publication primitive.
- **Finding B — refusal counter conflation.** `gres->valid` collapsed
  "read grant, not applicable" with "write mode held but epoch zero" —
  a real gap. The downstream `shared` bucket was structurally
  unreachable (an early return skipped it). Ruling: split at snapshot
  construction into a tagged status enum (not another boolean), one
  helper `mxfs_mode_can_write()` used everywhere instead of mixing
  `>= PW` with exact `== EX || == PW`.

Leading NONE hypothesis at this point (later disproven by sess106):
install attempted during read→write conversion before the epoch is
visible, fails, nothing retries after publication. `i_mxfs_auth_line`
ruled NOT decisive — it records only the last *successful* transition; a
failed install doesn't move it. Ruling: record the last install
*attempt* instead (reason + line + monotonic sequence), and instrument a
rate-limited trace at the first `NONE && write-mode` dirty per inode.

## sess105 — landed, unmeasured (0.11.437) `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

Ruling items 1-3 built: `valid` boolean replaced by
`enum mxfs_grant_auth_status` (UNSET/WRITE_EPOCH/NONWRITE_MODE/
WRITE_ZERO_EPOCH/NO_RESOURCE); `mxfs_mode_can_write()` and
`mxfs_grant_result_proving()` become the only two predicates used anywhere;
the unreachable `shared` bucket is gone by construction. Per-inode last
install-attempt fields added, with `i_mxfs_auth_try_gen` the load-bearing
one — it snapshots `i_mxfs_auth_gen` at attempt time, so `try_gen < gen`
at read time means a revoke happened after the last attempt with nothing
retrying, without needing a new global sequence counter. `P241-AUTHTRY`
classifier added at the dirty point. En route, fixed a real bug:
`mxfs_iclus_lock` only zeroed `auth_epoch` on failed stamp for `mode ==
EX`, missing PW — now both go through `mxfs_mode_can_write()`.

## sess106 — measured; root cause found, NOT the sess104 hypothesis `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

0.11.437 deployed. `P241-AUTHTRY` fired unanimously fleet-wide:
`try=16` (UNSET — the grant result was **never filled**, not a read
grant, not zero-epoch), `try_gen == gen == 1` on every node (no revoke
ever happened — this kills the sess104 hypothesis outright), `line=32350`
= inode allocation is the last successful transition ever recorded on
these inodes, `mode=5` (EX) at dirty time. **An acquire succeeds and
produces no grant result at all** — a row the sess104 classification
table didn't have.

Two defects, one root:

1. **Adopt-without-fill.** `caw_wait_for_grant`'s `P6H-ADOPT` arm
   (dlm/dlm_caw.c:2756-2794) — when we were granted by someone else while
   waiting — does `rc = 0; goto out;` with no `caw_grant_result_fill`
   call. Init values (UNSET) survive. Hot: 463-936/node.
2. **Direct-handoff mints nothing (the serious one).**
   `mxfs_dlm_caw_unlock_gen`'s direct-handoff block (default-on,
   `mxfs_caw_direct_handoff=1`) sets the grantee's holder bit, `dir_epoch`,
   `last_ex_slot` — but never calls `caw_grant_epoch_update`, so
   `ex_grant_epoch` is left naming the *releasing* node's ended tenure.
   (Trap: the `epoch=` field logged on `P6H-HANDOFF` is `dir_epoch`, not
   `ex_grant_epoch` — don't read it as evidence the grant epoch moved.)

Fixing defect 1 alone (filling `gres` from the adopted image) would stamp
durable write images with the previous node's grant epoch — the
false-attribution failure the earlier sess96 ruling was written to
prevent. **Defect 2 must be fixed first.**

## sess107 — GPT ruling: mint allowed, 10 blockers, 1 new latent defect `docs/rulings/direct-handoff-mint-10-blockers.md`

Core ruling: a write-authority epoch is minted in the same atomic durable
slot transition that first grants EX-class ownership; the *identity* of
which node issues the compare-and-write is irrelevant — the CAS is the
linearization point, so the releaser minting the grantee's epoch is sound
(adoption is recognition of a durable grant, not creation of authority).
Refactor the mint helper to take the actual grantee explicitly, never
`ctx->node_slot`.

New latent defect the consult surfaced, not previously ledgered:
`ex_grant_epoch` is a zero-extended 32-bit cyclic token (`generation`
truncated), so it wraps after 2^32 CASes (generation bumps on *every*
CAS, not just grants — hot resources wrap fast) and mints the
explicitly-invalid token zero at the wrap. Ruled: a durable 64-bit
per-resource `+1` sequence, skipping 0 forever. Caveat found in the same
session: `caw_tombstone_slot` zeroed `ex_grant_epoch` while preserving
`generation`, which would restart the `+1` sequence at 1 after every
tombstone+reclaim — the tombstone must also carry `ex_grant_epoch`.
Residual *pre-existing* hazard flagged and not fixed here: a slot
tombstoned and recycled by a *different* resource restarts that
resource's epoch namespace at its new slot's lineage — authority must
always be validated as the tuple (resource identity, ex_grant_epoch),
never a bare scalar.

10 release-blocking items enumerated (mint on every handoff; explicit
grantee in the mint helper; populate+validate the adopt result; reject
zero/stale epochs; thread the AG grant result instead of rereading;
prove/fix adopt-vs-reconcile linearization; handle 32-bit wrap; gate
mixed-version operation — a local module param is insufficient, an old
releaser can hand off to a new grantee with no epoch; audit every
first-install-EX transition; confirm replay binds epochs to the resource).
Sharpest hazard (blocker 6): if the existing abort/reconcile can clear a
live node's holder bit based only on an abandoned-waiter observation,
direct handoff is unsafe regardless of the epoch fix — reconcile must
compare expected epoch/generation + holder mode, not the node bit alone.

## sess108 — producer half landed (0.11.438) `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

Blockers 7, 2, 1 landed: `caw_next_grant_epoch(prev)` = `prev+1`, skipping
0 forever, is the new epoch source (closes ledger entry
D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID, code-proven, not yet
test-exercised at this point); `caw_grant_epoch_update(s, grantee_slot,
mode)` takes the grantee explicitly; the direct-handoff arm now calls the
same helper as self-promote, giving the tree one mint policy. Nominee
validation (`caw_handoff_nominee_ok`) added before installing a handoff.
The sess107 tombstone caveat implemented: tombstone preserves
`ex_grant_epoch`, restored on same-resource re-claim, deliberately *not*
cleared on the `is_free` reset path — monotonic-across-inode-reuse is
what prevents a stale record matching a new incarnation. `P6H-HANDOFF`
now logs `gep=` (the real minted token) alongside the pre-existing
`dir_epoch`-based `epoch=` field.

## sess109 — adopt validation landed (0.11.439) `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

Blocker 3: `caw_wait_for_grant` gains `reg_epoch` (the slot's
`ex_grant_epoch` at our waiter-registration CAS). The adopt block now
validates before filling: `last_ex_slot == us`, `ex_grant_epoch != 0`,
and — the load-bearing check GPT's own list didn't have —
`ex_grant_epoch > reg_epoch` ("unminted"). All five of GPT's original
checks pass for a *pre-0.11.438 releaser* (old code set `last_ex_slot`
correctly and left a nonzero, just stale, epoch); only strictly-greater
distinguishes "a new tenure was minted since we queued" from "a releaser
set our bit without minting" (mixed-version case, closing half of
blocker 8 for free) or "the slot lineage restarted under us." Any
rejection does **not** adopt — falls through to the existing
`-EDEADLK` path, which drains via the BAST pipeline and re-acquires
through a correct, minting transition. Structural defense B added:
`P242-GRANT-UNSET-{WAIT,LOCK,CONV}` WARNs if `rc == 0` and the result is
still UNSET, at the single exit of each lock/wait function. Blocker 4
(PR must never mint) reviewed and already satisfied by construction.

## sess110 — blocker 5 landed, RIG-VERIFIED (0.11.440) `docs/history/docs/history/docs/history/compiled-step53-authcap-handoff-mint-campaign.md`

AG-lock paths (`mxfs_v5_dlm_ag_lock`/`_nb`) gain a threaded
`mxfs_grant_result` out-param instead of a separate post-acquire
`mxfs_v5_dlm_ag_grant_epoch()` I/O; the consumer now requires
`mxfs_grant_result_proving()` **and** `kind == AG` **and**
`resource == pag_agno(pag)` before trusting the epoch — anything else
publishes 0 and logs `P243-AGAUTH-UNBOUND`. Both the old reread function
and its TCP-side twin (`mxfs_dlm_caw_read_ex_grant_epoch`) deleted with
their only callers.

Deployed to 32/caw, 4/4 board PASS, no RULE-0 regression (dir_reuse
actually improved 8s — direct handoff is the pace-setting path and
minting added no measurable cost). **The sess106 defect population is
gone fleet-wide**: `P241-AUTHTRY nonewr_samegen=0` on all 32 nodes (was
7117 on test1 alone). `P6H-HANDOFF` shows 0 unminted handoffs; adopt
epochs advanced 9950 times, regressed never; `P6H-ADOPT-REFUSE`,
`P242-GRANT-UNSET-*`, `P243-AGAUTH-UNBOUND` all zero.

Two follow-ups opened, not yet closed: `st=0` on `P6H-ADOPT` turned out
to mean `gres == NULL` (a caller that structurally cannot install
authority), not `UNSET` — 9.4% of adopts, needs a census of which
inode-lock callers pass NULL. And `equal=1384` (epoch unchanged across
adopt) should by construction be entirely non-write adopts given
`REFUSE=0` — worth cross-tabulating to confirm rather than infer.

Three harness traps banked: `grep -o 'PROBE[^\n]*'` breaks silently —
inside a bracket expression `\n` means literal backslash-or-n, truncating
every match at the first letter `n`, which reads exactly like "field
missing"; select the line then `sed` out the field instead. dmesg
survives a module reload, so raw counts must be scoped to post-reload
before tallying (19.3k stale P6H-ADOPT lines had no `gep=`/`st=` field at
all and would corrupt any naïve tally). `tools/mxfs_sshpass.sh` takes a
bare hostname and prepends `root@` itself — passing `root@test1` yields
`root@root@test1`, which fails exactly like a bad credential.

## State at end of cluster

Blockers 1, 2, 3, 4, 5, 7 landed and verified; blocker 6
(adopt-vs-reconcile linearization, audit `caw_drop_own_waiter`) and
blockers 8/9/10 (mixed-version gate, first-install-EX audit, replay
resource-binding) remain open, in that order.
