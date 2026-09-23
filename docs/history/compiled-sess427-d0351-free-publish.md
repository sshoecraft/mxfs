<!-- sess427: D-0351 ifree-never-published root+GPT FREE-PUBLISH ruling+0.38.1 scratch fix (unported); D-0352 flake, D-0349 regression, D-0348 step2. -->
## Topic

D-0351 — an ifree's free dinode (mode=0) never gets durably published before the
inobt marks the inode free, so a peer that allocates the same inode after an
AG-grant handoff reads a stale LIVE dinode and shuts down. Found, rooted, ruled
on by GPT, and fixed (in scratch, unported) in ccloop sess427, 2026-08-28,
while chasing D-0346's ESTALE reproducer on 0.37.0. Also carries sess427's
other findings (D-0352 flake, D-0349 regression, D-0348 step 2 draft) since
they landed in the same session and the same scratch tree.

## Discovery

s430 ran `dre` (the D-0346 reproducer) against 0.37.0 (sv 9FD110281921DA35CF07FF3).
D-0346's own mechanism did NOT reproduce (zero ESTALE, no P34H-POISON), but
test2 force-shut-down and fenced anyway: `P-CR3-CANCEL error=-117` after
`P-CR62 verdict=DISK-LIVE=>double-alloc(inobt-stale)`. New defect, filed as
D-0351.
`docs/history/docs/history/docs/history/compiled-sess427-d0351-free-publish.md`

## Root mechanism

On test1 (the freeing node), ordered by realtime: `rm -rf` frees ino 8388737
(ICLUSTER-routed). `xfs_inactive` holds CLUSTER EX and sets
`MXFS_IF_DLM_RELFLUSH`. `P150-FREE` marks it free in the inobt; `P82-REM`
discharges the pubob. Then `P128-INACT-DEFER` (pin=1, keeping the grant
cached) **clears `MXFS_IF_DLM_RELFLUSH`** (`xfs_inode.c:5463`). xfsaild's
`P119-NONEX-FLUSH-SKIP` then skips flushing it (routed, mode != EX, no
RELFLUSH token to force it). The inobt-free LSN gets published (`P144-WR`)
and the inode cluster gets written with the OLD (still-live) on-disk image
(`P170-CLWR`) — the inobt now says free while the platter dinode says live.
86ms later test2 allocates that same ino off the inobt, reads the still-live
platter dinode, its CR63 gate catches `-EUCLEAN` only after the transaction
is already dirty, and it shuts down. Same failure family as D-380
(ifree/inobt-free vs. dinode-publish ordering), different trigger path.
Harness bug found and fixed in the same pass: `tests/dir_recreate_estale.sh`
did `mkdir $D || echo "$(date) mkdir_rc=$?"` — the `$(date)` subshell reset
`$?` before the check fired, so the recreator silently ran only 3 laps; fixed
to assert recreator rc and per-node shutdown signatures directly.
`docs/history/docs/history/docs/history/compiled-sess427-d0351-free-publish.md`

## GPT rulings (the design-consult rule)

Ruling 1 rejected "keep RELFLUSH sticky through INACT-DEFER" as a complete
fix — acceptable only as emergency mitigation, since a sticky bit can't tell
"still the same uninterrupted EX tenure" from "released and reacquired."
Required invariant: **FREE-PUBLISH** — a peer may select an inode as free
under a newly-acquired AG grant only if the matching free dinode (mode=0,
correct incarnation) is already durable. Enforce at AG-grant handoff: force
the ifree LSN, unpin, do a sanctioned cluster write, wait for completion,
THEN unlock. Containment layer (deferred to a later change): validate the
platter is actually live BEFORE dialloc dirties its transaction.

Ruling 2 reviewed a concrete design and refused four parts of it: (1) a bare
`READ_ONCE(pag_mxfs_grant_epoch)==ob->epoch` predicate is TOCTOU between the
read and copy-in/delwri registration — needs a counted publication gate
(begin rejects if releasing/epoch-0/mismatched and increments a writer
count; end fires after the dirty/delwri registration is visible; release
sets releasing, clears epoch, waits writers==0, then drains). (2) arming the
FREE obligation only after `xfs_trans_commit` leaves a gap between unlink
discharge and FREE insertion — needs a continuous
UNLINK→FREE_PENDING→FREE_COMMITTED state machine; epoch 0 observed at ifree
time is itself a protocol failure. (3) the audit's own flush can't gate on
an active-epoch predicate since the epoch is cleared before the audit runs —
needs a separate retiring-epoch token (`pag_mxfs_rel_epoch == ob->epoch`,
release still holds the grant, unlock not yet done); RELFLUSH must never be
usable as a free bypass. (4) unconditional "mode==0 → discharge" is unsafe —
must classify by modular equality of `di_gen`: {mode=0, gen==ob.gen} is a
real publish/discharge; {mode!=0, gen==ob.gen-1} is the exact stale
predecessor and may be repaired under the token; any other gen must NEVER be
written and instead gets neutralized via `dead_incarn` before discharge;
read/CRC failure defers/escalates; no exact-predecessor shell present means
quarantine, not repair. Also ruled: AG-only sanction for ICLUSTER-routed
inodes needs a documented authority-subsumption invariant; inline FUA
repair must be two-phase (candidate validation, quarantine set, restart),
never an inline flush inside the ialloc AGI/inobt lock nesting; indefinite
AIL-tail pinning from a stuck obligation must be bounded (a recovery worker
acquiring the AG outside AIL context, or a reconstructable payload so a
laundered item can still be discharged later); "publish under protest" must
never let allocation from the AG proceed as if publication had actually
succeeded. Existing tokens reused: `pag_mxfs_grant_epoch` (nonzero iff EX
held and no release begun, cleared under `pag_dlm_lock` before the drain;
TCP fills it from `grant_seq`) and `pag_mxfs_rel_epoch` (saved at release
commit, `xfs_mxfs_dlm.c:37176`).
`docs/rulings/free-publish-invariant-d0351.md`

## Fix (0.38.1, scratch only — not yet in tree)

Written to scratch copy `w038`, not ported to `/src/mxfs` by end of session
(the 32/caw board was still running and the source-tree rule's "freeze the tree while a
rig run is in flight" trap applied). New state: `i_mxfs_freeob` +
`i_mxfs_freeob_strikes` on the inode; `pag_mxfs_pubwrite` (atomic gate) +
`pag_mxfs_freeob_split` on the AG; `m_mxfs_freeob_work[_armed]` on the
mount. `mxfs_pubob` extended with kind+epoch and
free_pending/free_commit/free_abort/lookup/free_strike; discharge
transitions fire only when `freeob==1`. `mxfs_ag_pubwrite_begin/end` quiesce
wired into `mxfs_ag_handoff_commit` after the epoch is zeroed. Audit gets a
FREE branch (P-FREEOB-PENDING/READ-FAIL/FOREIGN/NOSHELL/PUBLISHED/UNPUBLISHED)
that sets `pag_mxfs_freeob_split`. `bast_work_fn` adds an extra 8×2s
deferral, then fails closed with `P-FREEOB-REFUSED` regardless of
`mxfs_p87_refuse_unlock`. `xfs_inactive_ifree` sets `freeob=1` before
`xfs_ifree` and calls `free_commit`/`free_abort` around the transaction's
outcome. `xfs_iflush` gets a P55C gate ahead of P119
(FREE-HOME/FLUSH/DENIED/FOREIGN) that denies (-EAGAIN, keep dirty) any flush
of a free-obligated inode outside its sanctioned window; copy-in only
publishes `PUBOB_FLUSHED` for the free image once `freeob==2`. A
`mxfs_freeob_recover_fn` worker was added for the bounded-pin case (init in
`mxfs_defer_reap_init`, cancelled at the reap cancel site).
Verification plan: `tests/dir_recreate_estale.sh` (4 nodes) must show
P55C-FREE-FLUSH/P-FREEOB-PUBLISHED and zero
P-CR62-DISK-LIVE/P-CR3-CANCEL/P-FREEOB-REFUSED|FOREIGN|NOSHELL|NOEPOCH
fleet-wide, then the 32/caw board. The pre-dirty platter containment check
in dialloc (ruling 1's second layer) is intentionally deferred to a later
change.
`docs/history/docs/history/docs/history/compiled-sess427-d0351-free-publish.md`

## Other sess427 findings, same scratch tree

- **D-0352** (high, filed): `formation_test` has a pre-existing 1/10 flake
  (node `last_rc=-35` EAGAIN, `ledger_denies=1` during ramp) on the tree
  baseline; 10/10 PASS in scratch, so it is a flake, not a scratch-induced
  regression.
- **Token stage on 0.37.0**: D-0348 step 1 (collision-free tauth resolution)
  still verified (collisions=0); D-0350 (no TAKEOVER-NOINC) still verified.
  D-0349 (small-file workload timeout) got WORSE: 1092
  `P-TAUTH-REMASTER-PARKED` across 1083 distinct pages, with
  `P-LKTIMEOUT-HOLDER`/`-REMOTE` in the hundreds. Root: a new master's
  tauth pages activate lazily on first request (`cached_auth=-2`), so every
  page's first touch triggers a DENY(REMASTER) + retry storm. Next step
  identified: activate all of a new master's pages eagerly at
  attach/membership change (~66 pages for a 2115/32 layout) instead of
  lazily, and measure the requester's REMASTER retry delay (`dlm.c:3437`).
- **D-0348 step 2** (tauth ledger format v2 — mkfs-sized geometry,
  PROTO_GEN 9, seeded hash, `mxfs_tauth_res_hash`/`home_page`/`home_index`)
  drafted in the same `w038` scratch tree as VERSION 0.38.0; usermode
  suites pass except the D-0352 flake above.

## Handoff state at session end

The 32/caw board (s430, `tests/evidence/sess426_s430.log`) was still running
at the relay boundary — the next session must confirm DONE before building
or running `make tools` in `/src/mxfs` (the source-tree rule freeze). All of this
session's work product lives only in scratch copy
`/tmp/.../scratchpad/w038` plus a safety-net diff,
`tests/evidence/sess427_w038_0.38.1.patch` (37 files) — neither is applied
to the tree. The patch also carries several rig-state files that are STALE
relative to the tree and must not be reverted from it:
`.cluster_marker.json`, `.last_run.json`, `bench.json`, `criteria.json`,
`criteria.tcpmp.json`, `tests/criteria/OPEN_DEFECTS.json`,
`tests/dir_recreate_estale.sh`. A grind agent building `w038` died with the
session (its build log may be incomplete) — the build must be redone
out-of-tree before porting: `make modules` → fix errors → `make tools` →
`make -C tests/tauth clean test`, then port the changed source/doc/test
files (listed in the handoff note) and queue
`tests/sess427_chain.sh s431` (setsid nohup) for build → tools → tauth →
prep caw → chk-geometry → dre×2 (D-0351 verification) → board → prep tcp →
token → d0287.
`docs/history/docs/history/docs/history/compiled-sess427-d0351-free-publish.md`
