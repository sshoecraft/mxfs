<!-- sess432-433: single-node CAW authority defects — D-0353/D-0355 closed F&V, D-379(B) key retention landed, D-0357 ruling+landing, D-0354/D-0356 open. -->
# Single-node authority campaign (sess432-433): D-0353/D-0354/D-0355/D-0356/D-0357/D-379(B)

Chain of defects around MXFS's single-node CAW fast path treating "no peers seen" as
authority, and around what a departing node is allowed to do to its on-disk grants
before a peer can safely replay after it. All rooted in the same design flaw: the
single-node fast path minted only an in-memory/epoch-0 notion of ownership instead of
a durable, incarnation-bound grant, so every boundary around it (join, remount, dirty
departure, PR-key handling) had a gap.

## D-0353 — lone-mount double-alloc (found, fixed, closed sess432-433)

Root chain, proven on the LUN with `tests/lone_mount_create.sh`
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``):
`caw_lock` single-node fast path → non-proving grant (epoch 0) → sess291 epochless-hint
drop on every acquire (`xfs_mxfs_dlm.c:40088`) → P130 false-fresh classification →
`invalidate_ag_meta` stales PINNED AGI/inobt/finobt (P131) → platter re-read → `mkdir`'s
inode allocated twice → shutdown.

GPT ruling (``docs/rulings/single-node-false-fresh-discard.md``):
- Exempting single-node from the epochless-hint drop is only sound if the
  single→multi transition is a serialization boundary, never an unlocked live read of
  `single_node`. New provenance `GAUTH_SINGLE_NODE`: valid for cached reuse within the
  same single-node generation, never an authority proof for replay, must not survive
  the join barrier.
- Join must: enter JOINING, block new single-node acquires + dirtying, drain in-flight
  acquires, commit txns, `log_force` SYNC, `ail_push_all_sync` (failure = transition
  failure), verify no AG meta pinned/CIL/AIL/dirty/delwri/writeback, end all
  single-node lineages via the normal release path, invalidate cached views, enable
  multi CAW, admit peer.
- Never `log_force`+AIL-push at the *fresh* acquire — can clobber a peer's newer
  platter state; local state must land before authority is yielded, not after
  reacquiring.
- Fresh acquisition must reclassify continuous only if CAW slot state proves
  uninterrupted local ownership; otherwise force shutdown (P130 becomes an enforced
  invariant, not just a diagnosis). Fresh-and-clean path is two-pass, all-or-nothing:
  first pass excludes local AG-meta users and verifies nothing pinned/dirty/CIL/AIL/
  writeback (any hit → force shutdown, stale nothing); only if clean does a second
  pass do `xfs_buf_stale`.
- Additional stop-ship (became D-0354): lone node commits epoch-0 txns, crashes before
  landing, a peer must replay under token enforcement → refused. "No peers seen" is not
  proof of authority; needs durable single-node incarnation state or real epochs.

Fix landed in two steps: 0.39.11 = step 1 (`MXFS_GAUTH_SINGLE_NODE` +
`pag_mxfs_grant_single` + P243 exemption while DLM single-node); 0.39.12 = step 2 (P131
preflight+refuse via `agmeta_inval_enforce`, P130 enforce via `false_fresh_enforce`,
census callers retain, `single_era_hint_keep` diag knob) —
``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``. Both arms
(`p130`, `p131`) verified fail-closed (shutdown, `inuse=0`) via
`tests/lone_mount_create.sh`.

Closed FIXED AND VERIFIED sess433: 0.39.13 board run `20260828T202007Z`, 26 PASS,
`open_defects` policy-fail, `crash_consistency` budget-only (known D-401 face, not
widened), sweep `P130R=0 P131R=0 INUSE=0`
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``,
``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``).

## D-0355 — lone node cannot remount after its own dirty shutdown

Root (from timeline analysis): barrier inline replay rounds (4) ran ~50ms *before* the
node's own fence pipeline sealed (P236-CLAIM-UNCERTIFIED ×4, then P-RMAN-SEALED); the
30s admission poll only classified the state and never re-attempted replay. Fix in
0.39.13: the poll branch in `xfs_mxfs_dlm.c` no longer `continue`s after `msleep` —
falls through into a replay round each poll interval (bound unchanged) —
``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``.

Two sub-arms discovered during verification:
- On a real LUN, fence stayed `KEY_ABSENT_UNPROVEN` because `put_super` had already
  unconditionally retired the PR key → this became D-379(B) below.
- On loop devices, `purge_cas_zero` refuses (`-EOPNOTSUPP`) on non-CAW by design
  (sess419 ruling, D-PURGE-NONATOMIC stop-ship 5) — a loop device can never complete a
  recovery publication, so `vergate.sh` MB3 could never validly prove replay via mount.
  Rewritten as a byte-compare (md5) of the dirty log slice across the refused mount
  instead of requiring a live replay
  (``docs/rulings/d379b-key-retention-no-kind18.md``).

Closed FIXED AND VERIFIED sess433 on 0.40.0: `lone_mount_create.sh` arms
`remount_refused` (p302=1, p305p=1, mrc2!=0) and `remount_snx` (p302=1, p305r=1,
replay, file=1) PASS on the LUN; two laps on test1+test2, `vergate.sh mixed_build` MB3
(slice-md5 form) PASS
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``,
``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``). Operator path
for lone deployments: `echo 1 > /sys/module/mxfs/parameters/single_node_exclusive`
(kind 17) before remount.

## D-379(B) — dirty-departure PR-key retention (ruling, then landed as 0.40.0)

GPT ruling (``docs/rulings/d379b-key-retention-no-kind18.md``):
a PR registration belongs to an I_T nexus; a same-host/nexus next incarnation cannot
hold a second key while the stale one exists — REGISTER AND IGNORE EXISTING KEY only
*replaces* it, it is not a PREEMPT AND ABORT proof. Under WE-AR a stale registrant is
still an active privilege. Ruling shape: keep self-verified retirement for CLEAN
departures; for DIRTY departures leave the key registered as a fence target — the
incarnation stays unfenced until a verified PREEMPT AND ABORT completes. If the
stamp/release write fails, latch dirty/uncertain, do NOT unregister, no further FS
writes, next incarnation blocked until a valid fence. Ordering: clean path is durable
slot release → unregister → READ KEYS verify; dirty path is durable WITHDRAWN → keep
key. Rejected P2 (treat WITHDRAWN + key-absent + WE-AR + complete view as proof of
exclusion, "kind 18"): absence causality is unknowable (plain PREEMPT, CLEAR, target
reset, PR loss, ambiguous unregister all look the same), and SCSI tasks aren't tagged
by incarnation so a same-nexus successor's registration re-authorizes surviving
predecessor I/O. Only `PREEMPT_ABORT_DONE` (key present) or `SINGLE_NODE_EXCLUSIVE`
prove exclusion.

Landed as 0.40.0 (``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``):
- `mxfs_v5_dlm_slot_release_commit` now returns bool `released` (unmount_clean &&
  release rc==0).
- `put_super`: `blkdev_issue_flush` checked before slot release
  (P277-FINAL-FLUSH-FAILED → dirty) and after release (P277-RELEASE-FLUSH-FAILED →
  unreleased); PR key unregistered ONLY if released, else
  `P302-PR-KEY-RETAINED-FENCE-TARGET`.
- New `mxfs_pal_scsi_pr_register` = plain REGISTER (SA 0x00, flags 0); exact
  `PR_STS_RESERVATION_CONFLICT` → `-EEXIST` (P305-PR-NEXUS-ALREADY-REGISTERED).
  `mxfs_pal_scsi_pr_register_replace` keeps the old REGISTER-AND-IGNORE behavior.
- `mxfs_scsipr_register(ctx, replace_predecessor)`: `-EEXIST` → refuse mount
  (P305-PR-PREDECESSOR-KEY-PRESENT) unless `single_node_exclusive=1`, in which case
  P305-PR-PREDECESSOR-KEY-REPLACED.
- Why plain REGISTER and not READ KEYS: `node_uuid` is random per mount, so a key
  cannot be attributed to "our" nexus by identity; `dm_pr_register` fails early over
  all table paths and rolls back — fail-closed by construction.
- GPT re-review of the landing approved it, with two corrections applied (exact-conflict-
  only classification; "released" must include post-release flush durability; P305 text
  reworded to not claim proof of a dirty predecessor) and one new gap: a path *removed*
  from the dm table is invisible to all PR ops (documented in
  `docs/pr-fencing-departure.md`). A failed unregister after a released slot leaves
  slot=RELEASED, key=PRESENT — unfenceable stale registrant — filed as D-0356 (high).

## D-0354 — lone-era epoch-0 images can't be proven for replay (ruling, build started)

Core invariant (``docs/rulings/d0354-mint-durable-epoch-single-node.md``):
no journal image requiring authority may be formatted until that authority is a
durable, incarnation-bound, nonzero-epoch on-disk grant that recovery can place in the
fence manifest. Caching an already-durable grant is fine; replacing it is not.

Shipped candidate A: single-node mode must mint REAL durable epochs by entering the
*normal* grant state machine (full-word constructor/validator comparing the complete
old word — owner/incarnation/mode/epoch/gen — canonical successor word), with
waiter/BAST suppressed only *after* the grant is acquired. No separate single-node
promotion path (that's the sess25 OR-bug class: ORing the EX bit into an observed word
while preserving stale owner/count bits). Never steal a stale grant just because
`single_node==true` — stale ownership goes through fence/incarnation recovery. Durable
grant must precede token formatting; token immutable after format. Single→multi
transition must not release-and-remint retained grants (that changes epoch while
old-epoch records still exist) — gate new acquires, drain in-flight, verify every
live token-bearing grant has an identical durable grant, activate BAST/revocation on
retained grants, force+land txns for surrendered grants, release only grants whose
tokened txns are beyond replay. STOP-SHIP: a joiner must not become writable until the
incumbent acked the barrier or was fenced+recovered — measured concretely (joiner's
mount returned while incumbent kept writing single-mode for seconds). STOP-SHIP:
inventory *every* lock class carrying journaled state (AG, ICLUSTER, INODE,
superblock/global, quota, rt, rmap/refcount, mixed-AG txns) — a superblock-class image
must not silently get epoch 0. Rejected candidate B (automatic single-node-era HB flag
+ kind16 fence): the flag only proves "no other ACTIVE member at claim time", and
measured peer-overlap (peer active while incumbent still single-mode) is a live
counterexample; kind16 proves fence-time exclusion, not historical exclusivity.

Both `enforce0`/`enforce1` knob arms measured refused/quarantined
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``) — ruling
confirmed candidate A is required, build order set to D-0357 first, then candidate A.

Step 1 of the build started mid-session, tree left UNBUILT
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``): removed all
`single_node` memory-only shortcuts from `dlm/dlm_caw.c` (`caw_lock_body` fast path,
`unlock_gen_body`, `convert_body`, `set_dir_block0`, `held`, `granted_mode`,
`open_holders`, `open_set`, `open_probe`, `open_clear`, `dump_slot`, `ex_count`,
`self_held_scan`, `force_release_self`); kept the `bast_poll_fn` single-node
continue and `set_single_node` (now a no-op flush body). Remaining work enumerated for
the next session: (a) `pal/linux/xfs_buf_item.c:151`
`mxfs_buf_item_wants_authority` must not gate on `!is_single_node`; (b)
`xfs/xfs_trans_buf.c:624-649` three `!is_single_node` gates on `mxfs_ag_meta_track` /
`mxfs_dir_bmbt_track` / `mxfs_dir_data_track` — remove, now that AG grants are real and
can be BAST'd after a join; (c)
`xfs/xfs_mxfs_dlm.c` `mxfs_dlm_invalidate_cached_views` single→multi surrender must
NOT clear `pag_dlm_cached`/epoch/lineage anymore (keep retained grants, let BAST handle
them — release-and-remint changes epochs); keep only the AG-meta buf invalidation part;
(d) P243 keep-hint branches in `__mxfs_ag_dlm_lock` become dead code once epoch != 0,
leave as-is; (e) bump VERSION to 0.41.0; (f) re-run `lone_mount_create` fixed
(D-0353 regression), `lone_crash_replay` both enforce arms, `d379b`, and a lone rsync
bench vs 0.40.1 (the derived-budget rule: lone-node perf at multi-node parity is the accepted cost).
Step 3 (joiner barrier on incumbent HB "single" feature bit) and step 4 (mixed-version
gate: a 0.40.x memory-only-single-node peer must be rejected before a candidate-A peer
admits) deferred.

## D-0357 — dirty unmount releases on-disk grants before replay ("notheld")

Discovered while pursuing D-0354: dirty unmount currently calls `force_release_all` +
CAW `release_all`, which unlocks on-disk grants *before* the survivor can replay — the
survivor's fence manifest ends up empty, tokened images read as "notheld", and get
refused/quarantined. Filed critical
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``).

GPT ruling (``docs/rulings/d0357-retain-grants-on-dirty-departure.md``):
correct fix shape is in-core teardown WITHOUT on-disk unlock on a recovery-required
departure — grants stay held by the withdrawn incarnation, survivor's PREEMPT AND
ABORT + manifest seal captures them, existing post-replay purge frees them. This makes
dirty unmount behave like a crash. Conditional on:
1. Fail-closed predicate must be an explicit one-way departure state
   (`RECOVERY_REQUIRED` default vs `CLEAN_RELEASE_OK`, set only after durable
   clean-unmount proof), not raw `xfs_is_shutdown()`. `release_on_disk_grants =>
   CLEAN_RELEASE_OK && hb not WITHDRAWN && no remote recovery required`. The WITHDRAWN
   stamp and PR-key retention (D-379B) must key off the *same* classification.
2. Grants must be owned by `{node_id, incarnation}` (MXFS mints `node_id` per mount
   from a random UUID, so this holds by construction) — a same-node remount must never
   adopt/unlock/recognize a predecessor's grant.
3. Explicit ordering state machine: withdrawn observed → P&A complete → predecessor
   cannot CAW/write → serialize against purge/reclaim → seal manifest from a consistent
   view → replay → durably commit completion → purge → allow new-incarnation
   acquisition. P&A failure/ambiguity = no seal, no purge, no adoption. No purge on
   ATOMIC-SKIP/POLICY-REFUSED/manifest mismatch — grants stay held, domain quarantined
   (explicit admin-repair story needed). Crash after replay-commit but before purge
   must be idempotent.
4. Audit every *indirect* unlock path (ICLUSTER sweepers, shrinker/LRU eviction, final
   puts, error unwinds, delayed unlock work, mount-shutdown cancellation ordering) — the
   lifetime invariant (`on-disk unlock => no replay-eligible image can still require
   this grant generation`) is independent of unmount; fixing `put_super` alone is
   insufficient if a sweeper can release during normal operation while tokened images
   are unlanded.
- A departer-sealed manifest is a *worse* authority (can't prove completeness/no-writes-
  after) — usable only as diagnostic/cross-check. The survivor manifest is expected to
  be a superset of what's needed (cached unused grants); fine as long as matching is
  sound and purge handles the surplus.

Fix landed as 0.40.1 (P306 poison-release gate) alongside chk_mxfs recovery-guard-in-
progress classification and P300 text naming the remedy (peer-fence vs snx) for D-379
items 2/4/5. Verification chain (`d379b` armed ×2 + `d_mount_window_death_verify`) was
running at session end, gate proven mid-run: manifest `entries=8 WOULD_APPLY=9`
(``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``).

## Recurring operational notes from this campaign

- Never edit `tests/lone_mount_create.sh` or `tests/vergate.sh` while a chain is
  running them — bash reads scripts incrementally, so an in-flight edit corrupts the
  run (``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``).
- Never `make modules` while a `setsid`-detached chain is running — the rig `insmod`s
  the tree's `mxfs.ko` over NFS, so a rebuild mid-run splits the run's srcversion
  (``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``).
- `crash_consistency` timing out at its 90s budget recurred 3x in one day; recorded as
  a known D-401 face rather than widened (the derived-budget rule discipline held under pressure to
  just pass the board) — ``docs/history/docs/history/docs/history/compiled-single-node-authority-campaign.md``.
- vergate `mixed_build` MB3's original replay-based check was invalid on loop devices
  by design (non-CAW `purge_cas_zero` always refuses); rewritten as a slice md5
  byte-compare, which is the general lesson — a verification step that depends on a
  code path known to be refused-by-design for the test's own device class is not
  testing what it claims to.
