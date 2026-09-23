<!-- sess440: build trap on top-level make dlm/*.o, 0.45.2 unregister-skips-retained-key fix, GPT item-5 slotless-bootstrap 10-STOP-SHIP ruling. -->
## sess440 — item 5 (slotless bootstrap) build attempt, continuing D-437 whole-cluster-restart

Direct continuation of ``docs/history/docs/history/compiled-sess439-self-succession-prkey-bootstrap.md``, whose
next-session order was: compile-check 0.45.1, run chain 23, get a RULE-5 ruling on item
5's implementation, then build it. sess440 did all three and found item 5 not yet
shippable.

### Chain 23 s440a — aborted on a build trap

`[[trap-toplevel-make-dlm-o-builds-usermode-objects-breaks-make-modules]]`: the
per-object compile check for 0.45.1 was run as `make dlm/scsipr.o dlm/v5_mount.o
dlm/prledger.o dlm/bootstrap.o` at the repo root. The top-level Makefile compiles those
as USER-MODE objects (silent: implicit-declaration warnings for `READ_ONCE`,
`WRITE_ONCE`, `pr_warn_ratelimited`, `snprintf`, no `.o.cmd` written). The next `make
modules` linked them into `mxfs.ko` and failed at modpost — `undefined!` for
`READ_ONCE`/`WRITE_ONCE`/`pr_warn_ratelimited` — with `BUILD_RC=2` but `grep -c
'error:'` = 0, since modpost prints `ERROR:` not `error:`. Chain 23 s440a was scrapped.
Correct per-object check: `make -C /lib/modules/$(uname -r)/build M=/src/mxfs
dlm/scsipr.o`. Recovery: remove the bad `dlm/*.o` and `dlm/.*.o.cmd` by full name (no
glob), rebuild. Chain launchers should grep `ERROR:`, not `error:`, in build.txt.

### Chain 23 s440b (0.45.1, sv 6508F4CF) — remount_refused loses the retained key

``docs/history/docs/history/docs/history/compiled-sess440-item5-slotless-bootstrap-build.md``: prep
32/32; `remount_snx` PASS (same-boot key reuse → dirty-predecessor path → fence-own-key,
mrc2=0 file=1); fln churn VERDICT PASS (withdrew 74s). `remount_refused` FAILED a new
assertion: the refusal itself was correct (`P305-PR-SAME-BOOT-DIRTY-PREDECESSOR`
refusing, `P302-PR-KEY-RETAINED-ON-REFUSAL` logged) but `sg_persist -i -k` afterward
showed NO keys registered. RULE-4 root cause from code, not guessed: `err_scsipr`
(`dlm/v5_mount.c:7686`) calls `mxfs_scsipr_unregister` unconditionally on the refusal
path, and `mxfs_scsipr_unregister` never consulted `ctx->registered` — so
`retain_key`'s `registered=false` was a no-op and the retained key got unregistered
anyway.

Fix, 0.45.2: `mxfs_scsipr_unregister` now returns `-ENOENT` with
`P302-PR-UNREGISTER-SKIPPED` when `!ctx->registered` (and leaves the ledger entry
un-retired too). `scsipr.o` kbuild-clean per the corrected check above. Chain 24 s440c
(`tests/sess440_chain24_0452_unregister_retained_key.sh`) launched: build + prep +
`remount_refused` (now asserting `keyheld>=1`) + prep2.
`lone_mount_create.sh`'s `remount_refused` arm updated to assert `keyheld>=1`, reading
`sg_persist -i -k` before the teardown step clears the reservation table (the earlier
version read after teardown and could never have caught this).

### GPT RULE-5 ruling — item 5 phase structure right, not shippable

``docs/rulings/item5-slotless-bootstrap-build-review.md``: plan
was survivor-scan claim (A) → provisional identity with `owner_slot=0xFFFF` (B) → seal
of dead-record-named keys only (C) → phase-3 fencing via the existing
`recovery_acquire` pipeline (D) → `xfs_mountfs` hook with the `!mp->m_log` guard
relaxed, running the barrier loop before `xfs_log_mount` (E) → ordinary claim/join on
`RECOVERY_COMPLETE` (F) → bounded waiter polling (G).

Verdict: claim→seal→fence-all→replay-all→global-commit→ACTIVE is the correct phase
order; the concrete implementation is not shippable. Ten STOP-SHIPs:

1. Slotless (no-slice) keys must not be left unfenced without a term-bound waiter
   protocol — under WE-AR a registered key can still write.
2. Registrants that appear after seal-cut are not reconciled before replay and before
   global completion.
3. `m_log==NULL` replay ships only behind a full call-graph audit of every accepted
   log-item handler (buffer/inode/quota/intents), tested with `m_log` POISONED (not
   NULL) plus lockdep/KASAN/fault-injection — never a 2-line guard relaxation, and
   never a temporary `mp->m_log = shadow` assignment. Alternative needing its own
   review: fence the whole sealed set, recover one victim slice through the *normal*
   `xfs_log_mount` path, adopt it as the provisional recovery journal for the rest.
4. Per-victim evidence (record, key, generation, certificate, replay outcome) must
   stay durable until the GLOBAL `RECOVERY_COMPLETE` CAS — a completion bitmap + CRC
   cannot reconstruct an erased record. Escrow it on the bootstrap side if the slot
   must be zeroed earlier.
5. Same-key/same-boot resume after an owner crash mid-phase-4 is not a takeover
   (can't be P&A'd, self-succession proves nothing for it) — needs its own resume
   protocol keyed by `{host,boot,node,epoch,pr_key,key_gen,nonce,term}`.
6. Precise durable ordering required end to end: replay → log-clean → descriptor
   complete → completion bitmap → zero. No step may be reordered for convenience.
7. A terminal/quarantined slice must never count as globally recovered — global
   completion becomes a hard volume-level refusal (or RO/admin) in that case.
8. The provisional epoch minted at claim time MUST be the epoch that becomes ACTIVE —
   never mint a second epoch at phase 5.
9. `owner_slot=0xFFFF` sentinel is unsafe until every `owner_slot` consumer
   (indices/sector offsets, liveness/steal paths, CAS validation, bitmaps, range
   asserts, u16/int/-1 conversions, chk_mxfs/recov_forge decoders, slice-from-slot
   derivations) is audited; prefer an explicit `owner_kind=BOOTSTRAP` field instead of
   overloading the slot.
10. A final `READ FULL STATUS` reconciliation is required immediately before
    `RECOVERY_COMPLETE` — no unexplained key may remain.

Also ruled: self-succession vs. owner P&A of the old key resolves strictly by `READ
FULL STATUS` outcome (old present/new absent → retry; old absent/new durable-successor
→ certify; both absent with sealed P&A evidence → owner certifies; both absent with no
evidence → stays `KEY_ABSENT_UNPROVEN`, permanently unprovable without an admin repair
path; both present → do not certify, investigate multipath) — a successful no-op P&A on
an already-absent key proves nothing, and a waiting new key must be either a durable
term-bound inert waiter or fenced as slotless, never silently ignored.

### Seams identified for the eventual build (not yet implemented at session end)

`owner_slot` has exactly one reader (`disklock.c:4741`) plus the chk_mxfs/recov_forge
decoders — needs the `owner_kind` field per STOP-SHIP 9, with a `PROTO_GEN` bump.
Liveness is already tuple-based; `v5_incarnation_state` already consults a bootstrap
`owner_is`. The completion ladder in `v5_mount.c` (~6300-6420) currently makes
`GRANTS_RELEASED` durable and then immediately runs step 3
(`mxfs_disklock_purge_node`, zeroing the HB sector) — per STOP-SHIP 4 this must hold
step 3 until the global `RECOVERY_COMPLETE` CAS. The mount barrier already replays the
whole cohort before `mount_cohort_complete` (cross-slice evidence rule,
`v5_mount.c:6484-6493`) — reusable for item 5's replay-all phase. `recovery_acquire`
(`v5_mount.c:5670`) needs only a pending marker plus disklock, and foreign replay takes
no DLM grants. `claim_slot` draws the epoch at `v5_mount.c:8193` — bootstrap must
pre-draw that epoch once (STOP-SHIP 8) and carry it forward to the ACTIVE claim.

Registrant policy adopted from the ruling: fence every non-owner key at the seal cut
except valid self-successors (new key with a durable `succeeds{old}` naming a sealed
victim key); waiters must not `REGISTER` while a bootstrap is claimed (reads are
allowed under WE-AR, so read the record first); run the final `READ FULL STATUS`
reconcile before `RECOVERY_COMPLETE`; a terminal slice refuses the whole bootstrap
(STOP-SHIP 7).

Go/no-go gate for replay shape (a) (survivor engine foreign-replays every sealed
slice, including the bootstrap node's own predecessor's — the sess420/437 direction;
`no_survivor_crash_replay` already expects "32 foreign replay ... complete") is the
STOP-SHIP-3 `m_log==NULL` audit of the recovery item handlers. A scout sweep was
running at session end over `xfs_log_recover.c`, `*_item_recover.c`, the intent items,
`xfs_log.c:780-1330`, `xfs_trans_ail.c`, `xfs_buf_item.c`, `pal/linux/xfs_buf.c`,
grepping `mp->m_log`, `xfs_log_force`, `xfs_trans_alloc`, `m_ail`, `force_shutdown`,
`delwri`, `queue_work`, `l_ailp` — re-run it if the result was lost at relay.

Next-session order: land 0.45.2 (chain 24 s440c) as PASS with `keyheld>=1`, then build
item 5 against the STOP-SHIP list above — owner_kind field first (blocks the sentinel
question), then seal/fence-all, then the m_log audit before touching replay.
