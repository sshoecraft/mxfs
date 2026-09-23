<!-- sess434-435: D-0354 log-incarnation-boundary + D-0357/D-379 mount-window closed F&V; D-0359 non-CAW admission filed; D-401 pace root found. -->
# sess434-435: log-incarnation-boundary (D-0354), mount-window (D-0357/D-379), non-CAW admission (D-0359), shared-dir create pace (D-401)

Continuation of the single-node-authority campaign (docs/history/docs/history/compiled-single-node-authority-campaign.md,
docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md). Two sessions, 0.40.1 → 0.41.6,
ledger 69 → 67 open.

## D-0357 / D-MOUNT-WINDOW — mount-window peer-death barrier (sess434, 0.40.1)

d379b armed laps PASS on 0.40.1 (kind16=1, replay_complete=1, P227-FR-ENFORCE-ADMIT,
zero P240-QUAR/-117/P306)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
D-MOUNT-WINDOW window arm rc=1 but the kernel outcome was already correct (P233 death
recorded, hold released, RESOLVED-ELSEWHERE=1, mount rc=0) — both reported FAILs were
harness bugs, not kernel bugs: the late-mask check `drained &= ~elsewhere` must only run
in the apub=1 (A-replayed) branch, and the harness's node count sed'd kmsg for a MARK that
was only ever written on A and C, so B/C's 30-node fleet count read 0
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Fix: capture `T0` before `virsh destroy` and count fleet-wide via
`journalctl -k --since "$T0"` instead of a kmsg-MARK sed; move the late-mask check into
the apub=1 branch; add a `window_lone` arm (sweep-unmount all but B first) — confirmed
against a 31-node fleet sweep that showed exactly one `P163-RECOVERY-COMPLETE` cluster-wide,
matching the sess424 design
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
window arm reran 17/17 PASS; window_lone kernel-proven (late=0x800000 replayed=1
published=0x800000, A sole publisher) once the sweep was fixed to skip A; D-0357 CLOSED
FIXED AND VERIFIED
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE also closed after chain5 reran window + window_lone
clean on 0.41.0 `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
D-379 (dirty-slice-departure retires fence key, unmountable): items 2/4 landed sess433;
item 5 (chk_mxfs in-progress guard classification) verified via
`tests/chk_guard_inprogress_verify.sh` (recov_forge --live --stage 1 + chk_mxfs -Q);
CLOSED F&V once remount_refused/remount_snx reran clean and dmesg carried the rewritten
P300 text on 0.41.1
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

D-0358 filed: `recov_forge`'s descriptor version mirror had drifted (v2) against the kernel's
v3 since sess405 — forged-record checks had only ever exercised the version gate, not real
v3 content `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-0354 — candidate A: remove the single-node authority exemption (sess434-435)

**Step 1** (0.41.0): drop the `single_node` exemption everywhere authority/tracking was
gated on it — `mxfs_buf_item_wants_authority` now gates only on `mp && mp->m_mxfs_dlm`;
three `!is_single_node` track gates removed in `xfs_trans_buf.c`; the AG-grant-surrender +
inode `i_dlm_stale` invalidation block removed from `mxfs_dlm_invalidate_cached_views`
(real grants now survive a join; `caw_lock_body` self-hold same-mode is reentrant, so a
remint would have stranded lone-era images as stale) — AG-meta buf invalidation kept
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Measured on 0.41.0: `lone_mount_create` fixed PASS; bench regressed slightly (3.1s vs
0.40.1's 2.43s warm) but stayed inside the the derived-budget rule ceiling (native 3-4s → 6-8s); d379b PASS;
but `lone_crash_replay` FAILED both arms — enforce1: `wrong_incarnation` (winc=3) on 3 of 9
images (token's emitting incarnation != descriptor victim incarnation); enforce0: refused
via `uncapable_match`/`v2_no_lineage` (lone grants mint an epoch but no resource lineage)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

**Lap-2 root** (code-proven): the survivor's replay window `[head.h_tail_lsn, head)` still
contained the *previous* incarnation's last record next to the crashed lone incarnation's
new record → `winc` → ATOMIC-SKIP → `P227-FR-TORN-UNPUBLISHED` → refusal/quarantine.
Upstream `xlog_set_state` seeds `ail_head_lsn` from the last old record's LSN; the
empty-AIL tail fallback then makes the new incarnation's first checkpoint carry
`h_tail_lsn` pinned there — fine for idempotent upstream recovery, not for
incarnation-bound tokens. The enforce0 arm is shadow-only by definition and can never
PASS as a closure criterion
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

Fix landed for 0.41.1: `P308-LOG-INCARNATION-BOUNDARY` — write an unmount record in
`xfs_log_mount_finish` after recovery+force+AIL-drain; `P309-LOGTAIL` diagnostic in
`xlog_find_tail`; `MXFS_RI_VERDICT_PREINC` / `MXFS_TXNV_PREINC` +
`P310-FR-PREINCARNATION-SKIP` to whole-txn-clean-skip records from before the boundary;
`MXFS_HB_FEAT_ADOPTED` HB bit + `mxfs_v5_dlm_victim_adopted` provenance certificate;
`bast_poll_fn`'s `single_node` skip removed per GPT ruling (poll unconditionally, preferred
over a feature-bit barrier); `MXFS_PROTO_GEN` 10→11; `recov_forge` `RECOV_DESC_VERSION` 3
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
GPT stop-ships on the boundary placement: no straddling producer, keep the sickness rule,
assert `tail==boundary`, provenance certificate required for the adopted case; residual
own-crash-then-crash-again hazard filed separately as
D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

0.41.1 deployed (sv FA677B3F). Harvest (sess435): `chk_guard_inprogress` 11/11, d513 valid,
`lone_mount_create` fixed all PASS; `lone_crash_replay` enforce1 x2 REAL PASS (winc=0,
untagged=0, RECOVERY-COMPLETE) — the earlier reported FAIL was a harness bug
(`grep -ac quarantin` matched the string `quarantined=0x0`, fixed in
`tests/lone_crash_replay.sh`); but the adopted-dirty-slot arm hit a NEW bug:
`P308-LOG-INCARNATION-BOUNDARY did NOT advance ail_head_lsn` (P310 rescued it, so no data
loss, but the boundary wasn't doing its job); bench FAILed on `mrc=32` "unknown filesystem
type mxfs" because a virsh-destroyed node from the crash arm wasn't re-prepped before the
bench ran — harness now exits on `mrc!=0`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

**No-advance root** (code-proven): `ail_head_lsn` is written only by
`xlog_cil_ail_insert` and by recovery seeding; `xlog_unmount_write` calls `xlog_write`
directly, bypassing the CIL, so the head never moves and the empty-AIL tail fallback keeps
the stale record. Fix (0.41.2): `mxfs_log_head_past_boundary()` — after
`xlog_unmount_write`, compute `new_head` the same way `xlog_find_tail`'s after-umount path
would, and explicitly advance `ail_head_lsn` under `ail_lock`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
0.41.2 (sv BA8F6311) verified: adopted-dirty arm shows the head genuinely advancing
(`0x100000004 -> 0x10000000c`), winc=0, no P310 needed; both crash arms PASS; bench 2.76s;
armed 32/caw board 27/27 + death PASS; fleet sweep zero across every failure signal.
**D-0354 and D-379 CLOSED FIXED AND VERIFIED**
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-FOREIGN-REPLAY-UNGATED-IMAGES gate — rman matrix + vergate LUN port

rman matrix ran for the first time ever (sess420 had prep-failed every arm) — all 9 arms
PASS on 0.41.2, closing gate items 1/6
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
vergate `mixed_build` FAILed on the loop-device rig: a non-CAW device is admitted, then
every lock returns `-95`/EOPNOTSUPP, because candidate A's step 1 removed the lone-mount
memory-grant fallback that had been silently covering non-CAW media — filed as D-0359
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Later ported vergate's loop arms to the real LUN (`VG_DEV`): legacy_refuse, upgrade,
mixed_build all PASS including the B4 durability leg — gate item 7 CLOSED on the LUN
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Remaining UNGATED-IMAGES blockers: item 5 (mount-time (1,0) refusal, lands with the D-0359
flip), sess197 steps 7-10, item 14 B2-B4, stable-media oracle (exists only as a ccmemory
ruling, no test/doc)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-0359 — non-CAW device admitted, then every lock EOPNOTSUPP

GPT ruling (gpt-5.6-sol): make SNLOCAL_EXCLUSIVE a **separate, non-joinable, single-initiator
authority mode** — not a weaker CAW grant. A single FUA write is not a crash-durable
authority record (torn-write stop-ship); read/verify/write for all mounts is rejected (not
a CAS under contention). Invariants: I1 no ordinary clustered grant without atomic exclusion
and a non-CAW token must never be mistakable for a CAW-proven one; I2 grant-before-image
(nonzero incarnation+epoch, durable authority record, durable mode identifier, before any
token-bearing image commits — no epoch 0); I3 mode bound into token validation; I4
SNLOCAL_EXCLUSIVE not joinable while live/dirty, transition only after
recovery+drain+re-incarnation; I5 invalid/torn/contradictory records fail closed. Admission
probe: real operational CAW on an MXFS-reserved probe sector (CAW with matching compare,
verify readback, deliberately-mismatching CAW must miscompare) — classify
unsupported/transient/semantic-violation distinctly, never silently fall back on ambiguity,
no runtime downgrade after a passing probe, multipath failover to a non-capable path is
fatal. 24 verification arms specified, covering ordering-point crash injection, torn-write
redundancy, migration to CAW media, and race documentation
`docs/rulings/d0359-noncaw-snlocal-exclusive-domain.md`.

**Step 1 landed in 0.41.3**: `P311-CAW-ADMISSION-REFUSED` probe (`v5_mount.c`),
`mxfs_disklock_caw_capability` negative probe on the node's own HB slot,
`disklock_claim_via_caw`, `P378-TRANS-READ-FAIL` marker (`xfs_trans_buf.c`, D-378 item 1),
vergate `noncaw_refuse` arm. Verified: P311 32/32 OK on the LUN, `noncaw_refuse` PASS on
loop, regressions (fixed/crash/d379b) PASS, armed board 27/27+death PASS
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Step 2 (the SNLOCAL_EXCLUSIVE mode itself) remains open at sess435 end
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-PURGE-NONATOMIC-PUBLICATION

Arms on 0.41.2 exposed two bugs: `concurrent` 14/15 (P234 owner printed `%d` literally
instead of the value), `midscan` 10/11 (no P229 emitted on a mid-scan stop)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`. Fixed in `disklock.c`
for 0.41.4; reran 15/15, 11/11, 11/11 — **CLOSED**
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-32NODE-SHARED-DIR-CREATE-PACE / D-401 — pace investigation (sess435)

`crash_consistency` archive parse (`tests/cc_phase_walls.py`): 100 O_SYNC creates per node
into ONE shared directory at 32 nodes costs ~22ms/create serialized (datawrite median 30s +
md5write 39s of a ~90s row); verify only 9s; zero fault probes — this is D-401's mechanism
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Stack profile: 26.5% of blocked ticks in `caw_wait_for_grant` (acquire side), only 1.25% on
release. First hypothesis — the dir's INODE lock — was measured and refuted:
`cc_grantwait` report on 0.41.4 showed only 2 `P138-WAIT` (>5ms) lines fleet-wide
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Second hypothesis — AG lock contention (4 AGs × 8 nodes each, since inode+block alloc both
happen per create) — `P138-AGWAIT` instrumentation added (0.41.5) and also came back
negligible: 2 lines, 50ms total
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
Neither the grant-wait *loop* nor the AG wait accounted for the wall, so 0.41.6 added
whole-acquire accounting instead of just the wait-loop: `P138-ACQ` (>5ms whole
`caw_lock_body` acquire) + `P138-ACQSUM` (per-500-acquires rollup: n, sum_ms, count>5ms)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
**Root found**: INODE-class acquires total 19000 across the fleet, summing to 1989s =
62s/node — that IS the whole create wall. The shared directory's own inode: 772 acquires
>5ms, summing 1958s, p50 941ms, p90 7.75s, max 9.7s. The grant-wait-loop had never shown
this because individual poll iterations never exceed 5ms — the acquire is slow as a whole
(batched EX hand-off), not slow per poll
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
`tests/cc_tenure_timeline.py` (new miner tool, parses per-node journal greps): EX grants
arrive in batches of ~8-10 nodes within a 25ms window, then ~300ms gaps between batches;
per-node EX-tenure rotation p50 ~950ms, p90 7-9s, no round-robin fairness; BAST-driven dir
releases run ~500 times at 5-20ms with an ~11ms unlock-CAS cost on the wire
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`. Root is measured,
not yet designed: next step is to re-extract mode-split (EX vs PR) timing and hand the cycle
anatomy to a design consult (fix shapes under consideration: batched/longer EX tenures,
cheaper per-create work under the lock, or reducing the ~11ms unlock-CAS handoff latency)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## D-FOREIGN-SLICE-INTENTS-ABANDONED — burst arm still unverified

Scout inventory found the interim fix (0.32.0 census) has never actually been exercised:
`tests/d_intents_undischarged_verify.sh burst` timed out (rc=124, no fails=N verdict) in
both sess421 and sess423, and the dmesg evidence in both runs shows
`P226-ICENSUS ... intents=0 dones=0 open=0` — the burst workload (8 fragmented files, `rm`
in parallel, `virsh destroy` ~2s in) never actually left an undischarged EFI in the victim's
last checkpoint, so the `open>=1` refusal path has never fired on the rig. The clean arm
passes (open=0) but proves nothing about the refusal path. Needed: force a real gap between
an EFI's commit and its EFD (existing debug knob, or a slower/larger-extent-count workload)
so `intents>0 open>=1` actually occurs, then verify the refusal fires. Item 5 (real
completion of foreign intents on the reap path) remains the true, still-owed fix
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## Harness / process traps (both sessions)

- `recov_forge`'s descriptor-version mirror drifts silently against the kernel's; consumers
  now abort on version mismatch rather than testing stale content
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- `tools/ledger_set.py`'s prepend now handles list-valued fields
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- `lone_rsync_bench.sh`'s `sync_wall=` grep matched inside `rsync_wall=` — fixed
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- The enforce0 arm of `lone_crash_replay` is shadow-only by definition — it can never be
  used as a closure criterion, only enforce1
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- Pipeline discipline used throughout both sessions: every chain script is launched detached
  (`setsid`), gated on the previous chain's log printing DONE, and `make modules` is never
  run outside the one chain stage that builds — violating this splits `srcversion` across a
  run mid-flight
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- A single-row `run.sh` has ~37s of startup overhead alone — a 90s test row needs a wrapper
  timeout ≥150s, not just the row's own budget
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
- Chain-log naming drifted from chain numbering under renumbering pressure (chain 17's log
  is misnamed `..._chain15_0416_acq_....log`) — check the log's contents, not its filename,
  when resuming
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`
  `docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.

## End state (sess435, 01:15Z)

Fleet: 0.41.6 (sv FFBC6F6D), rig idle, tree == build. Ledger 67 open (69 at sess434 start).
Closed this arc: D-0357, D-MOUNT-WINDOW-PEER-DEATH-IMMEDIATE-PURGE, D-0354, D-379,
D-PURGE-NONATOMIC-PUBLICATION. Filed: D-0358, D-0359 (step 1 verified, step 2 open). Open
threads carried forward: D-0359 step 2 (SNLOCAL_EXCLUSIVE design), D-32NODE-SHARED-DIR-CREATE-PACE
(root measured, fix undesigned), D-FOREIGN-SLICE-INTENTS-ABANDONED burst-arm gap, P378 marker
live but unfired (sweep count 0 so far), remaining UNGATED-IMAGES gate items (5, sess197
steps 7-10, item 14 B2-B4, stable-media oracle)
`docs/history/docs/history/docs/history/compiled-sess434-435-authority-campaign.md`.
