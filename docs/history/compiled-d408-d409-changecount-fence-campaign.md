<!-- sess408-409: D-408 foreign-replay changecount-reincarnation fix (0.26.9, closed), D-409 log-shutdown withdraw gap (0.26.10), rman pre-replay verify,… -->
D-408/D-409 arc: foreign-replay victim-inode changecount reincarnation, rman pre-replay verify,
and fence_live_node/hbpause hardening, ccloop c7ee71c6 sess408-409, 0.26.3 -> 0.26.11.

## rman pre-replay verify (sess408 part 1) `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md`
mutate2 rerun on 0.26.3+scst.5: host clean, VERDICT FAIL frc=2. (a) known D-FSWIDE-407: replayer test1
claimed+replayed slot22 2.6s after the FSWIDE terminal (fix queued as 0.26.4, unbuilt at this point).
(b) NEW: D-RMAN-MUTATED-SLICE-REPLAYED-BEFORE-VERIFY-408 (major) — mutated slot17's own slice replayed
to completion (616.13s) before prepurge verify caught the mutation (616.156s); per-record live check
only covered referenced manifest entries. Fix (0.26.4): mxfs_fr_enforce_preflight live-verifies every
manifest entry before xlog_recover (P-RMAN-POSTSEAL-MUTATION / P-RMAN-PREREPLAY-VERIFY), sets
rman_abort + l_mxfs_rman_mutated; -EIO promotes to an AUTHORITY_MUTATED FSWIDE terminal with nothing
applied. 0.26.4 also folded in sess407's unbuilt edits (prot_lock, structural foreign-clear CAS rule in
caw_slot_ex, caw_repair_slot refusal + epoch/lineage preservation, FSWIDE replay halt). Scratch-compiled
clean, then run as a full 9-arm matrix. CHANGELOG.md is stale and unmaintained — ledger + ccmemory are
the record, not it.

## sess408 close-out `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md`
0.26.4 (8/9 arms PASS) closed FIXED AND VERIFIED: D-HOST-SCST-PR-ABORT-SESSION-SHUTDOWN-PANIC-408,
D-RMAN-WRITER-GUARD-MONITOR-LAG-407, D-FSWIDE-TERMINAL-REPLAY-CONTINUES-407,
D-RMAN-MUTATED-SLICE-REPLAYED-BEFORE-VERIFY-408. base_shared FAILED and opened two new defects:
- D-AGIFC-SHARED-AG-DOUBLE-VICTIM-REPLAY-DIVERGENCE-408 (critical): AG6 AGI freecount(61) vs inobt(62)
  mismatch after clean unmount; didn't recur in 3 reruns; original mismatch lines were lost because
  `dmesg -C` in arm_prep clobbered them and test1 rebooted — harness now prints P-AGIFC-MISMATCH with
  context so this can't happen again.
- D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408 ("D-408", critical) — ROOT PROVEN:
  P77-FRINODE on the replayer showed a reincarnation's creation image (log_cc=2) SKIPPED vs the freed
  core (disk_cc=7) because `xfs_inode_init` restarts `di_changecount` at 1 (xfs_inode_util.c:379) while
  foreign replay orders inode items by changecount (xfs_inode_item_recover.c:413-432) — a low fresh
  changecount loses the ordering race against the stale freed core. 8 of 29 chk files that day showed a
  bucket -> mode=00 core (always bucket N == victim slot, AG N == victim home AG). GPT ruling: option A —
  carry the prior changecount forward across reincarnation. Design (0.26.5, not yet built):
  `i_mxfs_prev_changecount` field, `mxfs_iget_create_prev_changecount` (fresh cluster read at iget CREATE,
  TRYLOCK-stale per sess38/91), `xfs_inode_init` sets iversion = prev+1. Inode chunks are already kept in
  multi-node (xfs_ialloc.c, sess54), so no chunk-reinit reset needed. `tools/chk_mxfs.c` now ERRORs on a
  free-core bucket member — rebuild tools after this change.

fence_live_node.sh (D-498) needed `--prout-type=7` (WE-AR), fixed. Injection: victim withdraws in 3-8s
(P277-FENCED-SELF-WITHDRAW) but the harness FAILED verdict because "victim still reports an mxfs mount
after withdrawing" and survivors showed no recovery/release line for the victim's slot in-window. Open
question left for next session: does withdraw mean unmount, or only FS shutdown (P131-SELF-FENCE
shutdown=1 seen in churn mode)? — do not widen the assertion without a ruling; answered in sess409 below.
Process notes: evidence dirs defaulted to /tmp (FLN_OUT mktemp) and were lost on reboot — always pass
FLN_OUT=tests/evidence/...; VERSION can say 0.26.5 on disk while mxfs.ko in tree is still 0.26.4 — always
build before a rig run, never mid-run; GPT consult prompts about this material trip a cyber filter on
words panic/crash/kill/iptables — frame as kernel-lifecycle/FS engineering instead.

## D-408 fix completed, closed (sess409 first half) `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md` `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md`
sess408's landing only covered `xfs_iget_cache_miss`; sess409 completed it. Three reincarnation entry
points now continue di_changecount: cache-miss CREATE, `xfs_iget_recycle` (dominant path under churn;
takes max(platter, in-core i_version)), and CREATE cache-hit on a VFS-LIVE shell (P-CR63 rescue path).
`xfs_iget_cache_hit`/`xfs_iget_recycle` now take `tp` (+`create`). Build sequence: 0.26.5 both paths +
P77 mode/gen + ccprev counters; 0.26.6 AG-tenure stamp (`bp->b_tenure_id = pag->ag_dlm_tenure_id` at the
fresh read, skip the stale check when equal); 0.26.7 TRYLOCK fallback to `xfs_trans_buf_item_match`
(made non-static, declared in xfs_trans.h) + BLOCKING lock, per GPT review; 0.26.8 `ccprev_enable` A/B
knob (0 re-opens the defect, for measurement only); 0.26.9 adds the live-shell path — closure candidate.
Evidence: lap1b was CONTAMINATED by an orphaned prep forming the cluster mid-churn — fixed by making
d385 arm_prep exit 3 on prep rc!=0 and bounding tmpfile_churn_kill's outer prep at 335s (was exceeding
PREP_TIMEOUT 320s). lap2-4 PASS, chk clean including a new oracle `chk P-ALLOC-FREE-CORE` (also fixed
sess408's gen offset bug, 0x44->0x5c). lap2 p77 proves an actual reincarnation APPLY (disk_gen != log_gen,
log_cc 1546 > disk_cc 1539). lap3 median 84s traced to survivors waiting 63.6s for PR on the parent dir
behind the dead victim's PR bit until fence/purge — a recovery-window cost, not a defect in the fix.
A/B on the 0.26.8 knob: churn 200 iters ON 0.42-1.03s vs OFF 0.95-1.25s; rsync_paired ON 16-17s vs OFF
18s — the extra read costs nothing measurable (the sess408->409 rsync/churn deltas exist with the knob
OFF too, i.e. rig/host noise, not the fix).

Closed on 0.26.9 (sv 8F59A85088DBA6459479F55): D-FREPLAY-VICTIM-INODE-CORE-...-408 FIXED AND VERIFIED —
three reincarnation entries continuing di_changecount, AG-tenure stamp, tp-held check + blocking lock,
ccprev_enable knob for A/B only. Matrix 9/9 PASS (am=0, base_shared clean), board 26/27 — the one board
FAIL (crash_consistency 90/90) is pre-existing D-401, proven by A/B (fix ON 85 PASS/90 EXH vs OFF 86
FAIL/89 FAIL). D-AGIFC-408 stayed open, no recurrence across 4 base_shared runs. Recorded lesson: a lap
whose victim dies during the mkdir phase stalls every survivor ~64s on the parent dir's PR bit until
fence/purge — kill later (TCK_KILL_AFTER=12) when pace matters for a run.

D-498 fence_live_node: confirmed withdraw = `v5_resv_conflict_withdraw` -> `fence_notify_fn` -> forced FS
shutdown, mount persists (this answers sess408's open question above). Harness assertions replaced
accordingly: 'Shutting down' logged on victim, zero target conflicts from victim after withdraw+10s,
survivor recovery line within 95s.

## D-409: log-error shutdown skips DLM withdraw (sess409 second half) `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md`
fence_live_node churn arm on 0.26.9 found D-LOG-ERROR-SHUTDOWN-SKIPS-DLM-WITHDRAW-409 (critical): the
victim's first bounced write was a LOG write, so `xlog_force_shutdown` set the mount's shutdown bit
first ("shut down due to log error"); the later fence_notify's `xfs_do_force_shutdown` then returned
early because the mount was already shutting down, so `mxfs_dlm_shutdown_withdraw` was never queued — HB
kept bouncing 61s with 24 conflicts past withdraw+10s until peers' SLOT_TAKEOVER forced it. The idle arm
(no log write in flight at fence time) withdrew immediately, which is why this was missed earlier. Fix
(0.26.10, sv 7DDECF8B1ECC4C58B80B659): the first-shutdown branch of `xlog_force_shutdown` now calls
`mxfs_dlm_shutdown_withdraw` directly (new prototype in xfs_log.c) — otherwise ANY non-fence log I/O
error leaves a heartbeating dead member forever, not just fence-triggered ones.

Also confirmed: preempt-mode cluster-side non-recovery is the DESIGNED refusal from sess381, not a
defect — KEY_ABSENT_UNPROVEN (P-PR-FENCE-ABSENT), P304-FENCE-RETRY x41 with backoff, replayer refuses
every 30s because out-of-band key removal has no published fence evidence. Recorded against D-498, not
ledgered separately.

Harness rewrite: fence_live_node.sh gained `FLN_INJECT=hbpause` as the default injection — sets
`mxfs.dl_inject_hb_pause_ms=75000` on the victim via a one-shot knob in disklock.c (0.26.11, sv
259D50B87A89FDC665F591F; has a user-mode stub) so peers fence for real and replay actually happens.
Asserts: withdraw <=90s, 'Shutting down' logged, 0 post-withdraw target conflicts, slot recovered <=95s,
victim key gone at the end. `FLN_INJECT=preempt` keeps only the victim-side assertions; recovery is
reported but not counted (per the designed-refusal finding above). Prep now has an outer 335s bound
(orphan trap, same fix pattern as the d385/tmpfile_churn_kill bound above).

## sess409 close-out `docs/history/docs/history/docs/history/compiled-d408-d409-changecount-fence-campaign.md`
D-408 stays CLOSED FIXED AND VERIFIED (0.26.9 matrix 9/9, board 26/27=D-401, unchanged by later work).

D-409's fix (0.26.10) is in the tree but only proven via the `xfs_bwrite`/`xfs_do_force_shutdown` path —
fln2_pre_churn PASSED on 0.26.11, but the xlog-first-shutdown branch itself is still UNEXERCISED. Next
step specified: force a deterministic log-first shutdown via `XFS_ERRTAG_IODONE_IOERR` (xfs_log.c:1809)
on an idle node (pwrite+fsync), expect P-WITHDRAW-QUEUE within 1s + HB stop; if the errortag sysfs knob
is absent, add a TEST-ONLY knob to fail the next iclog completion instead.

D-498 hbpause injection works end-to-end: fln2_hb_churn contained the victim (withdraw +68s, shutdown
logged, 0 post-withdraw conflicts, key gone) but the replayer (test1) logged "foreign replay of slot 12
failed: error -117" — and the context was LOST because the next prep power-cycled the node before the VM
journal (non-persistent) could be read. Harness fixed to capture `replay_<node>.txt` and poll 12s for the
pause ack (the hb_idle arm's 3s poll had missed the ack). NEXT: rerun `fln3_hb_churn` (+ idle), read
replay_test1.txt — a genuine replay failure of a live-fenced slice would be a new CRITICAL ledger entry,
not a harness artifact.

Landed this arc: d385 arm_prep exit-3-on-prep-failure; tmpfile_churn_kill/fence_live_node 335s outer prep
bound; P77 sweep; `chk P-ALLOC-FREE-CORE` oracle; fence_live_node rewritten end-to-end (withdraw=shutdown
semantics, hbpause/preempt injection modes, replayer capture); TIMEOUT_BUDGETS.md sess409 section;
docs/foreign-replay-inode-ordering.md; awareness xfs.md + dlm.md updated.

## Cross-cutting lessons
- A reincarnated inode's changecount MUST be seeded from the prior (freed-core) value, never restarted
  at 1 — foreign replay's ordering-by-changecount otherwise silently discards the newer image. This now
  has three seed points (cache-miss, recycle, live-shell cache-hit); any future iget path added to XFS
  must also seed prev-changecount or D-408 reopens through a fourth door.
  - Symptom fingerprint: chk_mxfs bucket -> mode=00 core with bucket N == victim slot, AG N == victim
    home AG.
- rman pre-replay verify must live-check EVERY manifest entry, not just referenced ones — a mutated slot
  can finish replaying before its own mutation is ever noticed otherwise.
- "withdraw" in this codebase means forced FS shutdown with the mount left present, not unmount — don't
  assert unmount in a harness without checking this first.
- log-path shutdowns bypass fence_notify's own withdraw call; any future new shutdown entry point needs
  the same DLM-withdraw call inline, not assumed to arrive via the fence path.
- Evidence discipline: always pass FLN_OUT=tests/evidence/... (not the mktemp default) and never let
  dmesg -C run inside arm_prep without capturing first — both have already lost first-occurrence evidence
  once each in this arc.
