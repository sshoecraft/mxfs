<!-- sess50-62 (0.11.398-407): foreign-replay step-4a pre-mountfs recovery barrier — design, mount deadlock found, 0.11.401 GPT STOP-SHIP, 6 of 8 items fi… -->
Continues the D-FOREIGN-REPLAY-UNGATED-IMAGES campaign
(`docs/history/docs/history/compiled-foreign-replay-authority-tokens.md`) into step 4: stop a mounting
node from destroying a dead peer's replay manifest before that peer's journal
slice is actually replayed. The arc: prove the purge ordering is wrong (sess50),
design the fix (sess51-54), discover the fix itself deadlocks mount (sess55),
land a pre-mountfs barrier (sess56-57), get it STOP-SHIP'd by GPT with 8 required
items (sess57), then land 6 of 8 (sess58-62). Items 3 and 4 remain open; **no rig
cycle has run since 0.11.401** — the whole arc is design + code-proof, unmeasured.

## sess50 — where authority dies, and why (code facts + GPT ruling)

Three sites can destroy CAW authority before a dead peer's slice is replayed
`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md`:
1. Live foreign replay (`recovery_complete`) — order already correct, replay is
   durable before purge.
2. **Mount own-slot purge** (`v5_mount.c:1765`) — runs BEFORE `xfs_mountfs`/
   `xlog_recover`. A node crashes holding AG EX with a dirty slice, remounts,
   purges its own authority, then heartbeats (looking alive to peers) for
   10-30s before PASS-1 replay runs UNGATED — a peer can legitimately acquire
   and write those AGs first, and the stale replay then overwrites the peer's
   newer work.
3. **Mount cross-instance stale purge** (`v5_mount.c:1831`) — a non-advancing
   heartbeat over 5 HB intervals proves "probably dead", not "slice clean or
   replayed". Purging on this readmits the exact bug D2 (sess9) fixed: a
   durable dangling dirent from an unreplayed peer.

GPT ruling `docs/rulings/step4-ordering-and-two-new-defects.md`:
the copied manifest (a separate descriptor) can be dropped — the CAW lock table
itself is a sufficient manifest if checksummed/immutable-before-REPLAYED — but
durable recovery IDENTITY + COMPLETION state cannot be reduced away, because
after a total-cluster crash disk state cannot distinguish "purged after replay"
from "destroyed before replay". Binding invariant: authority facts stay durable,
immutable, conflict-blocking until a durable REPLAYED(V,R) state exists; purge
and conflicting grants may occur only after. Both mount-time purge paths (B, C)
CONFIRMED as real defects, must fix before enabling any gate.

## sess51 — the manifest is EX-only (removes the naive self-conflict blocker)

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md`: three line-verified
facts compose to avoid GPT's feared `RECOVERING_OLD_INCARNATION` self-conflict
bypass entirely — `ex_grant_epoch` is stamped only for EX/PW; XFS never requests
PW or CW; `node_held_mode` returns the strongest held mode. So if mount purges
its own stale PR/CR/CW bits but RETAINS EX/PW, every subsequent acquire on that
resource lands on a fast path (EX ≥ every mode XFS requests) — no CAS, no wait,
epoch preserved. Residual hazard (adopting a stale EX bit skips fresh-grant
AG-meta invalidation/FUA reread) is contained: buffer cache is empty at mount,
nobody could have written the resource while the EX bit blocked all peers, and
the window closes before `mxfs_init_all_perag_data`. Also: BASTs cannot steal
retained bits (both BAST paths gate on in-core tracking state that's empty for
untracked stale bits) — but the mount-time cross-instance purge (CLAIM C) still
cannot be simply deleted; the monitor's `check_dead` requires the heartbeat to
first ADVANCE, so an already-frozen-at-mount slot is unreachable by any other
cleaner — the purge must be rerouted, not removed. Design only, no code shipped.

## sess52 — GPT rejects the naive "adopt via ctx->held", forces CAS discipline

`docs/rulings/adopt-window-and-settle-race.md`: sess51's plan
("blanket-purge retained EX/PW at settle") is itself wrong — some retained EX
bits get legitimately re-adopted by the live mount's own `xlog_recover` in the
interim (FS believes it holds the resource cached), and a blanket purge at
settle strips the on-disk bit out from under it → publish-without-authority.
GPT mandates: `track_held()` in both fast paths must not be best-effort (failure
fails the acquisition); settle must be SERIALISED against acquire via CAS, not
a snapshot-then-clear (named race: acquire observes retained EX → settle sees
untracked, clears it → acquire's track_held then "succeeds" on a local fiction);
close the single_node bypass during adoption; do not restamp `ex_grant_epoch`
on adoption (only on a real new/conversion grant). Resolution: make adoption a
real CAS (bump generation, leave epoch alone) that races the settle purge on
the same slot — whichever wins is correct by construction, no rwlock needed
(a read lock held across the 8-minute acquire retry hardcap would hang settle).
0.11.398 ships the primitive only (`MXFS_CAW_PURGE_KEEP_EX`/`SKIP_TRACKED`
flags, `caw_purge_candidate`, `is_tracked_held`) — no callers yet, behavior
unchanged.

## sess53-54 — step-4a lands as 0.11.399, then gets a 3-part correction

`docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md`: items 1-4 of 6 ship —
`caw_adopt_retained()` wired into both fast paths; mount own-slot reclaim now
KEEPs EX/PW; step 6.5 RECORDS the stale mask instead of purging; new
`mxfs_v5_dlm_mount_settle()` factored into 3 phases. Load-bearing finding: the
death monitor never covers PRE-EXISTING frozen slots (`nt->live` requires the
heartbeat to first advance), so the deleted step-6.5 purge was the ONLY handler
for previous-crashed-instance locks — deferring it without adding settle phase
3 would recreate the exact stuck-orphan deadlock the removed purge's own
comment warned about.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.399, build clean):
GPT review refuted two of sess53's mechanisms before shipping phase 3 async:
(1) chained short dead-confirm probes AND-ed together are NOT equivalent to one
long window — `get_stale_slot_mask` re-baselines every call, so an advance
landing between call N's last poll and call N+1's baseline is invisible to
both, and a live-but-slow node gets falsely fenced; (2) a final node-id check
alone cannot catch A→inactive→A' (rebooted host, same UUID-derived id) — only
the heartbeat epoch (mount incarnation) distinguishes them. Fix:
`mxfs_disklock_confirm_dead_mask()` — ONE baseline (ts+epoch+node-id) held for
the whole window, identity re-checked EVERY sample, drops a candidate on any
ambiguity. Settle phase 3 becomes an async worker; cancellation honored only
while WAITING (never mid-fence — GPT: stopping between fence and dispatch
strands the slice with no elected replayer). Async does not weaken correctness:
phase 3 only STARTS recovery, replay is async either way, so a synchronous
form would only add RULE-0 cost (+62s every cold-restart mount) without
shortening exposure. Open item flagged, unverified: whether anything inside
`xfs_mountfs`/`xlog_recover` takes an AG DLM lock — if so, a mount could still
park on a dead peer's retained bits, since step 6.5 used to purge before
`xfs_mountfs` and now only records.

## sess55 — the open item WAS the bug: a real mount bootstrap deadlock

`docs/rulings/step4a-mount-ordering-inversion-gpt-ruling.md`: 0.11.399
DOES have blocking AG-lock calls inside `xfs_mountfs` (`xfs_free_extent`,
`xfs_dialloc`/`difree`, iunlink insert, `__mxfs_ag_dlm_lock` — none phase-guarded),
reachable from `xlog_recover_finish`/iunlink processing. Two failure modes:
(1) mount blocks on a frozen foreign slot until CAW's 120s timeout, `-ETIMEDOUT`
fails the mount, but the settle that would replay/release it runs only AFTER
`xfs_mountfs` returns — never reached; (2) at 32 nodes, a mount storm has every
node simultaneously holding its own retained EX/PW bits (kept through the whole
of `xfs_mountfs` per step-4a) AND heartbeating (so `holders_alive`→wait extends
to the 480s hardcap) — mutual block resolves only at the hardcap, ALL mounts
fail. Pre-4a this could not happen (step 6.5 purged foreign bits outright).
**No code shipped this session** — GPT ruled HOLD THE RIG RUN, rejected two
alternatives (strip PR/CR only: leaves the EX deadlock; re-entrant recovery
from inside the CAW wait: lock-order/recursion hazards) and mandated option D:
a synchronous pre-`xfs_mountfs` cluster-recovery barrier — confirm-dead→
fence→replay the WHOLE foreign cohort→flush→only then run per-slot purges
(cross-slice evidence rule: replaying slice A must not clear bits slice B's
gate still needs), with EX/PW cleared only after the whole cohort resolves.
Insertion seam identified: right after `xfs_log_mount()` returns in
`xfs/xfs_mount.c` — before any cluster lock is taken, since buffer-image
replay never routes through `mxfs_ag_dlm_lock`.

## sess56-57 — barrier lands as 0.11.401, GPT STOP-SHIPs it with 8 items

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.400, part 1):
DLM-side API split only — `v5_settle_resolve` (shared confirm/fence/mark-pending
core), `mxfs_v5_dlm_settle_own_slot`, `mxfs_v5_dlm_mount_recovery_cohort`
(barrier entry), `mxfs_v5_dlm_mount_cohort_complete` (deferred purge, run only
after the WHOLE cohort replays). Behavior still byte-identical to 0.11.399 —
call site not wired.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.401, part
2): `mxfs_dlm_mount_recovery_barrier(mp)` lands and is wired into
`xfs_mount.c` right after `xfs_log_mount()`'s error check. GPT's RULE-5 review
of the actual implementation found it RECREATES the deadlock plus 7 more
stop-ship items — **DO NOT BOARD**, no rig cycle spent:
- **6A (highest priority, real deadlock)**: fence-failure residue is deferred
  to post-`xfs_mountfs` retry, but `xfs_log_mount_finish` (inside `xfs_mountfs`)
  can block on exactly that unfenced residue — the retry that would unblock it
  never runs. Original deadlock restored.
- **6B**: a peer healthy at the barrier's snapshot can die DURING the 62s
  confirm window; its grants are never captured, can still block mount.
- **3**: publication is too early — the barrier zeros the dead peer's HB slot
  (declares it consumable) while recovered INTENTS are unprocessed, iunlink
  hasn't run, and the AGI sweep is only queued. Needs staged durable state
  (FENCED / IMAGES_REPLAYED / INTENTS_PENDING / CONSUMABLE).
- **4**: purging own retained bits before `xfs_log_mount_finish` is unproven
  safe — they may protect resources named by unfinished EFI/RUI/CUI/BUI/iunlink
  work; purge-then-reacquire is not atomic.
- **2/5**: the cached-view invalidator preserves individual dirty/pinned/IN_AIL
  buffers (correct) but then unconditionally clears the whole AG's
  `pag_dlm_cached`/lineage flags — a single preserved buffer means the AG must
  NOT be declared uncached.
- **6C**: cohort-complete must key off a real "fully recovered AND durably
  published" per-slot mask, not "anything replayed".
- **6D**: the completion sequence (purge→unregister→clear-pending→zero
  HB→beacon) has irreversible publish points with no failure checks.
- **6H**: cross-slice LSN comparability is unverified — ordinary XFS LSNs are
  cycle/block within ONE log; if slices' ranges overlap, replay could skip a
  newer image or clobber it with an older one.
Also flagged: `mxfs_blkdev_flush_epoch` is a no-op under `mxfs_fua_disable=1`
(default since sess94) — the barrier's durability claim silently doesn't hold
in the default config (this becomes item 1, fixed sess59).

## sess58-62 — the STOP-SHIP fix chain (6 of 8 items closed)

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.402):
6A's real shape corrected — not an infinite hang, each blocked acquire stalls
120s then `-ETIMEDOUT`s the mount (still a RULE-0 failure). Fixed: a read-only
`caw_footprint_scan` census + `mount_residue_blocking` check; if the residue
still owns anything after 5 bounded fence retries, the barrier fails the mount
immediately with a named cause instead of stalling minutes first. **New defect
found along the way**: `v5_pr_fence_dead_node` returned success (`true`) for
EVERY fence error except `-ESTALE` — including a READ-KEYS failure the function
itself logs as "cannot classify, skipping preempt" — so callers replayed a
node's journal slice believing it was fenced. Split into an rc-returning
variant; this defect is *why* the 6A residue path was reachable at all.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.403): item 1
— new `mxfs_blkdev_flush_durable()` that ALWAYS issues the device flush
(unlike `flush_epoch`, which is a coherency-only no-op under `fua_disable`),
wired into the barrier AND into the live foreign-replay path, which had the
identical hole and is the far more common trigger. Item 6D — both purge
functions (`caw_purge_dead_nodes_ex`, `disklock_purge_node`) were silently
swallowing per-slot read/write failures and reporting success-shaped counts;
worst case, `disklock_purge_node` could report "purged" while the
**heartbeat-zero broadcast itself failed to write** — the exact bit that tells
peers "slice replayed". Both now return honest failure counts;
`recovery_complete`'s 3-step sequence (CAW purge → device flush → HB purge)
now stops and blocks publication on the first failure, in that specific order
(purge-then-flush, not the reverse — flush-then-purge would survive a power
loss as "node looks alive, redo cleanly"; the shipped order fails as
recoverable, the reverse would fail as an unrecoverable wedge). Failed slices
get a retry duty bit and re-queue every 30s rather than stranding.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md` (0.11.404): item
2/5 — invalidator now returns a per-AG census of every buffer it had to
preserve; the pag lineage clear is gated on that census being zero, not just
holder state, closing the "declare uncached while an un-destaged buffer
survives" hole. Callers (`peer_joined_flush`, live replay, the barrier) all
now check and either retry (flush path) or refuse-and-defer (barrier, which
cannot force the log at that point since intents are unprocessed). **Item 6H
resolved as already-tracked, not new**: line-verified that inode recovery is
already gated on the mxfs-safe `di_changecount` comparator, but buffer/dquot
recovery still do a raw cross-slice `XFS_LSN_CMP` — this IS ledger #1
(D-FOREIGN-REPLAY-UNGATED-IMAGES), contained today by the untagged-skip +
ATOMIC-SKIP taint scan, fixed by campaign step 5, not a new defect.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md`
(0.11.405, partial): 6B turned out to be a correctness defect, not just an
availability gap — the heartbeat + `v5_lease_expire_cb` wiring starts BEFORE
`xfs_mountfs`, but `dead_node_notify_fn` (the slice-replay hook) is registered
AFTER. Old code fell through to a LEGACY IMMEDIATE PURGE whenever the hook was
absent: clears CAW authority AND zeros the dead node's HB sector — the
cluster-wide "replayed" broadcast — for a slice nobody replayed. Reachable on
every 32-node rig cycle where one node dies while another is still mounting.
Re-gated the legacy-purge fallback on slot ownership (`dead_slot >= 0`), not
hook presence: a journal slice may never be purged pre-replay regardless.
Deaths during the window are now deferred (recorded, not purged) rather than
immediately destroying the manifest. Full round-trip drain/dispatch mechanism
left for sess62.

`docs/history/docs/history/docs/history/compiled-step4a-mount-recovery-barrier-campaign.md`
(0.11.406-407): 6B completed — barrier step (c) becomes bounded ROUNDS (cap 4)
that fold newly-drained late deaths into the replay set each round, with
`cohort_complete` still called exactly ONCE after all rounds (the sess50
cross-slice evidence rule). Settle gained phase 3a to dispatch any deaths still
undrained after the barrier returns. **Item 6C exposed a SECOND shipped
defect**: `mxfs_xlog_recover_foreign_slice()` returns an error on failure and
BOTH callers (live path and the barrier) discarded it — a slice whose replay
FAILED was published exactly like one that succeeded, destroying the only
evidence that would trigger a redo. Both callers now check and refuse to
publish on failure. Also resolved: the "foreign shadow AIL" question from
sess57 — intents are deliberately SKIPPED during foreign replay and the shadow
AIL is a throwaway; `xlog_recover_finish` never runs for it, so the slice is
left dirty on purpose for the next claimant to replay fully. This directly
confirms item 3 (publication staging) is real, not hypothetical: the barrier
publishes a slot as consumable while that slice's intents/AGI-unlinked-inodes
are still unprocessed, and if nobody re-claims the slot, they're never
finished.

## State at end of cluster (sess62)

Fixed: 6A, 6B, 6C, 6H (resolved as tracked elsewhere), item 1, 2/5, 6D — 7 of
GPT's original 8 items, plus 2 additional shipped defects found en route
(fence-error misreported as success; foreign-replay failure discarded and
published as success). **Open: items 3 (publication staging redesign) and 4
(own-retained-bit purge timing, unproven safe before `xfs_log_mount_finish`)**
— the two GPT called "the big ones." Zero rig cycles since 0.11.401; everything
in this arc is code-proof only, unmeasured on the 32-node board.

## Recurring lessons

- Every "obvious" fix in this arc created a new deadlock or a new honesty gap:
  keep-EX (sess51) needed CAS adoption (sess52) needed a pre-mountfs barrier
  (sess55) which itself needed 8 more corrections (sess57) before two remained
  genuinely open. Iterating against GPT RULE-5 review caught each one before
  a rig cycle was spent — no fix in this whole arc was disproven on the rig,
  they were disproven by review.
- "Returns success" is not the same as "succeeded" — three separate functions
  (`caw_purge_dead_nodes_ex`, `disklock_purge_node`, `v5_pr_fence_dead_node`,
  and the foreign-replay call) all silently downgraded a real failure into a
  success-shaped return, and each one fed directly into a publish-without-proof
  defect. Purge/fence/replay honesty is a standing category to re-audit
  whenever a new call site is added to this machinery.
- A conservative individual-item preservation (skip a busy buffer) does not
  make the aggregate operation conservative — the invalidator correctly kept
  single buffers cached but then unconditionally cleared the whole AG's
  lineage anyway (item 2/5); always propagate a per-unit failure/incompleteness
  census up to whatever coarser-grained decision it gates.
- Durability and coherency are different properties with different default
  behavior: `mxfs_fua_disable=1` (the shipped default) makes the "flush" used
  by hot per-modify paths a coherency-only epoch bump with no device flush —
  correct for that use, silently wrong for a once-per-mount barrier that must
  survive a target power loss. Never reuse a hot-path primitive for a
  cold-path durability claim without checking what it actually does under the
  shipped defaults.
