<!-- sess225-252: CAW grant-wait profiling, F4 registry, finobt-481(#21), open-protect-demote(#23), AG-lock livelock(-488), noino mass-wedge(#18) precurso… -->
# ccloop c7ee71c6 sess225-252: CAW grant-wait, F4 registry, finobt-481, open-protect-demote race, AG-lock livelock, noino mass-wedge

Direct predecessor of `docs/history/docs/history/compiled-d488-agdlm-livelock-campaign.md` (sess253-283). Five
overlapping threads on the same 32-node CAW rig, 0.11.480→0.11.489, each discovered
while closing the previous one.

## Perf baseline (sess225)

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`:
closure board 27/28 PASS on 0.11.480 (only `open_defects` policy red, 31 ledger
entries). Virgin-fs `crash_consistency` stackprof (32 nodes, 95651 ticks):
`caw_wait_for_grant` still 26.7% of all ticks — many sub-5ms nudge/poll cycles per
grant (52.6 slot READs/grant), invisible to a ">5ms wait = noise" probe. Release/
holder side only 1.73% (holders not stuck); AG-DLM alloc/journal serialization
refuted as the wall. Secondary: `md5sum`/open-cold-lookups 11.9%, unidentified.
Sampler trap: `mxfs_stackprof.py` writes output only at duration end — harvesting
early reads `nodes=0`.

## F4 obligation registry (sess227) — D-FOREIGN-REPLAY step 4

`docs/rulings/f4-obligation-registry.md`: GPT ruling on the
committed-never-submitted registry, shape directionally correct but not yet a hard
barrier. Required before enforcement: enumerable records with buffer identity
(not count-only — a fence-suppressed "success" can leave a buffer invisible to the
fork walk forever); an F4-own u64 generation (never reuse `b_mxfs_logged_seq`, a
log-call counter that doesn't advance for `XFS_BLI_ORDERED` dirty buffers); abort
cancel restricted to `xlog_is_shutdown` only (a later aborting txn must never
cancel an older committed obligation); ino-keyed registry safety depends on
induction that doesn't hold in telemetry-only/dynamic-enable mode (needs tenure
tagging or full drain-at-enable); close/check race needs linearized
close-new-opens → observe-zero → unlock; buffer eviction with an open obligation
must fail closed (orphan the record, never silently clear); retire condition is
"any non-suppressed FULL covering write at/after latest committed gen", not "abort
stales newer data". Landed telemetry-first (knob default 0) in 0.11.481:
descriptor-without-bp-hold (holding bp would wedge `xfs_buftarg_drain` at unmount
on a leak), per-buffer gen/owner/record under `b_sema`, per-mount 256-bucket hash +
spinlock, mempool-backed. Enforcement blocked on tenure tagging + close-race
linearization.

## finobt/inobt mismatch — D-FINOBT-IBT-FREE-MISMATCH-481 / #21

`docs/rulings/a2-ifree-shape-and-finobt-triage.md`: incident481
confirmed the cross-node ILOCK-over-CAW-poll convoy (12 nodes, kworker/inodegc);
post-recovery `chk_mxfs` found finobt/inobt divergence (2 AGs, +4 delta each,
AGI agrees with finobt) plus 10 leaked nlink=0 orphans. GPT ruling: land a2 first
(fleet-stability) — split-phase `xfs_inactive`/`xfs_ifree`, ZERO wait under ILOCK
(if a "nonblocking" CAW try can submit SCSI synchronously it isn't nonblocking
enough to run under ILOCK); on miss, drop ILOCK, acquire AG tenure, relock, run a
single `xfs_ifree_revalidate()` (identity/authority/eligibility/unlinked-list/AG
tenure/txn-state), restart. Wedge detector needed separately: replace fixed
patience with a progress-aware deadline (holder live/fenced/under-recovery,
replay/purge progress, grant gen, AIL-min movement) — 8×2s can shoot bounded
recovery. Triage plan for finobt-481's four candidate mechanisms (stale replay
clobber / authority race / asymmetric containment skip / sequential-tenure stale
cache): audit containment-branch semantics first (which txn items survive each
skip path), then correlate the "+4 per chunk" delta with skip probes.

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`:
mechanism found. Foreign-replay ATOMIC-SKIP (`P227-FR-ATOMIC-SKIP`, the #1
containment) skips any txn with an untagged image — since inode log items carry
no authority tokens, essentially every real victim txn is skipped (all 29 in
incident481). Skipping a *committed* txn is only safe if none of its buffers were
already written home by the victim's AIL before withdrawal. Here victims wrote
AGI+finobt home but not inobt, then withdrew → durable tear (finobt/AGI ahead of
inobt by the frees; freed inodes resurface as nlink=0 orphans on no bucket). AG5
(all-or-none writeback) stayed clean as the control. Code audit exonerated
`xfs_inode_uninit`/`mxfs_ifree_unlinked_preflight`; found a latent hole in
`pal/linux/xfs_buf_item_recover.c:1062` (stock LSN compare, no cross-node
discriminator) currently unreachable only because atomic-skip fires first — must
be fixed alongside full tokenization or partial-apply becomes the new tear
source. Root shared with #1 (missing tokenization) and #6 (recovery published
complete over the tear).

`docs/rulings/finobt481-atomic-skip-fail-closed.md`: GPT
endorsed the mechanism and ruled atomic-skip unsafe under mixture (all-or-none
writeback is safe; partial is not). Immediate fail-closed change: any committed
foreign txn that atomic-skips blocks `recovery_complete`/RW publication — no
join/mount, mark needs-repair, preserve evidence. Then: transaction-wide
tokenization/manifest for all replayable item types, authorize the transaction as
a unit (subset application forbidden); replace cross-node buffer LSN compare with
persistent predecessor/post per-object lineage (governs normal live writeback
too); then authoritative idempotent redo, retiring atomic-skip. Option (c)
("repair at skip", i.e. apply the remainder around the untagged item) rejected —
unsound until full txn-wide authority/coverage/lineage/CAS exists, at which point
it's just ordinary authoritative redo. #21 closure requires a 7-part evidence set
(partial-checkpoint fault matrix, recovery-crash idempotence, later-writer tests,
block-reuse tests, fsck invariants, 32-node withdrawal-storm repro, publication
assertions) — interim fail-closed is valid containment but doesn't itself close
#21.

`docs/history/21-gate-verified-and-mass-false-death-storm.md`: the #21
P0 fail-closed gate landed (0.11.482) and verified live —
`tests/incident474_load_kill.sh` killing test16 mid-rsync produced
`P227-FR-TORN-UNPUBLISHED` refusal on slot 10 and **zero**
`P163-RECOVERY-COMPLETE` fleet-wide; nothing published. But the frozen grants left
by the refusal cascaded: fleet cleanup blocked on them (`P-ACQ-STUCK` >110s) → 20
LIVE nodes' heartbeat sectors stopped advancing >62s → mass lease expiry → 18
slices refused-TORN-and-latched on survivors, and one LIVE node (test29, slot 14)
got `PREEMPT_ABORT_DONE`'d — its PR key preempted while still mounted, spewing
reservation-conflict errors. Victims never self-detected lease loss (no
re-registration, no self-fence). New defect recorded: mass false death of live
members under frozen-grant stall + missing victim self-detection + PR preempt
against a live member (cross-ref D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION, #13, #9).

## D-OPEN-PROTECT-DEMOTE-RACE-SPURIOUS-EIO / #23

`docs/rulings/open-protect-demote-race-fix-shape.md`:
`mxfs_dlm_open_protect` returned -EIO when a post-ride re-read saw mode==NL,
proven a benign race (BAST worker's terminal release landed 16us before the
re-read on a live published file). GPT ruling: treat live-NL as a cold-open
restart, never a synthetic -ESTALE for the live-NL arm (only for the tombstone
arm — O_CREAT|O_EXCL would -EEXIST on stale re-walk). Fix shape: snapshot release
generation, drop lock, wait for the *old* release epoch to fully complete, redo
acquisition, re-run full admission from scratch; bound livelock with a per-inode
admission gate honored by the release worker, never converting contention into
-EIO/-ESTALE.

`docs/rulings/relflush-arm-interleave-epoch-wait.md`:
narrowed interleave — the sess47 relflush-admit arm (`xfs_mxfs_dlm.c:28957`, no
mode check) admits an opener into the ms-long post-terminal-store tail
{NL, DEMOTING, RELFLUSH-set}. sess236's plain restart loop is insufficient:
laps burn in microseconds, instantly re-admitted by the same arm, so -EIO
persists. Correctness fix: epoch-aware completion wait — capture release
epoch/seq under the lock, drop ILOCK+holder, wait on `i_dlm_wait` for that exact
epoch completed/superseded (state-only check is ABA-vulnerable), then full
restart. RELFLUSH-clear alone is too early a completion signal (precedes device
flush + wire unlock).

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`: RULE-4
proof on 0.11.486 — A/B injection (ride delay + park after terminal store) landed
the exact interleave 60/60 times, all failures stamped arm=29008 (the relflush
arm), restarts burning ~30µs per lap before -EIO. Fix (0.11.487) verified:
removed bounded-restart -EIO exhaustion, added the epoch-aware completion wait
(30s capped slices, -EIO only at shutdown fence); same injection now 60/60 PASS,
all restarts converging at try=1.

`docs/history/23-closed-488-new-aglock-livelock-defect.md`: #23 CLOSED
FIXED AND VERIFIED on 0.11.488 (both race-exercise and gate-defer A/B PASS;
ledger 33 open). Same session's `rsync_paired` board cell then failed 0/32
NO_TERMINAL_RECORD: test30's rsync permanently livelocked in
`mxfs_ag_dlm_lock_bounded`, cycling all 25 AGs at 40×100ms each forever while all
31 peers sat idle with `holders=0 cached=0` — no live node believed it held any
AG. New AG-lock livelock defect (unledgered at session end).

## D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488

`docs/history/aglock-orphan-ondisk-evidence-slotdump.md`: built
`tools/caw_slotdump.c` (SG_IO READ(16)+FUA dump of the on-disk CAW slot table,
built by hand, deliberately not in the Makefile). On-disk truth during the
livelock: all 25 AGs held EX, zero waiter bits, test30 itself holding both ag=12
(untracked in its own sweep) and ag=13 (which its own sweep reported as
"peer-held"). Initial hypothesis: in-memory hold-state lost for on-disk-retained
EX grants — an untracked own bit read as a peer's hold. Named
`mxfs_ag_strand_repair` (sess20, designed for exactly this) as not firing despite
20+ minutes of BASTs.

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`: ledgered as
critical (34 open/81), then partially **refuted** its own hypothesis: test16's
ag=1 tracking was NOT lost (`cached=1`, demote ran, BAST-driven unlock succeeded,
local rsync legitimately re-acquired EX — normal cached hold awaiting a BAST that
never arrives). test13/ag=2 (`holders=0 cached=0 sched=0`) looked like a genuinely
different, possibly-true-orphan class. Root suspect narrowed to: the bounded
sweep (`mxfs_ag_dlm_lock_bounded`) submits no BASTs at all (`P265 submitted`
frozen) — cached holders that would release on a BAST never get one. Also found
`caw_unlock_gen_body`'s wall-clock unlock-retry deadline (5000ms) is armed only
for INODE+ICLUSTER; AG keeps a tight 100-retry cap with the -EIO swallowed by
`void mxfs_v5_dlm_ag_unlock` — a candidate for test13-class strands, separate
from the main mechanism.

`docs/rulings/aglock-livelock-sticky-revoke.md`: mechanism
PROVEN, superseding sess241/242's orphan/tracking-loss framing entirely — no
orphan, no tracking loss, zero "unlock exhausted" fleet-wide. Root: NOQUEUE
trylock exits `caw_lock` before waiter registration and before
`caw_send_bast_mcast`, so a nonblocking bounded sweep never registers a waiter
bit and never sends a BAST hint — lazily-cached holders (which release only on
BAST by design) never demote, and with all peers idle there is no other signal
source anywhere. GPT fix ruling: **sticky anonymous on-disk REVOKE** — a
resource-level `REVOKE_REQUESTED` bit in the slot, set (never cleared) by a
contender on NOQUEUE conflict, treated by the holder's poll thread like a BAST,
consumed only in the holder's release CAS or by fresh acquisition of an unowned
slot. Plain silent NOQUEUE probes (e.g. dialloc's first pass) stay silent;
`NOQUEUE|REQUEST_REVOKE` is for the bounded dirty-grow path only. Hint cadence:
immediate on first conflict, then wall-clock-jittered re-hint (not
iteration-count), deduped per (fs, resource, owner-gen). Holder demotes
unconditionally on a valid revoke — no idle-grace. Requires generation/ABA
binding (a delayed hint for owner-gen G must not demote owner G+1). Rejected
alternatives: transient waiter-bit registration (reopens the samenode
waiter-cancel race family, #15), idle decay (kills lazy-cache perf), and hint-only
without the sticky bit (UDP loss can be systematic — architecturally still
livelocks).

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`: sticky-revoke
implemented and shipped as 0.11.489 (sess244-248 had produced nothing — tree was
still stale 0.11.488). Slot gained a `revoke` byte (old on-disk images read
revoke=0, no proto-gen bump needed); new `MXFS_LKF_DEMAND` flag;
`__mxfs_ag_dlm_lock` gained a `demand` param, true *only* from
`mxfs_ag_dlm_lock_bounded` (first try + every ≥500ms wall-clock + jitter); poll
thread checks revoke before the `!slot.waiters` skip that was the actual hole.
**Not verified** — the livelock didn't recur in this session's runs, so the fix
path was never exercised (0 new P5G, 0 P280 fleet-wide).

Same session: mass reproduction of a *different*, pre-existing critical defect,
#18 D-NOINO-RELFENCE-AIL-FREEZE-474 — `rsync_paired` at 32 nodes FAILED
0/32 NO_TERMINAL_RECORD with 20 of 32 nodes wedged, one each, via
`P-NOINO-DRAIN-STUCK` (AIL min frozen across 8 bounded pushes) →
`P-NOINO-RELFENCE-WEDGE` → shutdown. Working (untested) hypothesis at session end:
the module-swap remount strands AG holder bits on the platter
(`P5N-AG-ORPHAN-NAK ... disk_held=0`), starving AIL drain.

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`: refuted the
sess249 handoff hypothesis on its own evidence — `disk_held=0` in the P5N log is
the *benign* branch (a multicast BAST hint for an AG the node provably does not
hold, pending >3s; it means someone else held it that long, not that the bit is
stranded). test8's own capture showed a **live** in-core holder
(`P12-AGBAST-RX ag=2 holders=1 ... page_ms=137446 holder=rsync`) blocked for 137s
while holding the AG EX. Refined hypothesis: AG EX holder threads block for
minutes while holding the AG (blocked on something else — another AG's CAW poll,
log space, or ILOCK, per the CLAUDE.md `xfs_bmap_btalloc` ILOCK-over-CAW-poll
design tension that never got the `xfs_create` fix) → peer AILs freeze → noino
relfence fail-closed shutdowns → shutdown nodes never release their AG EX →
cascades to 20/32. The post-mortem's 24/25 EX-held AGs are the *effect* of the
shutdowns, not the cause. Missing link: `P12-HOLDERTASK` (stack dump of a
blocked holder, exists in 0.11.489, capped 6/boot) fired during the wedge but was
never pulled before teardown — test-node journald is not persistent across
reboots. Lesson: always capture dmesg (`scripts/collect_incident_dmesg.sh`)
*before* fleet teardown.

## Aged platter unmountable — consequence of the #21 gate (sess252)

`docs/history/docs/history/docs/history/compiled-sess225-252-finobt481-openprotect-aglock-livelock.md`: attempting
to remount the aged, mass-crashed platter from the sess249/251 incident (no mkfs,
recovery-only) failed **permanently**: every one of the 31 dead slices' foreign
replay hit `P227-FR-ATOMIC-SKIP` → `P227-FR-TORN-UNPUBLISHED` refusal (every
victim txn contains an untagged inode image), and after 4 inline rounds the mount
aborted cluster-wide with "still requires recovery." `P273-SHADOW-EVAL` confirmed
these txns were `ENFORCEABLE_WOULD_APPLY=1` under #1 tokenization. **Production
consequence: the #21 interim fail-closed gate (0.11.482) converts any mass crash
into a permanently unmountable cluster** — site-wide crash with no recovery path.
This raises #1 (D-FOREIGN-REPLAY-UNGATED-IMAGES tokenization, sess175 rulings)
from a correctness fix to also being the sole unbrick path for basic post-crash
availability. Rig left with the platter still aged/dirty (nothing published or
zeroed — gate held); the #18 repro now needs a fresh mkfs since the aged-platter
angle is exhausted.

## Threads still open at sess252, carried into sess253+

- #1 tokenization (transaction-wide manifest, authoritative idempotent redo) —
  now blocks both correctness and availability.
- #18 noino-relfence mass wedge — mechanism refined to "live AG-EX holder blocked
  for minutes," root blocking edge (which resource) still unidentified; needs a
  fresh-fs repro with `P12-HOLDERTASK` stacks captured before any teardown.
- Sticky-revoke AG-livelock fix (0.11.489) shipped but never exercised under load.
- The sess234 mass-false-death storm (frozen-grant stall → 20-node false lease
  expiry → live-member PR preemption) recorded but not yet fixed.
- F4 obligation registry shipped telemetry-only; enforcement blocked on tenure
  tagging and close-race linearization.
