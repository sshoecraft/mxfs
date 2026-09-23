<!-- sess419-421: TCP authority-ledger steps 1-2 landed+spec-frozen-step3, mount-recovery-barrier GPT rulings, intent/done census, purge/recov-advance ver… -->
# TCP authority ledger + mount-recovery-barrier campaign (sess419-421, 2026-08-28)

Continuation of `docs/history/docs/history/compiled-sess418-tcp-durable-authority.md`. Central thread: TCP transport lacks
CAW's durable-image grant record, so a remaster/replay can observe stale authority; the fix is
a durable TCP authority ledger built in three steps, landed alongside a mount-recovery-barrier
hardening pass and a purge/intent-census safety net. All work UNBUILT-as-.ko at each session end
per the unkillable-wedge rule/the derived-budget rule (fleet trailed the tree; never rebuild `mxfs.ko` while a rig chain is live).

## sess419 (05:00Z-)

D-0286 departure-race harness bug found and fixed: fleet `dead_timeout_ms=0` gives a CAW dead
window of 31x2s=62s, but the harness only waited 45s, so p1 read as a false FAIL. Fix: derive
harness grace from the observer's `dead_timeout_ms` (+12s) — a the derived-budget rule instance (derive from
measured behavior, not a round number). After the fix: p1 13/13 PASS, p2 PASS. Reachability
analysis proved race-points 3/4 are inside the TCP-only GOODBYE block and point 5 is unreachable
on every transport (a clean unmount always defers slot release via Arm C and frees the ctx
first) — harness SKIPs them rather than chasing unreachable coverage. Full CAW board 28/28 clean.
`docs/history/docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

Landed: 0.29.1 `foreign_replay_token_enforce` setter refuses `icluster_dlm=1` (gate item 2,
verified). 0.29.2 D-0133 SB-mutation gate: `mxfs_sb_mutation_refuse()` at every runtime
non-counter whole-SB producer (only `-o sunit/swidth` reachable on the shipped `.ko`; ioctl
surface + quota excluded by Kbuild, LARP needs DEBUG) plus `purge_cas_zero` -EOPNOTSUPP
fail-close (P235-PURGE-NOCAW). 0.29.3 D-PURGE-NONATOMIC injectors per the GPT ruling below:
disklock `dbg_purge_hook` points 1/2/3, `dbg_purge_pause_ms`/`dbg_purge_refreeze=1|2` (reason
DBG_INJECTED=7), `dbg_purge_victim`. D-CROSSNODE-OPEN-UNLINK item 2 answered from code:
`mxfs_unclaimed_bucket_scan` covers a clean departure but is armed only at mount settle /
recovery batch. D-MOUNT-WINDOW items 3/4 flagged as still open before any rig cycle.
`docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

GPT ruling on D-PURGE-NONATOMIC-PUBLICATION verification design: concurrent-purger test =
one-shot trigger on a non-owner while the owner is paused mid-scan, expecting phase-0 refusal
(-EBUSY, P234-PURGE-FROZEN) with zero non-owner writes — bypassing phase 0 is not the zero-defect bar
evidence. Descriptor-change arms need an owner-side one-shot injector through the *real*
`publish_refusal` path, two required modes (2A FIRST_MIDSCAN_REREAD -> P234-PURGE-REFROZE-MIDSCAN
scan-stops/HB-not-zeroed; 2B PRE_FINAL_HB_GATE -> P235-PURGE-REFROZE on the exact HB image, no HB
CAS) — 2A is not a substitute for 2B, that was the second historical hole. Two stop-ships: the
-EOPNOTSUPP plain-write fallback in `purge_cas_zero` must never be reachable on a shared LUN
(CAW-unavailable must make the purge INCOMPLETE, never publish); record-zero CAWs must be
durably ordered before the HB-zero publication (FUA or an explicit flush between them).
`docs/rulings/purge-nonatomic-verification-design.md`

Operational trap (rig): `run.sh`'s `tcp` board condition is wired to a LIO tcm_loop rig
(`/dev/sda` as a free LUN) that no longer exists on the current fleet — the fleet is now the
dm-multipath rig, so `./run.sh 32 tcp prep_cluster` dies in `prep_fs` because `/dev/sda` is
claimed by `dm-1`. To exercise the TCP DLM transport on the current fleet:
`MXFS_DEV=/dev/mapper/mpatha MXFS_CRIT=/src/mxfs/criteria.tcpmp.json ./run.sh 32 tcp prep_cluster`
— the separate `MXFS_CRIT` file keeps results off the primary board (cells key on `<N>/<dlm>`
with no rig dimension, so running the same condition against a different rig in place would
silently overwrite the column). The transport gate (`force_transport` sysfs param) is satisfied
either way. [[trap-32-tcp-condition-device-is-xml-sda-use-mxfs-dev-mpatha-and-mxfs-crit]]

## sess420 (~06:10-07:50Z)

0.30.0 landed: TCP token plumbing, tcp-authority-ledger step 1. `v5_tcp_grant_result_fill()`
fills `mxfs_grant_result` after every successful TCP `mxfs_dlm_lock*` across the 7 lock arms
(no TCP convert path exists). Token = master-minted `grant_gen`; `grant_epoch=gen`;
`lineage=(master<<32)|gen`; status semantics mirror `caw_grant_result_fill`
(WRITE_EPOCH/WRITE_ZERO_EPOCH/NONWRITE_MODE); `reaffirm=0` since a TCP fill is always
first-hand from the response. Known limitation carried forward: `gen` is u32, per-master,
restarts at 1 on master restart, so `{master,gen}` is unique only within one master
incarnation — step 3 needs `{authority_epoch, grant_seq64}`.
`docs/history/docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

0.31.0 landed: D-RECOV-ADVANCE-UNBOUNDED-RETRY bounded/classified completion ladder
(`recovery_complete2` typed outcomes, `v5_complete_classify`, `relinquish_slot`, fail-stop on
FATAL, skip-replay past IMAGES_REPLAYED, `recov_complete_inject` knob).
`docs/history/docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

GPT ruling on the bounded-retry design: the latch-only shape (my proposed A/B/C) converts an
infinite retry into a *permanent in-memory stranded recovery* while the node stays the
positional elected owner — must couple to supersession, durable decline, or fail-stop
withdrawal. SHIP option (ii): after a successful per-slot relinquish (exact freshly-read
expected image, never blind), fail-stop the whole mount (not RO), withdraw heartbeat/election
eligibility so the next-lowest survivor claims the descriptor; relinquish failure takes the same
withdrawn path. Same-owner -EBUSY is an invariant only if every auth-covered field is immutable
while held; classify by typed site/reason, never errno alone. Eight missing failure classes
enumerated (committed-but-reported-failed needs re-read+stage classification; -ENOENT means
"published elsewhere" only for a verified well-formed record; TAKEOVER cancels only the current
recovery identity, never the whole victim epoch; -EPERM is not inherently terminal; a purge
failure may have committed, so never publish GRANTS_RELEASED without durable proof; etc).
Backoff: exponential capped with jitter 5/10/20/40s, deadline anchored on a durable event so a
restart can't reset it. Five distinct outcomes replace an overloaded -ECANCELED: PUBLISHED /
SUPERSEDED / RETRY / FATAL_INVARIANT / FATAL_WITHDRAW.
`docs/rulings/recov-advance-bounded-retry-design.md`

GPT ruling on the mount-recovery barrier (D-MOUNT-WINDOW items 3/4/6C): NOT rig-ready, two
stop-ships. Item 3: a slot may reach GRANTS_RELEASED/heartbeat-zero only if
`IMAGES_REPLAYED && (OBLIGATIONS_DONE || enforced QUARANTINED)`; until
D-FOREIGN-SLICE-INTENTS-ABANDONED supplies obligation completion, the acceptable interim
behavior is FAIL-BEFORE-PURGE. Canonical durable order: FENCED -> IMAGES_REPLAYED ->
OBLIGATIONS_DONE/QUARANTINED -> authority purge+flush -> GRANTS_RELEASED -> heartbeat zero; no
alternate path may set GRANTS_RELEASED during barrier step (c). Item 4: 0/91 pass-1 observations
is not itself a safety invariant — closure requires the fresh claim provably inherit no
authority and `settle_own_slot` perform no destructive purge on the unproven pass-1 path (move
any remaining destructive purge to after `xfs_log_mount_finish` + obligation completion). Late-
death double recovery needs one durable descriptor keyed by victim slot+incarnation, one
linearizable execution-lease winner every survivor consults (never a second election), idempotent
CAS transitions. The proposed window-arm test does not necessarily exercise late-death folding
(timing races) — use a deterministic hold/faultpoint (pause after mphase armed, kill B, hold
until B confirmed dead and durable, release) instead of timed kills.
`docs/rulings/mount-barrier-items-3-4-6c-window-arm.md`

End state: 8-chain rig queue (token build first: token verify -> rman 9-arm matrix -> nosurv ->
zeroinc -> radv x3 -> fixups -> radv_takeover). NEXT off-rig, in order: (1) intent/done census +
INTENTS_UNDISCHARGED refusal — `xfs_log_recover.c` was skipping every intent/done
(P226-UNTRUSTED-INTENT-SKIP) and still publishing the slice; track by id per foreign replay,
refuse via `mxfs_freplay_publish_refusal` on leftover intents. (2) `settle_own_slot`: refuse
purge when `!slice_adopted`. (3) barrier hold knob + window/control death-verify harness. (4)
tcp-authority-ledger step 2 once step 1 is rig-proven.
`docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

## sess421 (2026-08-28)

Rig: s419 master board on 0.29.3 held 28/28 PASS + open_defects POLICY; `vergate2` mixed_build
rerun FAILED again with mount ENOTCONN + `umount: Input/output error` on test32, escalated to a
test32 root-fs health question (rig-runner probe dispatched, not yet an MXFS defect). s420 token
chain: 0.31.0 built (sv 8C78C9DB), `tcp_token_plumbing_verify` PASS (noepoch/durnoep 0 on
test1-4, 32/tcp) — **tcp-authority-ledger step 1 is rig-proven.**

0.32.0 landed (the sess420 NEXT item 1): `xfs/xfs_mxfs_icensus.{c,h}` intent/done census hooked
into `xlog_do_recover` (P226 site) and a `xfs_log.c` terminal predicate
P226-FR-INTENTS-UNDISCHARGED, wired to new reason 6 `MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED` /
wire code 8 `MXFS_RECOV_REFUSAL_INTENTS_UNDISCHARGED`. `settle_own_slot` gained
P226-SETTLE-PASS1-NOPURGE (refuses purge when `!slice_adopted`, sess420 NEXT item 2) and a
P226-SETTLE-FRESH-LEFTOVER anomaly line. Added `mxfs.dbg_barrier_hold_ms` +
`mxfs_v5_dlm_mount_peek_late_deaths` (sess420 NEXT item 3). 10 the ledger-date rule UNKNOWN ledger date holes
resolved from stated provenance (validator: 144 OK).
`docs/history/docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

0.33.0 landed: tcp-authority-ledger **step 2**. `include/mxfs/mxfs_tauth.h` freezes the on-disk
layout (128B entry; 4KiB page = 128B hdr + 31 entries; 65536 slots -> 2115 pages, 2 copies + 2
header copies = 16.5MiB region), `dlm/tauth_store.{c,h}` (I/O-free pure helpers, region CRC
wraps around the field to avoid a 4KiB stack copy), envelope flag `F_TAUTH=0x4` +
`tauth_offset/size` + **PROTO_GEN bumped to 8** (every node must run 0.33.0+ and every volume
must be re-mkfs'd — prep does this). mkfs writes copy A of every page as committed EMPTY seq 1
(full coverage), copy B zero. `chk` gained `-U` gate + `regions[6]`. `v5_mount` plumbs
`tauth_offset/size` into opts/ctx with no consumer yet. `tests/tauth` 21/21 PASS. Test-design
lesson banked: a torn write whose partial range happens to contain every changed byte is
byte-identical to a full write and validates — tear tests must change bytes beyond the tear
window to be meaningful. `docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`

GPT rulings, tcp-authority-ledger **step 3** (master-side ledger) — SPEC FROZEN. Page-aligned
mastership (`slot = hash%65536`, `page = slot/31`, `master = active_nodes[page % N]`) approved
but must be fenced across membership transitions: revoke the old ownership generation, drain/
storage-fence the old node, only then let the new master reload both copies; every pending op
carries the page-ownership/membership generation, rechecked before I/O and before delivery.
`authority_epoch` must be a non-reusable writer generation `{persistent membership epoch,
page_master_node, page_master_inc}`; per-page `grant_seq_next` in the checksummed page header,
distinct per grant, exhaustion fails closed. Grant path needs an explicit
`PENDING_DURABLE_GRANT` table state (blocks other transitions, not yet returned/sent); failure
outcomes: proven-not-committed -> cancel+deny, UNCERTAIN -> poison the page and reconcile from
both copies before any further op (never roll an uncertain ACTIVE back to FREE in memory).
Release requires an ACK: validate `{node, inc, full grant_id}`, commit one page transition, then
deliver successor grants + RELEASE_ACK; releaser keeps pending-release state until ACK. Owner
incarnation goes on LOCK_REQ; full `grant_id` on GRANT/RELEASE/ACK/upgrade/reaffirm. ACTIVE
records found on page load must always be honored (ledger-backed blocker import) — never cleared
because the epoch is old or the table was purged; blockers must survive a membership-change
table purge. Multi-holder layout (ruling 2, frozen): 64-bit PR-holder slot bitmap + one explicit
EX/PW holder `{node, inc, grant_id}` + resource lineage + per-page `grant_seq_next`; a PR release
clears its bit only if lineage, the *current* HB row `{node_id, incarnation}` (must be carried in
the message, never inferred from the HB row), and the current lock-service epoch all match —
mismatch leaves the bitmap untouched, cleanup is recovery's job. Fail-closed on: seq exhaustion,
holder-capacity, slot collision, no valid copy, inconsistent duplicates, unreconcilable
uncertain write, unsupported version. `docs/rulings/tauth-step3-master-ledger-design.md`

End state: 0.33.0 in tree, unbuilt. Implementation plan for step 3, in order: 3a page-aligned
mastership in `mxfs_dlm_resource_master` (`dlm.c:2840`) + ownership generation; 3b wire-protocol
additions (`lock_req` += sender_inc/sender_slot/req_id; `lock_resp` += authority_epoch/
grant_seq64/lineage; `lock_release` += grant_id + sender inc/slot; new
`MXFS_MSG_LOCK_RELEASE_ACK`, `MXFS_LSTATE_PENDING_DURABLE`, `MXFS_ERR_LEDGER`; refactor both the
v5 and legacy dispatchers to take the message struct); 3c `dlm/tauth_ledger.{c,h}` (page cache +
per-page mutex + allocators + poison + gen check) opened from `mxfs_v5_dlm_init`'s TCP branch;
3d/3e grant and release call sites go through PENDING_DURABLE-then-commit-then-deliver and
ACK'd release respectively; 3f blocker import; 3g the fail-closed list. Also still owed: the
late-death serialization audit (barrier ruling item 3) and D-RECOV-ADVANCE residuals (durable
decline mask, pre-lease wait audit).
`docs/history/docs/history/compiled-sess419-421-tcp-authority-ledger-mount-barrier.md`
