<!-- sess353-363: #94 SB-ATTRBIT closure, #92 races 6/7 verified, race-5 exposes #1→grant-freeze→dirty-withdraw cascade, #1 enforce built, #3 purge redo r… -->
# sess353-363 campaign: SB false-refusal closure, races 6/7, and the #1/#3/#4 foreign-replay-refusal cascade

One continuous ccloop c7ee71c6 arc, 0.13.1 → 0.14.3. Starts closing #94 (SB
idle-slice false refusal), verifies #92 races 6/7, then a race-5 mixed-death
run exposes that #1 (D-FOREIGN-REPLAY-UNGATED-IMAGES) blocking recovery
freezes victim-held grants outside the refused domain and forces dirty
withdraws — spawning the #1 enforcement-machinery build and two new ledger
defects (#3 grant-freeze, #4 umount-dirty-withdraw) whose fix churns through
two wrong designs before a GPT-approved CAW-layer purge redo.

## #94 — SB idle-slice false refusal: root + fix + close

`docs/history/94-attrbit-root-and-fix-0133.md`: root proven via
SBCLEAN-CONTENT-DIFF probe — `mkfs_mxfs` versionnum 0xB4A5 lacks
XFS_SB_VERSION_ATTRBIT even though features2 has ATTR2, so the first
xattr-bearing create anywhere (AppArmor security xattr on the rig) does a
lazy per-node uncoordinated whole-SB feature transition (`xfs_add_attr` +
`xfs_log_sb`). Victim's slice carried the transitioned SB image; content
compare correctly refused (fail closed) — this was correct behavior on a
malformed mkfs, not a DLM bug. GPT ruling: preset ATTRBIT in mkfs
(0xB4B5, matches stock mkfs.xfs), never mask versionnum in the classifier,
version-gate old-format cluster mounts. Also surfaced a NEW broader defect:
per-node divergent in-core `m_sb` + whole-SB logging means any peer SB txn
can overwrite another node's persistent non-counter SB changes — contained
by forbidding all runtime non-counter SB mutations in cluster mode
(attr/quota/log_incompat-LARP/growfs/label/NEEDSREPAIR) until a real
protocol exists. Landed 0.13.3.

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: 0.13.3 deployed
32/caw; `tests/sbclean_fence_idle.sh` PASS 2/2 — #94 CLOSED FIXED AND
VERIFIED. Two false test fails fixed en route (kernel was correct both
times): GUARD flags legitimately persist ~10s after the "foreign replay
complete" print (poll window must be ≤45s, not tighter); `caw_slotdump`
omits all-zero hb records after replay, so an absent row is the PASS
signal, not a gap. #95 (D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE)
ledgered as the broader defect from sess353's GPT ruling item 4 — 0.13.3
only closed the ATTRBIT arm.

## #92 races 6/7 — P225 mount barrier, monitor-blind knob, verified

`docs/history/race67-p225-barrier-collision.md`: both race
variants ran INVALID (74s/66s vs <40s cap). Mechanism: B's mount(2) does
not return quickly because its 10s join scan sees suspended A's frozen hb
timestamp, classifies A's slot as stale, and enters a 62s P225-SETTLE-VERIFY
mount barrier — the test script resumes A only at ~66s, past the real 64s
death threshold, so A gets fenced. Two traps found: (1) "fresh umount+remount
A first" (the sess349-era PREP_A advice) is WRONG — a fresh mount takes
root-ino PR, the only live lock on an idle fleet, making the barrier worse;
use long-idle A/B instead. (2) Even with zero live locks held by A, B's
mount still computed A's slot as held authority — P225-STALE-DEFERRED
apparently derives holder-ship from tombstoned lock records/lineage, not
live grants (open question at handoff).

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: GPT
RULE-5 ruling revises the "no kernel change" position — race 7 is
arithmetically impossible under `virsh suspend` because B's cycle-1 mount
always blocks in P225 SETTLE-VERIFY for exactly the death-threshold
duration, so A always crosses the fence line before a second cycle can
occur. Ruling: add a test-only `monitor_blind` knob (gates the peer HB scan
at a scan boundary with an acked generation; own-hb CAS/self-fence/conflict
relay stay live; 120s auto-clear = INVALID run) as a faithful realization of
a stretched monitor interval, keep the suspend variant only for race-6
corroboration. Landed 0.13.4. Result: blind CYCLES=1 and CYCLES=2 PASS,
suspend CYCLES=1 PASS. Two durable test-harness bugs fixed: `caw_slotdump`
zero-pads slot numbers ("hb[04]") but kernel logs "slot=4" — normalize with
`$((10#$BSLOT))`; VM journal clocks skew 1-2s from clyde, so an event can
timestamp before a same-instant `date -u` T0 and be permanently excluded
from `journalctl --since` — backdate T0 by 5s.

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md` (races 6/7
half): second-run verification completes — blind C1 2/2, blind C2 2/2,
suspend 2/2, races 6/7 fully closed.

## Race 5 mixed-death run exposes #1 → grant freeze → dirty withdraw

Same session, `docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`:
new `tests/clean_depart_mixed_death.sh` dirty-kills a victim under metadata
load while 4 peers clean-umount concurrently. Death/fence/recovery-claim all
correct, but replay is REFUSED (P227-FR-ATOMIC-SKIP, legacy blanket
atomic-skip) even though the shadow evaluator shows every token would have
been enforceable (P273-SHADOW-EVAL WOULD_APPLY=10 ENFORCEABLE=10) — i.e.
the only reason for the refusal is that #1's enforcement gate doesn't exist
yet. AG2 quarantines cluster-wide (containment works, no suicide) but the
victim's root-ino EX grant, outside the quarantined AG, stays frozen
forever — no release path. The 4 concurrent clean umounts wedge on that
same root-ino EX for ~5min, DLM times out (-110/ETIMEDOUT), and each does a
forced *dirty* withdraw (not a clean depart) even though the local FS state
was otherwise fine. End state: survivors alive but root-dir creates
livelock under an endless BAST-notify storm. Conclusion: #1 is the proven
blocker of ANY non-snlocal dirty-death recovery — a victim sharing dirs
with live peers will refuse, and refusal degrades the whole cluster, not
just the quarantined domain. New ledger candidates raised: the frozen-grant
scope defect and the forced dirty-withdraw defect. Test-script lesson:
over ssh, `A && nohup loop &` parses as `(A && loop) &` — the backgrounded
loop still holds the ssh channel open; use
`A || exit 1; setsid nohup loop </dev/null >/dev/null 2>&1 &` to actually
detach.

`docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md` +
`docs/rulings/cascade-dispositions-and-gate-order.md`:
fleet re-prepped clean on 0.13.4. GPT RULE-5 ruling on the cascade, in full:

- **Build order**: build the foreign-replay preflight + per-txn verdict
  cache + `foreign_replay_token_enforce` knob (default 0) NOW — one
  whole-txn verdict, shared by shadow eval and enforcement, zero side
  effects before preflight completes.
- **F2 domain-mode binds enforcement too**: on an `fua_disable=1` rig,
  `knob=1` is permitted only with an explicit coherence-only domain
  admission knob (never inferred from `fua_disable`), `proto_admitted>=4`,
  homogeneous fleet, `release_proof_enforce=1`, cluster-coordinated. Runs
  under that knob only count toward the coherence-only campaign, never
  toward stable-media/default-on qualification.
- **New defect (grant freeze, becomes #3
  D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356)**: policy = conservative
  closure. After fence + txn classification, build a closure of every
  resource named by refused images plus conservatively-associated inodes
  (ambiguous buffer→inode mapping puts the inode IN the closure). Then: (1)
  resources in the closure stay frozen, new waits get a distinct
  terminal-quarantine error, existing waits are cancelled the same way,
  only operator repair clears it; (2) successfully replayed resources
  regrant normally after replay+flush/epoch order; (3) resources provably
  OUTSIDE the closure with no outstanding recovery obligation get
  force-revoked from the dead owner (real recovery revocation with epoch
  advance/publish before peer regrant, never a fabricated release
  certificate). A dead owner alone is never sufficient reason to freeze.
- **New defect (dirty withdraw, becomes #4
  D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356)**: quarantine must not
  present as local DLM corruption to umount. DLM needs a distinct
  terminal-quarantine error instead of a 5-minute wait; umount must acquire
  root/teardown grants before its irreversible commit point; on that error
  pre-commit, abort the unmount and stay mounted degraded rather than
  withdraw; dirty withdraw is reserved for real corruption/membership
  loss/post-commit failure.
- **Final order**: preflight/cache/knob@0 → F2 domain admission → scoped
  dead-grant disposition + DLM fail-fast quarantine errors → umount
  escalation fix → knob=1 on rig (all predicates satisfied) → coherence-only
  capture campaign → stable-media/B2-B4 before any default-on.

Gate-build recon in the same note locates the shared evaluator
(`mxfs_shadow_eval_token`, xfs_log_recover.c ~2607), the admission
predicate (`mxfs_report_replay_authority`'s all_apply rollup), the class
enum (AG=1, SB=2, INODE=3), the decision site
(`xlog_recover_items_pass2` ~3104-3222), and confirms machinery already in
tree but not yet armed: `mxfs_target_cache_protected` (F2 domain knob),
`replay_gate_enforce` (fail-closed per-class bitmask gated on
F1/F3/F4_READY consts, all still 0), `release_proof_enforce=1`.

## #1 foreign-replay-token-enforce: build, review, verify, live-repro grant freeze

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: enforcement
machinery landed 0.14.0. Design decision: a SEPARATE
`foreign_replay_token_enforce` knob rather than reusing `replay_gate_enforce`
bits, because that setter fails closed on the still-unset F1/F3/F4_READY
consts and would make the ruled knob=1 campaign unreachable. Fail-closed
setter refuses arming when `fua_disable && !target_cache_protected` (F2) or
`!release_proof_enforce`. Evaluator config (`se->enforce_cfg`) is snapshotted
once at creation so a slice is never half-enforced. New P227-FR-ENFORCE-ADMIT
admit arm sits between snlocal-accept and sbclean-skip in
`xlog_recover_items_pass2` — admission is never a refusal path; any refusal
still fails the whole replay per existing sess233 semantics. Not
GPT-reviewed, not deployed.

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: RULE-5
review — **knob=0 board: GO**; **knob=1 campaign: NO-GO as landed**, with
stop-ships. Fixed and landed as 0.14.1: (1) attempt-local enforcement mode
(`l_mxfs_fr_enforce_mode`) set only by preflight, replacing global resampling
— the single OFF→ARMED transition point; (2) config serialization via
`DEFINE_MUTEX(mxfs_fr_cfg_lock)` plus guarded setters for `fua_disable` and
`target_cache_protected` that reject invalidating changes while the knob is
armed (an armed-but-invalid state now aborts retryably at preflight instead
of silently disabling enforcement); (3) explicit proto-demote logging when
`!m_mxfs_proto_admitted` (kept as blanket refusal, not abort, since a mixed
fleet is a real steady state, not an error); (4) admissibility taint became
a STRICT ALLOWLIST — only INODE items and the EFI/EFD/RUI-CUD_RT intent/done
set don't taint; dquot/quotaoff/icreate/iunlink/unknown all taint (knob=0
blanket-scan behavior deliberately left unchanged); (5) one-shot
fault-injection consume moved after successful preflight. Also recorded six
outstanding PROOF obligations (not code) required before any knob=1 rig
work: epoch anti-ABA on every release/reacquire, token epoch captured at
image-generation time, physical-buffer authority domain demonstrated per
enforceable class (inode-cluster buffers flagged as an aliasing risk),
in-slice replay order preservation, no release/regrant before admitted
replay completes, and an LSN-gate-replacement test matrix. Needs
`make clean` before deploy (multi-file .c+.h change).

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: 0.14.1
clean-built and deployed 32/caw. Board: 27 PASS, identical shape to the
0.13.4 baseline, zero P227-FR-ENFORCE-* markers at knob=0 — GO condition
met. (One `crash_consistency` FAIL→rerun-PASS flake noted as pre-existing
harness behavior seen 4x already that day, unrelated to 0.14.1, left
unledgered.) A knob=0 dirty-kill exercise reproduces the exact same blanket
refusal as sess356 (no behavior change, as expected) and gives a clean live
repro of the #3 grant-freeze defect: quarantine scoped to one AG, but the
victim's root-ino EX grant outside it freezes with no release path — a
`touch` on another node hangs in D-state all the way down through
`caw_wait_for_grant`, with no distinct terminal-quarantine error, just a
poll to DLM -110.

## #3/#4 fix: two wrong designs, then a GPT-approved CAW-layer redo

`docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: first #3 fix landed,
0.14.2 — a selective closure purge in `disklock.c` that scans the 65536-slot
`mxfs_disklock_record` table for ACTIVE records owned by the victim outside
the refused AG mask and CAS-zeroes them. Not reviewed, not deployed.

`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`: STOP-SHIP —
the sess361 purge targets the wrong table. `mxfs_disklock_write_grant` (the
only writer of `mxfs_disklock_record`) has ZERO callers, so that table is
always empty at runtime; the landed purge would log `purged=0 kept=0` and
fix nothing. Real grant state lives in the CAW slot table
(`struct mxfs_caw_lock_slot`, `holders_ex`/`pw`/... bitmasks) — sess360's
stuck waiter was polling a CAW slot, not a disklock record. Freeze mechanism
confirmed: death triggers `mxfs_dlm_caw_purge_dead_nodes_ex(KEEP_EX)`, which
retains the victim's EX/PW bits; the success-path release lives in
`mxfs_v5_dlm_recovery_complete`, but the refusal path has no equivalent
release — that gap IS defect #3. GPT RULE-5 review of the 0.14.2 design
carries forward as requirements for the redo: bind the classifier to the
platter mask (fail on mismatch), fail closed on unreadable gate mid-purge,
revalidate the gate before every destructive CAS (not amortized), and add a
re-purge path for missed cases pre-ship.

`docs/rulings/caw-selective-purge-redo.md`: GPT
conditional approval for the CAW-layer redo, target 0.14.3 (0.14.2's
disklock-record purge deleted). Key conditions: gate revalidation via a
fresh authoritative HB read before every destructive CAS, never amortized
or cached; separate `closure_gate_snapshot`/`closure_gate_revalidate` APIs
with no zero-sentinel bug (node 0 is a valid id); Phase 0 must compare the
HB image against the already-imported canonical outcome, not re-derive it;
exactly one victim per invocation, so a victim's gate can never authorize
stripping another node's bits; a tri-state classifier
(OUT_OF_CLOSURE / KEEP / abort-retry-required) that never lets an I/O error
silently classify as KEEP; gate failure aborts the whole purge as
retry-required, with completed CASes standing; reuse the existing full-purge
mutation discipline (field list, mode recompute, generation++, tombstone
rules) rather than forking new strip logic. Separately approves a
generalized G1/G2 "Shape 1" repair path (Shape 2 — 31 concurrent 64k-slot
import scans — REJECTED as an HB/eviction risk): trigger on any victim-owned
state blocking a live op (holder bits, waiters, yield_to, open_holders,
stale allocation-blocking slots), hooked into both wait/defer and
slot-allocation paths, attempting repair well before the timeout cascade,
using the same fresh-read/gate/CAS discipline as the publisher path, backed
by a leaseless gate proof obligation (terminal state must be irreversible
per {fs_gen,node,epoch,recov_gen}; a quarantined node's slot must not be
re-adoptable while its terminal descriptor stands — MUST be verified in code
and test, not assumed). Lists 7 hazards to close before ship, notably:
publisher-crash-after-publish leaving grants frozen forever with no
re-purge path, and proving no salvage/replay-authority path still reads an
out-of-closure slot's `ex_grant_epoch` before tombstoning.

## State at end of arc (sess363)

Ledger: #94 closed FIXED AND VERIFIED; #95 (SB per-node divergent whole-log)
and #3/#4 (grant-freeze / dirty-withdraw) open, #3 mid-redesign on a
GPT-approved CAW-purge shape targeting 0.14.3; #92 races 6/7 fully verified
closed; #1 enforcement machinery built and reviewed at knob=0 GO / knob=1
NO-GO pending #3/#4 landing plus the six proof obligations from
`docs/history/docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`.
