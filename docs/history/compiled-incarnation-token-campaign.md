<!-- sess77-88: HB blind-write clobber fix, authority-token step5 scope refutation+5.1 ship, mount-incarnation-constant-zero found+landed+rig-verified. -->
# HB blind-write clobber, authority-token step 5, and mount-incarnation landing (sess77-88, ccloop c7ee71c6)

One continuous campaign: a fence-evidence defect (HB blind write) surfaced during
RULE-5 review of the foreign-replay authority-token gate, and fixing it exposed
that the mount-incarnation field the whole recovery/fence/token design depends on
was a hard-coded constant zero. Each session's fix unblocked the next.

## 1. HB own-slot blind write clobbers the recovery guard (sess77-79)

RULE-5 review of the fence-evidence channel (one-shot fence certificate,
intent-holder SPOF) found a second, worse defect while refuting four of the
reviewer's own premises: ``docs/rulings/hb-clobbers-guard-and-yield.md``.
`disklock_hb_fn()` did `memset+fill+blind write_sector_fua()` on its own slot —
no read, no CAS. A survivor's `RECOVERY_GUARD` written into a dying node's slot
gets overwritten by that node's next heartbeat 2s later, destroying the one-shot
fence certificate before it can be certified — permanently unreplayable slice,
and the victim never notices (self-fence only fires on fs_uuid change).

Ruling: CAS-guard every own-slot write against the last-written image
(`hb_img`/`hb_img_valid`); MISCOMPARE = someone is recovering us = self-fence.
Also ruled: yield-in-place as `GUARD{FENCING, owner=UNOWNED}`, never roll back to
ACTIVE; retry certify until success or self-fence, never give up; unsupported/
advisory PR rigs must refuse RW clustered mount at mount time.

Fix landed and measured: ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``.
Direct rig proof first (`tests/hb_guard_clobber_probe.sh`, O_DIRECT-only —
buffered reads return stale page-cache data and fake a PASS; `timestamp_ms` is
per-node boottime-relative, comparable only to itself, never cross-node) — guard
survived 0.8s, victim logged nothing. Fix (0.11.417): `hb_own_record()` /
`hb_cas_own_slot()` convert all three own-slot write sites (heartbeat, release,
withdraw) from blind writes to CAS-from-last-image; -EPERM (foreign) =
self-fence, -EAGAIN = cached image drift, resync and retry.

Verified on rig sess79 (0.11.418): ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``.
Guard held 12s, self-fence fired, withdraw refused to stamp over the guard.
Detection latency ~1.8s (one HB interval) — feeds into the still-open
D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION. Two more defects found and fixed same
session: (a) self-fence hardcoded one message text for four different trigger
reasons — 3 of 4 falsely told an operator their LUN was destroyed; fixed by
plumbing an explicit `enum mxfs_self_fence_reason` through both callback
typedefs so a new detector can't be added without an operator-facing
explanation. (b) `P49-STALEBASE` had 16 format specifiers and 15 args —
uninitialized va_arg garbage in a probe's own summary line; `-Wformat` only
surfaces on a full rebuild, and `grep -iE "error|warning"` hides which file —
the name is on the `note: in expansion of macro` line. A parallel investigation
(missing/false-negative dmesg greps, dangerous because they turn real failures
into PASSes) was run down to three refuted mechanisms and closed in sess80.

Ledger banking + evidence-integrity closure: ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``.
D-HB-BLIND-WRITE-CLOBBERS-RECOVERY-GUARD, D-SELF-FENCE-REPORTS-FALSE-CAUSE,
D-P49-STALEBASE-FORMAT-VAARG-GARBAGE all filed and closed FIXED AND VERIFIED
(sess79 had fixed two of these without ever adding ledger entries — root cause
of the missed-grep chase was cross-boot printk stamps: the probe self-fences
its victim, rebooting it, so a later grep's "earlier" timestamp belonged to a
different boot and was never comparable). Trap found chasing it: `dmesg -S` is
capped (returned a constant 164483 lines while the live log grew past 176000)
and a flood-probe that wraps the ring buffer destroys all prior evidence on
that node. New reusable tool: `tests/rig_dmesg_grep.sh` — exit 0=HIT/1=proven
MISS/2=ERROR, sentinel carries dmesg rc + line count + boot_id + uptime, so
absence is proven rather than inferred.

## 2. Foreign-replay authority-token step 5 scope: refuted, then landed narrower (sess80-82)

sess80 also re-scoped the stale ledger `next` field for
D-FOREIGN-REPLAY-UNGATED-IMAGES: steps 1-4 (atomic skip, token parse, ordering)
were already in the tree; the actual remaining gap is an exact-match
`{class,resource,epoch}` taint predicate to stop skipping fully-authorized
transactions.

RULE-5 review found that scope itself unsound: ``docs/rulings/step5-scope-is-wrong-false-apply.md``.
Two producer-side bugs meant an AG-exact-match gate would **apply** — not just
skip — records under the wrong authority: (A) buffers inside an AG but under
inode authority (dir/da-node/attr/symlink/bmbt) were mislabeled `class=AG`
purely by containing-AG, and (B) `pag_mxfs_grant_epoch` was written on acquire
but never cleared on release, so a released AG grant still stamped a live
(stale) epoch. Net effect: a genuinely inode-authorized survivor write could be
reverted by applying a stale AG-labeled record. v1 tokens ruled permanently
report-only — never trustworthy authority evidence. Landing order set as
6 independently-safe steps (5.0 report-only freeze, 5.1 grant-state lifecycle +
classification conjunction, 5.2 token v2, 5.3 AG-only apply, 5.4 inode
authority, 5.5 DQUOT/QUOTAOFF/ICREATE/SB, 5.6 optional envelope). Epoch
mismatch ruled = atomic skip + telemetry, not quarantine; quarantine reserved
for trust-breaking conditions (malformed token, owner/manifest inconsistency,
impossible epoch ordering).

Step 5.1 edit sites verified: ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``
— clear `pag_mxfs_grant_epoch` at the single `pag_dlm_demoting=true` site (the
release commit point, before any drain/unlock), and require `b_ops` allowlist
AND BLFT agreement AND nonzero epoch at the buf-item fill site.

Shipped and measured: ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``
(0.11.419). Producer-only, no replay behavior changed. New probe `P228-TOKCLASS`
measured the predicted false-APPLY exposure directly: 27.2% of 40960 sampled
authority tokens were mislabeled `class=AG` for buffers the AG grant didn't
authorize (dir blocks, da-nodes, and — the conflation case the ruling
specifically warned about — inode bmbt blocks classified as AG btrees by BLFT
alone). Grant-lifecycle clear had zero false-negative cost (noepoch=0 across
the sample). Confirmed on a real foreign-replay reproducer too
(`tests/foreign_replay_ab.sh`): a record the old rule would have shipped as
`class=1 res=26 epoch=1` now correctly downgrades to classless. Step 5.4 (inode
authority), needed to actually close the critical dir-image false-skip case,
remained undone.

## 3. Mount incarnation is a hard-coded constant zero (sess83)

Starting step 5.2 (token v2, "bind to victim slot + incarnation") required an
incarnation identifier that varies. It doesn't:
``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``.
Raw sector read of the live 32-node LUN's HB region (independent of the kernel
module) found all 31 live records at `epoch=0`; grep confirmed exactly one
write to `ctx->epoch` in the whole tree, `= 0` in the constructor, never
reassigned. This makes ~8 recovery/fence authority predicates vacuous by
construction: `hb_own_record()`'s foreign-incarnation branch unreachable, the
recovery descriptor's `victim_epoch` can't name which incarnation is being
recovered, ownership/prover-epoch checks degrade to node-id-only, and the
guard idiom `if (victim_epoch && …)` universally skips the check because every
epoch read off disk is 0 — a rejoined incarnation of the same node silently
adopts its own prior incarnation's recovery lease.

RULE-5 ruling on the fix: ``docs/rulings/incarnation-and-token-v2.md``.
Rejected the proposed `(timestamp<<16)|rand16` construction (16-bit collision
resistance is too weak against clock-stuck/VM-snapshot cases) in favor of an
opaque, nonzero, cryptographically random 64-bit value, generated before first
claim publication, equality-only (never ordering — a numerically lower
incarnation is not "safe to prefer"), immutable for the tenancy's life, never
reused after the tenancy is lost. Zero must become a hard "no valid published
incarnation" sentinel, never a wildcard, in one atomic protocol transition
under a proto_gen bump — never a mixed-version window with 0-as-wildcard live.
Token v2 shape fixed at 40B (version/class/flags/resource/grant_epoch/
owner_epoch/owner_slot/owner_node) with an explicit VALID/MIXED/INCOMPLETE/
WRITE_AUTH status field — NONE must not keep double-duty as both "no authority
required" and "capture failed". Provenance must be captured at dirty/join time
and snapshotted with the CIL image, never last-writer-wins (a final buffer
image can span several transactions/grants; differing contributing provenance
must merge to MIXED, not silently pick the newest).

## 4. Landing the nonzero incarnation (sess84-88)

Edit-site inventory: ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md``.
Blast radius confined to `dlm/disklock.c` + `dlm/v5_mount.c`. Generator: draw
via `mxfs_pal_get_random_bytes` until nonzero (bounded retry; the only real PAL
failure mode already zero-fills, so draw-until-nonzero is itself the fail-closed
detector — no time fallback). Every optional-epoch idiom
(`if (victim_epoch && …)`) becomes a required nonzero-on-both-sides equality
helper. Identified the activation hazard up front: an epoch-change detector at
disklock.c:952 had never fired (since `last_epoch` was always 0) and, once
live, fires exactly when a node crashes and reclaims its own slot inside the
62s dead window — the rejoin case — which without explicit handling would lay
a recovery guard over a live rejoined node and shoot it via the next
`hb_cas_own_slot` MISCOMPARE.

Landing proceeded over three sessions, explicitly marked DO NOT DEPLOY at each
uncommitted midpoint until publication+validation could activate atomically
with the proto_gen bump:

- ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md`` —
  established the load-bearing proof that unblocked the whole design: the
  journal slice is slot-indexed, never incarnation-indexed, and claim pass-1
  own-stamp reclaim matches on `node_id` only (never add an epoch test there —
  doing so would push every rebooted node onto a fresh-claim path that
  silently abandons its own journal slice). Landed the generator, the
  `inc_valid`/`inc_eq` helpers, and 13 predicate-substitution groups. Left
  outstanding: `recovery_begin` still only warned and adopted the sector's
  epoch on mismatch instead of treating it as supersession; the pending-marker
  bug (the epoch-change path adopted the successor's epoch B *before* firing
  the death, so the pending marker would have named the live successor as
  victim, matching it under the new required-match rule).
- ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md`` —
  fixed the pending-marker bug and a sibling: the auto-monitor re-arm clobbered
  `slot_node_id[]` with the successor's id before the epoch-change arm read it,
  so the death would have been declared against the wrong node. Introduced
  `MXFS_RECOVERY_SUPERSEDED` (-EREMCHG) as a named outcome distinct from
  FENCEFAIL (which retries and would livelock against a now-live node), and
  `P237-SLOT-REOCCUPIED` to suppress a second death declaration when the
  pending marker already names the exact victim. Also fixed: completed
  recovery left `node_track[].last_epoch` pinned to the departed incarnation,
  causing a spurious second death for the next occupant.
- ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md`` —
  code-complete, builds clean, 0.11.420, `MXFS_PROTO_GEN` 3. Deliberate
  divergence from the sess86 plan recorded here: the lease-path callback must
  pass epoch 0 (unobserved), not resolve one via a `node_epoch()` accessor —
  that accessor read "who holds this slot now," which is the same category
  error the whole campaign removes; it was implemented then deleted in the
  same session. 0 is also the true answer at every site that consumes it,
  since `v5_start_slice_recovery` only reaches the marker when the monitor
  itself never observed the incarnation stop.
- ``docs/history/docs/history/docs/history/compiled-incarnation-token-campaign.md`` —
  deployed and measured on the 32-node rig. 32/32 live incarnations nonzero and
  distinct (vs sess83's `[0]`); a killed node's exact pre-kill incarnation
  propagated verbatim into `P163-RECOVERY-PENDING` on all 31 survivors and into
  the durable recovery descriptor; incarnation changed across remount on the
  same slot (proving it identifies the tenancy, not the node); zero
  `P237-RECOV-INC-MISMATCH` / `P237-PENDING-REARMED` / `P237-COMPLETE-REARMED`
  in steady state. Deploy trap re-hit: `make clean` also removes
  `tools/mkfs_mxfs`/`tools/chk_mxfs` and `make modules` does not rebuild them —
  doubly dangerous here since a stale mkfs binary stamps the old proto_gen and
  formats a volume the new code refuses to mount; always `make tools` after
  `make clean`. `tests/hb_slots.sh` was rewritten — it computed age from
  per-node-boottime `timestamp_ms` against wall-clock now and reported "0 live
  nodes" on a fully healthy 32-node cluster; fixed to sample twice under
  O_DIRECT and check for advance. New instrument:
  `tests/incarnation_death_probe.sh`, which asserts the logged death epoch
  equals the pre-kill on-disk epoch exactly (distinguishing zero-epoch defect,
  fabricated/mismatched epoch, and wrong-node failures).

  Still owed at session end: the full 32/caw regression board on the
  proto_gen-3 build (never run), and rig exercise of the
  `P237-RECOV-SUPERSEDED`/`P237-COMPLETE-SUPERSEDED`/`P237-SLOT-REOCCUPIED`
  arms specifically — sess88's rejoin happened after recovery had already
  completed and zeroed the slot, so the supersession code path (a victim
  reclaiming its slot *while* recovery is still pending) has never executed.

## Recurring failure modes across this campaign

- **Blind writes to shared state are the default bug shape here**: own-slot HB
  write (sess77-78), pending-marker epoch (sess85), successor node_id in the
  monitor re-arm (sess86) — each was "adopt/overwrite the latest read value"
  where the fix was always "compare against the specific value you meant."
- **Optional/zero-as-wildcard predicates hide correctness gaps.** `if (x && …)`
  guards silently no-op when the real value is legitimately absent (epoch) —
  found identically in the token gate (sess81) and the incarnation predicates
  (sess83-85).
- **O_DIRECT vs buffered reads and per-node-relative timestamps are a standing
  trap** for every rig probe touching the HB region (sess78, sess88) — a
  buffered read or a wall-clock comparison against boottime silently reports
  the opposite of reality.
- **A fix is not FIXED AND VERIFIED until rig-measured**, not just built
  (explicit DO NOT DEPLOY markers sess85-87) — and even rig-measured, an
  un-exercised code path (SUPERSEDED arm, sess88) stays open.
- **`make clean` deletes `tools/` and `make modules` does not restore it**
  (hit twice: sess79, sess88) — always `make tools` after `make clean`.
