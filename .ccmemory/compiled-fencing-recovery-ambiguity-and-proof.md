---
name: compiled-fencing-recovery-ambiguity-and-proof
description: Compiled: PRESENT-key ambiguity, the fail-fast recovery-blocked gate, and the three-operations ruling for SCSI-PR fencing/disklock recovery
metadata:
  type: project
tags: [compiled, fencing, scsipr, disklock, dlm, recovery, design]
---

ic Recovery from an ambiguous or contested SCSI-PR fence/registration state — what a PRESENT key proves, how a waiter is kept from hanging on an unproven fence, and what "resume this attempt" is allowed to mean. Three design rulings on the same mechanism, chronological.

## 1. A PRESENT key/registration proves nothing about the past or future (D-0965, 0.87.11)

[[design-the-mount-threads-retire-grace-lives-inside-the-admission-barriers-bound]]

A clean unmount leaves its disklock slot RETIRE_PENDING, naming its per-boot PR key. A same-boot remount re-registers the IDENTICAL key before the predecessor's RETIRE_PENDING record settles (P305-RETIRE-SETTLED-OWN lands ~40ms-8s after REGISTER, gated by a 1.5s READ KEYS delay). The target cannot distinguish "departure never unregistered" from "successor registered the same key," and the live-member guard can't see a successor that hasn't claimed a slot yet. A peer that withdrew a PRESENT key immediately fenced the live successor (P303-FENCECAP-SELFABSENT, measured 2/2 on 0.87.10).

Ruling: expiry authorizes recovery, it does not prove anything happened or didn't. Safety only requires the mount not go writable beside a contested registration. So the mount thread holds admission (P-ADMIT-RETIRE-PENDING-HELD; the admission barrier re-sweeps) for a grace window that starts at first sight and is never reset by a barrier round.

Two different grace constants, and they must stay different: `MXFS_DISKLOCK_RETIRE_MOUNT_GRACE_MS` (10s, the mount thread) lives INSIDE `MXFS_DISKLOCK_RETIRE_GRACE_MS` (30s, the admission barrier's own bound) — because a genuinely stalled record still has to be withdrawn, its key fenced, and its clean slice replayed, all inside the barrier's bound. Measured with mount-thread grace wrongly set to 30s (same as the barrier): withdraw landed at 29.3s of the bound, fence+replay took 12s more — the mount only succeeded because the retire worker's first sight happened to precede the barrier's first poll; this is not a margin, it's luck. With the correct 10s split: withdraw ~10.5s, fence certified ~1s later, mount admitted ~22.7s. Anyone raising the barrier bound, the fence cost, or the replay cost must re-derive this split — it is not independently tunable.

Harnesses: `tests/d0965_remount_bracket_race.sh` (both interleavings), `tests/d0965_stalled_record_mount_thread.sh` (withdraw still happens), `tests/d0965_successor_killed_after_register.sh` (dead successor, live registration).

Related, same design: `mxfs_scsipr_own_registration_proven` re-brackets only when the bracket was disturbed (generation-moved or invalidated-during-bracket), bounded by `dbg_pr_own_proof_brackets` (default 4; 1 = pre-fix single-bracket control), 50ms × attempt between tries. A COHERENT bracket missing the key or reservation still refuses outright — only a *disturbed* bracket gets retried. This is the same principle as the PRESENT-key case: a clean negative read is trusted, an ambiguous one is not laundered into either polarity.

## 2. The fail-fast gate: two "blocked" structures, only one stops a waiter hanging (0.89.11, D-381)

[[design-the-acquire-path-fail-fast-gate-was-reachable-only-from-the-precommand-fence-leg]]

`dlm/v5_mount.c` has two structures that both sound like "this slice is blocked" and do unrelated jobs:
- `ctx->blocked[slot]` (`v5_blocked_set`) is a REPORT only — feeds `/sys/kernel/debug/mxfs/<dev>/recovery_blocked`, changes no behavior.
- `ctx->fence_retry[slot].blocked` + `ctx->recovery_blocked_n` is the GATE. `mxfs_v5_dlm_node_recovery_blocked()` reads it on the acquire path (via the DLM's `recovery_blocked_cb`) and is what makes an acquisition behind a dead node's frozen grants fail fast with EIO instead of waiting out the acquire budget. It also makes `v5_node_live_cb` answer "not live."

Until 0.89.11 the gate was armed in exactly one place: `v5_fence_retry_arm()` with `nonproving=true` — only when the PRECOMMAND bounded retry series ran past `fence_blocked_after_ms`. The `MAY_HAVE_SUBMITTED` (ambiguous) leg calls `v5_fence_retry_disarm()` and never arms the gate. Consequence, measured on 2/tcp: after a fencing attempt whose command may have run, the survivor's own root-inode acquire sat behind the fenced victim's EX grant for 764s and climbing (`P-LKTIMEOUT-HOLDER`, `P36-RETRY` counting down); `umount` and `fuser` hung; the module could not be released; only a power cycle cleared it. Zero BUG, zero Oops, zero shutdown — debugfs printed the slice and asserted "this is a REFUSAL, not a hang," true of the refusal, false of what the waiters experienced.

Lifecycle rules for touching this gate:
- Lifted only by `v5_fence_retry_disarm()`, which certify/takeover/supersede all already call — don't add a second lift path.
- `disarm` DECREMENTS `recovery_blocked_n`; any new call site that sets blocked must guard `if (already blocked) return;` or the counter drifts.
- `disarm` clears `blocked` — if a leg both disarms and (re-)blocks, the block must come AFTER the disarm, not before.
- Leave the slot `armed = false` when blocking outside `arm()`. The retry worker only visits armed slots, and `mxfs_disklock_recovery_fence_retryable()` already answers 0 for any descriptor carrying `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN` — but an armed slot would still be visited and then disarmed, silently lifting the gate again.
- `disarm` does NOT clear `fence_retry[slot].victim` (the lookup key) — set it explicitly when blocking outside `arm`.

Principle: refusing to recover a slice without proof of exclusion is the invariant. Making every waiter hang on that refusal is not part of the invariant — no proof means no recovered grants, but it also means failing the local operation explicitly (EIO) rather than deadlocking its teardown.

## 3. Three operations, not two — and the sole-survivor gate is not a free pass (Astra s74)

[[design-fence-outcome-legs-are-precommand-retryable-ambiguous-terminal-and-the-third-operation-is-proof-resume]]

Ruling on D-FENCE-POSTSUBMIT-AMBIGUITY-NO-RECONCILIATION-381 after the lost-response entry (the case in §2) was measured live on 2/tcp.

| Operation | Meaning |
|---|---|
| Ordinary retry | Re-enter the victim-key fencing op after PRECOMMAND |
| Proof resume | Advance an unresolved attempt using independently sufficient evidence or a fresh fencing op |
| Takeover | Change the OWNER of the durable recovery attempt |

The actual failure needs proof resume BY THE SAME OWNER. The tree only had the other two operations, and the takeover sweep explicitly declines an attempt whose holder is "our current incarnation" — so a live prover could never resume its own unresolved attempt. It was stuck.

Forbidden ways to "fix" this: broaden `mxfs_fence_attempt_is_retryable()` to include `MAY_HAVE_SUBMITTED`; make `mxfs_disklock_recovery_fence_retryable()` answer yes for a descriptor carrying `MAY_HAVE_RUN`; weaken `v5_node_is_dead()` or the live-owner takeover check; or route the continuation through a generic entry point that can fall through to another victim-key P&A. All of these launder an unproven state into a proven one.

The trap in "the sole-survivor gate doesn't name the victim key": the sole-survivor exclusive-write gate issues `rk=own, sark=0, type=WE(1)` — it never names the victim key, so it looks like it can't collide with an in-flight predecessor against that key. Not sufficient on its own:
1. The original P&A removes the victim's registration.
2. Aborting the victim's already-accepted tasks may still be in progress.
3. The gate observes the key absent and completes; post-state is `own_n==1`.
4. Recovery starts while an old victim write can still complete.

A second P&A over *currently registered* nexuses is not a drain of tasks belonging to an *already-removed* registration. A host mutex around the two calls does not order execution at the target after a timeout — a late *response* is harmless, a late *command execution* is not. So the gate may supply proof only once the outstanding-I/O / task-drain obligation is closed by an applicable target-enforced ordering/drain guarantee (right nexus, LU, multipath scope), or by showing all unresolved predecessor effects are harmless. A coherent PR snapshot does not repair the drain gap.

Also: a zero-SARK P&A is STILL a P&A — count gate commands in the ambiguity accounting, and give the gate its own durable command boundary, or a lost gate response is simply a second ambiguity.

Key-still-PRESENT case, same principle as §1: presence proves neither that the predecessor did not execute nor that it cannot execute later, and no retry count or elapsed timeout converts it into either fact. Correct behavior: stay `FENCE_UNPROVEN`, don't enter the absent-key branch, don't resubmit merely because time passed. The only legitimate bound is an OPERATIONAL one — after a finite window, get a valid certificate or transition the local filesystem to an explicit failed/withdrawn state. That deadline authorizes loss of local service, never a weaker certificate.

## Cross-cutting rule

Every one of these three rulings resolves the same tension the same way: an ambiguous or absent signal (PRESENT key, lost response, "may have run") NEVER gets converted into a positive proof by waiting, retry count, or mutex ordering alone. The only thing time is allowed to buy is an operational deadline that fails the local operation explicitly (EIO, admission block, failed/withdrawn state) — never a certificate the design didn't actually earn.
