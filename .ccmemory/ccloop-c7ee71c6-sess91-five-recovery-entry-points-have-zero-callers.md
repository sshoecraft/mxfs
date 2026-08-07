---
name: ccloop-c7ee71c6-sess91-five-recovery-entry-points-have-zero-callers
description: sess91: PROVEN by exhaustive grep — 5 of the 7 recovery-descriptor entry points have ZERO callers, so no abandoned recovery is ever taken over and th…
metadata:
  type: reference
tags: [sess91, disklock, recovery, dead-code, takeover, fence-certificate, measured, D-RECOVERY-TAKEOVER-UNREACHABLE, D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION]
---

# sess91 — five of the seven recovery entry points are never called

Found while building the reproducer for `D-RECOV-ADVANCE-UNBOUNDED-RETRY`.
Proven by exhaustive grep over every `.c` and `.h` in the tree at 0.11.421, then
corroborated on the rig.

## The count

| entry point | real callers |
|---|---|
| `mxfs_disklock_recovery_begin` | **1** — `dlm/v5_mount.c:2201` |
| `mxfs_disklock_recovery_advance` | **2** — `v5_mount.c:2254`, `:2301` |
| `mxfs_disklock_recovery_takeover` | **0** (`disklock.c:3167` def; `:4908` a comment) |
| `mxfs_disklock_recovery_claim` | **0** (`:3915` def) |
| `mxfs_disklock_recovery_fence_intent` | **0** (`:3486` def) |
| `mxfs_disklock_recovery_fence_certify` | **0** (`:3645` def; `:3009` a comment) |
| `mxfs_disklock_recovery_fence_takeover` | **0** (`:3787` def) |

Careful with the grep: the definitions span two lines, so a filter that excludes
`^int mxfs_...` still reports the definition line as a "hit". Match the bare
symbol and read every occurrence.

## Consequence 1 — no abandoned recovery is ever taken over

`MXFS_RECOV_ABANDON_MS` (disklock.h:446) is 6000 and the takeover CAS is fully
implemented, with abandonment correctly defined as ABSENCE OF CHANGE in
`owner_stamp_ms` rather than by comparing clocks. Nothing calls it, so the
timeout is never consulted. `disklock.c:4908` even states "abandoned recovery is
resumed via `mxfs_disklock_recovery_takeover()`" — a comment describing a
mechanism that never runs.

**MEASURED** with the new `tests/recov_takeover_retry_probe.sh`: kill test32
(slot 14), wait for the descriptor (GUARD at t+63.4s, stage=3,
owner_node=3454184023), then rewrite **only** `desc.owner_node` to a phantom and
reseal. The real owner refused exactly once and stopped; every survivor then
logged `P234-RECOV-OWNED … another survivor owns this recovery; not publishing`
(×4 and counting) — deferring to a node that does not exist.
`P163-RECOVERY-COMPLETE = 0` for the whole window, slot frozen at stage=3, the
victim's CAW grants frozen behind the `GRANTS_RELEASED` freeze gate.

Real trigger, no injection needed: **the elected replayer dies mid-recovery** —
an ordinary double fault. Filed `D-RECOVERY-TAKEOVER-UNREACHABLE` (critical).

## Consequence 2 — the fence certificate is dead code, which is why two criticals survived

`recovery_begin` writes `want->recov.desc.stage = MXFS_RECOV_STAGE_FENCED`
**directly** at `disklock.c:2912` and never touches `fence_kind`. Only the
intent path (`:3610`) and the certify path (`:3754`) set it, and neither runs.
So every descriptor the cluster actually publishes reaches FENCED with
`fence_kind = 0 = MXFS_FENCE_KIND_NONE` and no certificate.

And `disklock.c:2996-3003` asserts:

> the milestone ladder starts at FENCED, and the ONLY way to reach FENCED is
> `fence_certify()`

**That statement is false in the shipped build.** It is the reason
`D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION` and
`D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION` survived the sess74/75/76 campaign:
the certificate was designed, given an on-disk wire format and a proto_gen bump,
and then never invoked. Wiring it in is the mechanism those two entries need —
recorded on the FENCED-stage entry.

## The descriptor CRC, for any future injection

`recov_desc_crc()`: `crc32c(0xFFFFFFFF, desc[0 .. offsetof(crc32c)=116])` then
**continued** (not restarted) over packed `{fs_gen:u32, node_id:u32, epoch:u64}`
taken from the **record HEADER**, not from the descriptor's own `victim_*`
fields — so a payload spliced next to a different victim's header fails. In a
GUARD record the header still carries the victim's identity (never overwritten),
so it reads straight off the sector. Descriptor lives at HB offset 40;
`owner_node` at desc offset 44; crc at desc offset 116 (HB 156). Always
self-check against the unmodified descriptor before writing.

## Method note

The unbounded-retry defect I filed earlier the same session was **too broadly
scoped**, and this probe is what showed it. A takeover-class permanent failure
does NOT loop — the owner refuses once and `recovery_begin`'s re-entry also
fails the ownership test, returning `-EBUSY` with `P234-RECOV-OWNED`. The
unbounded loop needs the owner to keep PASSING the ownership test while FAILING
something downstream. Narrowed in the ledger rather than left overstated.

The same run positively verified the 0.11.421 `P234-RECOV-NOTOURS` rework, which
had shipped observed only in its not-firing state: `kind=TAKEOVER` fired with
both full tuples printed and zero spurious `kind=TOKEN-MISMATCH`.
