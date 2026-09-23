---
name: reference-a-two-node-total-outage-is-recovered-by-the-bootstrap-owner-which-adopts-one-victims-slot-as-its-own-log
description: REFERENCE (s118): when both nodes are down, the next mount is a whole-cluster bootstrap owner and ADOPTS one victim's slot as its own log — no P163 f…
metadata:
  type: reference
---

## What happens

On the 2-node rig, if BOTH nodes are down when one comes back, its mount does
not foreign-replay both dead slots. The disklock scan finds a frozen table with
two victims, declares a TOTAL OUTAGE and the mount comes up as the whole-cluster
bootstrap owner:

```
P-BOOT-SCAN-FROZEN 2 occupied record(s) unchanged for 63989 ms — TOTAL OUTAGE
P-BOOT-SCAN-VERDICT victims=2 moved=0 unread=0 noident=0 window_ms=62500
P-BOOT-CLAIMED node=<us> victims=2 — provisional bootstrap owner; no slot, no
  grant, no filesystem write until RECOVERY_COMPLETE
```

It then fences and certifies every victim, and splits their slices between TWO
DIFFERENT recovery routes:

- **One victim's slot is ADOPTED as the owner's own log.** `P-BOOT-ADOPTED`,
  `P-BOOT-ADOPT slot=N victim=<node>/<inc> rc=0`, `P-BOOT-ADOPTED-LOG slot=N —
  bootstrap owner mounting a certified victim's slice as its own log: FULL
  replay, authority-evaluated; a refused transaction is terminal`. The slice is
  then recovered by the mount's ORDINARY log recovery (`Starting recovery`
  … `Ending recovery`), and completion is reported as
  `P-BOOT-ESCROW-K-REPLAY-OK`. **No `P163-RECOVERY-COMPLETE` is emitted for
  that victim.**
- **Every other victim is foreign-replayed** the usual way and DOES get
  `P163-RECOVERY-COMPLETE slot=N node=<victim>`, then `P-BOOT-TOMB kind=DIRECT
  slot=N`.

The owner finishes with `P-BOOT-COMPLETE` and
`P-BOOT-RECOVERY-COMPLETE term=1 … — the whole-cluster bootstrap is complete;
this node is an ordinary ACTIVE member and admission is open`. Its
`complete=0x…` mask has a bit set for the foreign-replayed slots only; the
adopted slot K is accounted for separately (`K=0` in the final line).

## Why it bites a harness

Any assertion of the form "the survivor recovered the dead node's slice, so
`P163-RECOVERY-COMPLETE` must appear for it" is measuring the foreign-replay
route only, and it FAILS a recovery that ran — the adopted victim is recovered
more strongly (full, authority-evaluated replay as the owner's own log), not
less. `tests/fence_crash_cuts.sh` failed exactly this way at s118a: every cut
destroys the prover while the victim is already down, so every cut is a total
outage and the prover's slice is always the adopted one.

Grade the adoption route on its own three lines together — `P-BOOT-ADOPT` for
that slot and victim, `P-BOOT-ESCROW-K-REPLAY-OK`, `P-BOOT-RECOVERY-COMPLETE`
— because adoption without the replay would be the real hole.

## Where the code is

`dlm/bootstrap.h` / the bootstrap owner path; the adoption is wired through the
disklock record (`ACTIVE|BOOTSTRAP_PENDING`). Note the earlier lesson that the
whole-cluster bootstrap once had a single CAW-only call site — it reaches TCP
now, which is why banked pre-TCP evidence grades differently.
