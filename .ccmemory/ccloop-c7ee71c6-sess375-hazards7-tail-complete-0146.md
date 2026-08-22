---
name: ccloop-c7ee71c6-sess375-hazards7-tail-complete-0146
description: sess375: #3 Hazards-§7 tail COMPLETE on 0.14.6 sv DE6AAF014FB3916088F23B5 — mount_race, waiter_only, open_only, reuse_race L1+L2 all PASS at 32/caw;…
metadata:
  type: project
---

# sess375 — D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356, Hazards §7 tail

Build **0.14.6 sv DE6AAF014FB3916088F23B5**, 32/caw. Board on that build:
**24 PASS / 3 FLAKY(passing) / 0 FAIL / 1 POLICY** — no regression from the
new per-strip counters or the two timing hooks.

## What closed

| shape | evidence |
|---|---|
| mount/adopt races terminal import | joiner: classify t=635.10855 → `P240-QUAR-IMPORT` t=635.10856 → `P-H22-PURGE-MASK ENTRY` t=635.1253 → `P225-ADOPT-WINDOW closed` t=635.5260, barrier `quarantined=0x20`. Import strictly precedes adopt; victim slot excluded from the mount purge mask. |
| waiter-only slot | platter precondition: slot 54139 ag9 foot=**0x0a0** (WAIT_EX\|YIELD, no holder bit) → `P299-CLOSURE-STRIP slot=54139 vfoot=0xa0`; post-audit victim bit gone from every slot; root-dir pace 235ms vs 306ms baseline. |
| open-holder-only slot | 12 slots foot=**0x100** proven on the platter → all 12 stripped `vfoot=0x100`, kernel counter `open_only=12`; post-audit clean. |
| tombstone/slot-reuse, L1 | `PAUSE_WHERE=1` widened hint→authoritative-read; a survivor scrub removed the victim inside a strip attempt; `bit_gone=1`, publisher did nothing. |
| tombstone/slot-reuse, L2 | `PAUSE_WHERE=2` widened gate→CAS under live contention; `cas_miscompare=4`, each retry re-read AND re-classified. |

Zero strips landed on an in-closure resource in any lap; every lap ended with
an independent `caw_slotdump` post-audit.

## The one transition that is NOT reachable

"Slot tombstoned then re-bound to a DIFFERENT resource inside one strip
attempt." Slot binding is open-addressed: `index = hash(resource) % 65536`
with a linear probe past tombstones (`dlm/dlm_caw.c:3126`, `3187-3279`). With
a few dozen live slots the probe chains are length 1, so a freed index is
re-bound only by a resource hashing exactly to it — order 1/65536 per
acquisition. No workload makes it reachable at rig scale, and forging it means
writing a false slot image (fabricated evidence). Both defenses that cover it
were exercised separately instead (L1, L2 above), and the counters for the
transition itself (`moved`, `flipped`) are logged so a future hit is
recognised rather than silently passing.

## New in the tree

- `tests/closure_footprint_shapes.sh` — arms `waiter_only|open_only|reuse_race`,
  exit 2 = PRECONDITION-NOT-MET (never a pass).
- `tests/closure_foot_parse.py` — platter/dmesg footprint parsing.
- `tests/closure_mount_race.sh` — rewritten (see traps).
- kernel: `vfoot=0x%x` on `P299-CLOSURE-STRIP`/`P299-SCRUB-STRIP`;
  `P299-CLOSURE-SHAPES` line; knobs `caw_inject_closure_pause_{n,ms,where}`
  (timing only, never forge data).
- `tools/caw_slotdump`: prints `ag=` for ALL types, adds `yield=`, and the
  default filter no longer hides open-holder-only slots.

## Traps that cost real cycles

1. **`resource.ag_number` is meaningless for INODE/ICLUSTER** — it is 0, and
   both `caw_slotdump` and the kernel's own strip log print that 0. The
   classifier uses `XFS_INO_TO_AGNO(ino) = ino >> (agblklog + inopblog)`
   (`xfs/xfs_mount.h:799`), read from xfs_dsb bytes 124/123. An audit that
   trusts `ag=` concludes every inode lock is in ag0 and silently passes an
   in-closure strip.
2. **The forged AG mask cannot be a constant.** Inode allocation picks the AG
   and it moves every run — measured ag16, ag6, ag1, ag5 on consecutive laps.
   A fixed `0x2` quarantined the victim's own AG and left the purge nothing to
   do. Derive it from the observed footprint.
3. **Files created flat in one directory all land in ONE AG.** XFS rotates the
   AG per new DIRECTORY — spread grants over subdirectories.
4. **A pure WAITER cannot be built by contention.** MXFS caches grants, so a
   churning node ends up a cached PR/EX holder (measured: `pr=[31]` on ino 128,
   `ex=[31]` on three others after 12s of contention). Use an unanswerable
   request: a survivor caches EX, is `virsh suspend`ed (<30s, inside the ~62s
   death-confirm window), and the victim's FIRST request for that resource
   parks as a pure waiter.
5. **`virsh destroy` on a spare node is a SECOND DEATH.** `closure_mount_race`
   destroyed its joiner, so the cluster ran a second fence + foreign replay,
   that replay competed for the ONE-SHOT refusal knob, and it published a
   quarantine of its own — one run had the knob consumed by the joiner's slice
   (`ag_mask=0x2`) while the real victim refused genuinely with `0x80001`
   (contains ag0, so the root grant stayed frozen CORRECTLY and the run
   measured nothing). Fix: the joiner leaves CLEANLY (umount + rmmod), which
   releases the slot and leaves no slice to replay.
6. **`freplay_force_slot=-1` is wrong when more than one node is down** — it
   fires on whichever slice is replayed first. Pin the victim's slot.
7. **Always check the forged domain actually took.** Genuine refusals happen on
   this build (defect #1 is live), they run with `error != 0` so the forge
   branch is skipped, and they publish their OWN refused AG set. Both closure
   harnesses now assert `P227-FR-INJECT-ARMED` present AND published
   `ag_mask == armed ag_mask`, else exit 2.
8. **Board test ordering matters.** `dirent_publish_integrity` /
   `dirent_type_integrity` scan a window `dirent_durability` stamps; running
   them without it FAILs correctly ("unverifiable is not a pass"). Splitting
   the board into chunks must keep that dependency together.
9. `pkill -x bash` to stop a fleet workload also kills the harness's own ssh
   shells — use a stop-file the loop polls.
