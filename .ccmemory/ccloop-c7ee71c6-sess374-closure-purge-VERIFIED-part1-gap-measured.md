---
name: ccloop-c7ee71c6-sess374-closure-purge-VERIFIED-part1-gap-measured
description: sess374: #3 ruling part (3) FIXED AND VERIFIED both halves at 32/caw on 0.14.3; part (1) cancel-existing-waits gap MEASURED (296s stall); board 24 PA…
metadata:
  type: project
---

# sess374 — closure purge VERIFIED; the part-(1) gap is now measured

Build **0.14.3 sv B2F4EE0E599570AA4461C61**, deployed 32/caw.

## Infra trap (cost ~20 min)
The SCST target was DOWN at session start: `scst.service` failed since
Aug 13, `/sys/kernel/scst_tgt/targets/iscsi/` had NO target dirs, every
node's mpatha paths were "failed faulty", `sg_persist`/INQUIRY gave EIO,
and mkfs died with `pwrite at offset 4096 failed: Input/output error`.
NOT the CAW/READ wedge (no D-state tasks, suspend=0) — the runtime-only
target config was simply gone. Recovery, no reboot, ~10s total:
`scripts/scst_setup.sh setup` then `scripts/mpath_up.sh up 32`.
**If mkfs EIOs at offset 4096, check the target before anything else.**

## VERIFIED — sess357 ruling part (3), both halves, in isolation
`tests/closure_purge_scrub.sh 32 test32 0x2` (new, in tree):
- PUBLISHER: `P299-CLOSURE-SCAN ENTRY victim_slot=18` ->
  `P299-CLOSURE-STRIP slot=7390 type=1 ino=128 ag=0` (**the root inode** —
  the exact grant sess356 measured stranded) -> `P299-CLOSURE-PURGE
  purged=6 kept=0 unread=0 wfail=0 abort_rc=0`. A prober launched at the
  kill and blocked on the root dir: **rc=0 after 63s**. Fresh probe 1s.
- SURVIVOR (`SCRUB_ONLY=1`, publisher suppressed): `P299-CLOSURE-SKIP`
  then `P299-SCRUB-STRIP slot=16749 victim_slot=30 type=1 ino=128 ag=0`;
  blocked prober **rc=0 after 64s**.
- Both: 0 shutdowns, 31/31 mounted, no refroze / incomplete / scrub-abort.
- FULL 28-cell board on this build: **24 PASS / 3 FLAKY(pass now) / 0 FAIL**
  / 1 POLICY. No regression from the new acquire-path hooks.

## MEASURED GAP — ruling part (1), cancel-EXISTING-waits
`INCLOSURE=1 tests/closure_purge_scrub.sh 32 test32 0x1` (ag0 IN closure):
NEW acquires refuse correctly and fast (`P240-QUAR-AG-EIO agno=0`,
`P240-QUAR-REFUSE ino=128`). But a waiter ALREADY inside
`caw_wait_for_grant` when the quarantine imported at **t=171s** did not
reach the refusal gate until **t=467s** — ~296s later — and never returned
inside its 210s budget. That is the sess356 five-minute wedge, surviving.
Containment holds (0 withdrawals, 31/31 mounted), so this is a STALL, not
a cascade.
FIX SHAPE (untried): no-I/O quarantine oracle in the caw_wait_for_grant
poll loop, at the SAME hook site as the sess374 scrub (proven cheap —
gated on a register test); return a distinct terminal-quarantine error
instead of waiting out the DLM timeout. v5 already imports the quarantine
map locally, so no platter read. Part (2) is unaudited.

## Test-harness lesson that cost a full run
Shape-1's forged domain used to be `l_mxfs_refused_ag_mask |= forced`.
A real replay contributes its OWN refused AGs, so the forged 0x2 became
**0x83** — ag0 back IN closure — and the probe's immediate EIO was correct
containment misread as the defect. Now it ASSIGNS, and the harness has a
SETUP GUARD that exits 2 INCONCLUSIVE if the published domain includes
ag0. Also: the churn files are dotfiles, so the liveness check needs
`ls -a` (plain `ls` cost another run).

## New assets
- `tests/closure_purge_scrub.sh` (+ env SCRUB_ONLY / INCLOSURE / VICTIM_LOAD).
  Use a 560s shell timeout; the internal budgets are the assertions.
- knobs `freplay_force_ag_mask`, `closure_skip_publisher_purge`
  (ruling hazard 7: publisher death post-publish).
- NEW ledger entry **D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374**
  (high): 90s budget exhausted, nodes_pass=0/32 NO_TERMINAL_RECORD=32,
  then PASS in 22s on re-run; 6 occurrences across 3 builds. sess360 saw
  it and left it unledgered — RULE 6 has no such category. open=45 of=98.
