<!-- sess374-376: closure-purge fix landed+gap-fixed, full Hazards-§7 fault matrix (8 rows), D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 CLOSED FIXED AND VE… -->
---
name: docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md
description: sess374-376 — D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 closure-purge landing, gap fix, full Hazards-§7 fault matrix, CLOSED FIXED AND VERIFIED.
metadata:
  type: project
tags: [compiled, closure-purge, dlm_caw, hazards-7, aba, fencing, rule6, ccloop-c7ee71c6]
---

# sess374-376: D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 taken to CLOSED

Direct continuation of the sess363 GPT-approved CAW-layer closure-purge redo
(see `docs/history/docs/history/compiled-sess353-363-fr-enforce-grant-freeze-cascade.md`). This arc lands
the fix, measures and closes its own residual gap, then works the sess363
ruling's Hazards-§7 fault-test list to completion and closes the ledger
entry. sess365-373 died at startup on bad model selection — no work lost,
sess364's plan carried straight into sess374.

## sess374 — landing (build 0.14.3, srcversion DA8D50EBF86F28CAECF7C54)

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`: the sess364
plan plus 2 the design-consult rule review rounds landed. Shared strip discipline
`caw_strip_node_state()` + 9-bitmap `caw_victim_state_mask()` (NOT
`caw_purge_candidate`, which predates waiters_ex/yield_to and is narrower);
`caw_closure_strip_one()` = reread→reclassify→regate→CAS→tombstone→grant
wake; scrub oracle (`closure_scrub_fn`/`closure_cand_mask`/`noq_scrub_busy`)
hooked at two sites — Hook A in `caw_wait_for_grant` after the magic check
(immediate try, 2s re-arm), Hook B at the NOQUEUE conflict exit (atomic
winner election). `disklock.c` gate is LEASELESS: every gate read is its own
fresh 512B read, unreadable = refusal, never amortized. `v5_mount.c` purge
takes `expect_victim`/`expect_ag_mask` and returns `-ESTALE` on drift.

GPT review round 2 REFUTED, with evidence, three worries that must not be
reopened without new facts: a missed wakeup on the polling CAW wait loop
(worst case 250ms re-eval, `dlm_caw.h:58,71`); holding the publisher lease
across a partial purge (sess363 ruling item C already says release
regardless — the leaseless survivor scrub *is* the retry protocol); and
fencing not being storage-level (the victim self-fences via
`hb_own_record`/`hb_cas_own_slot` the instant its own sector holds
`RECOVERY_GUARD`, and slot reuse cannot orphan CAW bits because the full
purge's HB-zeroing gate refuses `QUARANTINED`).

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`:
deploy attempt (build sv B2F4EE0E599570AA4461C61) opened on an infra trap —
SCST target was down since Aug 13 (`sg_persist`/INQUIRY EIO, mkfs EIOs at
offset 4096); not a CAW/READ wedge, no D-state tasks. Fixed in ~10s with
`scripts/scst_setup.sh setup` + `scripts/mpath_up.sh up 32` — **check the
target before anything else when mkfs EIOs at offset 4096.**

Ruling part (3) (out-of-closure revocation) VERIFIED both halves in
isolation: publisher purge strips the root inode grant sess356 measured
stranded (blocked prober rc=0 @63s); survivor demand scrub (`SCRUB_ONLY=1`)
does the same when the publisher itself is suppressed (rc=0 @64s). Zero
shutdowns, 31/31 mounted both runs. Board: 24 PASS / 3 FLAKY(pass now) /
0 FAIL / 1 POLICY, no regression from the new acquire-path hooks.

Ruling part (1) (cancel EXISTING waits) MEASURED but not yet fixed: a
waiter already parked in `caw_wait_for_grant` before quarantine import at
t=171s doesn't reach the refusal gate until t=467s — **296s later**, the
same five-minute wedge from sess356, surviving containment (0 withdrawals).
Fix shape identified but untried: a no-I/O quarantine oracle in the same
poll loop, returning a distinct terminal-quarantine error instead of
waiting out the DLM timeout — v5 already imports the quarantine map
locally. Part (2) unaudited at this point.

Test-harness trap that cost a full run: the forged domain used to be
`l_mxfs_refused_ag_mask |= forced`; a real replay contributes its own
refused AGs, so forcing `0x2` became `0x83` (ag0 back in closure) and the
probe's correct-containment EIO was misread as a defect. Fixed to ASSIGN,
plus a setup guard that exits INCONCLUSIVE if the published domain includes
ag0. New ledger entry **D-CRASH-CONSISTENCY-NO-TERMINAL-RECORD-CAPTURE-374**
(high, unledgered since sess360): NO_TERMINAL_RECORD on 0/32 nodes within a
90s budget, then PASS in 22s on rerun, 6 occurrences across 3 builds.

`docs/rulings/all-three-ruling-parts-verified-0143.md`: build sv
B0F00E729CA59423AEDDFA2, 32/caw, board 24 PASS / 3 FLAKY(pass now) / 0 FAIL
/ 1 POLICY. Part (1) fix landed and verified: quarantine-import→cancel
causal gap collapsed from the measured 296s down to **33ms**
(`P240-QUAR-IMPORT` t=232.715 → `P240-QUAR-WAITCANCEL ... el_ms=64091` —
i.e. the cancel now fires essentially immediately, not 296s later — labeled
64091µs/33ms wall in the new instrumentation). Part (2) confirmed correct
by construction: the refused ag_mask is built only from refused items'
AGs, so an AG with no refused item is out of closure and gets revoked by
part (3); demonstrated by the prober then acquiring and using the released
root inode.

the design-consult rule round 3 caught two real defects in the cancel path before ship: the
cancel skipped `caw_drop_own_waiter`, stranding a waiter bit (the sess48
phantom-waiter class — only the TIMEOUT path had been dropping it, not the
new `out:` path); and cancel could race a direct handoff, orphaning a
just-granted holder bit (closed with a `!self_h` guard + a post-drop
re-read, `P240-QUAR-WAITCANCEL-RACE`). GPT's lost-update worry about the
quarantine map was refuted — writes already serialize under
`mp->m_mxfs_quar_lock`.

Remaining before this ledger entry can close: the sess363 ruling's
**Hazards-§7** fault-test list — the fix's OWN failure modes, to be
INJECTED not argued: gate failure at every CAS boundary, HB sector
unreadable, descriptor CRC fail, expected-vs-platter mask mismatch
(`-ESTALE`), tombstone/slot-reuse race, racing waiters, a slot carrying
multiple victims, waiter-only/open-holder-only slots, victim node 0,
mount/adopt racing the terminal import, CAS-exhaustion partial reporting.
(Publisher-death-post-publish already done via
`closure_skip_publisher_purge`.)

## sess375 — making slot-reuse testable, then closing 4 of the 7 remaining rows

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`: the
initial argument that tombstone/slot-reuse was UNREACHABLE (open-addressed
binding, ~1/65536 collision odds per acquire) was WRONG and the design-consult rule correctly
refuted it. `resource_hash_raw` is seedless FNV-1a over the raw
`mxfs_resource_id` bytes — no boot seed — so home slots are computable
outside the kernel. `tools/caw_slot_hash.py` verified 788/788 live slots at
their computed home (0 mismatches) and found 2478 real cross-AG colliding
inode pairs among 18669 candidates — enough to construct a genuine directed
collision with two ordinary files, nothing forged. The transition itself
(slot magic flips A→B under an injected hint→read pause) was reproduced
4/4 runs via direct platter READ(16)+FUA. What blocked full attribution: the
rebind landed AFTER the publisher had already passed the slot (`moved=0`) —
closing it needed the publisher's OWN blocked waiter to demand-scrub the
slot, and that scrub appeared not to fire. Filed
**D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375** (high) — later
DISPROVED in sess376 (see below; the scrub was firing correctly, sess375
misread a shared timing knob).

Structural facts banked here: the publisher purges before it publishes
(later shown FALSE in sess376 — see there); the publisher IS the
recovery-lease owner; a re-bound slot can never carry the dead victim's bit
(so `flipped` is unreachable on a reused slot; `moved` is the achievable
proof); eviction (`sync; drop_caches`) drops live CAW slot counts
substantially; `find -printf '%i'` binds every inode it stats, so pairs
must be picked before quiescing; `dd iflag=direct` returns a stale image on
this target (FUA bit dropped) — use `caw_slotdump --slot N`; `lmod` is a
per-node monotonic clock, not cross-node comparable.

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`: build sv
DE6AAF014FB3916088F23B5, board 24 PASS / 3 FLAKY(passing) / 0 FAIL /
1 POLICY, no regression from new per-strip counters/timing hooks. Four more
Hazards-§7 rows closed: mount/adopt racing terminal import (import strictly
precedes adopt, victim slot excluded from the mount purge mask);
waiter-only slot (foot=0x0a0, stripped correctly, root-dir pace unaffected);
open-holder-only slot (12 slots foot=0x100, all stripped, `open_only=12`);
tombstone/slot-reuse L1 (hint→authoritative-read window, survivor scrub
removed the victim mid-strip-attempt, publisher correctly did nothing) and
L2 (read→CAS window under live contention, `cas_miscompare=4`, every retry
re-read and re-classified). One transition judged genuinely unreachable at
rig scale and left as instrumented-but-unforced: a slot tombstoned then
rebound to a DIFFERENT resource inside one strip attempt (order 1/65536 per
acquisition; forging it would mean writing a false slot image).

Traps recorded here, load-bearing for anyone re-running these harnesses:
`resource.ag_number` is always 0 for INODE/ICLUSTER resources — trusting
the printed `ag=` value concludes every inode lock is in ag0 and silently
passes an in-closure strip; derive AG via `XFS_INO_TO_AGNO`. The forged AG
mask cannot be a constant — inode allocation picks the AG per run
(measured ag16/ag6/ag1/ag5 across laps) — derive it from the observed
footprint. Files created flat in one directory all land in one AG; XFS
rotates AG per new directory, so spread grants across subdirectories. A
pure WAITER cannot be built by contention alone (MXFS caches grants) —
build it via a `virsh suspend`d cached holder inside the death-confirm
window. `virsh destroy` on a spare node is a SECOND DEATH that can consume
the one-shot refusal knob meant for the real victim — have the joiner leave
cleanly instead (umount+rmmod). `freplay_force_slot=-1` fires on whichever
slice replays first when more than one node is down — pin the victim's
slot. Always assert the forged domain actually took
(`P227-FR-INJECT-ARMED` present AND published `ag_mask` matches). Board
test ordering matters: `dirent_publish_integrity`/`dirent_type_integrity`
depend on a window `dirent_durability` stamps. `pkill -x bash` to stop a
fleet workload also kills the harness's own ssh shells — use a stop-file.

## sess376 — two disproofs, matrix complete, ledger entry CLOSED

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`:
builds sv D15316B499606FC03B8B4C0 then 25057F6813DDAF1ECB477CF, 32/caw,
final board 25 PASS / 2 FLAKY(passing) / 0 FAIL / 1 POLICY.

Two log-reading traps, each of which had cost a prior session, both
resolved as DISPROOFS:
1. `caw_inject_closure_pause_n` is a single global consumed by whichever
   caller (publisher scan OR blocked waiter's demand scrub) arrives first —
   sess375's 76s wait was the demand scrub firing at el_ms=1 and then
   sleeping inside the pause meant for the scan. New knob
   `caw_inject_closure_pause_who` (0=any, 1=scan, 2=scrub) isolates them;
   `who=1` shows the scrub really does fire immediately (rc=0, elapsed=0).
   **D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375 → DISPROVED.**
2. "The publisher purges before it publishes" (sess375's structural claim)
   is FALSE. Durable publish is `mxfs_v5_dlm_recovery_publish_refusal()`
   (`xfs/xfs_mxfs_dlm.c:46711`); the purge scan is `:46759`; the "terminal
   outcome PUBLISHED" line at `:46791` is only a trailing summary — publish
   precedes scan. Decisive proof: a publisher destroyed mid-scan never
   emits that line at all, yet all 30 remote survivors still logged
   `P240-QUAR-IMPORT` ~2.1s after their own fence-done. Scan wall
   un-injected: 418ms.
   **D-CLOSURE-REMOTE-WAITER-NO-REPAIR-BEFORE-PUBLICATION-376** filed and
   DISPROVED in the same session (8/8 remote probers rc=0 @62s vs 120s
   timeout).

Hazards-§7 matrix now COMPLETE at 8 rows. Row 5 (hint→read reuse, A→
tombstone→B) PASS 3/3, attributed per-attempt by new `P299-HINT-MOVED`
line. Row 6 (read→CAS window, ABA, A→tombstone→A) PASS 2/2 via `ABA=1`:
generation is per-binding (restarts at 1 on fresh claim) but a tombstone
preserves resource/lineage/`ex_grant_epoch`, and the CAS still miscompared
(`P299-STRIP-CASMISS ... expect_lineage=... expect_vfoot=0x1`) because the
expected image necessarily carries the victim footprint and a tombstone
requires every holder/waiter/open bit clear first. Row 7 (publisher death
BEFORE publication, `KILLPUB=1`) PASS.

Row 8 (node-slot incarnation reuse) is the interlock that settled the last
GPT-named blocker — a new node incarnation reusing a heartbeat slot could in
principle re-set "the victim's bit" since CAW bitmaps index nodes by
reusable heartbeat slot, not identity. It cannot: `recov_desc_present()`
(`dlm/disklock.c`) requires every closure gate to read the victim's HB
sector FRESH and see `flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD (3)` plus
a descriptor naming its own sector — a live tenant writes `FLAG_ACTIVE (1)`
and cannot present a descriptor at all. Measured 2/2
(`tests/closure_hb_slot_reuse.sh`): rebooted victim takes a different slot,
guard record keeps its original node_id+epoch byte-for-byte, zero strips
after rejoin.

New critical defect found while chasing a flake, still OPEN:
**D-FDW-REJOIN-BNOBT-OVERLAPPING-FREE-SHUTDOWN-376** — a just-fenced,
rejoined node hit a free-space double-free in a truncate
(`bno + len > gtbno`, `xfs/libxfs/xfs_alloc.c:2490`) → corruption shutdown,
node never rejoined; reproduced 3/3 on `fence_during_write` including "own
data intact(exp=1 got=0)"; a fresh-prep control ran 3/3 PASS. Trigger not
identified — back-to-back fencing alone does not reproduce it. Leading
hypothesis: an EFI completed twice (peer replay + rejoined node) — instrument
EFI provenance before patching.

`docs/history/docs/history/docs/history/compiled-sess374-376-closure-purge-hazards7.md`:
session end state, build sv 25057F6813DDAF1ECB477CF, ledger 47 open of 103
(was 46 of 99): 3 closed, 4 filed.

**D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 → CLOSED FIXED AND VERIFIED.**
The sess363 Hazards-§7 matrix is complete at all 8 rows, each with its own
harness and platter/dmesg artifact, causal acceptance with timing knobs OFF
passing, board 25 PASS / 2 FLAKY(passing) / 0 FAIL / 1 POLICY. Both sess375
disproofs (demand-scrub-not-firing, remote-waiter-no-repair-before-
publication) close alongside it.

Newly filed, all still OPEN at session end: **D-QUARANTINED-SLOT-EXHAUSTS-
CLUSTER-ADMISSION-376** (critical) — a terminal quarantine permanently
occupies a heartbeat slot; usable slots equal the volume's log-slice count
and mkfs caps `-n` at 32 (2GiB−10MiB internal log limit), so at max cluster
size one refusal permanently costs a node and there is NO implemented
repair path (only `mkfs -f` clears a quarantined GUARD record) — measured
via a rejoining node getting `claim_slot -28` and aborting its mount.
**D-FENCE-RECONVERGE-POSTCONDITION-280S-376** (high) — now instrumented
(run.sh records alive/N trajectory + dissenting nodes into criteria.json)
and reproduced on first repeat: flat 31/32 the whole window, dissent
attributable to the test6 corruption shutdown above rather than mere
slowness; the original 2026-08-15 incident stays unattributed.

Rig-health facts recorded for anyone trusting this board later: clyde's
nvme0n1 was 88% full (1.5T/1.8T) with elevated block-layer await
(r_await 68-157ms vs a documented healthy p50 of 1.19ms w_await); test4
wedged in an unkillable D-state sync whose stacks were ext4/jbd2 on dm-0
(the node's OWN root disk, MXFS nowhere in the path) — its qemu became an
unreapable zombie and `virsh destroy` failed for 20+ minutes. clyde itself
had zero D-state tasks and 15-27% util, so per the never-reboot-clyde rule nothing was done to
the host. The board's node-fault diagnostic previously misattributed a
bare `sync[sync_inodes_sb]` stack to `D-BAST-WRITEBACK-ABBA-DEADLOCK` (an
MXFS defect); run.sh now tags each D-state task's subsystem
({EXT4-ROOTDISK} vs {MXFS}) from its top stack frames to prevent that
misattribution recurring.

Harness/rig facts from this session worth not re-learning: `prep_cluster`
does `mkfs -f` and clears dmesg on every node (`tests/setup/prep_fs.sh:79`)
— harvest a node's evidence BEFORE re-prepping. Restart every destroyed VM
before prep, or the marker records an ssh error string as the srcversion
and later runs error out. Backticks inside a double-quoted remote heredoc
are LOCAL-shell command substitution — a prose comment containing `` `moved` ``
actually ran `moved`. The reuse test must HOLD the re-bound resource live
across the publisher's wake, since a single read binds-and-releases in
milliseconds and a tombstoned slot short-circuits `strip_one` at the magic
check before the resource comparison that scores `moved`.

New assets landed across the arc: `tests/closure_purge_scrub.sh` (+
SCRUB_ONLY/INCLOSURE/VICTIM_LOAD/PROBE_FANOUT/KILLPUB), `tests/
closure_reuse_directed.sh` (+ PAUSE_WHO/PAUSE_WHERE/REUSE_TO/ABA + a hold
loop), `tests/closure_footprint_shapes.sh`, `tests/closure_foot_parse.py`,
`tests/closure_hb_slot_reuse.sh`, `tools/caw_slot_hash.py`, `tools/
caw_slotdump` (`ag=` for all types, `yield=`), knobs
`caw_inject_closure_pause_{n,ms,where,who}`, `freplay_force_ag_mask`,
`closure_skip_publisher_purge`; run.sh reconvergence trajectory/dissent/
wall recording, MXFS_LOG_SLICES pass-through, subsystem-tagged node-fault
diagnostics; `tests/setup/prep_node.sh`'s `blockdev --flushbufs` now FAILS
instead of warning.
