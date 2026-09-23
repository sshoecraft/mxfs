<!-- D-500/D-501 starvation fixes, D-488 leg7 readopt-mint GPT ruling+landing, D-503 pace-collapse discovery/diagnosis (ccloop c7ee71c6 sess284-294) -->
# D-500/D-501 starvation closure, D-488 leg7 readopt-mint, and D-503 pace-collapse genesis (ccloop c7ee71c6, sess284-294)

## D-500 agwait-relock convoy — FIXED AND VERIFIED (sess284)
`mxfs_trans_agwait_handoff` relock loop was plain blocking per-inode `xfs_ilock`.
Fixed in 0.11.501 with FIX-L3 Phase A/B: `xfs_lock_inodes(ips, nips, XFS_ILOCK_EXCL)`
for nips>=2 (all cross-node DLM grants first, ascending, no rwsems held; rwsems
nowait-only), plain `xfs_ilock` for nips==1, `xfs_trans_ijoin` only after the whole
set is locked. GPT gates verified: never call `xfs_lock_inodes` with <2 inodes;
shutdown postcondition (ilock_begin refuses on shutdown, Phase B still takes every
rwsem, caller's one `xfs_iunlock`/inode stays balanced). Verified: `dlm_fairness`
32/caw PASS 32/32 (28s/30s), convoy signature (P-ACQ-STUCK, AG-AIL-STALL, D-state
fleet) absent in all 4 post-fix runs, max P139-LOCKTOTAL 6.4s (was 480s). GPT flagged
as a separate, unproven architectural risk: mixed inode-DLM/AG-DLM class-order cycles
are not proven absent fleet-wide. Trap: pre-fix 480s stalls persist in node dmesg
across the fix (prep doesn't reboot) — always map by wall/uptime before attributing
a dmesg line to the current build.
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`

## D-501 hot-dir EX starvation — opened, measured, root-caused, fixed (sess284-287)
Opened sess284: `dlm_fairness` 32/caw failed the 30s budget 3-of-4 on 0.11.501 —
fast nodes did 16 rounds in 7-14s, starved nodes took ~25s to their FIRST round.
Starvation = repeated consecutive losses (max single wait 6.4s fleet-wide), not one
long wait; 6.4s ≈ the 5s `MXFS_CAW_YIELD_TIMEOUT_MS` stale-clear + backoff. Initial
H1: releaser's `yield_to` round-robin EX-waiter nomination is biased/re-snapshots
the same batch.

Measurement probe P291-EXWIN landed sess285 (0.11.502): one line per successful
exclusive-class INODE grant across every path (promote/adopt/cold/claim/convert/
mint/nom), gated LTYPE_INODE + `mxfs_mode_can_write`, capped 20000/module-load,
logged post-CAS (not at P6H-HANDOFF, which prints pre-CAS and over-logs on -EAGAIN
retries — don't trust P6H-HANDOFF counts for distribution). Established:
nomination is `caw_pick_next_ex_waiter` — first EX waiter strictly after the
releaser's bit, cyclic, no persistent cursor; direct handoff makes last-holder's
release CAS the winner directly; upgraders bypass the ticket entirely (sess130
conversion priority); streak yield hands the ticket to the whole PR class after
`MXFS_CAW_EX_STREAK_YIELD` consecutive EX tenures with PR waiters present.

Root proven sess286 on 0.11.502: H1 (biased nomination) REFUTED — dir-EX rotated
fair and fast (887 grants/30s, median inter-grant gap 23ms, 2/886 consecutive
repeat wins). Real mechanism: `mv` preacquires participating inodes' home AGs;
a trylock miss on a peer-held AG (ag21) triggers ILOCK handoff, and dir-EX gets
granted away 17ms after a 642ms-wait adoption, blocking ~600ms while holding
nothing for ag21, then re-queues ~600ms for dir-EX on relock — two serialized
cross-node waits per rename that touches no AG metadata. Census: 1590 in-window
AG waits, 850+ comm=mv, 1227 on ag=21; per-node AGwait count correlated almost
perfectly with round slowness. Gotcha: P291's `yt=`/`wex=` fields are hex with no
`0x` prefix — a naive `\d+` regex silently drops most lines (parser:
`scripts/p291_aggregate.py`). Also: dmesg timebases differ per node — always
calibrate boot epoch via P291 `realms=` (wall-ms) before cross-node windowing.
GPT ruling: split AG preacquire into MANDATORY (target_ip on rename-with-existing-
target, RENAME_WHITEOUT wip, xfs_remove's victim ip — miss still handoffs/blocks/
-EAGAINs) vs OPTIONAL (src/target dir + src_ip home AGs — miss just proceeds, no
handoff, doesn't consume the 8-handoff budget); rejected holding dir-EX across the
AG wait (hidden hold-and-wait); did not approve a blanket "always proceed on miss"
pending a restart-safety audit of ifree/defer-finish/trans-roll/dir-shrink.

Fixed and verified sess287, 0.11.503: `mxfs_trans_preacquire_inode_ags` took the
`(tp, inodes, num_inodes, mand_inodes, num_mand)` signature; optional-AG misses log
`P293-PREACQ-OPTSKIP` (capped) and proceed; dedupe seeds mandatory inodes first so
a shared AG keeps the stronger class; new tripwire `P292-DIRTY-AGWAIT` at the deep
P1-AGWAIT blocking fall-through flags cases where the skipped insurance would have
mattered. Verified: `dlm_fairness` PASS 32/32 in 19s/30s (was 0/32), P293 fired
~16/node on the hot AG, P292/P271/P290/P13-CLEANRETRY all zero in-window fleet-wide;
D-488 birth-suite regression clean (`rsync_paired` 17s/60s, `scaling_curve` 36s/90s).
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/rulings/501-root-proven-preacq-optional-ruling.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`

## Recurring harness trap: `make clean` deletes `tools/` binaries
Hit repeatedly (sess287, sess292, sess294): `make clean` also wipes `tools/`
(mkfs_mxfs, chk_mxfs, ...), so the next `prep_cluster` fails with "mkfs tool not
found". Always run `make tools` immediately after any `make clean` and before
deploying. Related: `tools/mxfs_sshpass.sh` wants a bare hostname — it prepends
`root@` itself, so passing `root@testN` double-prefixes and auth-fails.
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`

## D-POSTLOAD-SYNCWRITE-PACE-COLLAPSE-503 — opened, second occurrence, diagnosis (sess288, 292-294)
Opened sess288 on 0.11.503: after a full board sweep (27/27 PASS on the first
chunk, ~30min continuous load), the immediately-following chunk-2 run hit
`crash_consistency` 0/32 NO_TERMINAL_RECORD (all nodes stuck in datawrite/md5write,
test17: 50 O_SYNC dd ≈ 88s, ~1.8s/op vs 13ms solo/115ms@8-node) and `dir_reuse`
0/32 pace (5/8 rounds, correctness clean). Not reproduced by standalone/pair/chunk
re-runs. Unproven suspects at the time: background release churn competing for
CAW/LUN bandwidth, tri-state unlock read-back doubling release cost, ungated
P291-EXWIN printk flood. Note: `crash_consistency` has a multi-week history of
standalone-PASS/in-suite-flake with this identical signature — not new.

Second occurrence sess292 (0.11.505, chunk D): `crash_consistency` FAIL 0/32
NO_TERMINAL_RECORD again. Evidence isolated the stall to shared-dir EX acquire
latency, not the release torrent: dd's P36-MHT-REARM on the shared dir showed
exh_ms=1672 with 114+ re-arm strikes @6ms; datawrite phase 52s for 50 ops
(~1s/op ≈ dir-handoff cadence). REFUTED: serial console printk stall (ring-only,
console_loglevel=1, negligible volume). REFUTED as sole cause: the qsrc=16
(dir_ex_sweep) release torrent — the PASS control window had the *same* torrent
volume and still passed in 20s. Discriminators between fail/pass windows:
P50-RD dir-block re-reads 3463 vs 500, P12-AGBAST-RX 100 vs 10 per 40s; per-create
tracing showed the expensive part was pure EX-wait, not the adopt/read/demote work
itself. Both real occurrences needed ~10-13 accumulated board cells first — new
hypothesis: dir demote/handoff work queued behind sweep-release work on the shared
`m_mxfs_inode_bast_wq`.

sess293: full board completed clean on 0.11.505 (27/27 PASS). `dir_reuse_coherency`
FAILed once (7/8 rounds in 100s) then PASSed immediately on re-run (8/58 in 112s);
phase-timeline comparison showed no dominant phase and a much smaller exh_ms
(≈200ms vs 1672) and zero qsrc=16 lines in the fail window — reclassified as
**chronic marginal pace riding the 12.5s/round threshold**, tracked as the
pre-existing D-32NODE-SHARED-DIR-CREATE-PACE, NOT a new D-503 occurrence and not a
new ledger entry. (Separate recurring trap noted same session: after any
re-prep/reboot, `dirent_publish_integrity`/`dirent_type_integrity` fail with "no
MXFS_DIRENT_WINDOW marker" unless `dirent_durability` runs first in the same boot
— always order durability → publish → type.) Designed the P296-BASTQLAT probe to
test the wq-delay hypothesis: stamp `i_dlm_bastq_qns` (expected-run ktime) at both
`mxfs_bast_arm_queue`/`_delayed` call sites, log excess>100ms at the two work-fn
entries, capped. Established every per-inode dir-demote and sweep-triggered
PR-demote (`mxfs_dlm_queue_pr_demote`) share the same workqueue.

sess294 landed P296 in 0.11.506 and reproduced D-503 (`crash_consistency` FAIL
0/32 NO_TERMINAL_RECORD, `dir_reuse_coherency` FAIL 0/32 pace 43/44) after a
20-cell full-board accumulation. **Wq-queue-delay hypothesis DISPROVEN**: P296
showed zero excess-latency events on all 32 nodes inside each node's fail window
(each node's 400-event cap saturated only *after* its window, so the absence is
real, not cap-censoring); the src=16 sweep torrent does backlog the wq (up to
~900ms excess) but only in inter-test gaps and during `dir_reuse`, never during
`crash_consistency`'s collapse. **Proven instead**: `P34-ACQ-SLOW` on the shared
cc dir showed 4 create-path stalls of 1-2 full 6000ms ACQUIRE_WAIT BAST-retry
periods (dur_ms 6366/12471/11619/12543) — the EX holder sat through BASTs with no
wq delay anywhere, so the cause is either release aborting on the holder, a BAST
swallowed before it's ever queued (P296's blind spot — it only measures queued
work), or a multi-second-slow drain pipeline. Evidence artifact:
`scratchpad/dir_timeline_raw.txt` (3679 lines, all 32 nodes). Next step identified:
reconstruct the grant chain around the stall to name the holder and why it held,
then design consult before any fix — **not done as of sess294**, D-503 remained
OPEN.
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`

## D-488 leg 7/8 — readopt-mint GPT ruling and implementation (sess289-292)
sess289 design-consult ruling, driven by a code audit showing the CAW already-held fast
path reaffirms with the slot's OLD `ex_grant_epoch` (no CAS/mint), the
STILL_HELD re-arm comment claiming a fresh mint was FALSE, and rx readopt setting
`cached=true` with epoch 0 (an epochless-writing-tenure window via cached
reclaim):
- **Ruling 1a**: restoring a surrendered epoch is never acceptable. A narrowly
  scoped READOPT mint is legal only when: own bit present for the expected
  incarnation, local published epoch == 0, no incompatible peer, proven
  post-drain/surrendered orphan (not an ordinary reentrant acquire), and the
  compare-image still matches expected Eold/identity/gen/lineage. Must write a
  fresh monotonic Enew != Eold, publish in-core only after a definite CAS
  success or verified read-back, and on any mismatch: never restore Eold, no
  metadata writes, quarantine. A crash after CAS but before publication must
  cause the NEXT readopt to mint again, never republish Enew just because it's
  found on disk.
- **Ruling 1b**: the rx path must set a `READOPT_PENDING` state (own bit + no
  tenure observed via BAST) rather than ever silently setting `cached=true`; a
  worker rereads the slot and performs the same verified mint as 1a, or
  quarantines if provenance/CAW is unprovable. P243 (no-authority probe) must
  extend to every writable-tenure entry path, not just fresh acquire.
- **Ruling 2 (leg 8)**: shape A — a resumable copy-before-clear sweep: fence via
  positive SCSI-PR confirmation bound to the exact victim incarnation; a durable
  victim manifest built off the heartbeat thread (validate identity/mode/epoch/
  gen/lineage, append to a durable descriptor BEFORE clearing, then
  gen/incarnation/lineage-protected CAW clear, resolve ambiguity by read-back);
  replay evaluation reads the sealed descriptor manifest, never live bits; a
  recovery-ordering barrier survives physical purge; unresolvable replay must
  produce an explicit RECOVERY_BLOCKED quarantine, never CAW-holder livelock or
  a restored dead bit.

Implementation: part 1a landed sess290 (0.11.504) — `caw_lock_body` gained
`(attested, local_epoch)`; new `mxfs_dlm_caw_lock_attested()` (old
`mxfs_dlm_caw_lock()` delegates unattested, zero behavior change for non-AG
callers); already-held EXACT-MODE arm mints via real CAS when
`local_epoch==0`, fails closed (`-ESTALE`, P294-REAFFIRM-EPOCH-MISMATCH) on any
nonzero mismatch. Correctness rests on every release-commit that zeroes
`pag_mxfs_grant_epoch` running strictly after the Invariant-1 drain pipeline, so
an own-bit orphan with local epoch 0 can never cover undrained pre-surrender
state.

Part 1b landed sess291 (0.11.505): new `pag_dlm_readopt_pending` bool (set/cleared
under `pag_dlm_lock`, single-flight via the existing `bast_scheduled` latch); the
rx strand detector no longer sets `cached=true` (that was exactly and only the
fabrication producing the epochless window) — it now sets `readopt_pending` and
queues a worker (`mxfs_dlm_ag_rx_readopt_mint()`) that rereads the slot and either
clears pending (bit gone), mints via the 1a path (bit ours), or fails without
publishing (mint fail — rx watchdog re-arms on the next ~1/s BAST). P243 extended:
cached-reclaim arms now fail closed on CAW+epoch==0 and fall through to a fresh
attested acquire (re-mints via 1a); release_pending reclaim arms got probe-only
treatment since their sole setter (P275-AGUNLK-QUARANTINE) makes the path
currently unreachable — chose to detect first per the instrument-first loop rather than change
behavior there.

Rig-verified sess292 on 0.11.505: `ag_strand_repair` PASS 32/32 (79s/240s);
verified chain on test1 (`P200-STRAND-INJECT` → `P5N disk_held=1 repair=1` →
`P294-READOPT-MINT` Eold=1/Enew=2 → `P295-RX-READOPT-MINTED` → normal drain/
COMMIT/release, no Eold republish); fleet sweep all 32 nodes: MINT=1 each,
P295-FAIL=0, P295-GONE=0, P243-AGAUTH-UNBOUND=0, P294-REAFFIRM-MISMATCH=0. Board
continued clean through most cells on .505 (remaining incomplete cells finished
sess293). Leg 8 (manifest/replay-gate work) and the D-488 ledger rewrite were
still not started as of sess292.
`docs/rulings/488-legs7-8-readopt-mint-manifest-purge.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`
`docs/history/docs/history/docs/history/compiled-sess284-294-d500-d501-d488leg7-d503-genesis.md`

## State at end of sess294
0.11.506 built (sv 289E4A3F4164D39FFC7DF90). D-500 and D-501 CLOSED/FIXED AND
VERIFIED. D-488 leg 7 (1a+1b) rig-verified; leg 8 and the ledger rewrite pending.
D-503 (pace collapse under sustained board load) OPEN — wq-delay hypothesis
disproven, dir-EX acquire stall proven via P34-ACQ-SLOW, holder identification
and design consult were the next steps. D-32NODE-SHARED-DIR-CREATE-PACE
identified as the pre-existing chronic explanation for `dir_reuse_coherency`'s
recurring single-round margin failures, distinct from D-503.
