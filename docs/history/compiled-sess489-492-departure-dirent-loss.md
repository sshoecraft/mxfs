<!-- sess489-492: D-0490 untokened-departure double-retire + D-0491 BTREE-dir evict-drain gap closed F&V; D-0492 filed; D-0487 root proven (dead-holder re… -->
# sess489-492: departure-token double-retire, BTREE-dir evict-drain gap, dead-holder replay convoy

One continuous rig campaign (2026-09-04, sess489→sess492) that opened on a stale chain-139
harness bug and closed with three defects rooted, fixed and two of three verified: D-0490
(untokened dirty departure), D-0491 (dirent loss on BTREE-format shared dirs), D-0492 (filed,
open), plus D-0487 (SB-summary-lock convoy) advanced from "wait site unknown" to "root proven,
fix designed, not yet coded". All four share one mechanism family: an MXFS buffer/log-item
terminal-completion or lock-release path that fires on a stale or duplicate trigger and either
retires a departure token twice or releases/evicts a dir data block before it actually reached
disk.

## Harness discipline fixes (sess489, prerequisite to everything after)

Chain 139 (`tests/sess487_chain139_persig_ab.sh`) had been silently measuring nothing: its armed
`crash_consistency` re-run reused the previous failed row's mount with no prep, so every write was
an `O_TRUNC` overwrite of an already-existing per-node file, not a shared-directory create — 102
create-probe lines on 9 nodes instead of ~3200 on 32, PASS in 23-29s of a 90s budget read as "quiet
fleet" when it was "nothing ran". Fix: `CC_TAG=<word>` gives each armed row a fresh
`.crash_consistency_<word>` directory; going forward, read the create-probe COUNT against the
planned population before trusting any per-sample statistic out of that harness
([[trap-rerunning-a-create-workload-on-the-same-mount-measures-overwrites-not-creates]]).

With that fixed, `docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`
surfaced two real findings the same session: (1) `dir_persig_flush=0` lost an entry — node23's
last create vanished, readers logged `mxfs-cc-FAIL` 10-17s after node23's own write barrier — the
first sighting of what becomes D-0491; (2) every unmount after a big-dir workload departs DIRTY:
`P304-RETIRE-NOT-QUIESCED untokened=65..177` in 5/12 captures, `mxfs_departure_quiesced` fails
closed, slot stays ACTIVE + PR key retained on an otherwise-clean unmount, forcing peers to fence +
recover. No ledger record existed for it yet — this becomes D-0490.

## D-0490 — sync-emulated completion runs the terminal ioend twice

Root proven in `docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md` via 133
stack chains: `xfs_buf_ioend()` runs `__xfs_buf_ioend` (retires the departure token) then wakes the
sync waiter, whose `xfs_buf_iowait` loop (`while (!__xfs_buf_ioend(bp))`) runs the same retiring
call a second time — untokened, hence dirty-departure on every unmount that follows a dir-release
drain. Upstream has the same two-pass shape but its second pass is idempotent; MXFS's is not.

GPT-reviewed fix, landed 0.70.3
(`docs/rulings/sync-ioend-marker.md`): a per-buffer marker
(`b_mxfs_ioend_ran`) published only by the actor that wins the sync-wake credit, only AFTER
claiming that credit and BEFORE `complete()` (a losing actor must never publish), cleared at every
FRESH submit generation (a resubmit keeps the earlier credit and never re-publishes). Called out as
a separate future fix, not bundled: `xfs_buf_delwri_fail`'s single un-tokened pass should be classed
`b_mxfs_io_soft` rather than folded into this marker. General coverage rule stated for any future
path that runs `__xfs_buf_ioend` before waking a sync waiter: publish only on true return, only by
the wake owner, before `complete()`, never gated on `XBF_ASYNC`, never on resubmit.

First verification attempt looked like a FAIL (`key_retained=32 shutdown=32`) but was a harness
artifact: the verify script's `SINCE` timestamp was taken before test prep, so it captured the
*previous* chain's 0.69.5 teardown, not the 0.70.3 window under test. Fixed by moving `SINCE` to
open after prep. Inside the corrected window: `P304-IOCNT-UNTOKENED=0`, quiesced 32/32,
`NOT-QUIESCED=0`, `P490-SYNC-IOEND-SKIP` firing non-vacuously on all 32 nodes — **D-0490 closed
FIXED AND VERIFIED** (`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).

## D-0491 — dirent loss: BTREE-format dir data blocks reclaimed EX-undrained

Filed critical same session as D-0490
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`): a dir data
block committed (`lseq=4`) but never written (`wseq=0`) gets its lock released at PR
(`P123-DIRFENCE-SKIP`), the release drain re-lands it (`P3R-RELAND`), the re-land's sync write is
suppressed by the fence check, `P287-F4-SUPPRESSED-COMPLETION` leaves the retire obligation open,
then the buffer is freed anyway with the obligation still open (`P286-F4-ORPHAN`) — the block's
content is gone from core while another node reads and overwrites it, durably losing the entry.
`rerr=-11` on the release is `xfs_iflush_cluster -EAGAIN` on the dinode loop, not the data block —
a dead end investigated and ruled out.

Investigation initially misread the lock-mode population: a truncated subagent table (80 of 647
rows, all shown rows `held_mode=3`/PR) was generalized to "all 53 releases entered at PR", which
drove a wrong hypothesis (no EX→PR downgrade path exists, so something outside `bast_process` must
be ending EX tenures). A full-population histogram request corrected it to 36 PR / 17 EX-entered
releases on that node, EX-entered releases on all 32 nodes
([[trap-a-truncated-subagent-table-is-a-sample-never-generalize-a-field-from-the-shown-rows]],
mechanism detail in `docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).
That correction pointed straight at the real mechanism: EX-mode reclaim.

Root candidate H6, code-proven
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`): `mxfs_dlm_evict`
only drains dir data blocks on the `XFS_DINODE_FMT_EXTENTS` arm (sess83 fix); a BTREE-format dir
(this one: fmt=3, nx=48) skips the drain entirely and `mxfs_v5_dlm_inode_unlock` releases the
on-disk EX lock undrained. `mxfs_dir_flush_data_blocks` (the in-lock variant) already handles BTREE
correctly (owner scan + bmbt scan + extent walk), so the gap is specifically in the evict path, not
the general flush path. Confirmed recurrence in chain 139 leg B on node6
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`) before the
fix landed.

0.70.4 added instrumentation only (per the instrument-first loop — proof before patch): `P491-EVICT-UNDEST`,
`P491-REL-UNDEST`, `P491-NEWTENURE-RETIRE-UNDEST` census points plus `b_mxfs_done_site` stamped at
every overlay retire caller. Result: `P491-EVICT-UNDEST` fired at `mode=5 fmt=3 drain_arm=0`
precisely on the three nodes that lost entries, one per lap, each followed 4-5s later by the same
re-land → suppress → orphan chain; zero undest on `P491-REL-UNDEST` across all 1336 ordinary
releases — H6 proven
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).

Fix 0.70.5, GPT-reviewed: `mxfs_dlm_evict`'s drain-arm gate widened to `EXTENTS||BTREE`, plus
`mxfs_dir_noino_land_scan(mp, ino, land=true)` after the drain, a post-drain census
(`P491-EVICT-DRAINED`: landed/left/undest/inail/f4_open/undrained), and `xfs_force_shutdown` under
`evict_obligation_shutdown` if anything remains undrained at EX — fail closed rather than repeat the
silent-loss shape. Verified clean across 6 laps / cause exercised 4× more times in a second
identical run (s492a + s492b) — **D-0491 CLOSED FIXED AND VERIFIED**
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`, harness detail
in `docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`,
`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).

## D-0492 — filed, open: newtenure-retire drops in-AIL log items without writing them

A second, related arm found while proving D-0491: `mxfs_dlm_evict` isn't the only place a
committed-unwritten dir block gets its log item retired without I/O. The acquire-time
newtenure-retire path (site 9993) also retires in-AIL items of `lseq>wseq` blocks — 2313
occurrences observed, all EX-held, 1293 at `wseq=0`, 1145 mid-tenure
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`). Candidate fix
is the same shape as the D-0491 fix: add the `mxfs_dir_buf_is_undestaged` guard to this retire arm
(mirrors an existing guard at ~3517). 0.70.8/0.70.9 built a discriminator (disk_match histogram
split by new_tenure / wseq state) to characterize the population before patching; the harvest run
was blocked by the disk-headroom issue below and had not returned as of session end
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`,
`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`). Remains
OPEN.

## D-0487 — SB-summary-lock convoy: wait site found, then a second, worse mechanism under it

Carried in from sess483-488 (`docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`); this campaign found
the actual wait site and a second layered defect. Convoy A/B injectors were vacuous for the
question (victim fail-stops ~8s into umount before ever taking the SB-summary lock)
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`). Stack
sampling the victim's umount task pinned the real wait site on both 0.70.0 and 0.70.1:
`flush_workqueue(mp->m_mxfs_inode_bast_wq)` at `pal/linux/xfs_super.c:1987`, called from
`xfs_fs_put_super` — zero `P-SB-SUMMARY-LOCK` waits on the victim in either leg
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).

An under-lock fault injector (`mxfs.dbg_sb_inject_unheld_agno`, 0.70.6) then bounded that specific
quiesce path at a clean 10s fail-stop — but exposed a second, worse mechanism: the victim's dead
slot leaves its grants FROZEN until the elected lowest-live-slot peer replays its slice; 7 peers
convoyed for a full 120s DLM timeout (`-110`) waiting on a replay that never happened, and all 7
departed DIRTY (slot + PR key retained)
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`). Root, proven
by session end: the elected replayer refused the replay because the closure classifier
(`mxfs_freplay_res_out_of_closure`, `xfs_mxfs_dlm.c` ~53968) returns 0 (in-closure, so frozen) for
`agno >= sb_agcount` — the synthetic SB-summary key decodes to `agcount+66`, outside the real AG
range, and the classifier has no case for it. GPT-approved fix: an exact-key helper
(`mxfs_sb_summary_key_is`) that classifies the synthetic key OUT of closure for AG-scoped verdicts
while keeping it frozen for FSWIDE verdicts. Designed, not yet coded when the session ended
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`). Remains
OPEN.

## Rig blocker at session end: clyde root disk, not NFS evidence

Preflight started failing at session end (88% used, floor <88%). Measured root cause: clyde's ROOT
ext4 (`/dev/nvme0n1p2`, 1.8T, 226G free) carries the SCST LUN image and VM images — the rig itself —
not the project tree (`/src` is NFS, 1.3T free; `tests/evidence` at 18G lives there and is not the
consumer). The actual eater: `/tmp/claude-1000` at 15G, almost entirely `tools/scratch_build.sh`
copying the whole tree per version into per-session scratchpads (~600-700MB each; one session alone
accumulated 3.2G across 5 versions). All regenerable — frozen kos/tools already live on NFS under
`tests/evidence/*_frozen_*`. Fix filed as a to-do, not yet done: remove scratch trees by explicit
full path (the permission-prompt rule bars `rm` on a variable/glob path), and make `scratch_build.sh` clean up after
freezing, or point scratch builds at NFS instead of local `/tmp`
(`docs/history/docs/history/docs/history/compiled-sess489-492-departure-dirent-loss.md`).

## Net state at end of sess492

Ledger: 90 open. D-0490 CLOSED FIXED AND VERIFIED. D-0491 CLOSED FIXED AND VERIFIED. D-0492 OPEN
(discriminator built, fix designed, harvest blocked on disk). D-0487 OPEN (root proven, fix
designed, not coded; rig blocked on host headroom before it can be verified). Tree at VERSION
0.70.9, mxfs.ko stale at a 0.70.3 build — needs `make modules` before further tree-build work.
