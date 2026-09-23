<!-- D-0496 leaf-hash-index-loses-entries: sess496-499 root hunt, P123 fence mechanism, D-0492 attribution, GPT retirement bar, code audit. -->
# D-0496: directory leaf-hash-index loses entries, masked by the datascan heal (sess496-499)

Central defect: `D-DIR-LEAF-HASH-INDEX-LOSES-ENTRIES-MASKED-BY-DATASCAN-HEAL-0496`. A shared
directory's on-platter leaf/node hash index can lag its data blocks — new dirents land on disk
but the index entries that make them findable by hash lookup do not — and the gap is invisible
because `mxfs_dir2_datascan_lookup` (a full data-fork rescan on ENOENT) silently heals every
cold lookup that hits the hole. Filed critical in ``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md``, ledger 87.

## sess496: finding the pace term, then the defect it was hiding

``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md`` first
closed an unrelated ledger item — `D-DIR-INODE-DURABLE-BARRIER-FAILS-ARM-UNCLASSIFIED` DISPROVED
via `tools/p13_release_shape.py`: all 700 sampled P13 releases were orphan no-tenure releases of
already-clean dinodes: the relbar ledger gate never opened, so there was nothing to fail. Then it
ran down the `create_scale_curve` pace ceiling's lookup term: `mxfs_dir2_datascan_lookup` fires on
every ENOENT in a multi-node dir unless `i_mxfs_dscan_clean_key == (dir_gen, valid_epoch,
loaded_gen)`, and peers' `DIR_MODIFY` ring keeps bumping `dir_gen` through a node's own tenure, so
the scan re-runs constantly (up to 38 data blocks/window). Critically, `P22-DATASCAN-HIT` showed
the heal is load-bearing, not just slow: dir ino 75513091 (`node17_f42..45.md5`) and ino 117440640
were healed repeatedly across a crash+replay chain — a real leaf-hash hole, live since sess22, that
the heal has been quietly papering over. GPT ruling on the spot: do not ship "skip the scan under
continuously held EX" — a name-specific negative scan is not a directory-wide completeness
certificate (skip + pre-existing hole for another name => duplicate dirent on create, ENOENT on
unlink/rename of a leafless ghost). Only sound paths: (A) a directory-wide completeness
certificate, or (B) find and fix the hole and remove the heal.

``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md`` filed
the defect and started the root hunt. 0.70.16 verified (skip 32/32, rfr 1.0→0.6ms). Of that day's
two P22 events, one was the D-0492 control lap on a known-buggy 0.70.9 build (not live); the other
— `run_crash_consistency_20260904T083456Z`, dir 75513091 — was real: the four healed names hashed
into four *different* leaf ranges, meaning readers' index predated test17's entire last tenure, not
one stale block. Timeline: test17 released the dir at 08:36:40; `P34-LEAF-DRAIN` showed several
index blocks `CACHED=1 needs_flush=0 done=0` (invalidated in-core, but never flushed) versus one
block correctly flushed; all nodes cold-read the dir at 08:36:41-42, and 4 of 32 missed the names
(healed at :45/:47/:49/:51) while 28 found them. First hypothesis (H-H3): index blocks touched in
the last tenure got DONE-cleared by a peer's gen-bump invalidation before their logged content was
actually written, so the release drain classified them `needs_flush=0` and never landed them — data
landed, index didn't catch up until later (if ever, absent the heal).

``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md``
found the mechanism. At test17's 08:36:40 release: the data block carrying the four new dirents
(daddr 59326456) WAS written. `P123-DIRFENCE-SKIP ... sub-EX stale dir-block write suppressed`
fired on the index ROOT (25433712) and one leaf (105924880) at that same release — both were
skipped. H-H3 refined: a release whose pipeline entered at PR (demoted from EX, `held_mode=3`)
treats just-modified INDEX blocks as "sub-EX stale" and suppresses their write, while DATA blocks
written under the earlier EX tenure go through — platter data gets ahead of platter index until an
unrelated push lands the index (or never, absent the heal).

## sess498: the fence mechanism, then the day-wide attribution

sess497 was killed by a server-side safeguard mid-investigation (read-only, nothing written); its
findings (retire-arm locations, `P285-F4-BLI-FREED-OPEN` on leaf daddrs 16947184/127106400) were
folded into ``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md``,
which mapped the P123 fence in full (`pal/linux/xfs_buf.c` ~10828-10933): on a dir-block write, if
`mxfs_v5_dlm_inode_granted_mode(owner) < EX` and the buffer has no log obligation
(`!in_ail && !dirty && !pinned`), the fence suppresses the write — sets `b_mxfs_fence_skipped`,
stales+clears DONE (if no BLI), then calls `xfs_buf_ioerror(bp,0)` + `ioend`, so the submitter
(`xfs_bwrite`) observes `rc=0`: a phantom success. `__xfs_buf_ioend` then stamps
`written_seq = logged_seq` on that phantom completion — the undestaged-write bookkeeping marks
content "landed" that never reached the LUN. The release-drain postlude
(`mxfs_dir_flush_one_daddr`, `xfs_mxfs_dlm.c` ~6575-6709) compounds it: after `werr==0` it stamps
`written_seq=logged_seq`, retires the in-AIL clean BLI, skips FUA republish specifically when
`b_mxfs_fence_skipped`, then stales the buffer and clears DONE — so a fence-suppressed drain write
leaves the logged index content nowhere: not on the platter, and the in-core copy invalidated too.
The drain sanction registry (`mxfs_dirdrain_set_mode`) only sanctions EX and is attribution-only,
so it can't prevent this. Self-demote setters located: `xfs_mxfs_dlm.c` ~34091 (P109 `-EDEADLK`
upgrade recovery) and `xfs_inode.c` ~5138 (inactivation `-EDEADLK` retry) — candidates for why
test17's grant was `< EX` at a release immediately following its own creates.

``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md`` then
ran a day-wide census (`scripts/d0496_census.py`, 1472 kernlogs / 46 run dirs) and reversed the
emphasis: ALL 101 `P22-DATASCAN-HIT`s trace to exactly two events, both on pre-D-0492-fix builds
(0.70.3/0.70.4, and the 0.70.9 D-0492 control lap itself) — every run on 0.70.5+ shows zero.
`P-FENCE-AILLEAK` is 0 day-wide; `P123-DIRFENCE-SKIP` with `in_drain=1` is 0 of 97080. Re-reading
the 083456Z window in full: the index ROOT (25433712) was in fact written at every EX-held release
— it is NOT the hole. The 18 P123 suppressions on root/leafs at PR releases were cold-read copies
(`has_bli=0 lseq=0 wseq=0`) — harmless. The real leafn blocks showed `P285-F4-BLI-FREED-OPEN`
(`committed_gen > submit_gen`) — the already-fixed (0.70.11) D-0492 retire-of-undestaged-log-item
shape, on a pre-fix build. Conclusion: D-0496's two *observed* events are the closed D-0492
mechanism recurring on old builds, not a new bug — but it is NOT yet proven no other producer
exists (residuals per the GPT ruling below). Landed: 0.70.18 (`mxfs.dir_datascan_heal` knob,
default 1, gating both `mxfs_dir2_datascan_lookup` call sites and both
`mxfs_dir2_leafless_removename` sites) plus `tests/sess498_heal_off_board.sh` (full 32/caw board
with the heal off), launched as chain s498a.

``docs/rulings/retire-datascan-heal-conditions.md`` — RULE-5 consult on
whether the heal-off board alone justifies flipping the default to 0. Verdict: experiment sound,
default flip on board+crash-pass alone UNSOUND. Six conditions must be excluded first: (1) stale
foreign replay of an older leaf/node image over a newer home image
(`D-FOREIGN-REPLAY-UNGATED-IMAGES` family); (2) split/leaf→node conversion where the release drain
lands data + new leaf but not the parent, leaving the new leaf unreachable; (3) the PR-mode fence
gating on `mode < EX` is unsafe if a residual *obligated* write from the preceding EX tenure
exists — must gate on "no local committed obligation", not raw mode; (4) xfsaild writeback
completing after EX handoff — handoff must wait for completion, not submission, of old-tenure dir
writes; (5) data landed before its leaf is durable, then handoff/death — the heal isn't always
benign, it can expose an uncommitted create; (6) mixed-version fleets, especially heal-on/heal-off
mixed. Also flagged: CIL-capture-vs-release races, buffer alias/registry misses, I/O-error paths
advancing `written_seq`, stale writes onto freed+reallocated dir blocks, rename cross-dir lock
sets, and index-algorithm bugs the scan masks identically. No sound sub-linear detector exists
without a new on-disk summary; cheapest sound options: piggyback a hashed (name,dataptr) probe onto
readdir, a sampled bidirectional census under a mutation-excluding lock, or mutation postcondition
checks — detection kept strictly separate from repair (report-only, never auto-expose an unindexed
dirent). Remove-side (`leafless_removename`): retire the lookup-side scan first; keep the remove
scan as a separately-knobbed counted diagnostic — it doesn't protect against LEAF-ahead-of-DATA.
Clean-key hazard: never update `i_mxfs_dscan_clean_key` on a miss while the heal is off; the key
needs a config epoch or must be invalidated on knob-mode change; read the knob with `READ_ONCE`.
Full retirement bar: replay family fixed/made impossible, trace-proof that no old-tenure write
completes after the next EX grant, release invariants cover every committed dir buffer including
split parents and delayed CIL/AIL, targeted fault tests + crash oracle pass heal-off, bidirectional
report-only census available during rollout, mixed-version mounts rejected.

## sess499: auditing the GPT conditions against the landed code

``docs/history/docs/history/docs/history/compiled-d0496-leafhole-datascan-heal-campaign.md`` — sess498 was
also killed by the safeguard flag right after launching s498a (heal-off board) and gating s498b
(the D-0492 crash-durability harness with `dir_datascan_heal=0`) behind it; a grind agent was left
blocking on both logs. Note: the ccloop Stop gate did NOT hold the session open on that live grind
agent — `keepgoing` fired anyway, so rig-gated background chains are not a safe reason to end a
turn (consistent with the project's don't-poll/don't-rely-on-remote-work guidance). Code audit
against the GPT ruling, reading 0.70.18: **Q4 (clean-key hazard) holds** —
`i_mxfs_dscan_clean_key` is written only inside `mxfs_dir2_datascan_lookup` on a no-hit scan, and
heal-off short-circuits before that call is ever reached, so no change was needed. **Condition 2
(split parent not drained)** — `mxfs_dir_flush_data_blocks_relsafe` snapshots every mapped
data-fork block under `i_lock` after commit, plus level-1 bmbt children and an extent-map-
independent `mxfs_dir_data_owner_scan`; no enumeration gap found by reading (residual: the
BTREE-fork `xfs_need_iread_extents` bail, covered by the bmbt/owner scans). **Condition 4 (xfsaild
after handoff)** — the drain write is a synchronous `xfs_bwrite`; an in-flight xfsaild write holds
the buffer lock so the drain blocks on its completion, and the postlude then retires the in-AIL BLI
and stales the buffer, leaving xfsaild nothing to act on later; no gap found by reading. Conditions
1, 3, 5, 6 remained unaudited at handoff, and s498a/s498b results were still pending harvest (rows
red, crash-consistency wall vs 90s pace budget, `dscan=0`/`heal_hit=0` confirmation, RESULT
missing/extra).

## State at handoff (sess499)

D-0496 open, severity critical. Root mechanism for the two *observed* leaf-hash-index-loses-entries
events is confirmed as the already-fixed D-0492 shape recurring on pre-0.70.11 builds — not a new,
distinct bug. `mxfs.dir_datascan_heal` knob (0.70.18, default 1) lets the heal be disabled for
experiment without removing the safety net. Default flip to 0 is blocked on the GPT six-condition
bar; conditions 2 and 4 are code-audited clean, 1/3/5/6 are not yet excluded, and the heal-off
board + crash-durability chain results were still in flight when sess499 handed off.
