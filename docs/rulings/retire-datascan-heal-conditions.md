<!-- sess498 GPT RULE-5 ruling: heal-off board is a valid experiment but NOT sufficient to flip dir_datascan_heal default; 6 conditions + residual produce… -->
# sess498 GPT ruling — retiring mxfs_dir2_datascan_lookup / leafless_removename (D-0496)

Context given: all 101 P22-DATASCAN-HIT of 2026-09-04 trace to D-0492 (retire of undestaged log item, fixed 0.70.11); proposal = knob mxfs.dir_datascan_heal (landed 0.70.18, default 1), control board + crash chain with heal off, then default 0.

## Verdict
Experiment sound; default flip on "board + crash chain pass" alone is UNSOUND while these are unexcluded:
1. Stale FOREIGN REPLAY of an older leaf/node image over a newer home image (D-FOREIGN-REPLAY-UNGATED-IMAGES family). Settling test: save an older committed leaf record, let another tenure land a newer image, replay the saved record, prove the veto by trace + LUN read; also across block free/reuse. Instrument home_lsn_before/replay_lsn/disposition/home_lsn_after.
2. Split / leaf->node conversion where the release drain lands data + new leaf but NOT the parent (new leaf unreachable). Force splits at release boundaries; assert every touched block has written_seq >= committed_seq before the next EX grant; verify reachability of BOTH split leaves.
3. PR-mode fence: "mode < EX => suppress" is unsafe if a residual obligated write from the preceding EX tenure exists; must be "no local committed obligation". Test delays between commit/CIL/AIL/submit/complete with EX->PR downgrade at each point.
4. xfsaild writeback after EX handoff: handoff must wait for COMPLETION (not submission) of old-tenure dir writes; inject I/O delay, verify no tenure-N completion after tenure-N+1 grant.
5. Data home-written before leaf durable + handoff/death: the scan can expose an UNCOMMITTED create (heal is not always benign). Live handoff needs the leaf landed or the acquirer consuming committed log state.
6. Mixed versions: reject incompatible mounts (on-LUN protocol epoch) or test rolling combos; heal-on/heal-off mixed fleets are especially bad.
Also exclude: CIL capture racing release (buffer absent from drain set), buffer aliases/registry misses, I/O error paths advancing written_seq, old writes/replay on freed+reallocated dir blocks, rename cross-dir lock sets, index algorithm bugs (split/compaction/dup-hash) which the scan masks identically.

## Detector (Q2)
No sound sublinear per-negative-lookup detector exists without a new on-disk summary. Cheapest sound ones: (a) piggyback on readdir: for each enumerated live name, hashed-probe (name,dataptr) and report mismatch (sound per entry under stable PR/EX state); (b) sampled/background BIDIRECTIONAL census under a mutation-excluding lock (restart on gen change); (c) mutation postcondition checks (must cover all entries moved by a split, not just the target). Separate DETECTION from REPAIR: report-only, never auto-expose an unindexed dirent.

## Remove-side (Q3)
Retire lookup-side scan first (hot path). Keep leafless_removename temporarily as a separately-knobbed, COUNTED high-severity diagnostic/cleanup path; it does not protect LEAF-ahead-of-DATA (stale dataptr) and masks DATA-ahead-of-INDEX after a lost data-side unlink. Modes: off / detect-only / repair. Retire both once the persistence protocol is proved.

## Clean-key hazard (Q4)
Do not update i_mxfs_dscan_clean_key on a miss while the heal is off; include a config epoch in the key or invalidate all keys on mode change; READ_ONCE the knob; on off->on the first miss must not trust pre-transition state.

## Retirement bar (GPT)
Replay family fixed or made impossible by recovery/locking order; trace-proof no old-tenure write completion after next EX grant; release invariants cover every committed dir buffer incl. split parents and delayed CIL/AIL; targeted fault tests + crash oracle pass heal-off; bidirectional report-only census available during rollout; mixed-version mounts rejected. Decisive measurement: under forced replay/split/downgrade/delayed-write/crash interleavings, every stable directory image has exact equality between live data-dirent set and reachable index set.
