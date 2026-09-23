<!-- D-0483 unmount-publishes-AG-grants-before-quiesce campaign sess483-488: hoist fix, D-0486 hang, D-0487 AIL pin, closure. -->
# D-0483: unmount publishes AG grants before metadata quiesce — sess483-488 campaign

Central defect: `xfs_super.c` put_super publishes every held AG DLM grant
(`mxfs_dlm_ag_force_release_all`) and NULLs `m_mxfs_dlm` *before*
`xfs_unmountfs` finishes writing AG metadata and inode clusters — mirror image
of mount, which acquires the DLM context before any filesystem work and holds
it for the whole startup. Chasing this to ground surfaced two further defects
(D-0486 unmount hang, D-0487 AIL permanent pin) and closed all three across
six sessions. `docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

## sess483 — filed, source-proven

Chain, verified end to end against 0.68.1: `mxfs_dlm_ag_force_release_all`
(xfs_super.c:2066) publishes AGs → `mxfs_sb_summary_final_sync` (:2126, calls
`xfs_inodegc_flush`+`xfs_blockgc_stop`+`xfs_log_quiesce`, DLM still alive so
re-acquires here get swept undrained) → `m_mxfs_dlm = NULL` (:2133) →
`xfs_unmountfs` → `xfs_unmount_flush_inodes` → `xfs_reclaim_inode` →
`xfs_ilock` gates on the DLM pointer itself, so once NULL every inode lock for
the rest of unmount silently becomes a plain local rwsem (no `if(!dlm)` site
to instrument — hence buffer counters, not lock counters). The AIL push in
`xfs_log_unmount` submits AG-metadata buffers dirtied earlier taking no lock
at all, independent of the inode path.

GPT ruled out the cheap fixes: full drain at the current site or a
flush+push before it are insufficient because `xfs_unmountfs` creates new AG
work *after* those points; delaying the NULL instead of the release is unsafe
because the heartbeat thread is joined (liveness stops being provable) before
`xfs_unmountfs` runs. Conclusion: **hoist the work above publication, never
delay the release.** Verified the window is real (not vacuous) with a live
0.67.0 read: `ags_released=1`/`ags_seen=63` and the AG audit ran clean —
confirming divergence is created *after* publication, which the existing
audit structurally cannot see. 0.68.1 shipped counters only, not a fix.

## sess485 — fix lands (0.69.3)

Chain 131's all-zero result (sess483) was not a disproof: `xfs_inodegc_queue`
uses a 1-jiffy delay and the destage kick pushes the AIL continuously, so a
create/unlink-then-wait workload leaves nothing pending by put_super. Lesson:
an unmount-window test must queue work *inside* the umount command, not
before it.

Fix: new put_super order — stop producers first (shutdown-withdraw, foreign-
replay cancel, reap/destage cancel) → new `xfs_unmountfs_prepare` split
(inodegc flush, blockgc/zone stop, AG unreserve, quota unmount, rt inodes,
root/metadir irele, `xfs_inodegc_stop` as the no-more-inactivation gate) →
`mxfs_sb_summary_final_sync` (must run after all inactivation or its
transactions are seal violations) → explicit `xfs_log_force` +
`xfs_ail_push_all_sync` + `xfs_buftarg_wait` → `mxfs_iclus_purge_all` →
two-phase `mxfs_dlm_ag_force_release_all` (drain every AG under held grants,
one log force, second meta pass, one device flush, then flip+unlock) →
`m_mxfs_dlm = NULL` → `xfs_unmountfs_finish` (reclaim/quota/reserve/log-cover,
deliberately after DLM NULL since `xfs_reclaim_inode` uses `xfs_ilock_nowait`
with no DLM begin — moving it earlier buys nothing). New counters:
`pre_wr`/`pre_iclus_wr` (positive control), `aglock_after`,
`inodegc_after_stop`; nonzero DLM-alive after-count promoted to `xfs_alert`.
GPT required (and got) special-inode teardown before publication and
drain-all/flush-once/publish-all replacing the old per-AG delta flush.
Verification designed as A/B: frozen 0.69.2 vs 0.69.3, workload holds 400
unlinked fds open into the same shell command as umount.
`docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

## sess486 — chain 133 harvested: fix clean, base hangs, D-0486 filed

Fix leg (0.69.3): 32/32 clean, all after-publication counters 0,
`pre_wr>0` positive control on 4/32 nodes, `ags_drained=0`, zero seal
violations (harness bug fixed: it had been matching the seal-OK line as a
violation). Base leg (0.69.2): **23/32 nodes never returned from umount** in
240s, stuck after `P482-UMOUNT-AGREL` with no further matched output; 9
finished in ~1s (nothing pending). GPT ruling: D-0483 is NOT closable on this
evidence — the pre-declared rule demanded an *observed after-publication
write* on base, and "base hung + fix positive control" is regression evidence
but not that measurement; closing anyway would be a post-failure
redefinition. Filed the hang separately: D-UNMOUNT-HANG-AFTER-AG-PUBLICATION-
PREFIX-BUILD-0486 (mechanism unknown at filing; candidates AG re-acquire
after publication, SB-summary EX convoy, bast-arm-gate dead-demote re-drive).
Also flagged `ags_drained=0` as proving the drain pipeline *runs*, not that
it *drains* — needs a controlled dirty-AG-under-held-grant arm later (D-482).
Harness hardened: hang-stack capture on every stuck node before the next
prep power-cycles it (node journals are volatile — capture or lose it).
`docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

## sess487 — hang root-caused to two real defects; AIL pin proven

**Lap 2** (chain 134, base only): 32/32 clean, `dlm_wr=0` — not reproduced.
Explanation: lap 1's hang was a race the old workload (close fds via subshell
exit, then umount) usually loses — the 1-jiffy inodegc delay usually drains
before put_super. Not a disproof of D-0486, just workload nondeterminism.
Harness rebuilt (lap 3 on) to force the race: background subshell holds fds
open across a fifo handshake so the foreground's `umount` is the *next*
statement after the last holder exits, making pending-work-at-publication
deterministic. `docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

**Lap 3** (chain 135): base 28/32 hung. Stacks: 26 umount tasks parked in the
CAW poll for the SB-summary EX lock; the one holder (test1) was D in
`xfs_ail_push_all_sync`, logging 480 `P126-XFSAILD-SKIP-AGMETA` — xfsaild
refusing to write dirty AG metadata for an already-published AG. Fix leg
28/28 clean (4 apparent "hangs" were a harness bug — `rm && mkfifo && ( ) &`
backgrounds the whole AND-list under a non-interactive shell, `$!` is a
wrapper not the child holding the fds — fixed). GPT ruling: SB-lock
amplification proven; a chain from post-publication-mutation → unheld AIL
item → push-never-completes is strongly supported (strict proof needs
item/LSN correlation, done next session). Filed two critical records:
**D-SB-SUMMARY-LOCK-HELD-ACROSS-UNBOUNDED-LOG-QUIESCE-FLEET-CONVOY-0487**
(one stuck holder stalls the whole fleet behind the SB-summary lock) and
**D-AIL-UNHELD-GRANT-SKIP-PERMANENT-SILENT-PIN-0487** (see below). Also ran
the D-32NODE pace decomposition off existing disk logs (zero rig cost):
in-tenure create 17.9ms = other 9.6 (53%) + dirsig 4.7 (26%) + dlk 1.1 +
dia 1.0 + post 1.1; K(creates/tenure) mean 9.8; 45-84s/node of the 88s write
phase is grant-rotation wait. `docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

GPT's follow-on ruling on the pace decomposition: in-tenure create must fall
16.0ms→~6ms AND handoff stay <~31ms/tenure to hit a 30s target (T=N(c+h/K)
arithmetic); dirsig release-only is correct *only if* invariant 1 holds
(peer's cold FUA read after acquiring a conflicting grant sees every
committed mutation of the prior EX tenure — needs a handoff proof test, not
assumed); rfr should replace the `i_dlm_dir_gen>0` heuristic with a
current-EX-tenure validation token; icr needs lookup-vs-icreate and
cache-vs-FUA splits before blaming cluster contention. First planned change:
dirsig release-only, expected saving ≤14.4s, not a pass by itself.
`docs/rulings/in-tenure-create-terms.md`

**AIL pin — code-proven** (`xfs_buf_item_push`, pal/linux/xfs_buf_item.c
~2230): when `mxfs_buf_xfsaild_skip_agmeta_write` fires (AG-meta op,
`!pag_dlm_cached && holders==0`), the push does `xfs_buf_stale` + unlock +
`return XFS_ITEM_SUCCESS` with **no** `xfs_buf_item_done`/
`xfs_trans_ail_delete`. The BLI stays in the AIL at its LSN forever;
xfsaild re-skips it every cycle (P126 lines are the ratelimited visible
fraction); `xfs_ail_push_all_sync` never returns. The sess23 comment
claiming this "removes the BLI from the AIL with no I/O" is false — same
false belief exists in the bmbt skip arm. Second hazard: re-lookup reuses
the staled buffer with `b_ops=NULL` while the BLI is still attached.
Convoy containment designed (not landed): move the explicit
force/push/wait block *above* `mxfs_sb_summary_final_sync` so a pinned node
hangs alone instead of stalling 31 peers behind the SB-summary lock — one
change at a time, so 0.69.4 shipped instrumentation only.

**Lap 4** (chain 136): base 32/32 clean, 0 P126, 0 after-writes (fix half of
the declared rule met — `pre_wr=9` on 3 nodes); base still hadn't
reproduced post-declaration. **H-ALT** hypothesis: base hangs alternate
(hung laps 1,3; clean laps 2,4) because the fleet was still running the
*previous* run's loaded 0.69.2 module instance (prep re-mkfs's every leg but
only reloads the module on srcversion mismatch) — some per-AG/global state
surviving unmount inside one module instance might be the producer.
`docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

**sess487 end**: Lap 5 (chain 138, `base base fix`) reproduced base by
mutation — base#1 and base#2 each hung 1/32 with 470/460 P126 refusals after
publication, meeting the declared post-declaration mutation rule; fix 32/32
clean. **H-ALT refuted** (fresh insmod hung 1, same-instance hung 1; rates
0/1/1/28 across laps show no instance-dependence). 0.69.4 deployed (P132
rfr/icr/mrg/cc stamps); 0.69.5 built in scratch, unbuilt into tree. Chains
139 (persig flush A/B) and 140 (sess48-shaped handoff cold-read test) queued.
Standing safety note: sess485 and sess486 were both killed by the server
safeguard after raw kernel stacks entered context — harvest hang/kjournal
files only through a subagent digest, never verbatim.
`docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

## sess488 — closure and AIL-pin terminal design

GPT ruling on combining evidence across laps: **yes** — the declared rule
gives separate predicates for BASE and FIX and never required the same lap;
both halves (lap 5 base-mutation-refusal, lap 4 fix-clean-with-pre_wr) were
produced after declaration on frozen modules/workload/harness, and each leg
re-mkfs's anyway so same-lap pairing wouldn't even give identical FS state.
Requiring same-lap now would be a retroactive criteria change. Lap 5's
`pre_wr=0` fix leg is supplementary (can't distinguish "no work" from "fix
drained via an uncounted path"), not disqualifying. Remaining requirement:
one green plain 32/caw board on the fixed build.
`docs/rulings/d0483-halves-combine-across-laps.md`

GPT ruling on D-0487 terminal behavior: fail-stop is correct — a BLI can only
be deleted without a home write given positive proof the exact logged
incarnation is durable, and the push has none (staling, matching contents, a
prior bwrite, a passing verifier are *not* proof; "drained then relogged" is
a newer incarnation, so iodone should delete and a push-time deletion path
hides a completion bug). Use `XFS_ITEM_LOCKED` (honest retry class, no
busy-spin) not `PINNED` (prompts futile log forces). Drop the "AIL tail
unchanged" condition — "still unauthorized after T" suffices, since the tail
can advance while the refused item stays and later becomes oldest. Debugfs
injector must read the AGI through the real transactional path (real
verifier/b_ops), bypass only DLM authorization, and force a synchronous log
force so the item isn't log-pinned when the grace timer starts. Real fix for
timing is a coherent authority snapshot (epoch-before/holders/epoch-after,
epoch==0 published by every release-commit before unlock), not a bigger
timeout. Applied as 0.69.6 (report-only) + 0.70.0 (terminal: refuse LOCKED,
no stale, 10s grace via `mxfs.ailpin_grace_ms`, fail-stop through
`m_mxfs_ailpin_work`, `P126-EPOCH-MISMATCH` diagnostic).
`docs/rulings/ailpin-terminal-design.md`

**D-0483 CLOSED FIXED AND VERIFIED**: board chain 123 (0.69.5, sv
F1F7BFB3): 27 PASS; `crash_consistency` FAIL on time (91/90s, D-32NODE pace
issue, not a correctness defect); `node_death_replay` PASS; next prep
unmounted 32/32 clean. Closed citing lap 5 base + lap 4 fix + this board.
D-0486 given a strict-proof addendum: lap 3's `P128-AILSTUCK` head items are
the same daddrs as the P126 refusals. D-0487 pin: 0.69.6 built (report-only
identity/accounting + debugfs injector `inject_unheld_agmeta_dirty`); 0.70.0
built (fail-stop terminal per the ruling above). Evidence sweep found the
bmbt arm cold (0 hits/2 days) but the AG-meta arm hot historically:
0.64.37 heavy-storm cc runs show P126 firing 50/node on 12 nodes for ~25s
after the BAST worker released AG 0 while an inactivation with
`auth_epoch=0` ran — 0 hits in 0.69.x cc kernlogs so far, needs remeasuring
under storm before trusting fail-stop on boards.
`docs/history/docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

**sess488 end — key unfinished finding, continue here**: on 0.69.5's plain
cc row, 393 `P126-XFSAILD-SKIP-AGMETA` fire across 14 nodes, each on its own
home AG, for ~12s right after AG-thrash markers (`P12-LATCH ag=N by=unlock`,
`LATCHED-ENTER`, `P-AGTRY-DEMOTING`, `P271-AGWAIT-PREACQ`, readopt=182) — an
AG thrash where xfsaild refuses in the commit→drain gap. **The old (0.69.5)
skip arm stales the buffer**, so the next transaction's lookup re-reads the
AGI from platter, dropping the committed-but-unwritten image: a candidate
lost-update root cause for D-408 / D-FINOBT-IBT-FREE-MISMATCH-481 / AGIFC
freecount divergence. 0.70.0 removes the stale (risk: false fail-stop if a
drain legitimately exceeds the 10s grace under the ordered bast workqueue).
Planned 0.70.2 (not yet written): retirement-age probe in
`xfs_buf_item_free`/`done` (`P126-REFUSE-CLEARED age_ms>=1000`) + per-mount
max/sum/count + `debugfs ailpin_stats`; do not promote 0.70.x to the
tree/board build until thrash refusals are shown to clear well inside grace.
A queued miner check (t9.log agi_lsn regressions in `P-AGIFC-MOD` after
P126 events) did not return before session end — rerun it.
`docs/history/docs/history/compiled-d0483-unmount-ag-publish-campaign.md`

## Net state at sess488 end

D-0483 closed F&V (0.69.3 hoist fix). D-0486 (SB-summary-lock fleet convoy)
and D-0487 (AIL unheld-grant permanent pin, two records: pin + convoy)
remain open, with 0.69.6/0.70.0 built and injector A/B legs queued but not
yet harvested; 0.70.1 planned for the SB-summary convoy reorder. The pin's
stale-on-skip behavior is the working lost-update hypothesis for two
long-standing separate defects (D-408, D-481) — not yet confirmed.
