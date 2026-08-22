# Resume — run c7ee71c6-d6a4-4316-9b43-cb64295f419d, after session 388

## Original task

Continue the MXFS production-readiness campaign.

Current project state — build identity, board tally, and the RULE 6 open
defects in severity order with each one's next step — is GENERATED FRESH
into the "## Current project state" section at the END of this prompt.
Start there, not with discovery. It is computed seconds before you read
it and supersedes anything earlier in the prompt that conflicts.

Work the open defects in the order that section lists them unless you
state why not.

Do NOT read or maintain state.md. It is a deprecated artifact of the
pre-ccloop handoff system (user directive, sess35; ccmemory
state-md-deprecated-do-not-maintain) and it is stale.


## Previous session

- session-id: `816f7198-e175-40f7-8ead-465dcafa572a`
- transcript: `/home/steve/.claude/projects/-src-mxfs/816f7198-e175-40f7-8ead-465dcafa572a.jsonl`
- approx context at last assistant turn: 501884 tokens
- tools used: Bash×137 Edit×9 Read×8 mcp__ccmemory__memory_write×5 mcp__ask_gpt__query×3 mcp__ccmemory__memory_get×2 ToolSearch×1 mcp__ccmemory__memory_list×1

## Files written or edited in the previous session

- /src/mxfs/xfs/libxfs/xfs_ag.h
- /src/mxfs/xfs/xfs_mxfs_dlm.c

## Last text from previous session

eness-doc updates (xfs.md + tests.md).
Chunk C: 5/5 PASS. Now chunk D (last 6 rows, 91 s walls → 240 s cap) and, in parallel, the session-state memory.
Rig: 25 AGs on 0.21.2, `ag_readopt_window_ms=50` + requeue=1 armed. Lap 1 of the treatment now; in parallel, documenting the 0.21.x knobs/probes in tests.md.
Built 0.21.3 (sv `A0308D3A12C83AC1FB12A1C`). Deploying at 25 AGs with the window armed, then lap 1.
Chunk A: 10/10 PASS on 0.21.3. Chunk B now (cap re-derived: 156 s walls + 20 s × 7 + 15 s = 311 → 330 s), and in parallel the xfs.md note for the 0.21.x lifecycle/gate code.
Chunk B: 7/7 PASS (crash_consistency 86 s of a 90 s budget — tight, same as before). Chunk C now.
Deployed 0.21.4 (sv `DFB4C46B445E6BBF308BEA1`). Running the rm-heavy rows that exercise the seam, followed by `kernel_health` (193 s walls + 20 s × 5 + 15 s → 320 s cap).
While the consult runs, reading the pieces any of the L-shapes will need: the rest of the ULBP unlock branch (quantum/eager-drain logic), and the worker's exit sites — independent reads, one batch.
Relay boundary reached — wrapping up. (A RULE-5 consult on the handoff-latch shape, task `k6vt2xojl`, is still in flight; its prompt is in this transcript and the ledger's PACE-388 entry carries the constraint set, so the next session can re-ask if the answer does not land before it starts.) Criteria not met; marker not written.

## Session 390 — what was done

**Root found and fixed (0.20.1, sv 99EB…) — the sess389 25-AG relfence wedge.** Every `P-AILMIN` on both wedged nodes named the frozen item as `type=4662 = 0x1236 = XFS_LI_EFI`; with the probe armed, zero `P129` lines → the EFI alone froze the noino fence while its owner (an extent-free defer chain) sat 13 s in a blocking wait for the shared AG. A convoy, not a deadlock. GPT rejected exempting intents; landed convoy-aware stall accounting instead: per-AG `pag_mxfs_agwait_inflight` brackets the blocking CAW acquire, `mxfs_noino_freeze_is_convoy()` attributes a frozen min (EFI→extent AG, BUF→daddr AG, INODE→ino AG) and such stalls are not charged against the 8-stall budget (45-try hard wall unchanged); `P-NOINO-CONVOY`, EFI detail in `P-AILMIN`.

**Second root found by stack and fixed (0.20.2, sv 1F8C…) — splits published under protest at 25 AGs.** `__mxfs_ag_dlm_lock` parked *nonblock* callers in `wait_demote` at entry; rsync's inline inactivation (`xfs_inactive_truncate → defer_finish → __xfs_free_extent → trylock`) slept there holding ILOCK on the just-unlinked inode while that AG's demote publication needed the ILOCK → `P87-TARGET-TIMEOUT stage=ilock` → `P86` split. Now nonblock returns -EAGAIN during demote (`P-AGTRY-DEMOTING`) and the existing -488 seam drops the ILOCKs.

**Verified:** 25 AGs (agcount < nodes) on 0.20.2+: **0 wedge / 0 shutdown / 0 split / 0 dirty-cancel** across 10 laps (was 2 wedges + 24 splits). 64-AG full board on 0.20.2 and on 0.21.3/0.21.4: every criterion passed. Evidence: `tests/logs/ag25_sess390_convoy_demote.txt`, `…readopt_close_wedge.txt`.

**Lifecycle item (0.21.x):** reference-free `xfs_icache_ino_lifecycle()` probe + `noino_lifecycle_requeue` (default 1, requeues BASTs on INEW/IRECLAIM/INACTIVATING/NEED_INACTIVE inodes); measured reachability ≈ 0 (RECLAIMABLE dominates), no regression.

**The honest negatives — re-adoption closure (PACE-388, ruling item C):** two knob-gated attempts both failed at 25 AGs: blocking waiters wedged two nodes (inode BAST worker holding ILOCK in the gate); nonblock-refuse + pinned re-adopt livelocked (1.5–2.2 M/lap) and starved peers. Root of the storm = the worker/re-adopter race at the last-holder unlock, not admission policy. Knob `ag_readopt_window_ms` stays -1 (inert). Constraints and the next design (latch at ULBP, bracket `wait_demote`) are in the ledger and ccmemory; consult in flight.

**Rig:** 32/caw, 64 AGs, 0.21.4 sv `DFB4C46B445E6BBF308BEA1`, 32/32 mounted. Board 25 PASS + 2 history-FLAKY + POLICY. **52 defects open (39 critical) — MXFS is not production ready.**

## Continue

Continue the original task from where the previous session stopped. This
summary is only an index — the full record is the transcript at the path
above, and the preamble ahead of this document tells you how to read it.
(Loop mechanics and how to signal DONE are in that preamble too.)
