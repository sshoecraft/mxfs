---
name: sess31-ROOT-merge-gate-skips-99pct-targeted-fix-design
description: sess31 ROOT: P-MERGEGATE proves dir_merge gate SKIPs ~99% (runs ~1×/tenure). Targeted fix = run a CHEAP per-block transactional reconcile only when a…
metadata:
  type: project
---

## sess31 — WHY dir_merge skips, and the targeted fix (P-MERGEGATE probe, build BCFA3AA6)

### Decisive evidence
Added gated probe P-MERGEGATE at the merge gate (xfs_mxfs_dlm.c:~5331, build BCFA3AA6 = keeper 37A37B10 + this probe; gated behind dirwr/instr → INERT at default). Repro with dir_merge=1 dirwr=1: **P-MERGEGATE decision=SKIP on ~99% of creates** (test1: 60 SKIP / 1 RUN; test2/5/8: 100 SKIP / 0 RUN). So `mxfs_dir_merge_peer_into_tp` runs ~ONCE per tenure then the gate (`evicted_incarn==i_generation && dir_gen==evicted_gen`) skips every subsequent create. That ONE run's snapshot (P18 added=0) missed the lost entry → never re-merged → lost. (dir_merge also still DLM-timeout shuts down — test2 shutdown=6 — so it's perf-doomed AND gated-off.)

### Targeted fix design (cheap, transactional, runs only when needed)
The whole-dir merge is too slow to run per-create (DLM timeout). Instead:
1. In the acquire-evict / modify-refresh, when a block is KEPT stale (the SKIP branch in mxfs_dir_drain_evict_data_blocks ~6128 and mxfs_dir_evict_data_blocks ~3055 — `in_ail && undestaged` DATA block), record its daddr (per-inode small list or set a flag + the daddr).
2. At the next modify (in the create transaction), for ONLY that specific kept-stale block: FUA-read disk, find dirents present on disk but absent in-core (peer adds), and `xfs_dir_createname` each (transactional → updates leaf/freeindex/freespace coherently, unlike write_merge's bnobt-corrupting data-only graft). Clear the record.
This reads ONE block (cheap, no DLM timeout), runs ONLY when a stale block was kept (rare), and folds in the peer's missing dirent before our destage → no clobber. It is a per-block variant of mxfs_dir_merge_peer_into_tp (xfs_mxfs_dlm.c:5291) — reuse its dirent-snapshot + createname loop, scoped to one daddr.

### OPEN question to verify first (RULE 4)
Confirm the kept-stale block's disk image actually CONTAINS the peer's add at modify time (publish-before-notify makes the peer's release fence FUA-write+flush before granting us EX, so it should). If the FUA read at modify time does NOT show node1_f4.md5, the root is instead a publish/transport-coherency gap (or a TCP DLM double-grant letting the peer add concurrently while we hold EX) — a different fix. Instrument the per-block FUA read content vs in-core at the kept-stale block.

### Build note
BCFA3AA6 deployed (= keeper + gated P-MERGEGATE; identical at default). To restore exact keeper, rebuild without the probe or just keep it (inert). [[sess31-merge-gate-once-per-tenure-is-why-dir_merge-ineffective]] [[sess31-HEAD-handoff]]
</body>
