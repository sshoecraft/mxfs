---
name: compiled-foreign-replay-crash-consistency
description: Compiled: live foreign-slice XFS journal replay for crash_consistency+fence_during_write; non-comparable per-node LSNs; di_changecount fix.
metadata:
  type: project
tags: [compiled, foreign-replay, crash-consistency, fence-during-write, journal, di_changecount, lsn]
---

# Live foreign-slice journal replay + crash consistency

Central topic: MXFS gives each node its own XFS log *slice* (`daddr = logstart + (slot % node_count) * m_mxfs_log_slice_bblks`, each with its own cycle/block numbering via `xlog_alloc_log`). When a node dies mid-write, its fsync-acked data is durable only inside its slice, so a survivor must **replay a dead peer's slice live**. That feature (v0.5.0) makes `crash_consistency` pass but introduces a data-reverting regression in `fence_during_write`, whose root is that **per-node slice LSNs are not comparable** and whose fix is to gate the foreign-replay skip on `di_changecount` instead of LSN.

## sess17 — root cause + design ([[sess17-crash-consistency-root-and-foreign-replay-design]])
On build `9C2D4FA6`, `crash_consistency` FAIL root-caused: writer acked 113 fsync'd records, reader saw `visible=1`. Proof: a fresh mount that claimed the freed slice triggered XFS recovery and the file then had all 114 records — data was durable in the dead writer's per-node slice, but **v5 had NO live replay of a dead peer's slice**. `v5_lease_expire_cb` (`dlm/v5_mount.c:485`) only purged CAW locks + disklock; the lazy-drain "surviving peer replays our journal slot" comment (`xfs_mxfs_dlm.c:8459`) was an unimplemented promise and portable `dlm/journal.c` was vestigial (`commits=0`).

Also passing this session: `zero_silent_loss` (prior 4800-loss FAIL was duplicate-ccloop contamination + an accounting bug booking mount-fail as N*DPN loss) and `mkfs_timing` (531ms).

Design of live replay on ONE elected survivor via a shadow xlog, safety pillars:
1. **Private dummy AIL** for the shadow log (kzalloc, INIT lists/locks, no xfsaild) — `xlog_find_tail` writes `ail_head_lsn`, so sharing `mp->m_ail` would clobber live log accounting.
2. **Skip the intent family (EFI/EFD) in pass2** under the foreign flag; leave slice DIRTY so the next mount-time claimer replays intents (LSN gating makes buffer re-replay a no-op → double replay is SAFE → election is perf-only).
3. **Skip mount-only steps** in `xlog_do_recover` under foreign (`xfs_ail_assign_tail_lsn`, sb re-read, `xfs_reinit_percpu_counters`).
4. **Skip the sb_lsn check** in `xlog_recover` under foreign (cross-slice LSN cycles incomparable — foreshadows the sess76 bug).
5. **Election**: lowest-live disklock-slot survivor runs replay.
6. **Cache invalidation**: `mxfs_dlm_peer_joined_flush(mp)` before (flush own dirty + invalidate perags so pass2 reads fresh disk) and after (drop stale views).
7. Slice geometry mirrors `xfs_mount.c:1038`.
8. `xlog_alloc_log`/`xlog_dealloc_log` are static → orchestrator `mxfs_xlog_recover_foreign_slice(mp, dead_slot)` lives in `xfs/xfs_log.c`; sets `XLOG_MXFS_FOREIGN_REPLAY` bit + shadow `l_ailp` before `xlog_recover`.
9. Trigger chain: `v5_lease_expire_cb` → `mxfs_v5_dlm_set_dead_node_notify` → `xfs_mxfs_dlm.c` handler queues work on `system_unbound_wq`.

Edits DONE (unbuilt): `xfs_log_priv.h` (`XLOG_MXFS_FOREIGN_REPLAY` bit 5 + `xlog_is_mxfs_foreign_replay()`), `xfs_log_recover.c` (pass2 intent skip, early-return gate, sb_lsn gate). Remaining: orchestrator in `xfs_log.c`, `mxfs_disklock_lowest_live_slot`, `dead_node_notify` in `v5_mount`, work struct/handler in `xfs_mxfs_dlm.c`, VERSION 0.4.11→0.5.0.

Secondary (16-node only): false-fence storm at `mxfs_lease_duration_ms=10000` — survivor replay/fence I/O delayed heartbeats → mutual PR preempts → reservation-conflict storm, 12/16 guests livelocked. (Attribution later refuted — see sess18.)

## sess18 — foreign replay SHIPPED, crash_consistency PASS ([[sess18-crash-consistency-PASS-foreign-replay-shipped]])
Build `CB1C5FEF` (VERSION 0.5.0). `crash_consistency` PASS: 2 nodes (123/123), 4 nodes (110/110), 4-node repeat (acked=106 visible=107); wall 106–108s, budget tightened 210→150s. Dmesg confirmed: `lease_timeout_ms=16000` → death at kill+16s → lowest-live-slot election → foreign replay ~160ms → reader saw all acked records.

Implementation completing sess17 design:
- **Orchestrator** `mxfs_xlog_recover_foreign_slice(mp, dead_slot)`. **First-deploy bug**: slice index must be `dead HB slot % m_mxfs_log_node_count` — passing the raw slot hit the `>=node_count` guard and silently no-op'd. HB slots keep incrementing across re-mkfs (a 4-node run used slots 8–11 then 12–15), so the modulo is mandatory.
- `xlog_dealloc_log` guard: only NULL `mp->m_log` if it owns it (shadow shares `l_mp`).
- Election `mxfs_disklock_lowest_live_slot(ctx, skip_slot)`.
- Trigger sets a bit in `mp->m_mxfs_foreign_dead_slots` (64-bitmap) + `queue_work`; `cancel_work_sync` added to both unmount paths in `xfs_super.c`.
- `lease_timeout_ms` module param → `mxfs_disklock_set_dead_timeout_ms` (ms → samples at 2s HB, floor 2). Default 0 = 31 samples = 62s (production).

**Critical infra discoveries**: `mxfs_lease_timeout_ms`/`mxfs_lease_duration_ms` module params NEVER EXISTED — `crash_consistency.sh` passed them for ~all of history and insmod silently ignored them; death detection was always hardcoded 62s while the script slept 60s → reader always checked before recovery. Therefore sess17's "10s test leases caused false-fence storm" attribution is WRONG (that storm ran at 62s detection; re-test). Also: **insmod on an already-loaded module fails File-exists SILENTLY and swallows INSMOD_OPTS** — `fresh_cluster_mount` now rmmod-then-insmods.

Accepted risks documented: purge→election gap ~13s (total kill→replay-complete ≈29s, fine for 60s window); **cross-slice LSN gating in pass2 (`xlog_recover_get_buf_lsn`) compares incomparable per-node LSN spaces** — flagged here, mitigated by flush-before-replay + drain-pipeline invariant, but this is exactly the latent bug that surfaces at sess76.

## sess76 — fence_during_write ROOT: foreign replay reverts peer data ([[sess76-fence-foreign-replay-reverts-peer-dir-LSN-noncomparable]])
Run `14d31183`. `fence_during_write --nodes 4` FAIL lost=400: test2 and test4 each wrote+fsync'd 200 files into their own subdir of shared parent `fence_test`; after victim test3 is fenced, node0 AND the writers themselves see 0 files and the n2/n4 subdir entries vanish. `drop_caches` does not recover → DURABLE loss.

Decisive repro `tests/diag_fence_visibility.sh` (KEEP): kill victim AFTER it finishes (progress=200) → survivors visible 200/200; kill victim EARLY (`KILL_AT=30`, progress≈145, cycling dir locks) → n2/n4 + files GONE durably. Bug needs the victim fenced WHILE actively modifying the shared parent dir.

ROOT (dmesg trace): test1 (slot 0, lowest live) replays the dead node's slice (`mxfs_dlm_foreign_replay_work_fn → mxfs_xlog_recover_foreign_slice (xfs/xfs_log.c:721) → xlog_recover`). test3 had RELEASED EX on `fence_test` after its mkdir n3 (letting n2/n4 in) but its on-disk journal still carries the stale `fence_test={.go,n1,n3}` image; replay re-applies it, reverting peers' committed n2/n4. `fence_test` is a tiny 5-entry SHORTFORM dir → stored in the inode → recovered via INODE recovery (`xfs/xfs_inode_item_recover.c:394-402`), whose skip is `if (XFS_LSN_CMP(on_disk dip->di_lsn, current_lsn) > 0) skip;`. With per-node slices the two LSNs are from independent sequences → `XFS_LSN_CMP` is meaningless → skip fails → stale test3 inode overwrites peers'. Same class as sess17's "foreign-replay incomplete".

Why zsl passes but fence doesn't: zsl's cold verify + normal storms always have a LAST EX-writer with a fresh base that overwrites → disk converges. Fence FREEZES test3's stale version (no later writer; victim dead) → durable.

FIX LEAD (proposed, not yet implemented): use a NODE-INDEPENDENT ordering. `di_changecount` exists both on-disk (`xfs_format.h:959`) and in the log (`xfs_log_format.h:448`) and is per-inode monotonic across all nodes. When `XLOG_MXFS_FOREIGN_REPLAY` set, skip the replay if on-disk `di_changecount >= ldip->di_changecount`. Analogous block-format dir / AG-meta buffer path (buffers use `xlog_recover_get_buf_lsn`) still needs a node-independent generation — harder, bound later; prove the shortform inode path fixes fence first. Boundary build `EAE5F4C0` (zsl fix) + P-DRAINSTUCK probe.

## sess77 — fence_during_write FIXED → PASS ([[sess77-fence-during-write-FIXED-foreign-replay-changecount]])
Run `14d31183`, build `3DC74E7D`. Fix in `xfs/xfs_inode_item_recover.c` `xlog_recover_inode_commit_pass2`: when `xlog_is_mxfs_foreign_replay(log)`, skip replay if `be64_to_cpu(dip->di_changecount) >= ldip->di_changecount`. `di_changecount` = VFS `i_version`, force-incremented on every dir/inode modify (`XFS_ILOG_CORE` set; reloaded from disk on DLM reload via `inode_set_iversion_queried`) → globally monotonic per-inode, unlike per-slice LSN. Non-foreign (mount-time own-slice) replay keeps the original LSN path.

Proof via P77-FRINODE probe (gated behind `mxfs_instr`), `KILL_AT=30 tests/diag_fence_visibility.sh --nodes 4`, replaying node test1: the ONE reverting record `ino=131 disk_di_lsn=0x100000004 cur_lsn=0x100000004 lsn_cmp=0 disk_cc=7 log_cc=5 verdict=SKIP`. `lsn_cmp=0` means OLD code (`>0` false) would have APPLIED the dead node's stale image (cc=5, pre-n2/n4) over on-disk cc=7 → reversion; new code 7>=5 → SKIP → peers preserved. All 219 other records APPLY correctly (test3's own n3 subdir ino=2097280 cc 139→146 + its 200 new files cc=0), so legitimate dead-node data still replays.

Validation: all 4 subdirs n1..n4 visible 200/200 live AND after `drop_caches`; `fence_during_write --nodes 4` RESULT PASS lost=0 (×2, builds `D5530967` ungated and `3DC74E7D` gated). `crash_consistency` no-regression expected: a sole-writer dead node has `disk_cc=0`/low < `log_cc` → APPLY, unchanged.

State after sess77: build `3DC74E7D` deployed (NFS /src), `fence_during_write` PASS, `zero_silent_loss` PASS held. Remaining FAILs: `posix_semantics_multi16` (>600s), `rsync_paired` (148%). Marker NOT written.

## Load-bearing constants
- Foreign-replay flag: `XLOG_MXFS_FOREIGN_REPLAY` (bit 5, `xfs_log_priv.h`), tested via `xlog_is_mxfs_foreign_replay()`.
- Orchestrator: `mxfs_xlog_recover_foreign_slice(mp, dead_slot)` in `xfs/xfs_log.c`; slice index = `dead_slot % m_mxfs_log_node_count` (modulo mandatory).
- Election: `mxfs_disklock_lowest_live_slot(ctx, skip_slot)`, `dlm/disklock.c`.
- Skip key: `di_changecount` (node-independent) NOT `XFS_LSN_CMP` (per-slice LSNs incomparable).
- Death detection: `lease_timeout_ms` module param; default 0 = 31×2s = 62s.
- Build progression: `9C2D4FA6` (root-cause) → `CB1C5FEF` v0.5.0 (replay shipped, crash_consistency PASS) → `EAE5F4C0`/`D5530967` → `3DC74E7D` (fence PASS).
