---
name: caw-16node-sess2-starvation-cascade-and-fixes
description: 16/caw sess2 (ccloop 26c41354): dominant 16-node failure = cascade at test#3 (posix_multi); rotating victim nodes lose content. Built reintro_skip +…
metadata:
  type: project
---

## 16/caw multipath — sess2 findings (ccloop 26c41354, 2026-07-06)

Continues [[caw-multipath-16node-instability-diagnosis-sess1]] [[caw-16node-dirent-loss-CASE-B-PROVEN]] [[sess130-caw-yield-livelock-conversion-priority-FIXED]].

### Build lineage this session (from 591A76FB)
- `72371C38`: added reintro probe/skip (xfs_buf.c) — dir dangling-dirent fix, gated `dir_reintro_probe`/`dir_reintro_skip` default 0.
- `1D6280DD` (HEAD): + CAW fair-handoff (dlm_caw.c), gated `caw_fair_handoff` default 0.
- All new params DEFAULT 0 → ship behavior == 591A76FB unless flags set.

### What the 16-node suite ACTUALLY does (measured, 2 runs, IDENTICAL pattern)
Running `cache_coherency posix_multi strong_consistency mmap_coherency zero_silent_loss` at 16:
- **cache_coherency PASS 16/16, strong_consistency PASS 16/16** (both were FAIL in the OLD criteria.json records — so those records are stale/variance).
- **posix_multi FAIL 0/16, then mmap_coherency + zero_silent_loss FAIL 0/16** — a CASCADE starting at test #3.
- Convergence is CLEAN (all 16 active_count=16 stable ~40s) — membership is NOT the problem this session (contra sess1 ranked-#1 hypothesis).

### Failure CHAIN (proven)
1. During posix_multi, a ROTATING set of ~3 victim nodes (run A: 5/7/9; run B: 5/6/7) get EX-STARVED — highest SESS50-STARVE counts (test5=21-35). test5 consistently worst.
2. Starved victims can't land their writes before the coherency barrier → readers see their content EMPTY: `pm rN sees node5 renamed content(exp=posix_5 got=)`, `total count exp=1600 got=1597` (3 files missing). Same shape in mmap (`MISSING`) + zsl (`size got=`).
3. Harness RULE-0 cascade guard tears down the wedged mounts → victims unmount (mnt=n) → a stray write hits SCSI **reservation conflict** → `log I/O error -52` → `shut down due to log error (0x2)`. **The shutdowns are a TEARDOWN ARTIFACT, not the root** (they fire during `DLM shutdown complete`/`journal destroyed`).

### RED HERRING ruled out
- **`xfs_assert_ilocked` flood** (hundreds/node, stack `xfs_dir_lookup→xfs_dir2_format→xfs_bmap_last_offset→xfs_iread_extents`): PRE-EXISTING NOISE — test1 (which PASSED) also has ~96. MXFS's `xfs_ilock_data_map_shared` recurses into the DLM hook (dropping/relying-on-DLM); the upstream rwsem assert just complains. NOT the failure root. Re-adding ILOCK risks the deadlock MXFS deliberately avoids. Do NOT chase.
- **dir dangling-dirent reintroduce**: fired only 1× cluster-wide (P-REINTRO on test6). Real mechanism but MINOR at 16 — not the dominant failure. reintro_skip kept default-off, untested at scale.

### FAIR-HANDOFF FIX (caw_fair_handoff=1) — REFUTED as-is for the cascade
Root of self-promote free-for-all: `caw_wait_for_grant` (dlm_caw.c) — every EX waiter polls + self-promotes the instant `is_compatible`; release set `yield_to = ALL waiters` (line ~2759) so no ordering → unlucky node's poll cadence never wins. Fix (build 1D6280DD): release picks ONE round-robin next EX waiter (`caw_pick_next_ex_waiter`, first bit after releaser, INODE only); `caw_wait_for_grant` defers a non-chosen fresh waiter (upgraders exempt = conversion priority; 5s stale-clear = dead-node safety).
**RESULT: A/B run with caw_fair_handoff=1 gave the SAME 2-PASS-then-cascade; test5 starve 35→21 (partial) but victims still lost content + wedged.** So either (a) my round-robin doesn't fully engage, (b) starvation is on a DIFFERENT lock (AG?, not just inode-EX), or (c) the cascade is CONTAMINATION not fairness. NOTE P131-WAITLONG is caw_instr-gated (0 unless instr=1) — not usable as a signal without instr.

### NEXT (in-flight when this was written)
Run C: the 3 failing tests (posix_multi mmap_coherency zero_silent_loss) FIRST on a fresh cluster, ship config. If they PASS when first → CONTAMINATION/cumulative degradation (cluster doesn't settle between tests) is the root, not per-test bug → find what accumulates (leftover waiters? AIL backlog? starvation debt?). If they FAIL first → posix_multi has an inherent 16-node bug. Memory sess1 said "posix_multi ALONE = PASS 16/16" → leans contamination.

### Infra reminders
- `scripts/caw_preflight.sh 16` before every run (power-cycles wedged, mounts /src, mpath_up). `scripts/memb_watch.sh` written but UNRELIABLE (reads latest dmesg beacon; ring-buffer rotates it out under probe logging → false X/DIVERGE). Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass.
