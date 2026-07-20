---
name: caw-16node-sess3-fua-saturation-hypothesis-and-lever-map
description: 16/caw sess3 (ccloop 26c41354): mode2 unlock-wedge FIX built+testing (3DC2B488, wall-clock unlock retry); modes 1+3 root = fua_always=1 shared-LUN sa…
metadata:
  type: project
---

## 16/caw multipath — sess3 (ccloop 26c41354, 2026-07-06, build 3DC2B488 from DC39A8DC)

Continues [[caw-16node-sess2-HANDOFF-levers-and-next]] [[caw-16node-ROOT-cumulative-backlog-settle-fixes]].

### Recorded state at session start (criteria.json)
- 1/2/4/8 caw: ALL PASS (17/17 each). **BUT device unconfirmed** — criteria.json doesn't record MXFS_DEV; must confirm they ran on /dev/mapper/mpatha (multipath), not /dev/sda. run.sh default DEV=/dev/sda; multipath needs `MXFS_DEV=/dev/mapper/mpatha`.
- 16 caw: 11 PASS (with MXFS_SETTLE_MS=8000) + 2 FAIL = dlm_scaling (rate<floor 0/16), dir_reuse_coherency (wedge). fence/fault/soak/dlm_lock_correctness UNTESTED behind wedge.
- 32: never run.

### MODE 2 (dir_reuse wedge) — FIX BUILT + TESTING (build 3DC2B488)
Proven cause (sess2 dmesg `unlock exhausted 100 retries`): INODE unlock CAS miscompares under 16-node hot-shared-dir storm → exhausts fixed 100-count → **-EIO → caller leaves lock HELD → peer re-BASTs → mxfs-ino-bast requeues → 1000+ kworkers → load 870 WEDGE**.
FIX (mxfs_dlm_caw_unlock_gen in dlm/dlm_caw.c, gated `caw_unlock_backoff=1`): an inode-unlock miscompare is ALWAYS transient (concurrent slot mutation; our bit-clear still valid on re-read) and unlike acquire, retrying longer is SAFE (we still hold the lock, only release later — no double-grant). So bound the retry by a wall clock (`MXFS_CAW_UNLOCK_DEADLINE_MS=5000` in dlm_caw.h) instead of 100-count → lock ALWAYS eventually releases → breaks the re-BAST amplification. (sess2's backoff-only was insufficient: caw_inode_backoff 0-6ms ALREADY ran each retry, wedge happened anyway → the CAP was the bug, not lack of backoff.)
TEST IN FLIGHT: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_unlock_backoff=1" ./run.sh 16 caw dir_reuse_coherency`. Through +485s: load STEADY ~2.0 (healthy; wedge=load>100), unlock_exhausted=0, bast_kworkers=0. Prev wedge hit at round 3 well before this → fix holding. Budget 140*16=2240s.

### MODES 1+3 — same suspected root: fua_always=1 shared-LUN FUA saturation
FUA read gate at pal/linux/xfs_buf.c:6647: `(mxfs_fua_always || !(bp->b_flags & _XBF_FUA_FRESH)) && ... needs_fua_read(bp)`. **fua_always=1 (DEFAULT, xfs_mxfs_dlm.c:24188) BYPASSES the _XBF_FUA_FRESH amortization → EVERY metadata read = synchronous SCSI READ(16) FUA round-trip to the one shared LUN.** The gate's design intent (v6a phase1, docs/v6-cache-architecture-proposal.md §11.9 H1): amortize O(metadata_reads)→O(invalidations) SCSI RTs while holding the DLM lock (should drop 2-node rsync 9min→60s). But fua_always=1 papers over coherency HOLES in the amortization (`fua_always=0` gave 4/tcp crash_consistency 3/4 + dir_reuse 0/4). _XBF_FUA_FRESH SET only at xfs_buf.c:4904 (successful FUA read); cleared at ~15 sites (dir-release invalidate, acquire-side dir_addname_coherent, gen-handoff). Coherency machinery heavily TCP-tuned; CAW may differ (SCST emulate_write_cache?).
- Mode 1 (cascade posix_multi/mmap/zsl as suite #3-5): tests DO `sync` before each barrier, yet under cumulative backlog a rotating victim's dirents/content go missing → a race window that WIDENS under load. MXFS_SETTLE_MS=8000 masks it (11/12 pass). RULE-0 legitimacy Q unresolved.
- Mode 3 (dlm_scaling): each node 2000×(create+stat+unlink) in its OWN PRIVATE subdir (.dlm_scaling/nodeR); FLOOR=50 ops/sec, WINDOW=60s. All 16 <50/sec (~20ms/op vs native µs). Disjoint → FUA reads on a node's own AG/inode bufs are coherency-UNNECESSARY (no peer touches them) but fua_always=1 forces them anyway. **sess79 tried "skip FUA when AG owned" → hung-task (ILOCK spin), REVERTED — that exact optimization is landmined.**

### RULE-4 GAP to close NEXT (before any risky FUA fix)
Mode 3 root is INFERRED (ruled out contention → concluded saturation), NOT measured. MEASURE first at 16: run dlm_scaling standalone with (a) iostat/IO-wait per node, (b) FUA-read count/op (mxfs_fua_count counters), (c) diagnostic `fua_disable=1` A/B — if rate jumps >>50 with FUA off, FUA IS the bottleneck (proves it). Only then decide: careful per-buf "held-continuously-since-fresh → skip FUA" (safer than sess79's AG-wide skip) vs plug _XBF_FUA_FRESH holes for CAW so fua_always=0 is coherent (honest RULE-0 fix, high risk) vs floor/settle legitimacy argument (weakest).

### Infra (unchanged)
`scripts/caw_preflight.sh N` before EVERY run (power-cycles wedged). MXFS_DEV=/dev/mapper/mpatha for multipath. NEVER pkill -f 'run.sh 16 caw' (self-match). Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass. Monitor long runs via local file /tmp/run16_dr_monitor.log (do NOT `find /mnt/shared` under storm — hangs 2min). Module auto-deploys via NFS /src/mxfs/mxfs.ko (nodes insmod it; no copy).
