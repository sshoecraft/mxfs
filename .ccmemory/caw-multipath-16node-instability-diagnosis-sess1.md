---
name: caw-multipath-16node-instability-diagnosis-sess1
description: 16/caw multipath (ccloop 26c41354): 1-8 pass, 16 FAILS with high-variance multi-mode instability (membership undercount, coherency lost-update, EX st…
metadata:
  type: project
---

## 16/caw multipath ladder — deep diagnosis (ccloop 26c41354, 2026-07-06, build 591A76FB)

**Criterion**: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh N caw` 17/17 at N=1,2,4,8,16,32 on ONE build. Marker `/src/mxfs/.ccloop/runs/26c41354-6702-4fa8-98e7-0aa08fef2e9a/criteria-met`. criteria.json shows 1/2/4/8 PASS (8 on 591A76FB); **16/32 = REAL WORK**.

### Infra (all working now)
- All 32 VMs boot via `virsh -c qemu:///system start testN`. mpatha (2-path) via `scripts/mpath_up.sh up N` (idempotent; run TWICE — post-reboot nodes often get 1 session on pass 1). Host: 2nd portal 192.168.120.2 + SCST auto-configured by mpath_up host_up.
- **Restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass after any reboot** (7 bytes).
- **/src NFS is NOT fstab-mounted** — every VM reboot loses it → run.sh mkfs "prep_fs.sh: No such file" PREP FAIL. run.sh power_cycle_node does NOT remount /src or reassemble mpatha.
- **NEW: `scripts/caw_preflight.sh N`** (I wrote it) — teardown wedged mxfs (power-cycle if needed) + mount /src + mpath_up up N + verify all N READY(src+mpatha+ko+mxfs-unloaded). RUN THIS before every ./run.sh so run.sh never power-cycles mid-prep. Works, verified 16/16 READY.

### 16-node is HIGH-VARIANCE — 4 distinct failure modes seen across runs
1. **Formation/convergence flake**: run.sh converge gate FAILs — test1 sees `MXFS-MEMBERSHIP active_count=15` while others see 16, stuck 170s. active_count = live disklock slot-table count (dlm/dlm.c:2716; NOT UDP). HB=2s, DEAD_THRESHOLD=31 samples=62s (generous, so it's a slot-table READ-coherency miss, not false death). memb_settle_ms=20000 (EX-freeze on membership change, sess39 anti-split-brain gate).
2. **Coherency lost-update**: rotating single "victim node" (node3 run1, node13 later) whose data is bidirectionally invisible — cache_coherency `uv gone node13_file30 / none remain got=1`, strong_consistency `node13_final value exp=20 got=`, posix_multi `sees node3 renamed content empty`, zsl `size ...got=`. ~1 file/hundreds. **HYPOTHESIS (unproven): membership undercount → nodes disagree on active_count → master=nodes[hash%count] differs → split-brain EX → durable lost-update.**
3. **EX-writer starvation**: cache_coherency TIMEOUT 300s (passes 85s other runs). SESS50-STARVE (dlm_caw.c:3704) fires 100s-800s×/node on hot inodes (root=128, test dirs 135-142). Fields are HEX bitmasks (h_ex=0x100=node8 holds EX), NOT counters.
4. **Self-fence wedge (catastrophic → 0/16 cascade)**: `P132-ILOCK-TIMEOUT ino=X waited_ms=180000 wr_last=xfs_lock_inodes comm=mv` — a rename holds inode i_lock(WRITE) 180s+ while blocked (starved DLM acquire), release-drain (mxfs_drain_ilock_read xfs_mxfs_dlm.c:472) can't get i_lock(read) → force_shutdown. Also `P-NOINO-RELFENCE-WEDGE` (noino bast drain, 12865). xfs_lock_inodes ALREADY pre-acquires inode DLM before rwsem (sess16 FIX-L3, Phase A) so it's AG-alloc-lock or a post-lock acquire that hangs. Fenced node's data vanishes + holds locks → peers wedge → 0/16.

### Established this session
- **posix_multi ALONE = PASS 16/16 clean/fast (~30s)**; middle-seq (posix+mmap+zsl) PASS 16/16, dlm_fairness 15/16 (test1 `drained got=1`). So 16-node FS is NOT fundamentally broken; failures are load/variance/contamination-dependent (matches [[sess43-STATUS-real-vs-contamination-map-and-plan]] — most suite fails are contamination).
- **MHT increase REFUTED**: `inode_mht_ms=600 dir_sf_mht_ms=120` made coherency WORSE (posix_multi PASS→0/16) — longer hold delays cross-node visibility. Defaults inode_mht_ms=300, dir_sf_mht_ms=40 tuned for 8 nodes (dlm_caw.c:9500/9509 comment: "per-syscall handoff bill scales with N, window does not"). Coherency needs SHORT MHT, starvation needs LONG — no single value wins at 16.
- Multipath paths healthy (not the victim-node cause); 8/caw passed on multipath, so victim-incoherency = DLM not multipath.

### NEXT (untried, ranked)
1. **Membership stability is the most tractable unified root** — monitor each node's active_count every 2s DURING a 16-node test; if it flaps mid-test → split-brain proven. Fix: harden disklock slot-table read coherency / undercount at 16 (FUA read of slot table, or count-hysteresis). This likely fixes the coherency lost-updates (mode 2) AND formation (mode 1).
2. Prevent self-fence cascade (mode 4): the 180s i_lock-drain shutdown is catastrophic; investigate what the rename blocks on (AG alloc lock?) — needs live /proc stack capture during wedge.
3. RULE 5: proven diagnosis done; MHT refuted. If ≥1 more distinct fix refuted → consult Fable (tier-1 now, `mcp__ask_fable__query`, omit max_tokens) — architectural: coherent+fair CAW DLM membership at 16-32 nodes.

Related: [[sess48-phantom-ex-waiter-bit-leak-rootfix]] [[sess50-phantom-ex-waiter-recompute-rootfix]] [[sess123-caw-ex-starvation-gemini-fairness-design]] [[sess130-caw-yield-livelock-conversion-priority-FIXED]] [[caw-multipath-ladder-progress-sess-5bea4199]]
