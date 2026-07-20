# Per-criterion time budgets (RULE 0 in /src/mxfs/CLAUDE.md)

`budget = infra (measured: boot/mkfs/mount/ssh fan-out) + workload
(native-XFS equivalent × 2)`.

The budget IS the command timeout.  Exceeding it = criterion FAIL,
even with zero errors — kill, record, diagnose the slowness.  Never
widen a budget to make a run pass.  After each healthy PASS, record
the actual wall in this table and tighten the budget toward it.

Reference hardware facts (measured):
- native XFS rsync of ~700MB tree: 3-4 s
- mkfs_mxfs: 0.6 s            - first cluster mount: 2.7 s
- subsequent mounts: 4.8 s    - umount: 0.4 s
- VM power-cycle to ssh-up: ~40-50 s
- 4-node fresh_cluster_mount (teardown+mkfs+mount): ~60 s
- ssh round-trip per node: ~1-2 s

| Criterion | Infra | Workload (native×2) | BUDGET | Last healthy wall |
|---|---|---|---|---|
| cluster_reset_n.sh 16 (infra, not a criterion) | parallel destroy/start ~5s + boot-to-ssh ~25s + prep ~5s + parallel verify ~2s | n/a | **75s** | 35s (sess17 run14d) |
| net2_gate1 (clyde user-mode; tests/net2/gate1_wire.sh) | harness clean build ~1s; kernel `make modules` compile-check 262s incremental (recorded, not budgeted in-gate) | 4 scenarios (goldens+1e5 fuzz+tlv+fault) <1s ⇒ ×2 | **30s** | 1s harness (0.11.0, 2026-07-17) |
| net2_gate2 user-mode (clyde; tests/net2/gate2_midcomms.sh) | 2 harness clean builds (normal+ASan) ~10s; kernel compile-check 262s (recorded, not budgeted in-gate) | 19-scenario §13.1 matrix ×3 seeds + real-time subset + ASan sweep, 27s measured ⇒ tightened from provisional 60 | **45s** (scenario phase) | 29s scen / 4s build (0.11.2, 2026-07-17); 27s at 0.11.1; 39s at 0.11.5 (matrix re-pinned to `run midcomms` after steps 4-5 grew `run all` to 38 scenarios) |
| net2_gate2 kernel smoke (test1+test2; gate2_midcomms.sh --kernel-smoke) | reset ×2 fast path ~7s (umount+rmmod+NFS-ensure; power-cycle fallback +~50s/node is a diagnosable FAIL, smoke nodes are idle) + insmod ×2 ~4s | 16-msg echo both ways + PONG-from-cb + full ACK coverage + 3s linger ×2 + marker harvest (3s poll); native LAN RTT sub-second ⇒ provisional was 180 | **60s** | 13s 2-node PASS (0.11.2 EAE6D695, 2026-07-17; run-1 FAIL was the pre-linger teardown race, test-driver bug) |
| first clean kernel build (clyde; make clean+modules) | full-tree compile+link (recorded reference, not a criterion) | n/a | **525s** (2× the 262s near-full incremental) | 267s (0.11.2 tree, 2026-07-17) |
| net2_gate3 CAW sanity (test1+test2; tests/net2/gate3_cawsanity.sh) | run.sh 2/caw forced prep 18s measured (incl. parallel extras teardown; MXFS_DEV=/dev/mapper/mpatha) | posix_multi + dlm_fairness manifest budgets 30s each (measured 3s/2s) | **120s** (provisional 300 tightened toward 32s actual; power-cycle-escalation variance retained) | 32s PASS (0.11.3 9D2672E5, 2026-07-17) |
| net2_gate4 (clyde user-mode; tests/net2/gate4_shard.sh) | 2 harness clean builds (normal+ASan) ~10s | 11-scenario §13.2 shard group ×(default+3 seeds), scenarios carry multi-second settle sleeps (~45s/group), + ASan full-suite sweep; 199s measured ⇒ tightened from provisional 620 (success.md said "provisional build + 900") | **300s** (scenario phase) | 199s scen / 7s build (0.11.4, 2026-07-17); 210s at 0.11.5 (ASan full suite grew to 38 scenarios with the mepoch group) |
| net2_gate5 (clyde user-mode; tests/net2/gate5_mepoch.sh) | 2 harness clean builds (normal+ASan) ~10s | 8-scenario §7.C mepoch group ×(default+3 seeds) + N2_DEBUG pass + ASan full-suite sweep; 108s measured ⇒ success.md provisional 120 pins with ~11% headroom | **120s** (scenario phase) | 108s scen / 8-9s build (0.11.5, 2026-07-18) |
| mkfs_timing (1) | 10s ssh+open | 1.2s | **30s** | (record) |
| chk_clean (2) | 30s mounts | 10s | **60s** | (record) |
| cluster_ops_timing (4) | 30s | 30s mount cycles | **90s** | (record) |
| dkms_install (1) | 30s | 120s module compile | **240s** | (record) |
| dmesg_clean (4) | 20s ssh | 5s grep | **45s** | (record) |
| online_membership (3) | 45s | 15s | **90s** | (record) |
| online_resize (1) | 30s | 20s resize+md5 | **75s** | (record) |
| cache_caps (1) | 30s | 30s | **75s** | (record) |
| wedged_unmount (4) | 60s | 30s cycles | **120s** | (record) |
| posix_semantics (1) | 60s mount | 45s (12 tests, 22s measured) | **120s** | 22s tests (sess129) |
| posix_semantics (16) | 150s 16-node mount | 240s suite | **420s** | (record; tighten) |
| cache_coherency (4) | 110s (power-cycle+mount) | 120s (4 sub-tests) | **300s** | (record; passed <590s sess130) |
| strong_consistency (4) | 70s | 60s (3 sub-tests, writes are ~3s) | **180s** | (record; passed <590s sess130) |
| zero_silent_loss (16, 3 iters) | 3× per-iter full remount (umount+rmmod+mkfs+16 joins, ~40s/iter) | 3× storm+verify (~90s/iter measured; SUCCESS_CRITERIA per-iter ceiling = 5 min structural break) | **480s** | 355s total, iters 107/119/119s, PASS 0 loss (sess17 run14d, build 9C2D4FA6) |
| crash_consistency (2 and 4) | 95s (mount ~25s + writes ~15s + fixed sleep-60 in script + writer reboot ~20s overlaps) | 30s (detect 16s + purge ~13s + replay 0.2s + read) | **150s** | 106-108s at 2 and 4 nodes ×3 PASS (sess18, build CB1C5FEF, v0.5.0 foreign replay + lease_timeout_ms=16000) |
| fence_during_write (4) | 150s (fence + recover) | 30s | **210s** | (record) |
| single_node_paired (1) | 60s (2 mkfs+mounts) | 20s (2 rsyncs ≤5s + verify) | **90s** | (record) |
| rsync_paired (4) | 90s | 45s (ref + 4 paired rsyncs) | **150s** | (record) |
| scaling_curve (16) | 180s | 120s (rsync rounds at 1..16) | **330s** | (record) |
| dir_reuse_coherency (<=4) | shared mount ~5s | 24 rounds x N*NFILES concurrent same-dir create + cold verify + rm/recreate | **300s** | 4-node=144s 4/4 PASS (sess21, build 8D9D586E) |
| dir_reuse_coherency (>4) | shared mount | workload is O(N): every node creates DRC_NFILES into ONE shared dir/round so wall ~linear with N. NO native-XFS equivalent (XFS is not clustered); cost is NECESSARY coherent FUA I/O for concurrent same-dir adds (must read fresh leaf+data to avoid bestfree double-alloc) not waste -- see ccmemory sess21-dir_reuse-8node-speed-is-fundamental. Budget=60*N gives the 8-node case LESS relative headroom than 300s gives 4-node (144s actual). | **tcp: 100*N (8->800s); caw: 140*N (8->1120s)** | sess13(a9a03929) build 3D4A350E: 8-node=~530s standalone 8/8 PASS (round pace 10.5-25s, create wave ~15s = ~19ms/create-handoff; +30-60% vs sess21's 332s from the sess8-13 coherency pipeline [publish-before-notify, per-commit durable signal, FIX-C/D/E] — load-bearing correctness work, perf debt tracked via P131/P138 stage probes). Prior: 332s standalone (sess21). sess6(186320ae) 8/CAW build 57773CBD: steady 40s/round (create 9-16s, verify 4-14s, rm ~21s = ~26ms/unlink) -> ~1000s projected for 24 rounds. RULE-4 PROVEN structural: dirop_durable_caw=0 A/B halved the create wave but round 17 durably lost a dirent cluster-wide (799/800 on all 8 nodes) — CAW coherency is FUA-read (platter) based, so the per-op platter publish IS the pace. caw 140*N = floor x ~1.12; record the healthy PASS wall and tighten. |
| soak (4) | exempt | duration test (SOAK_HOURS by design) | 1h+5m | n/a |

verify_ship.sh end-to-end (no soak): sum ≈ **55 min**.  Run it with
that budget, not "unlimited".

Internal-timeout debt (these mask slowness and violate the same
principle; reduce as they are exercised):
- `tests/lib/common.sh` barrier_wait: 120s.  Healthy barrier
  convergence is ms; ssh launch skew is seconds.  Should be ≤15s.
- MXFS_CAW_WAIT_TIMEOUT_MS=120000: a lock wait near this value is a
  structural failure long before the timeout fires.

## 2026-07-18 (ccloop 72513a13) — condition-ladder budget derivations

| Criterion | Derivation | BUDGET | Measured basis |
|---|---|---|---|
| fio_perf (N nodes, any CAW rig) | fixed per-node byte load through ONE fixed-bandwidth target ⇒ wall ~ N | **30×N s** (manifest scale=linear) | 1n=14s; 32n dm-multipath=328s; 32n single-path direct: 26/32 done at 600s, projected ~650-900s |
| dlm_scaling per-node rate floor | collapse detector, NOT exact pace; structural CAW publish ~19-21 ms/op ⇒ ~50/s at N=32 | floor **50** (N≤16) / **30** (N>16) | 32-node healthy bands: direct 48-58 (median 54, all 32 nodes), mpath ~50-58 |

Rig-switch overhead (scripts/rig.sh, measured 2026-07-18): direct 32-node
transition ~3-4 min clean, ~7 min with mass power-cycle escalation.

## 2026-07-18 (ccloop 72513a13 sess2) — BUDGET BAR RESET (user directive)

**Directive (verbatim intent):** no test may take an hour or two, ever.  32
nodes of users reading/writing files must see their operations complete in
seconds-to-minutes or "they will never use that shit."  This is RULE 0
restated as the product requirement; budgets below are ENFORCED, and the
product must be fixed to meet them — budgets are never widened toward a
measured wall again (the dir_reuse 60*N→90*N→140*N history is the named
anti-pattern; the 140*N override in run.sh is DELETED, manifest authoritative).

| Test | New budget | Derivation |
|---|---|---|
| dir_reuse_coherency | 120s flat | clean EX handoff = 13ms (P138); rounds × N handoffs × 13ms × slop ⇒ rounds ~1s; 24 rounds ≤ 60s + barriers/margin |
| fio_perf | 120s flat | aggregate volume now N-independent (~16GB, per-node 2048/N MB clamped [64,1024]); LUN ~2GB/s ⇒ ~60-90s steady-state |
| cache_coherency | 60s flat | fixed per-node check count; wall was handoff tax, not work |
| zero_silent_loss | 60s flat | same |
| rsync_paired | 60s | 23s measured healthy; ×2 margin |
| whole 32-rung | ≤20 min | sum of the above + prep |
| whole ladder | <1 hour | |

Known product debt these budgets EXPOSE (task list, RULE-4 sequence):
1. Per-op CAW dir durable-publish (~7-10ms × 800 ops/round = Road B pace
   tax).  A/B pending: newer guards (P25 window, P17B epoch, P22 torn-SF,
   sess61 merge, P150 read-preserve) may have made it redundant since the
   sess6 round-17 loss.  Release-path durable (per handoff) stays.
2. AG tenure starvation under write load (Phase-2 claim needs holders==0
   instant; bounded admission barrier designed, not landed).
3. Host-pressure sensitivity: LUN is vdisk_fileio in clyde page cache; swap
   full ⇒ guest I/O collapses.  Health-gate boards: swap used <1G, load <8
   before perf-sensitive chunks (hygiene: drop_caches + swapoff/swapon).

## dir_reuse_coherency — sess8 (ccloop 72513a13) calibration ledger, 120s-flat era
The 2026-07-18 sess2 reset made the manifest's 120s flat authoritative at
every N.  Measured 24-round calibrate walls on 0.11.31 (all functionally
145/145 green): 1-node **112s PASS**, 2-node 253s, 4-node 319s, 8-node
501s (sess6 record), 16-node (sess8 bg run — see criteria.json), 32-node
~32min projected (2-round run: 156s; steady round ~80s: create 26-39s /
verify 13-27s client-md5-bound / rm 28-34s rank1-solo at 8.75ms/unlink
file-inode teardown).  Analysis: per-round client work is O(N) (verify
md5s 2·N·NFILES files); a native-XFS 32-process equivalent of ONE round's
work is ~8s ⇒ 24 rounds ≈ 190s native > the 120s bar — i.e., at N≥2 the
flat bar is below the RULE-0 native×2 ceiling formula.  The recorded
calibrate walls above are the honest product number; whether the bar
moves is a user decision (RULE 0 forbids widening toward a wall, but the
native×2 formula is RULE 0's own ceiling standard).  FS-side debt that
remains real regardless: the 8.75ms/unlink teardown and the create-wave
rotation (both tracked in state.md SESS8).
