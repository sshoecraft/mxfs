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

## Mount-path recovery barrier (0.11.401, sess57) — a CONDITIONAL mount cost

`mxfs_dlm_mount_recovery_barrier()` runs inside `xfs_mountfs()` right after
`xfs_log_mount()`.  When — and only when — this node finds a peer whose
heartbeat was ALREADY frozen at mount time and which still holds CAW grants,
the barrier blocks the mount thread for the dead-confirmation window before
it may fence that peer and replay its slice:

    confirm window = dead_threshold × HB interval
                   = 31 × 2000 ms = **62 s**   (shipped defaults)

then one foreign-slice replay per confirmed slot (0.2 s each, measured at
crash_consistency 2/4-node).  A clean cluster pays **0 s** — there are no
frozen-slot grants to confirm.  A crash-recovery mount pays 62 s ONCE for the
whole cohort (the confirmation is a single batched window over the mask, not
per slot).

This is NOT slack: it is the price of not fencing a node that is merely slow.
The pre-0.11.401 code paid the same 62 s off an async worker AFTER the mount
returned — which is exactly the bootstrap deadlock this build fixes, because
the grants being confirmed can block the mount's own recovery.

**Who pays it.**  Only a node MOUNTING while ANOTHER slot is frozen AND still
holds CAW grants.  It is not paid by a survivor that watches a peer die while
already mounted (that is the heartbeat monitor's async path, unchanged), and
it is not paid for the mounting node's OWN previous incarnation (mount step 4
handles that slot).  In practice it fires on: remount after a mass crash with
no survivor to replay, and a node rejoining a cluster whose dead peer nobody
has recovered yet.

Criteria that can hit it — verify a healthy wall on each before tightening:
crash_consistency, fence_during_write, fault_netpartition,
withdraw_recovery_test, ag_strand_repair.  crash_consistency's 90 s budget has
the thinnest margin on the board (86-88 s actual); if it starts timing out at
0.11.401, grep the mount's kmsg for `P225-SETTLE-VERIFY` / `MXFS mount
recovery barrier complete` to tell a paid confirm window from a real
regression — a paid window is a correctness cost to budget for, not slack to
absorb.

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

## 32-node CAW budgets (sess30) — derived, not round numbers

Written down BEFORE the run, per RULE 0.  The criterion carries its own
internal budget (printed by run.sh as `[wall/budget]`); the COMMAND timeout is
that budget plus the 32-node harness fan-out, nothing more.

| Step | Criterion budget | Harness fan-out | COMMAND timeout | Measured wall (0.11.262-265) |
|---|---|---|---|---|
| `./run.sh 32 caw prep_cluster` | n/a | mkfs+mount+converge | **240s** | 72s, 73s clean; 132s / 201s when a node needed a power-cycle (VM boot ~40-50s) |
| `cache_coherency` | 60s | ~30s | **90s** | 25s, 26s, 25s |
| `dir_reuse_coherency` | 120s | ~30s | **150s** | 105s, 106s, 108s |
| `dirent_durability` | 240s | ~30s | **270s** | 65s, 66s, 65s |

sess30 correction: earlier calls in this session used 500-540s blanket timeouts
on these same steps — up to 7x the derived budget on a 72s prep.  RULE 0 names
that a rule violation in itself, not merely wasteful: a blanket timeout cannot
FAIL a run for being slow, which is the whole point of the assertion.

### sess30 correction #2 — do not let the COMMAND timeout compete with run.sh

`run.sh` is itself the RULE 0 enforcer: it measures each criterion and prints
`[wall/budget]`, FAILing on overrun.  A command timeout set AT the criterion
budget therefore duplicates the assertion at a tighter value and kills the
harness mid-criterion — which leaves nodes unmounted and cascades into the next
run.  Measured: a 90s cap on `cache_coherency` (60s criterion budget + a GUESSED
30s fan-out) killed run.sh and left test6/test30/test32 without mxfs, so the
next run pre-asserted before it could measure anything.

Command timeout = criterion budget + measured 32-node fan-out (~30s) + one
power-cycle escalation (~50s, run.sh:433 destroy+start, parallel across nodes):

| Criterion | Criterion budget | COMMAND timeout |
|---|---|---|
| cache_coherency | 60s | **140s** |
| dir_reuse_coherency | 120s | **200s** |
| dirent_durability | 240s | **320s** |
| prep_cluster | n/a | **240s** |

The criterion budget stays the performance assertion.  The command timeout is a
BACKSTOP against an infinite hang, and must never be the thing that fails a run.

## Healthy-wall record — 2026-08-01, 0.11.317 board @ 32/caw (sess37)

Full 20/21 board (dir_reuse the only FAIL at 117s/120s — pace defect, open).
Actual walls vs budgets, for the RULE 0 tightening pass once a second healthy
board confirms them (do not tighten from one sample):

precond 1/10 · fio_perf 36/120 · cache_coherency 35/60 · strong 5/30 ·
posix_multi 8/30 · mmap 6/30 · zero_silent_loss 34/60 · dlm_fairness 22/30 ·
dlm_membership 6/30 · scaling_curve 42/90 · dlm_scaling 19/90 ·
rsync_paired 32/60 · crash_consistency 86/90 (thin — watch, do NOT widen) ·
fence_during_write 21/60 · fault_netpartition 10/60 · soak 31/60 ·
dirent_durability 67/240 · node_responsive 11/90 · kernel_health 3/120 ·
ag_strand_repair 81/240 · sustained_load 7/180 ·
dirent_publish_integrity 3/60 · dirent_type_integrity 4/60.

Candidates for tightening after confirmation: dirent_durability 240→120,
ag_strand_repair 240→160, sustained_load 180→60, kernel_health 120→30,
dlm_scaling 90→45, node_responsive 90→30.  crash_consistency runs 86-88s of
its 90s budget every board — its margin is the thinnest on the board and any
regression lands there first.

## D-513 forged-record probes (sess383, 2026-08-20) — MEASURED

`tests/d513_forged_record_checks.sh <shape>` forges an adversarial recovery
outcome record into an unused heartbeat slot, cycles ONE node's mount, and
asserts the disposition.  It is non-destructive: the other N-1 nodes stay
mounted, so it needs no re-prep.

Measured walls at 32/caw, 0.19.5 and 0.19.6:

- umount: ~1 s · forge/dump/restore (SG_IO round trip): ~1 s each
- mount that ABORTS on its first classification: **5-7 s**
- mount that ADMITS with an AG-scoped quarantine: **6-7 s**
- whole shape, end to end including the ssh fan-out: **13-20 s**

Budget: **60 s per shape** (`PER_SHAPE` in `tests/d513_forged_matrix.sh`).
That is ~3x the measured wall, and the failure it guards against is a wedged
mount, not a slow one — a shape that takes 60 s has not "nearly passed".

The two staged probes pay the dead-confirm window and are budgeted from it,
not from a round number:

- `tests/d513_lone_mount_refusal.sh` — the mount confirms a peer that was
  ALREADY frozen when we mounted, which costs dead_threshold heartbeat samples
  (~62 s at 31 x 2 s) by design, plus fence + the replay it refuses + the
  publish.  Budget **150 s**; the 62 s confirm dominates.
- `tests/d513_fswide_abort_preserves_death.sh` — two such mounts, each with
  the same ~62 s floor; the second also replays the victim's slice.
  Budget **150 s per mount**.
