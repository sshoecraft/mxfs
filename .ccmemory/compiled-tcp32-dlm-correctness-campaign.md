---
name: compiled-tcp32-dlm-correctness-campaign
description: Compiled: ccloop 72513a13 sess8-10 arc driving the tcp ladder from "tcp@8 dirent loss" to drc@32 first green — 9 proven fixes, 3 open fronts, recurri…
metadata:
  type: project
tags: [compiled, ccloop-72513a13, tcp, dlm, drc, RULE4, 32-node]
---

# The 32-node TCP DLM correctness campaign (ccloop 72513a13, sess8 → sess10)

Compiled from [[AAA-ccloop7251-sess8-TCP8-DRC-DIRENT-LOSS-dossier]],
[[AAA-ccloop7251-sess9-tcp8-CLEARED-pm-degeneracy-vs-methodology]],
[[AAA-ccloop7251-sess9-END-32tcp-fronts-and-fixes]],
[[AAA-ccloop7251-sess9-GPT-RULING-3fronts-32tcp]],
[[AAA-ccloop7251-sess10-FRONT-B-PROVEN-FIXED-reload-size-sever]],
[[AAA-ccloop7251-sess10-FRONT-A-CLOSED-drc32-first-green]],
[[AAA-ccloop7251-sess10-fio32-cascade-withdraw-relall-fix]].

Build lineage: 0.11.31 `2A8C8F26` → 0.11.32/33 (P152) → 0.11.34 (probe caps) →
0.11.35 `30FA152F` (epoch adopt) → 0.11.36 (reload_size_keep) → `C9087863` →
0.11.38 `0650D30A` (drc@32 green) → 0.11.39 `420FBA28` (withdraw relall).

## The arc

sess8 opened with what read as a catastrophe: at 8/tcp, `dir_reuse_coherency`
round 8 of 24 lost the entire shared dir image (ino 17318208, readdir=0 of
exp=800) on every rank simultaneously, including each node's own files, with
~5600 `LOOKUP_ENOENT REREAD_MISS` lines and a 1380s barrier timeout. Three
signatures fired together: divergent dir_gen views at the round-8 create wave
(test1 at gen=14 while peers sat at 57-63 — a stale incarnation winning EX),
a test8 AIL wedge (P128-AILSTUCK 90000+ iters on one inode cluster buffer,
liflags 0x21 = IN_AIL|FLUSHING — the `_XBF_DELWRI_Q` collision family), and a
P71-UNDERFLOW cycle every ~5s on the orphaned round-8 inodes.

sess9 decomposed it into **three stacked test-infrastructure artifacts, not one
FS bug** — the single most important lesson of the campaign. See "Recurring
failure modes" below. After the test fixes, the sess8 event was not reproducible
in 10 runs and tcp 1-8 went fully green.

sess9 then pushed to 16 and 32, landed four kernel fixes, and handed off with
three named fronts. sess10 closed A and B and left C open. drc@32/tcp reached
its first-ever green (102s/107s, 58/58 checks) on 0.11.38.

## Proven fixes, in landing order

1. **posix_multi wipe** (sess9, `tests/suite/posix_multi.sh`). rank1 `rm -rf $D`
   + barrier at test start.
2. **fio rand volume** (sess9, `tests/suite/fio_perf.sh`). Rand workloads own
   volume `128/N MB` floor 8m (`FIO_RAND_SIZE` overrides); seq keeps `2048/N`.
   Steady iops is volume-blind — a bandwidth-derived budget cannot gate an
   iops-bound workload.
3. **P152 trans-drain punt** (0.11.32/33, `mxfs_trans_drain_inode_unlocks`).
   Rename's final commit holds ILOCKs at `trans_free` by modern-XFS design;
   the deferred bast_process AIL drain needs those same ILOCKs → P113 22k-iter
   self-deadlock. When ILOCK owner==current, punt to `i_dlm_bast_dwork`,
   restoring CACHED+bast_pending under `i_dlm_lock` first (the defer had
   consumed them). Dossier: `tests/logs/tcp16_dlmscaling_wedge_20260719/`.
4. **demwait_redrive inline release** (0.11.33, `xfs_mxfs_dlm.c` ~22253).
   igrab refusal on a FREEING inode left a dead-DEMOTING unclearable when the
   waiter *was* the eviction. On igrab fail, run `mxfs_dlm_bast_process(ip)`
   inline (frame pins the struct; no ILOCK held).
5. **Probe-storm caps** (0.11.34). 22,822 dmesg lines/145s on one node during
   drc@32 rm = printk-serialized **DLM service blackout** — the master never
   processed requests while peers logged 119 remote lock timeouts against it.
   Capped P82-ADD/P140/P25-INSTR/P19/P2L-EX-GENMIS/P2L-INACT-LEAK/P61/P71.
6. **TCP epoch-consume adopt** (0.11.35, `xfs_mxfs_dlm.c` ~17172). Dropped the
   `transport_caw` qualifier: `ea_adopt = param || ea_self_clean`. Epoch adopt
   had been CAW-only; TCP's sole trigger was the P63 one-shot bit, documented
   in-code as lost ~80% of the time. RULE-4 basis: a 61s drc@32 repro where
   test21 ran round 3 on a stale DEAD dir incarnation (readdir 0/128, its 4
   creates orphaned = exactly the 4 names missing cluster-wide, zero P63 on the
   victim). Guards kept: `post_release=1` + clean-self. Killed the dirent-loss
   class.
7. **reload_size_keep** (0.11.36, default 1, 0644 runtime-writable) — Front B,
   below.
8. **batch_arm grace-slice clamp** (`xfs_mxfs_dlm.c` ~23052) — Front A, below.
9. **withdraw_release_all** (0.11.39) — the cascade fix, below.

## Front B — extending-write durable size=0 (data loss; ROOT PROVEN + FIXED)

Shipped first per GPT's ruling because it was direct data loss. Mechanism,
live-proven on test16 ino=16777344:

1. Writer mid-append: VFS `i_size`=16384 of an eventual 20480, `i_disk_size`=0.
   On 6.19 the data fork is mapped writeback-**unwritten** (`XFS_BMAPI_PREALLOC`
   in `xfs_bmapi_convert_one_delalloc`); `di_size` advances only in
   `xfs_iomap_write_unwritten` via `xfs_new_eof`, which **clamps to VFS
   i_size**. `xfs_setfilesize` is effectively dead code for buffered appends
   here — probe P-SFS proved 0 calls over full drc runs.
2. Grant bounce → reload (state=ACQUIRING) → disk dinode identical, or P34F
   dirty-skip forces `reload_identical=1` → fork kept, **but** `xfs_mxfs_dlm.c`
   ~19354 still ran `i_size_write(VFS_I(ip), ip->i_disk_size)` → VFS size
   16384 → 0.
3. Writeback converts the first extent with vfs=0 → `xfs_new_eof`=0 → `di_size`
   never advances, dirty pages beyond EOF discarded, delalloc punched at evict
   → durable size=0 nx=0. **`sync(2)` swallows all of it.**

Fix: `mxfs_reload_size_keep=1` skips the VFS-size re-sync when
`reload_identical` (from_disk skipped ⇒ `i_disk_size` is ours ⇒ VFS is
authoritative). The sess25 sync stays for genuine adopts. Validation was
two-sided: knob=0 reproduced the loss with both probes on the failing inode;
knob=1 ran 43/43 clean with 5 severs averted.

Probes left in tree (caps 300-1500): **P-RELOAD-SIZESEVER** (pre-19354),
**P-WU-CLAMP** (`pal/linux/xfs_iomap.c`, the durable-short signature),
**P-SFS** (`pal/linux/xfs_aops.c`, both arms incl. clamped no-op),
**P-IOEND-ERR**.

## Front A — round-open 300ms handoff staircase (CLOSED)

RULE-4 split isolated the round-open transient as the whole term: wave1 (64
creates) took 9.95s, then sync+wave2 (64 more) took 40ms. 10s/32 hops ≈ 312ms
per handoff = `inode_mht_ms=300`. The ACQUIRING-deferred BAST honor site armed
the dwork for the **full remaining mht window** instead of the grace slice;
every round-open first claim slept it out (P70-BP `held_ms`=301-307). BASTs
were arriving 22-75µs after grant — delivery was never the problem, the honor
path was.

Clamp to `dir_ex_batch_grace_ms` like the src=9 site: create phase 10s → 1.3-2s,
handoffs 0.7-2ms.

Faster handoffs then exposed two latent classes, both fixed:

- **Unanimous-48 dirent clobber** (all 32 nodes readdir=48/128): a write-side
  stale-base RMW made durable. Caught by the P-CCREGRESS tripwire
  (`xfs_inode_buf.c`, di_changecount regression at destage). Did not re-fire
  after the convoy fix; watch on regression runs.
- **TCP abandoned-mirror-grant convoy** — the 125-128s cluster-wide verify
  stalls. A granted-but-never-consumed mirror grant (gen never P74'd, requester
  gone) wedged with P15-REL-ABORT(orph=1) ×5993/126s. **Every escape was
  defeated**: the starving reader's own ACQUIRING reset both the 280-strike
  counter and the wall clocks every ~1s. Two fixes: (i) removed the ageless TCP
  `gg!=0` GRANTWIN-PARK (ACQWIN-PARK's `acq_inflight>0` already covers real
  mid-completion on both transports); (ii) **P15-TCP-ORPH-PROCEED** — when
  `orphan_live && acq_inflight==0 && gen unmoved && no holders` persists ≥
  `tcp_orphan_force_ms` (500, 0644) on `i_dlm_orphan_since_ns` (reset **only**
  on mode!=NL, never on ACQUIRING) → proceed to entry-anchored, gen-guarded
  release.

Test-side: **run_bounded 100ms polling** (`tests/suite/lib.sh`). The 1s
kill-0/sleep lap quantized rm-rf to a constant 4.02s against an isolated
1.1-1.65s, and burned ~1s per mkdir per round in pure sleep.

Round anatomy at green (rank1, ~12s/round): create 1-2s (slowest node up to
5.1s by rotation position), verify 2.2-2.7s, rm 1.6-3.3s, coord ~1s.

## The 32/tcp fio cascade — one starved AG lock takes down six nodes

Traced across four nodes' logs:

1. fio_perf@32 ground to 686s; cluster-wide degradation, cause **not** isolated.
2. A test29 writeback-alloc kworker starved on AG-17 EX against master test21
   (P-LKTIMEOUT-REMOTE type=3, ~1.024s cadence; the 10..5 countdown was the
   ratelimit *tail* of a 60-retry budget) → terminal -ETIMEDOUT →
   `xfs_trans_cancel` of a **dirty** tx → forced shutdown (`xfs_trans.c:1069`).
3. test29's DLM master service kept running post-shutdown (+634s granting PRs —
   the service is pure protocol, needs no FS) **but** its own held grants stayed
   in every master's table and its dead FS could never serve BASTs for them.
4. rm on five nodes needed dir ino=128 EX → BAST to the dead holder → never
   released → terminal rc=-110 → each node's `ilock_begin` unrecoverable arm
   force-shut it down too. Five dominoes off one root.

Fix: `mxfs_dlm_withdraw_release_all(ctx)` (dlm.c, exported in dlm.h) — on
withdraw, snapshot every `ctx->buckets` entry with `owner==local` (granted
mirrors, own local-master grants, abandoned WAITING) and run standard
`mxfs_dlm_unlock` per resource. Called from `mxfs_v5_dlm_shutdown_withdraw`
**before** heartbeat stop. TCP-focused; CAW's side is already handled by
disklock slot purge. Print: P-WITHDRAW-RELALL.

## GPT ruling (RULE 5) — the governing design theme

**A pending BAST is pressure to relinquish, not loss of grant.** Operations
admitted under the current EX epoch must COMPLETE under it; only NEW admissions
stop. This is the frame for the whole grant lifecycle:

ACTIVE/EX (admit, tag ioends with grant epoch) → QUIESCING on BAST (block new
admissions only) → DRAINING (already-admitted ioends run conversion +
setfilesize **under the still-held EX**; wait for data writeback, unwritten
conversion, setfilesize tx, log/destage) → only then wire unlock. Admitted
ioends carry a drain-owned authorization token and never re-check
`bast_pending` like new ops.

Hard rules from the ruling:
- **Never requeue an ioend after ending page-writeback / native accounting** —
  `sync`'s `file_write_and_wait` must keep covering it. There is no AIL item
  before the setfilesize tx exists.
- Failed conversion/setfilesize must **fail the drain** (quarantine the grant),
  never convert into a successful unlock.
- `nx=2` does not prove conversion ran — trace extent STATE.
- Eviction is a secondary safety boundary: the evict hook must synchronously
  quiesce all private async state before freeing. `I_FREEING` with
  bast_pending/stale + a live ioend = assert/quarantine.
- Ordered B → C → A, with the explicit warning that **A is not the correctness
  fix for B** (it only shrinks B's window).

## Front C — AGI unlinked-bucket leak (STILL OPEN)

P2L-INACT-LEAK fired 2001× at 32/tcp against an in-code comment
(`xfs_inode.c` ~3700) asserting it must be zero — the P2I demote+reacquire fix
is not holding. GPT's design, not yet implemented:

- Durable orphan/free intent must bind to **(ino, GENERATION)**; an incarnation
  may not be reused until orphan-removal + ifree commit atomically under a
  cluster LIFETIME lock (GFS2 iopen / OCFS2 orphan-dir semantics).
- **Demote+reacquire is NOT a freshness boundary** — cached grants and stale
  buffers defeat it. Likely why the "fix" fires 2001×: reload reuses a stale
  buffer, or is skipped during I_FREEING, or disk still holds the pre-free image
  because the previous freer's destage was skipped (cascading staleness).
  Diagnose via an **uncached read of di_gen**.
- Inode-number-only AGI chains are **ABA-vulnerable**: either forbid reuse until
  chain cleanup, or add a side orphan structure keyed (ino, gen).
- Lock order: DLM lifetime lock → AGI lock → buffer/inode locks.
- A stale actor must never act destructively on a newer-gen inode; a gen older
  than durable intent is a destage/visibility invariant failure and should be
  loud.

## Recurring failure modes

**Test-infrastructure artifacts impersonate filesystem bugs.** The sess8
"catastrophe" was three of them stacked. The sharpest instance: posix_multi
never wiped its dir, so on re-run `op_renamed_N` already existed as a hardlink
of `op_src_N`'s inode; GNU `mv` on two hardlinks of one inode errors rc=1 and
does nothing; the `test ! -e` assertions inverted. **The one "FAIL" node was
telling the truth and the seven "PASS" nodes were the stale ones.** Check test
determinism under re-run before believing a coherency failure.

**Budget violations hide inside calibrate-PASS.** tcp fio_perf walls of
813-1024s against a 120s budget recorded as PASS. A calibration tag is not a
pass; audit for it.

**Measurement legs must be paired in time.** `fio_perf_vs_xfs` @2 failed at 68%
on morning-mxfs vs afternoon-ceiling and passed at 101% when paired. Single raw
samples spread 254..1153 MiB/s at the same N (host cache absorption vs writeback
throttling regimes) — medians of 3 only (`RAWCEIL_SAMPLES`).

**Stale incarnations win races and publish authoritatively.** Both the sess8
divergent-gen event and the sess9 test21 repro are the same shape: a node acting
on a dead dir incarnation. Gen-qualified reads and the epoch adopt are the
defense; cross-incarnation reuse prints are expected noise.

**Instrumentation itself can cause the outage.** printk storms serialize and
blackout DLM service. Cap every probe.

**A dead node's grants outlive its filesystem.** The DLM service survives an FS
shutdown, so grants stay in master tables with nobody able to serve their BASTs.
Any force-shutdown path must release everything it holds.

**Escape hatches get reset by the very starvation they guard against.** The
convoy defeated all escapes because the starving reader's own retry reset the
strike counter and wall clocks each lap. Age counters must reset on state
transitions that mean progress, not on any activity.

## Open at the end of the arc

- **Front C** (AGI bucket leak) — designed, not implemented.
- **The fio@32 root grind** — why the run took 686s and why AG-17 was held >60s.
  Re-measure alone on `420FBA28`; if it grinds, live-probe P36-RETRY type=3 /
  LKTIMEOUT to catch the holder. **Instrumentation gap**: the master-side
  P-LKTIMEOUT-HOLDER dump exists for INODE type only — AG timeouts print no
  holder detail.
- **Leaf-hash-hole class** seen once on 0.11.35 (ROUND_FAIL rank=15,
  readdir=128/128 with lookup_fail>0).
- `mxfs_dlm_lock` default retry budget is 60×~1s; `ilock_begin` drives smaller
  sub-budgets in a loop with cooperative AG yields between.

## Infra landed across the arc

`scripts/run_adhoc_suite_test.sh` (run any `tests/suite/*.sh` on a prepped
cluster with run.sh's env contract, without touching criteria.json);
`tests/suite/dir_add_visibility.sh` (diagnostic, deliberately **not** in the
manifest — a new row would retro-un-green completed boards);
`scripts/raw_fio_ceiling.sh` median-of-3 with adaptive 46/N G stripe spacing;
drc fork-free pattern + wave markers; tds N-invariant total (1600/T floor 50);
run.sh prep step-1b /src NFS self-heal.
