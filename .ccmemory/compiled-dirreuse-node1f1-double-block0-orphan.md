---
name: compiled-dirreuse-node1f1-double-block0-orphan
description: sess65 compiled: node1_f1 loss in dir_reuse_coherency = dir block0 extent-map split + content clobber; fix = durable canonical-block0 DLM record.
metadata:
  type: project
tags: [compiled, sess65, dir-reuse-coherency, node1_f1, block0-double-alloc, cache-coherency, canonical-block0]
---

## sess65 — node1_f1 durable loss in `dir_reuse_coherency`: two-stage dir-block0 bug

All eight source memories cover ONE ship-blocker: in the `dir_reuse_coherency`
criterion, rank1's FIRST file `node1_f1` is silently, durably dropped from the
shared directory. 4/tcp fails EVERY round (`readdir=399/400`); 2/tcp is
INTERMITTENT (~round 20, `readdir=199/200`) — the earlier "2/tcp dir_reuse PASS"
in criteria.json was a lucky run. The bug is identical at all node counts, so
fixing node1_f1 fixes 1/2/4/8 together. Criterion NOT met at session end. In the
pure-baseline (no module args) case `corruption=0`/no shutdown — the loss is a
silent dirent drop, not a crash.

### Central diagnosis: TWO coupled bugs, both proven byte-level (RULE 4)

**Stage 1 — dir logical-block0 extent-map SPLIT (double-allocation).** Round
starts symmetric: rank1 mkdir's, barrier, all 4 nodes create concurrently from
fresh shortform. Each node's first modify runs `xfs_dir2_sf_to_block`, allocating
its OWN block0 in its node-affine AG. `node1_f1` lands only in rank1's block0
(fsb=15, daddr=120, AG0). A peer's competing block0 (high-AG daddrs
33491656/2093296/4186520/262153/6291465) wins inode-131's on-disk data-fork
extent[0] because last iflush wins. rank1's NEXT create (node1_f2) reload-ADOPTS
the peer's block0 lacking node1_f1, DROPPING it from rank1's in-core; f2..f50 go
into the peer block0 and survive. The code invariant "post_release ⇒ disk is a
strict SUPERSET of our entries" is FALSE here. Root nailed in
[[sess65-GPT-design-pending-dirent-replay-fixes-node1f1]] and
[[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]]. The
specific code hole: reload_inode's sess14 `merge_ours` (`xfs_mxfs_dlm.c` ~8152)
snapshots+re-applies in-core entries across adopt ONLY when BOTH in-core AND disk
are LOCAL (shortform); it does NOT fire for in-core→BLOCK adopt.

**Stage 2 — block0 CONTENT clobber (residual after Stage 1).** Even with the
extent map converged onto daddr=120, node1_f1's DIRENT can still be missing from
block0=120's on-disk content: a peer RMWs block0 from a STALE base lacking
node1_f1 and writes it. This is the sess17 union-merge / sess41 P-DATACLOBBER /
sess79-90 / sess84 block-dir durable lost-update family.

### The extent[0] FLIP-FLOP is the sharper framing

[[sess65-FINAL-block0-flipflop-flush-buffer-incoherent-canonical-record-needed]]
isolated it decisively: `P-DIRIFLUSH ino=131` shows the SAME node (test1)
flushing extent[0] as fsb=15 (1631×), fsb=262153 (204×), fsb=6291465 (322×) — one
node publishes 3 DIFFERENT block0s over the run. `node1_f1` is DURABLE in
block0=daddr=120 (`P64-N1F1 present=1` on EVERY write to 120, NEVER present=0), so
it is NOT content-clobbered in that lineage — readers whose cold-read dinode has
extent[0]≠15 simply read a block0 that never held it. So the dominant mechanism
is an extent[0] flip-flop, not (only) content loss.

Churn detail from [[sess65-CHURN-block0-daddr-instability-plus-stale-base-writes]]
(build 0B2188CC, round 2): within ONE incarnation node1_f1 is written present=1 to
daddr=120 (82×) AND daddr=4188360 (112×) — two physical block0s both contain it —
while a peer writes present=0 to daddr=8372968 (97×) and 14654472 (7×) from a
stale base. Only ONE `P42-SFCONV` conversion for ino=131 that round (sf_count=11,
dlm_mode=5/EX), so the extra daddrs are per-node divergent extent[0]s, not extra
conversions.

### The intermittency refinement

[[sess65-REFINED-loss-is-stale-cached-block0-RMW-even-single-conversion]] (build
621FD271, no flags): double-conversion is INTERMITTENT — round 2 had test1=1 AND
test3=1 (double), but rounds 3 and 5 had test1=1 only (single). Yet node1_f1 was
lost in ALL 4 rounds. So single-conversion rounds still lose it ⇒
double-conversion is NOT the sole cause; the primary loss is a block0 CONTENT
lost-update on the RMW READ side, even with one canonical block0. `P58 ex_pop`
fired 0× (no concurrent-EX double-grant via the self-skip path).

### Why every XFS-layer serialization guard failed (all fired 0× or regressed)

From [[sess65-convgate-0x-epoch-prelock-cant-serialize-conversion-need-dlm-record]]
and the churn/final memos:
- **P65-EPOCH-CONVGATE** (prelock: in-core LOCAL + dir epoch advanced > valid_epoch
  ⇒ reload+adopt before converting): 0×. The prelock-shortform + epoch-advanced
  window doesn't align with the conversion moment; when in-core is LOCAL the epoch
  hasn't advanced yet, and once it has, in-core is already BLOCK.
- **P65-LOWERB0-KEEP** (reload: keep lower block0): 0× — block0 transitions don't
  go through `mxfs_dlm_reload_inode` (test1's block0 goes 120→4188360 with no
  reload-guard hit).
- **P65-IFLUSH-FENCE / dir_iflush_fence** (iflush: skip flush when incore_b0 >
  disk_b0, lowest-block0-wins): 0× — the comparison uses the LOCAL cached dinode
  cluster buffer (`dip`), which is NOT cross-node coherent; each node's local
  buffer matches its own in-core block0 so divergence is invisible at flush. A
  correct fence would need a FUA disk read of the true dinode in xfsaild/iflush
  context = deadlock-prone (cluster-buffer lock + SCSI path) + ~2000 reads/run
  perf hit (RULE 0).
- **dir_epoch_adopt=1**: only PARTIAL convergence, and in one variant HARMFUL.
- **mxfs_dir_adopt_block=1** (pre-lock FUA adopt): P61/P62-ADOPT 0× — at the
  racing converter's moment disk is still shortform (peer hasn't published), so
  pre-lock can't see a not-yet-done conversion.
- **dir_merge / dir_force_block default-ON** (`mxfs_dir_merge_peer_into_tp`):
  CORRUPTS 2/tcp (Internal error, force_shutdown when combined with force_block);
  reverted.
- **P65-STALE-TRUNC** truncate-path staleness guard (`xfs_iops.c`
  `xfs_setattr_size`, FUA dinode-header gen/mode/nextents/size check): 0× even
  broadened — the staleness is in bmbt CONTENTS not the header. Inert; REMOVED.
  (The separate intermittent bnobt double-free in `do_truncate` →
  `xfs_itruncate_extents` → `xfs_free_ag_extent` (bno+len>gtbno) is a
  SAME-incarnation stale extent-map CONTENTS bug, high variance 0-38 shutdowns
  same binary — a distinct issue from node1_f1.)

Firm conclusion: the conversion race is decided in a window where NO disk-read,
epoch-query, reload, or iflush guard has a coherent, synchronously-checkable
"a canonical block0 already exists" signal.

### dir_epoch_adopt convergence — corrected to PARTIAL

[[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]] initially
claimed dir_epoch_adopt=1 fully cured Stage 1 (all 4 nodes ext0→daddr120).
[[sess65-CORRECTION-epoch-adopt-only-partial-convergence]] retracts this: the
clean all-=120 run had ALSO had dir_merge=1 active. With
`dir_epoch_adopt=1` ALONE (build FEF626A4): shutdown=0 (clean), but convergence is
PARTIAL — test1 ext0(131)=daddr120 only, while test2/3/4 show BOTH daddr=120 AND
daddr=2093296. node1_f1 still lost every round. A node caching EX through its whole
dd loop never re-acquires, so it never adopts mid-tenure and can still publish a
divergent/stale block0. The fix likely needs a WRITE-SIDE iflush fence combined
with acquire-side adopt.

### Why pending-dirent replay CANNOT fix it (the timing gap)

[[sess65-replay-timing-gap-adopt-at-coldread-not-create]] (build 0676923D, on
disk): built the pending-dirent list (`xfs_inode.h i_dlm_dir_pending[_bytes/
_incarn]`; `mxfs_dir_pending_add/replay` in `xfs_mxfs_dlm.c`; wired in `xfs_create`
after merge + after create success; freed in `xfs_icache.c`) plus epoch-adopt
(`xfs_mxfs_dlm.c` ~6880/~2755/~8152) and the truncate guard. Result: still 0/4;
EPOCH-ADOPT fired 2-18×/node but REPLAY fired ~0-1×. Reason: rank1 holds dir EX
through its whole 50-file loop, node1_f1 is visible in-core so lookup SUCCEEDS and
replay SKIPS; rank1 only OBSERVES the loss at the cold-read `drop_caches` reload in
the verify phase — where there is NO transaction to replay into. The split is
symmetric at round start (every node's modify advances the epoch, so there is no
clean FIRST converter to elect as winner). Forcing adopt on all (LOCAL-only variant)
made node1_f1 lost EVERY round ("adopt harder" is exactly wrong). So the fix must
be WRITE-SIDE, or serialize conversion to one block0, or trigger a DEFERRED replay
at cold-read reload.

### GPT-5.5 fix design (option a+c) — from [[sess65-GPT-design-pending-dirent-replay-fixes-node1f1]]

1. **Epoch-gate sf→block conversion**: a node may NOT call `xfs_dir2_sf_to_block`
   (or log a dir data fork) if its in-core dir base epoch < current EX-grant epoch
   — reconcile first. Prevents the 2nd block0.
2. **Generalize `merge_ours`** to ALL transitions (LOCAL→BLOCK, BLOCK→BLOCK
   different block0), not just LOCAL↔LOCAL.
3. **Per-dir PENDING POSITIVE-DIRENT list** (the key): append
   (name,child_ino,gen,ftype) on every successful LOCAL createname; tombstone on
   local unlink/rename-out; CLEAR on dir incarnation change (di_gen bump); filter
   by parent incarnation + child gen.
4. **Reconcile-before-modify**: when epoch stale → capture ours, FUA-read+adopt
   disk fork via a NO-FREE path (`mxfs_install_disk_fork_nofree` — do NOT
   `xfs_bunmapi`/free the stale in-core mapping, that IS the bnobt double-free; let
   the orphan leak for scrub), set base_epoch=grant_epoch, then REPLAY pending
   local dirents missing from the adopted fork via `xfs_dir_createname` using THE
   CREATE'S OWN tp + already-held EX grant (NO extra DLM acquire — that deadlocks
   rc=-110). Bounded 1-4 per tx; rest queued.
5. Replay idempotent: lookup name, skip if present w/ same ino, validate child
   di_gen, re-add dirent only (no new inode, no nlink double-bump). Hook near
   `mxfs_dir_merge_peer_into_tp` (which already does disk→ours; add ours→disk).
   For the reproducer, node1_f2's create replays node1_f1.
6. Allocator affinity (`preferred_ag=dir_ino_ag`) is NOT a correctness fix — the
   fork update still races. Don't rely on it.

### The REQUIRED robust fix — durable canonical block0 record (GPT-5.5 option C)

Converged across
[[sess65-FINAL-block0-flipflop-flush-buffer-incoherent-canonical-record-needed]],
[[sess65-convgate-0x-epoch-prelock-cant-serialize-conversion-need-dlm-record]], and
[[sess65-CHURN-block0-daddr-instability-plus-stale-base-writes]]: the dir inode
extent[0] alone is insufficient because (a) flush-time cluster-buffer cache is
incoherent and (b) multiple conversions race. The signal must live in the DLM
master (set in-memory at the FIRST converter's commit, delivered on every grant)
and be checked AT the conversion under EX. Implementation (`docs/
canonical_block0_fix_plan.md`): at FIRST sf→block conversion (holding dir EX),
allocate block0 AND atomically log a canonical record {dir_ino, di_gen,
block0_fsb} (small logged item / hidden btree / reserved field) + mirror in the
DLM LVB. Every later converter/modifier reads it (LVB fast-path, durable record
authoritative) and REUSES that exact fsb (adopts) instead of allocating a new
block0. iflush must REFUSE to publish extent[0] ≠ canonical. No extra DLM acquire
(already hold EX); no inline orphan free. Plumb parallel to the dir_epoch per-lock
work in `dlm/dlm.c` + `v5_mount.c`; publish at `xfs_dir2_sf_to_block`; query+adopt
at the prelock; iflush fence as backstop.

### Build/version progression (all baselines: new module params default OFF)

- **0B2188CC** — round-2 double-conversion trace (test1+test3 convert ino=131);
  churn evidence (multiple block0 daddrs).
- **0676923D** — pending-dirent list + epoch-adopt + P65-STALE-TRUNC on disk;
  REPLAY fired ~0×.
- **E3DFE11C** — baseline + inert P65 truncate guard (consider removing).
- **FEF626A4(A9D94B0D)** — adds `dir_epoch_adopt`, `dir_pending` params (default
  0); dir_epoch_adopt=1 alone = PARTIAL convergence, clean (shutdown=0).
- **283EE4CF** — carries dir_iflush_fence gated OFF + P65-IFLUSH-FENCE probe.
- **2E0FDC34** — all sess65 params default OFF; xfs_iops.c restored pristine.
- **621FD271** — final SAFE BASELINE: ALL sess65 module params default OFF
  (dir_epoch_convert_gate, dir_lower_block0_wins, dir_iflush_fence,
  dir_epoch_adopt, dir_pending, dir_merge, dir_force_block, dir_adopt_block);
  xfs_iops.c pristine; pal.md updated. Criterion NOT met (4/tcp 0/4; 2/tcp
  intermittent). All probes + gated infra retained for the DLM-record work.

Retained probes: `P42-SFCONV`, `P62-SF2BLK`, `P62-REL-DIREXT`, `P64-N1F1`
(byte tracer, present-flag per daddr), `P64-EPOCH-OBS`, `P65-EPOCH-ADOPT`,
`P65-IFLUSH-FENCE`, `P-DIRIFLUSH`.

### DO NOT repeat (refuted/regressed this session)

- `force_block=1 + merge=1` default ON → CORRUPTION at 2 nodes.
- `dir_epoch_adopt` LOCAL-only variant → node1_f1 lost EVERY round ("adopt
  harder" is wrong).
- Pending-dirent replay as the sole fix → REPLAY fires ~0× (cold-read timing gap).
- `mxfs_dir_adopt_block` pre-lock FUA adopt → 0× (peer conversion not yet
  published at the race moment).
- P65-STALE-TRUNC truncate header check → 0× (staleness in bmbt contents).
- Read-side keep-stale guards alone cannot fix per-node-divergent-extent[0] +
  stale-base-RMW churn.

### Next-session capture note
[[sess65-CORRECTION-epoch-adopt-only-partial-convergence]]: P64-N1F1 firehose
rolled out of dmesg; reduce probe noise or snapshot dmesg per-round (the test
already saves `/root/drc_create_r${N}_rank${R}.dmesg` and `drc_fail_*`) to capture
the present-flag on daddr=120.
