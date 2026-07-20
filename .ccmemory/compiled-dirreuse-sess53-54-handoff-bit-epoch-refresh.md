---
name: compiled-dirreuse-sess53-54-handoff-bit-epoch-refresh
description: sess53-54 8/tcp dir_reuse: handoff-bit under-fire proven root, GPT reliable-epoch design, addname epoch-refresh default-on; residual = write-side ser…
metadata:
  type: project
tags: [compiled, dir_reuse, tcp, coherency, handoff-bit, epoch-refresh, dlm, sess53, sess54]
---

## 8/tcp dir_reuse_coherency — handoff-bit under-fire, epoch-refresh, write-side residual (sess53-54, ccloop)

Central topic: the `dir_reuse_coherency` ship criterion on 8 TCP-DLM nodes durably loses a
single dirent (or, round-1, a mass batch). sess53 re-proved the root as READ-staleness from a
master **handoff-bit that under-fires**; GPT-5.5 designed a reliable-epoch + safe write-set
refresh; sess54 shipped the safe half (addname epoch-refresh default-on, net-positive) and then
exhaustively RULED OUT read-side AND the obvious write-side reflush, converging on an unproven
**DLM/transaction serialization hole**. Criterion still ~50% pass at end of sess54. Marker NOT
written either session. 1/2/4 tcp believed passing (sess48/58).

### The failure signature (stable across both sessions)
Durable, count-preserving loss of ONE `.md5` sidecar from the second create-wave (e.g.
node7_f29.md5, node6_f47.md5, node3_f13.md5). readdir=799/800, `LOOKUP_ENOENT REREAD_MISS` on
ALL 8 nodes ⇒ on-disk loss, not an enumeration/transient miss — the lost bytes are genuinely in
no durable data block. The `.md5` wave is created AFTER a `sync` of the f-files
(dir_reuse_coherency.sh:77), so the dir is already node-format (many data+leaf+free blocks) when
the entry is added. Round-1 / early runs can instead show a MASS variant (~83 lost ≈ 2 data
blocks, e.g. node3's whole f2..f50 clobbered, readdir=750/800). ~50% of clean-reboot runs fail.
Run-to-run variance is high and host-load correlated: slow runs (wall 449-531s) fail more than
fast (393-401s).

### ROOT re-proven sess53 (RULE 4) — handoff BIT under-fire, NOT phantom
See [[sess53-ROOT-PROVEN-dirreuse-is-handoff-bit-underfire-not-phantom]].
Clean baseline build **2A9ACF1E** (no probes): round 11/18, all 8 nodes incl. creator miss one
`.md5`. Decisive diagnosis via `tests/tcp/drc_phantom_diag.sh` on a clean reboot:
- **P42-STALEEX-SERVE = 0 on all nodes** ⇒ NOT a phantom / mutual-exclusion break. Fast-path
  never serves a dir-EX with held=0. This REFUTES the sess50/52 "phantom-EX" framing for this
  build (that was the old broken TCP held-check era).
- **P51-HANDOFF-UNDERFIRE fires** (test1 4×, test3 1×): `ino=131 hgg=1003 cached_gg=808
  acted=808` — grant token advanced (lock changed hands) but the handoff bit read FALSE, so the
  fast-path EX serve skipped the base refresh and RMW'd a STALE cached dir DATA block → durable
  clobber.
- MX-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0, no membership flap ⇒ master FIFO/compat
  serialization intact; not master-divergence/table-purge.

Mechanism: `dg_grant_ex()` computes `handoff = (last_owner != 0 && last_owner != owner)`
(dlm.c ~2762), backed by an evictable 8192-slot `dg_shadow`. `last_owner` only tracks the
IMMEDIATELY-prior owner, so the **A→B→A→A re-grant pattern** reads `owner==last_owner,
active_b4=0` and the edge-triggered bit misses the handoff even though grant_gen jumped ~19
(the lock DID change hands via other nodes). The downstream chain
(`dir_gen_per_handoff=1` → read-path `bgen<dir_gen` invalidation) WORKS, but only fires when
handoff is DETECTED — the break is purely detection. On slot eviction (`NEWSLOT`, mine<0) the
current code forces handoff FALSE = eviction-under-fire (the unsafe fail-OPEN bug).

Refuted THIS session (do not repeat):
- `dir_evict_prior_tenure=1` (aggressive read-side epoch-evict): did NOT fix loss AND caused
  WORSE corruption (round 19 readdir=863/800, DUPLICATE dirents — keep-guard bypass).
- `dir_epoch_adopt=1`: OUT — sess49 PROVEN 8/tcp 0/8 SHUTDOWN (post_release fork-adopt shrinks
  in-core fork → DABUF_MAP_HOLE + AG double-free). The epoch also derives from the same
  under-firing `handoff`, so it can't be the fix.
- `dirwr=1` probe faked a DABUF_MAP_HOLE flood — instrumentation artifact, ignore.

First-attempt fix (build **994CF57B**, default-OFF `dir_ex_grantgen_refresh`, xfs_mxfs_dlm.c
~14475 + param ~5316): arm `dir_ex_stale_refresh` when `hgg != i_dlm_cached_grant_gen && !ho`,
with `dir_ex_handoff=FALSE` (no fork adopt → avoids sess49 shutdown). This was REVERTED (see
handoff): it DELAYED loss (round 11→19) but REGRESSED to a DABUF_MAP_HOLE flood (readdir=0)
because it bumped XFS `dir_gen` → read-path re-reads LEAF blocks while `reload(post_release=false)`
KEPT the stale extent map → refreshed-leaf + stale-map = leaf refs a HOLE → `!HOLE_OK` shutdown.
LESSON: a refresh must NOT bump XFS `dir_gen` / disturb leaf+extent-map under churn.

### GPT-5.5 design (sess53 handoff, RULE 5 consult)
See [[sess53-HANDOFF-gpt-design-reliable-epoch-plus-safe-writeset-refresh]]. Baseline for the
handoff was build **9473C7AD** (baseline + P-DGEX probes, failed fix reverted). Probes added in
`dlm.c dg_grant_ex`: **P-DGEX** (EX grant: owner,last_owner,active_b4,handoff,epoch) +
**P-DGEX-NEWSLOT** (mine<0 → handoff forced FALSE = eviction under-fire).

Three-part design:
1. **Exact owner_epoch** replaces lossy `last_owner`. Master advances a per-resource epoch ONLY
   on cross-node EX owner change; same-node release+reacquire (peer only WAITING, never granted)
   → UNCHANGED; A→B→A → +2. Grant reply carries `owner_epoch` + `resource_incarnation`. Client
   handoff = `grant.owner_epoch != ip.owner_epoch_seen`. **On slot eviction/state-loss FAIL
   CLOSED = force refresh, NEVER "no handoff"** (fixes the unsafe NEWSLOT→false bug). Key the DLM
   resource by `fs_uuid + ino + GENERATION + class` (ino is reused every round).
2. **Safe refresh** = a SEPARATE MXFS coherency epoch (NOT XFS `dir_gen` — that caused the hole)
   + per-buffer `validated_epoch`. Before RMW of a dir buffer, if `bp.validated < ip.remote_epoch`
   do a LOCKED coherent reread of THAT daddr only (no fork adopt, no global evict). Apply to the
   op's WRITE SET (data+leaf+free+dabtree), not data-only (stale leaf/free also clobber) and not
   whole-fork. KEEP-GUARD non-negotiable: never reread dirty/in-AIL (flush/wait/slowpath, else
   DUPLICATES). Recompute dup-check/freeindex after reread. Extent-map HOLE → return
   `-EAGAIN_SLOWPATH` (do not let `xfs_dabuf_map` shutdown); slow path = grow-only extent merge.
3. Trigger on `owner_epoch` (NOT `grant_gen`) ⇒ cost O(handoffs) not O(creates); MHT preserved.

### sess54 — safe epoch-refresh enabled default-on (net-positive keeper)
See [[sess54-FIX-addname-epoch-refresh-default-on-reduces-dirreuse-loss]] and
[[sess54-RESIDUAL-is-writeside-AIL-stale-flush-not-readside]].
RULE-4 diagnosis on 9473C7AD/clean reboot confirmed the master epoch is RELIABLE:
**P42-STALEEX-SERVE=0**, **P64-MASTER-HANDOFF=93×**, epoch monotone 131→172→211→328. But
**P-FASTEX-EPOCH=0** ⇒ the level-triggered epoch was NEVER consumed (`dir_epoch_adopt=0` [sess49
shutdown], `dir_addname_epoch_refresh=0`). P-DGEX handoff=0 samples all show
`owner==last_owner, active_b4=0` = the A→B→A→A re-grant that the edge bit can't see but the level
epoch CAN (and does advance). Initial failure was a MASS loss (node3 f2..f50 clobbered,
readdir=750/800).

FIX — flip `int mxfs_dir_addname_epoch_refresh = 1` (was 0) at xfs_mxfs_dlm.c:5424. Consumes the
reliable master epoch at the addname modify site (xfs_dir2_node.c:2034) with the SAFE
data-block-only refresh: drop `XBF_DONE` + restart on the ONE chosen block; keep-guard (never
dirty/in-AIL/pinned/DELWRI); NO fork adopt (avoids sess49 shutdown); NO `i_dlm_dir_gen` bump
(avoids sess53 DABUF_MAP_HOLE). Build progression:
- **88F00076** — refresh=1. run1: loss 50→4 (`.md5` sidecars; first fail round 7, 796/800).
- **A204997E** — added P54-KEEPGUARD-STALE + P54-MEPZERO probes at xfs_dir2_node.c:2110; fixed
  `drc_phantom_diag.sh` snapshot pick (lexical sort r19<r7 captured wrong round → numeric-min).
  run2 PASSED 8/8, but one pass ≠ 100% (intermittent).
- **8705E114** — KEEPER (A/B PROVEN 2/4 fail vs baseline 1/4... net-positive). Adds
  **FAIL-CLOSED on epoch regression** at xfs_dir2_node.c:~2086: `mep==0 && b_epoch!=0`
  (dg_shadow slot evicted → master epoch reset to 0) now treats the block STALE. ELIMINATED
  P54-MEPZERO.
- **1A78AEBD** = 8705E114 + P54-NOTEX-MODIFY probe (all probes are capped/cheap diagnostics; the
  only behavior change vs baseline is refresh1 + fail-closed).

### sess54 residual — read-side ALL clean, obvious write-side reflush REFUTED
See [[sess54-RESIDUAL-six-hypotheses-ruled-out-next-is-reload-revert]]. After the keeper, the
residual single/contiguous `.md5` loss persists (~50%). Ruled OUT with instrumentation
(drc_phantom_diag captures all):
1. Read-side stale-base RMW — **P28E diff=0** every time (dir_addname_coherent=1 FUA
   ground-truth: in-core == platter at addname). Not a stale read.
2. Extent-map divergence — **P28E pcur=0** (in-core daddr always a valid dir block).
3. In-core dir-block double-alloc — **P54-DOUBLEMAP=0** (xfs_dir2_data.c:889 I/O-free iext scan).
4. Keep-guard-blocked stale refresh — **P54-KEEPGUARD=0**.
5. Epoch-regression/unavailable — **P54-MEPZERO=0** (post fail-closed).
6. Write-side stale reflush — `dir_tenure_reflush_skip=1` (sess37 destaged-zombie in-AIL dir
   DATA reflush skip, the most promising untested write-side lever) → **3/3 FAIL**, does NOT
   help. CONFIRMS sess50's refutation of `dir_relepoch_skip` (loss occurs with 0 relepoch skips).
7. Modify-without-EX serialization hole — **P54-NOTEX-MODIFY=0** (probe at
   xfs_dir2_data_use_free: every dirent placement holds dir DLM EX). Modification IS serialized.
Also clean: P42-STALEEX-SERVE=0, MX-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0. P62-RELOAD-FORK-SHRINK
shrink 1→0. P78-FMT-TORN-FIX (working writer fix) ~100/round.

Therefore: base is coherent at modify AND no stale image is reflushed ⇒ the durable loss is a
**DLM/transaction SERIALIZATION HOLE**, not a coherency-cache bug. The remaining mechanism is a
RELOAD-REVERT or COMMIT/LOG-ORDERING issue at the data-block level invisible to all
addname-time probes: dirent f47.md5 is placed under EX into block B (durable), then block B is
later REVERTED to a pre-f47.md5 image — either (a) an EX-acquire RELOAD reverts block B's in-core
image and re-destages it, or (b) a commit/log-checkpoint ordering writes an older block-B image
over the newer one.

Candidate holes to instrument NEXT (sess55+):
- **ILOCK vs DLM-EX**: node modifies dir holding ILOCK while its DLM dir-EX was REVOKED
  mid-transaction (BAST during the create txn) → peer modifies concurrently (cf. CLAUDE.md
  "ILOCK held across CAW poll"). Probe: log dir BAST/downgrade while a create txn for that dir is
  IN-FLIGHT on this node.
- **Round-1 FRESH-dir growth** (most reproducible MASS loss): shortform→block→leaf→node
  conversions (P78 ~100/round) rewrite the whole dir; a node converting from a STALE in-core
  shortform/fork loses peer entries. Round-1 has no prior tenure so tenure_reflush_skip/incarn-ABA
  can't apply — this is INODE-FORK reload staleness (P62-RELOAD-FORK-SHRINK family);
  `epoch_adopt=1` would adopt the peer fork but is PROVEN shutdown (sess49, adopts a
  stale-SMALLER disk when WE are ahead).
- Decisive probes: (1) at EX-acquire dir RELOAD (mxfs_dlm_reload_inode / xfs_da_btree.c read
  path) for a dir DATA block of ino≤256, when reload replaces/invalidates an in-core block,
  FUA-read platter and log whether post-reload in-core LOST a dirent vs platter. (2) at dir DATA
  buffer WRITE submission (xfs_buf_submit / mxfs_buf_xfsaild_skip_dir_write, xfs_mxfs_dlm.c:22087)
  FUA-read the platter daddr right BEFORE writing the in-core buffer; if platter has a dirent the
  in-core lacks, that write is the durable clobber — log b_mxfs_dir_epoch, dir_gen, in_ail,
  dlm_mode, comm. (3) at xfs_dir2_sf_to_block / da-format-conversion for ino≤256, FUA-compare the
  source (inode shortform/block) against platter BEFORE converting.

### Build ledger
- **2A9ACF1E** — clean sess53 baseline, no probes (reproduces the loss).
- **9473C7AD** — baseline + P-DGEX probes; sess53 handoff / sess54 diagnosis base.
- **994CF57B** — `dir_ex_grantgen_refresh` (default-OFF); REVERTED (dir_gen bump → DABUF_MAP_HOLE).
- **88F00076** — `dir_addname_epoch_refresh=1`; loss 50→4.
- **A204997E** — + P54 probes; run2 passed 8/8 (intermittent).
- **8705E114** — KEEPER: refresh=1 + fail-closed on epoch regression (mep==0 && b_epoch!=0).
- **1A78AEBD** — 8705E114 + P54-NOTEX-MODIFY probe.

### Standing rules that constrain the fix
- Refresh MUST NOT bump XFS `dir_gen` or disturb leaf+extent-map (sess53 hole).
- No fork adopt on refresh (sess49 shutdown: adopts stale-smaller disk when we are ahead).
- Keep-guard is non-negotiable: never reread dirty/in-AIL/pinned/DELWRI (else DUPLICATES).
- On epoch unavailable/slot-evicted: FAIL CLOSED (force refresh), never fail-open "no handoff".
- Instrumented proof before patching (RULE 4). Timing is first-class (RULE 0): ~50% pass and
  449-531s slow runs are themselves failures. Criterion scope is the FULL 8/tcp suite plus 1/2/4
  tcp (sess49).
