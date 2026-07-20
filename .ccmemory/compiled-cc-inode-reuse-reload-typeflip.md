---
name: compiled-cc-inode-reuse-reload-typeflip
description: Compiled: reused-inode/NL-cached reload coherency — type-flip (ENOTDIR/EISDIR), gen-check d_revalidate, ABA dir-block reuse; sess40-104.
metadata:
  type: project
tags: [compiled, cache_coherency, inode-reuse, type-confusion, d_revalidate, dlm-coherency, dir-block-lost-update]
---

# Compiled: Reused-inode / NL-cached-inode reload coherency (type-flip, gen-check, ABA)

Central failure family behind the `cache_coherency` ship criterion (SUCCESS_CRITERIA.md), spanning
sess40→sess104. One root shape in many disguises: **MXFS caches VFS inodes / dcache / dir blocks at
NL (no DLM grant), and disk-polled CAW has no targeted BAST — the poll thread only scans slots THIS
node holds — so a peer's free / realloc / dir-modify NEVER BASTs an NL-cached holder.** A node then
serves a STALE incarnation of a reused inode number or a stale shared dir block. Invariant MXFS keeps
violating: the VFS cache (dentry/inode/page/dir-block) must be a projection of DLM state — never serve
cluster-visible metadata without a covering grant (the GFS2/OCFS2 glock model). Confirmed across
[[sess54_lessons]], [[sess55_lessons]], [[sess90_lessons]].

The criterion has 4 sub-tests (each a separate `run_tests.sh --test` invocation, looped; each ends
`rm -rf .mxfs_test` and the next recreates from node1 → INODE-NUMBER REUSE on a WARM cache):
`cross_visibility`, `rename_visibility`, `unlink_visibility`, `cross_write_read`. cross_visibility runs
cold → passes; the others run warm → hit reuse. Progress: passed=1 (sess86 baseline) → 2 (sess86) →
3/4 (sess102/104), never 4/4 in these sessions. Marker never written.

## Symptom taxonomy (all one NL-cache-coherency root)
- **EISDIR** (`cat X: Is a directory`): reader holds a live in-core inode of the OLD type (S_IFDIR),
  number reused as a REG file; VFS serves the dir vtable. ([[sess54_lessons]] Failure A, [[sess72_lessons]] Face A)
- **ENOTDIR** (`Not a directory` on child create/delete): parent-dir inode flips DIR→REG mid-test;
  path resolution of children of a now-REG inode fails. ([[sess90_lessons]] unlink_visibility, [[sess86_lessons]] rename_visibility)
- **File invisible to own creator / missing-dirent**: concurrent shortform→block dir-conversion
  lost-update, or stale cached dir DATA block missing a peer's committed dirents. ([[sess54_lessons]] Failure B, [[sess72_lessons]] Face B)
- **Empty-content** (`.md5` sidecar reads di_size=0): reg-file di_size not flushed to cluster on
  BAST-release. ([[sess40_lessons]], recurs [[sess102_lessons]]/[[sess104_lessons]] as cross_write_read)
- **FS shutdown**: bnobt double-free (`ltbno+ltlen>bno` xfs_alloc.c:2244), dialloc EFSCORRUPTED
  i!=1, iunlink AGI-garbage — same lost-update family surfacing on alloc/free metadata. ([[sess40_lessons]], [[sess90_lessons]], [[sess102_lessons]])

## Two generation signatures (the key diagnostic, [[sess90_lessons]])
`P-RELOAD-TYPEFLIP` logs `incore_mode/disk_mode/incore_gen/disk_gen`. TWO cases:
1. **off-by-one gen** (`incore_gen=G / disk_gen=G+1`): legitimate REUSE by the owner (free→realloc
   bumps di_gen +1); peers hold a stale prior incarnation. A gen-check CAN catch this.
2. **same-gen** (`incore_gen==disk_gen`, type differs): inode number allocated TWICE without an
   intervening free (INODE DOUBLE-ALLOCATION), OR inode-cluster stale-flush clobber (a node flushes a
   stale 16KB cluster buffer carrying an OLD incarnation over the owner's new one). **Every gen-based
   defense slips through this.** ([[sess87_lessons]] proved double-alloc; [[sess90_lessons]] same-gen ino=2097285)

## Chronological fixes & build markers

### sess40 (build progression `210D0DD`→`45F00582`→`4545ABEA`→`598B434F`→`8816466`→`EF3E975F`→`214A3360`)
[[sess40_lessons]] — the founding session.
- **IRECLAIMABLE reused-inode create-race, ROOT+FIX (proven, repro_mode0 0/120):** node frees inode N
  → lingers in-core IRECLAIMABLE mode=0; peer reuses N. iget hits the stale struct via **cache-HIT**
  and bails -ENOENT at `xfs_iget_check_free_state` WITHOUT acquiring the inode DLM → never BASTs the
  peer creator → self-reinforcing staleness (`fua_disk_mode` stays 0). Cache-MISS path was correct
  (acquires DLM before disk read). FIX in `xfs_iget_cache_hit`: for multi-node IRECLAIMABLE mode=0
  dlm_stale inodes → pin, drop locks, `mxfs_dlm_ilock_begin(PR)` (BASTs peer→flush) + reload + return
  -EAGAIN. Gated `mxfs.reuse_reload=1`. Two sub-types: `fua=0x41ed` (in-core-only stale) vs `fua=0x0`
  (creator hasn't flushed). Detectors P-IGET-ENOENT, P-REUSE-RELOAD.
- **PERF TENSION (recurring theme):** the DLM round-trip per stale-reused iget times out cache_coherency
  — unlink phase does ~480 igets of genuinely-FREED inodes (mode=0 IRECLAIMABLE too) → wasted DLM
  round-trips. Can't cheaply distinguish "peer reused" from "genuinely deleted" by inode content alone.
  WIN 5: **cheap-only reload** (`reuse_dlm=0`, no DLM acquire) + creator's eventual flush is sufficient
  for the race and avoids the timeout (repro 0/40).
- **Empty-content FIXED:** `mxfs_reg_release_durable=1` flushes reg-file di_size to cluster on BAST;
  only safe AFTER the RELOAD-SIZE-DROP-SKIP guard (node won't clobber its own nonzero di_size to 0 on
  reload of a not-yet-iflushed cluster). cross_write_read → PASS 15s.
- **All per-op DLM logging gated behind `mxfs.instr`** — ungated logs were the ~100x slowdown. LESSON:
  any new DLM/iget/alloc hot-path diagnostic MUST be `mxfs_idbg`/instr-gated. **instr=1 HIDES the race**
  (100x printk slowdown serializes it) — recurs as a hard rule in [[sess54_lessons]].
- **AG free-space double-alloc CORRUPTION under concurrent rename** isolated: cached AG re-acquire
  fast-path (`mxfs_ag_dlm_lock` ~2277) adopts the kept on-disk grant WITHOUT invalidating/FUA-re-reading
  AG meta buffers (agf/agi/agfl/bnobt/cntbt/inobt/finobt) → allocator reads stale free-space btree →
  double-alloc → bmap/SB corruption → shutdown. FIX infra landed: `pag_dlm_meta_gen` + `b_mxfs_ag_gen`
  + helper `mxfs_ag_meta_invalidate_stale` (deadlock-safe XBF_TRYLOCK, skip dirty/pinned/delwri) wired
  into AGF (`xfs_read_agf`) + AGI (`xfs_read_agi`). **Btree-block hook NOT done** — `cur->bc_ag.pag`
  doesn't compile; needs correct AG pag accessor (later resolved: `to_perag(cur->bc_group)` per
  [[sess41]]). AGF+AGI hooks alone do NOT reliably stop corruption (intermittent — one clean run was
  variance/luck; a re-run corrupted with 7 shutdown lines). Final head `214A3360`.
- Params baseline: `reuse_reload=1, reuse_dlm=0, reg_release_durable=1, sync_iflush=1, instr=0`.

### sess53 — REFRAME: shortform-dir reload miss ([[sess53_lessons]], build `C2D30DB0`)
cross_visibility FAIL reproduced in 13s with ZERO corruption → **the bnobt/P88 hunt (sess44-52) is a
RED HERRING for the active failure.** `disk_differs=1` is an artifact (write-back time in-core=new
disk=old). Exact failure: only the HIGHEST-id node's dirent universally invisible. Root: the
cross_visibility dir has 4 tiny entries → `XFS_DINODE_FMT_LOCAL` (shortform, dirents inline in the
inode literal area, NO separate dir data blocks). So the `xfs_da_read_buf`/`b_mxfs_dir_gen`
invalidation hook (fires only for DATA_FORK BLOCK reads) NEVER runs — DIR-STALE-SKIP=0, P-H18=0.
Visibility depends on a fresh DIR INODE, not a fresh dir block. reload CAN refresh shortform (reparses
LOCAL fork) but ISN'T FIRING: reader serves the dir from a FAST-PATH cached PR re-grant, no ACQ-FRESH
→ no reload. All sess43-52 dir-BLOCK coherency work irrelevant to this mode.

### sess54 — REFUTES sess53's reframe, re-confirms NL-cache root ([[sess54_lessons]], build `C2D30DB0`)
sess53's "shortform reload-not-firing" reframe REFUTED. Reliable 19s repro (real harness, instr=0):
`run_tests.sh --nodes 4 --phase cluster --test test_cross_visibility`. Two faces, both NL-cache: (A)
inode-reuse type confusion → EISDIR (`INODE-REUSE-EVICT ino=6291584 incore_ftype=2(DIR)
dirent_ftype=1(REG)`; the "corrupt dir block" dump literally contains the reg file's `hello from node
3`); (B) file invisible to own creator = concurrent shortform→block dir-conversion lost-update.
Gemini-confirmed architectural root (NL-cache = no BAST). Existing sess48/49 xfs_lookup ftype-mismatch
evict is a CONSUME-side point patch that fires but too late / falls through if a dentry can't be pruned.
Fix direction: choke point in VFS methods (`->lookup`/`->getattr`/`->d_revalidate`) AFTER VFS locks,
NOT inside `xfs_iget` under ILOCK_EXCL (deadlocks xfsaild AIL-drain — proven constraint). Per-inode-
cluster on-disk generation/epoch, batch-polled.

### sess55 — Gemini 3-part design saved ([[sess55_lessons]], to notes/sess55_gemini_design.md)
Part 1 **CAW_EVICT_RING**: on-disk `{ino,gen}`+head_seq ring; producer=`xfs_ifree()`, consumer=CAW
poll thread lockless `radix_tree_lookup` on pag_ici_root → `set_bit(XFS_ISTALE_CAW)` + background
`d_prune_aliases`+`xfs_irele` (OUTSIDE iget/ILOCK). Part 2 **VFS staleness trap** in `xfs_vn_lookup`
(parent i_rwsem, not child ILOCK). Part 3 (Failure B): DLM grant-completion callback on NL→PR/NL→EX
does synchronous inode-cluster re-read of di_format/i_size before any txn ILOCK. Also codified RULE 5:
**omit max_tokens on ask_* consults.**

### sess72 — Face A FIXED (stale vtable), Face B isolated ([[sess72_lessons]], build `8B1A4AD6`, KEEP)
**Decisive proof:** ONE inode `ip=ffff8e0a99f7cd80` ino=131 had `i_mode=REG` but
`i_fop==xfs_dir_file_operations` → `cat`→`xfs_dir_open`→`generic_read_dir`→-EISDIR. ROOT: an in-place
dinode reload that flips S_IFMT updates `i_mode` in `xfs_inode_from_disk` but NEVER re-wires
`i_op`/`i_fop`/`a_ops` — `xfs_setup_iops` runs only on the XFS_INEW iget path, and in-place reload
returns a live cache-HIT (inew=0). This is why sess55-71's inode-layer chase never fixed it: the
residue was the VTABLE. FIX (`mxfs_dlm_reload_inode` ~L1420): capture `old_ifmt` before from_disk; if
S_IFMT changed, call `xfs_setup_iops(ip)` (pure pointer writes, safe in reload ctx). Detector
P-RELOAD-IOPS-REWIRE. Validated FAIL@iter2→8 consecutive PASS. **Remaining = Face B** (concurrent
dir-block lost-update): a contiguous suffix of a node's OWN Phase-1 dirents vanish from ALL nodes; a
peer modified+wrote the SHARED dir block from a STALE cached copy. Lead (sess69 H-DIR): on a FAST
dir-inode re-grant `i_dlm_dir_gen` is NOT bumped (bumps only slow-path acquire) → stale dir DATA
blocks served without FUA re-read. Criteria 10/12 pass here (cache_coherency + rsync_paired fail).

### sess86 — rename_visibility FIXED via d_revalidate gen-check ([[sess86_lessons]], build `5D6A63D2`, passed 1→2)
ROOT (NOT a dir-block lost-update — prior sessions mis-framed): warm-cache inode-number REUSE, dir→dir
SAME number+type (only gen/contents differ). node3/node4 got 20 ENOTDIR at file-create because their
cached resolution of the recreated parent was a STALE prior incarnation → files never created → all
renames `mv: cannot stat`. Why prior defenses blind: reuse is dir→dir (no ftype mismatch) so
ftype-evictions never fire; INODE_FREE evict-ring fired 0× (delivery gap); d_revalidate compared only
inode NUMBERS (same→valid) and never consulted XFS_ISTALE_CAW/i_dlm_stale. FIX (Gemini A+C, in
`pal/linux/xfs_super.c` `mxfs_drevalidate`): **Part A** — positive dentry with `i_dlm_stale ||
XFS_ISTALE_CAW` → return 0 (INVALID) before own-AG fast-path → forces xfs_lookup ISTALE-CAW evict.
**Part C** — peer-AG positive DIRECTORY resolving to same ino → LOCKLESS FUA read of on-disk di_gen via
`mxfs_inode_disk_di_size(ip,NULL,&disk_gen)` (SCSI READ(16), di_gen at dinode off 0x5c, no ILOCK/DLM);
if `disk_gen != incore i_generation` → set i_dlm_stale+XFS_ISTALE_CAW, return 0. Gated to peer-AG DIRS
only (reg files excluded — sess51 FUA-on-every-empty-reg-lookup → 120s barrier stall). PROVEN
81/240-fail→PASS 240/240 ~11s. Detectors P-DREVAL-GENMISS/STALEFLAG, ISTALE-CAW-EVICT. Remaining:
unlink_visibility + cross_write_read fail with deep AG/defer corruption shutdown.

### sess87 — reload-shutdown FIXED; deep root = INODE DOUBLE-ALLOCATION ([[sess87_lessons]], build `77C90663`, KEEP)
Shutdown signature `Corruption ... xfs_iflush_cluster` + `xfs_dir2_sf_verify` on the modified dir.
ROOT: `mxfs_dlm_reload_inode` calls `xfs_idestroy_fork(&ip->i_df)` BEFORE `xfs_inode_from_disk`
validates; the `down_write_trylock` spin loop opens a WIDE window in which a concurrent re-read of the
SHARED inode-cluster buffer mutates `dip` between check and from_disk → verify fails AFTER the fork was
destroyed → half-built inode → next xfsaild flush → sf_verify → SHUTDOWN (propagation cycle: bad
in-core flushed with valid CRC → peers reload it). FIX: after i_lock EXCLUSIVE, take a STABLE private
snapshot `snap=kmalloc(inodesize); memcpy(snap,dip,inodesize)`, verify the SNAPSHOT, retry torn reads
up to 8×, BAIL keeping authoritative in-core on persistent failure; `dip=snap`. An EARLY pre-spin
verify (build `183DB004`) did NOT work — mutation happens DURING the spin. **Deep blocker exposed:**
`.mxfs_barriers` (ino=4194435) is a REGULAR FILE on all 4 nodes → every barrier mkdir fails → 120s
timeouts. `P-RELOAD-TYPEFLIP incore=040755(dir) disk=0100644(reg) SAME gen` = inode number allocated
twice without intervening free = INODE DOUBLE-ALLOCATION (the long-standing bnobt double-free family).
Node-affine alloc (`m_mxfs_node_slot % m_maxagi`) means both should be one node's AG → single-node
double-alloc within own AG, UNLESS a peer's affine AG filled and wrapped.

### sess90 — refuted xfsaild theory; FUA-over-logged root PROVEN ([[sess90_lessons]], build `D1E532E2`)
**PROBE-A (AG-meta WRITE while not holding AG) fired 0×** → kills the sess89 "post-release xfsaild
CIL→AIL bnobt clobber" theory. **P90-PICK** (per-alloc slot/ino/agno, `xfs_ialloc.c` xfs_dialloc)
proves allocation is SINGLE-NODE-PER-AG (only test1/slot0 ever picks AG0 inos) → the conflict is
READER-SIDE cross-node CACHE staleness, NOT the allocator handing one ino to two nodes. Two TYPEFLIP
gen signatures (off-by-one vs same-gen, above). **ROOT CONFIRMED (Gemini + decisive probe):** mxfs
FUA-reads buffers carrying LOGGED-but-not-yet-checkpointed modifications, clobbering them with stale
disk content = the lost-update family (inode-cluster clobber AND bnobt double-free). `P90-FUA-OVER-
LOGGED` (in `mxfs_buf_read_fua`, before `mxfs_pal_scsi_read_fua_bdev`) traps FUA read when
`b_pin_count>0 || !list_empty(&b_li_list) || b_log_item` — **FIRED 7× on the shutting-down node
(test1)**; daddr=128 = inode-cluster holding ino 136 (explains P81-DEXT 0-extents). FIX to implement:
NEVER FUA-read / clear XBF_DONE on a buffer that is pinned or has log items — keep in-core, treat as
fresh. Also: STAMP preserved gen-lagging bufs with pag_dlm_meta_gen (once xfsaild cleans them the next
read re-stales+clobbers). Also landed **TYPEFLIP-STALE-SKIP** (`mxfs_dlm_reload_inode` ~L1989): refuse
a reload that flips S_IFMT unless `disk_gen > incore_gen` (mxfs bumps gen +1 on reuse, so same/older-gen
type-flip = stale/corrupt disk → keep authoritative in-core) — the reader-side defense for the
same-gen case that every gen-check missed.

### sess102 — fua_disable reframe; in_ail-discard fix ([[sess102_lessons]], build `B3C15760`, KEEP, 3/4)
**Decisive:** sess94 made `fua_disable=1` the DEFAULT — reads go plain-bio through the COHERENT SCST
write-back cache; the FUA-platter read path is now DEAD. **So all of sess80/90/92's consults analyzing
`mxfs_buf_read_fua` are moot; the bnobt double-free PERSISTS with FUA off ⇒ root is the plain-bio/SCST
path, not FUA.** Three shutdown signatures, same lost-update family: bnobt double-free (cross_write_read
free path), dialloc EFSCORRUPTED (create), iunlink AGI-garbage (unlink). **FIX #1 (B3C15760):** drop
the `!in_ail` protection in `mxfs_ag_meta_invalidate_stale` — under fua_disable=1 a buffer clean by
tx-flags has its content already on the coherent SCST cache, so discard+plain-reread is safe even if
in_ail; the `!in_ail` exclusion had served node A its OWN stale prior-hold AGI/inobt/bnobt snapshot
after release→peer-modify→reacquire → double-alloc. `!dirty` still protects current-hold work.
**sess43's "discard-in_ail lost-update" was a FUA-platter-behind-SCST false positive.** Eliminated the
bnobt/dialloc class (sig 1/2); failure MOVED to sig 3 (iunlink/inode-cluster, pre-existing). **Remaining
blocker = inode-number REUSE coherency.** Detector P-IRESURRECT (`xfs_iflush`) proves xfsaild flushes
in-core inodes disk says are a different incarnation: `incore_gen==disk_gen+1` (this node realloc'd
while peer still has gen G live), and at iunlink `ino=6291584 disk_dimode=040755 disk_dnlink=2
agi_disk_differs=1` (this node FREEING an inode disk shows as a LIVE DIRECTORY owned by a peer). Gemini
REFUTED a gen-mismatch-abort guard in iflush (gen mismatch is NORMAL during rapid reuse; would trap
legit reallocations — P-IRESURRECT is detector-only). Existing `INACT-SKIP-STALE` (xfs_inode.c ~2217)
INSUFFICIENT: skips only B1 (disk di_mode==0) or B2 (gen-mismatch AND i_dlm_mode==NL); failing case is
disk LIVE + gen MATCHES + i_dlm_mode=EX + disk_nlink>0 while in-core nlink=0. inode-cluster bufs are NOT
in `mxfs_buf_is_ag_metadata` (only AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/rmap/refcount) — Gap (c).

### sess104 — ABA inode-reuse root FIXED ([[sess104_lessons]], build `736ECD00`, KEEP, 3/4, wedge gone)
`84AC92ED`: wired `mxfs_dlm_dir_modify_refresh` into `xfs_rename` (both src_dp+target_dp) and
`xfs_create`. **`736ECD00` — ABA inode-reuse fix (Gemini, PROVEN 40→1/2→3/4):** XFS dir DATA blocks are
cached by PHYSICAL daddr, NOT by inode. When a prior test frees inodes and a new test REUSES the
numbers+blocks, peers retain the PREVIOUS incarnation's dir blocks at the same daddrs with XBF_DONE set
(owner==ino verifier passes). The `gen==0` short-circuit in modify_refresh + the eviction-ring
DIR_MODIFY consumer treated a fresh dir as "nothing to go stale" — FALSE under reuse; and `i_dlm_dir_gen`
collides across incarnations (old 1 == new 1). FIX: new inode field `i_dlm_dir_evicted_incarn`; in BOTH
modify_refresh and consumer_refresh drop the gen==0 early-return; force a one-shot whole-dir clean-block
evict when `i_dlm_dir_evicted_incarn != VFS_I(dp)->i_generation` (XFS bumps di_gen on every realloc →
monotonic incarnation key). Killed the 604s EX-timeout wedge/shutdown cascade. **Residual #1** —
intermittent WHOLE-NODE rename loss: alone 6/6 PASS; after cross_visibility ~25% fail and one node loses
ALL 20 renames (invisible to ALL incl writer = DURABLE). Evidence: `COHOLD=0` (no concurrent-EX,
exclusion correct), `SESS50-STARVE=29-35` (heavy dir-EX contention), `DIR-STALE-SKIP=0`, `i_dlm_dir_gen
stays 0` → the whole gen coherency machinery is OFF for a modify-only/weakly-read dir. Four holes in the
gen machinery: read-only arming (armed 0→1 only on read path + slow-path re-acquire), eviction-ring
gen!=0 gate, ring unreliable cross-node in CAW (sess82), evict skips undurable. Next hypothesis: ARM
`i_dlm_dir_gen` on the MODIFY path (sess43 warned write-acquire gen-bump timed out rename via FUA storm,
but sess94 fua_disable=1 removed that timing wall — retry it). Gemini's real invariant: EX-acquire must
GUARANTEE fresh dir blocks; gen is a band-aid. **Residual #2** = cross_write_read `.md5` small-file
content loss (reg-file writer-durability, separate bug — sess45/79 family).

## Recurring failure modes / rules to not relearn
- **instr=1 HIDES the race** — 100x printk slowdown serializes concurrent creates → false PASS. Diagnose
  ONLY with always-on detectors (SESS50-STARVE/COHOLD, P90-*, P-IRESURRECT). ([[sess54_lessons]], [[sess40_lessons]])
- **NO ILOCK_EXCL across CAW poll** — xfsaild AIL-drain wedge / D-state; in-place reload under ILOCK_EXCL
  in path-walk → D-state deadlock. All reuse-detection choke points must sit in VFS methods AFTER VFS
  locks, not inside xfs_iget. ([[sess54_lessons]], [[sess55_lessons]])
- **NO per-op FUA in the hot path** — barrier markers are empty files hit constantly → 120s timeouts.
  Gate FUA gen-checks to peer-AG DIRS only. ([[sess86_lessons]], [[sess54_lessons]])
- **Perf-vs-correctness tension is structural:** every reuse fix that adds a DLM/FUA round-trip per iget
  times out the criterion on the ~480 genuinely-deleted verify-gone igets. Cheap-only reload + creator's
  eventual flush is the escape. Can't distinguish "peer reused" from "genuinely deleted" by inode
  content alone. ([[sess40_lessons]])
- **gen-based defenses are all blind to the same-gen case** (double-alloc + inode-cluster stale-flush) —
  need a TYPE-aware trap or to stop the stale-flush at the source. ([[sess90_lessons]], [[sess87_lessons]])
- **`disk_differs=1` at writeback is an artifact** (in-core=new, disk=old), not evidence of corruption.
  ([[sess53_lessons]])
- Node-affine alloc: `m_mxfs_node_slot % m_maxagi`; slots test1=0 test2=3 test3=1 test4=2. Geometry
  ~20 AGs on a 20GB dev, 2097152 inodes/AG.

## Infra (test cluster)
4 nodes test1-4 under `LIBVIRT_DEFAULT_URI=qemu:///system`; recover a wedged/D-state node with
`virsh destroy+start` then reset4. `/mnt/mxfs-src` (192.168.120.1:/src/mxfs) NFS DROPS on node reboot —
remount on every node before reset4. `.ko` loaded over NFS from this host's /src/mxfs; `make modules`
is immediately visible. Repro loop kept mounted: `reset4.sh 4` → `run_tests.sh --phase cluster --test
<name>` in a loop, grep each node's dmesg for `Shutting down filesystem`. cache_coherency.sh
auto-backgrounds >10min AND unmounts at end (can't loop it — use the individual sub-test). srcversion is
NOT stable cross-session — verify a build by `strings mxfs.ko | grep <probe>`. Always
`pkill -9 -f 'cache_coherency|run_tests|mxfs_test'` + reset4 between runs. Clock drifts ~1s/node —
`date -u -s` per node before merging P-traces. `date -u` for journalctl.
