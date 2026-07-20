---
name: compiled-zsl-bmbt-leaf-dinode-torn-write
description: Compiled zero_silent_loss investigation (sess59-73): on-disk di_nextents runs ahead of bmbt leaf; writer torn release of hot shared dir ino=131.
metadata:
  type: project
tags: [compiled, zero_silent_loss, bmbt, dinode-torn-write, cache-coherency, ship-criterion]
---

# zero_silent_loss: torn (dinode, bmbt-leaf) on the hot shared dir

Compiles sess59-sess73 (all ccloop `14d31183`) on the ship-gate criterion
`zero_silent_loss` (tests/criteria/zero_silent_loss.sh --iters N --dpn 100 --mode 1,
budget ~300-480s, 16 nodes). **Criterion NEVER PASSED across this arc; marker never
written.** All work is on ONE symptom: 16 nodes hammering a single shared storm dir
`ino=131` (/mnt/shared/wa_iter1), which grows fast to BTREE-format. The on-disk
`dinode.di_nextents = N` ends up ahead of the on-disk bmbt LEAF record count (`N-1`,
occasionally `N-3`). A reloading peer walks the leaf, gets `ir.loaded = N-1`, trips
`ir.loaded != if_nextents` at **xfs_bmap.c:1286/1271** (xfs_iread_extents) →
EFSCORRUPTED / "Structure needs cleaning" / `corrupt dinode 131 (btree extents)` at
`xfs_iread_bmbt_block` → FS shutdown → the whole 16-node storm cascades. The reported
`total_fs_silent≈1600` is the **blast radius of whichever node shuts down first, NOT
1600 individual losses** — it is VARIANCE-DOMINATED (1600/375/1600/171/105/270 across
near-identical builds). **Judge every fix by per-SIGNATURE dmesg counts (P59-IREAD-MISMATCH,
P63-TORN-FLUSH, etc.), never by the RESULT line.**

## The three shutdown signatures (all one root — di ahead of leaf)
- **SIG1** `ir.loaded != if_nextents` xfs_bmap.c:1286, xfs_iread_extents — DOMINANT.
- **SIG2** `!(flags & XFS_DABUF_MAP_HOLE_OK)` xfs_da_btree.c:2814 — leaf references a
  dir block the extent map doesn't map.
- **SIG3 / Face-2** `i != 1` xfs_bmap.c:2800/2848, xfs_bmap_add_extent_hole_real
  BMAP_LEFT_CONTIG — `xfs_bmbt_lookup_eq` can't find the in-core left extent (iext
  ahead of bmbt). This one fails MID-TRANSACTION in mkdir, BEFORE any flush, so
  flush-time fixes cannot help it.

## Chronological root-cause progression

### sess59 — first localization; big drop from a read-side evict
[[sess59-zsl-bmbt-stale-child-root-and-residual]]: **concurrent-EX REFUTED** — P58
popcount showed `ex_pop=1/held=1` everywhere (single holder), so it is a single-holder
stale-base clobber, not mutual-exclusion. Fix A (63FD06FF, `peer_modified_since_load`
FASTEX reload) forced a cold bmbt read and EXPOSED a corruption the stale cache had been
MASKING. Fix B (**75C0C6AE, KEEP**) = new `mxfs_dir_evict_bmbt_blocks(ip)` (AG-walk for
`xfs_bmbt_buf_ops` bufs owned by ip, clear XBF_DONE on clean ones, never xfs_buf_stale,
skip pinned/undestaged) called in `mxfs_dir_drain_evict_data_blocks` before the BTREE
bail — because reload invalidated the inode CLUSTER (bmbt root in if_broot) but NOT the
cached bmbt CHILD blocks. **Result silent 1600→105.** [[sess59-zsl-residual-bmbt-leaf-disk-staleness]]
(build B24B321B) quantified the residual: `loaded < if_nextents ALWAYS` (e.g. 13<24,
broot_lvl=1 = 2-level tree). Since reload reads the dinode atomically (root + di_nextents
mutually consistent), the LEAF blocks on disk genuinely hold fewer records → **writer-side
release flush-ordering gap**, not reader staleness.

### sess60 — proven writer-side; refutes reader-FUA and xfsaild-reflush
[[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]] (probe build 503B10EC): the
decisive `P60-RELAUDIT` (`mxfs_dir_bmbt_release_audit`, runs ONLY in BAST-release drain
~xfs_mxfs_dlm.c:2833) showed `di_nextents=14 leafsum=13 nleaves=1 INCONSISTENT-AT-RELEASE`
— **the releasing writer hands EX to a peer with di=14 but the bmbt leaf holding only 13;
the 14th extent never appears in any leaf anywhere.** Off-by-ONE (the LAST extent) every
time. Two RULE-4 disproofs: (1) **reader-FUA REFUTED** — `mxfs_fua_disable=1` by default
(xfs_mxfs_dlm.c:10250) so ALL reads are plain-bio hitting the COHERENT SCST write-back
cache; `loaded<if_nextents` is therefore a genuine on-disk inconsistency, not a
per-initiator cache artifact, and reader-side FUA CANNOT fix it. (2) **xfsaild
stale-reflush REFUTED** — `mxfs_buf_xfsaild_skip_bmbt_write` / `P60-XFSAILD-SKIP-BMBT`
fired 0× (xfsaild never pushes a bmbt block for a dir held NL).

[[sess60-zsl-evict-gate-fix-and-stale-leafwrite-residual]] (**8E495999, KEEP**): the
**evict-gate fix** — `mxfs_dir_evict_bmbt_blocks` was being called UNCONDITIONALLY for
BTREE dirs; P60-RELAUDIT proved evicting a leaf while the in-core iext tree is LOADED
(need_iread=0) REVERTS the leaf buffer to its stale on-disk image (measured
`di=15 iext=15 leaf=14`). Fix: only evict when `xfs_need_iread_extents(&ip->i_df)` is
true. That specific `iext=N leaf=N-1 need_iread=0` corruptor GONE; residual INCONSISTENT
cases are all need_iread=1 (reloaders observing an already-torn disk pair).

[[sess60-zsl-bmbt-leaf-write-essentially-never-submitted]] (**3221AE35**): the
`P60-BMBTWRITE` probe at the single write chokepoint `xfs_buf_submit_bio` showed
**ino=131's bmbt leaf is essentially NEVER written to disk during the storm** (total=0
on most nodes), while the dinode (di_nextents) flushes frequently. Reframed root: NOT a
stale-leaf clobber but a **MISSING leaf flush** — record N is added in-core but its WRITE
never reaches xfs_buf_submit_bio; disk keeps N-1 while dinode advances to N.
Build path: B24B321B → 16FC7EC9 (bmbt-FUA, reverted/inert) → FD606B66 → 503B10EC →
4AF64BDF → 8E495999.

### sess61 — di published AHEAD of leaf; ordering framing; two more refutes
[[sess61-zsl-root-di-ahead-of-bmbt-leaf-ordering]] (build BA1771B9): PROVEN the on-disk
**dinode di_nextents reaches N while the on-disk bmbt leaf only reaches N-1** — the
inode-cluster (dinode) is published to the shared SCST store AHEAD of the bmbt leaf.
Run-d: dir grew to 16, di=16 flushed but NO node ever wrote leaf=16. Run-c: grower had
in-core `iext=18 / leaf=17` (in-core leaf one record behind its own iext tree).
**REFUTED (do NOT retry):** FIX-1 NL-skip at bio chokepoint (`P61-CHOKEPOINT-SKIP` 0×;
mode=0 writes were a contaminated-cluster artifact), FIX-2 bmbt read-over-logged guard
(`P61-BIO-OVER-LOGGED-BMBT` 0× — plain-bio read is not the revert vector). Fix direction:
COUPLE dinode+leaf durability (leaf durable before/atomic-with di_nextents). Note: pure
XFS keeps iext++ and xfs_btree_insert in lockstep (xfs_bmap_add_extent_hole_real case 0,
line 2848) when cur!=NULL — run-c's divergence implies an MXFS path (suspect the
ILOCK-drop-across-CAW-poll in alloc) bumps if_nextents without landing the leaf record.

### sess62 — leaf-write-never-submitted confirmed, then re-pinned to leaf=N-1
[[sess62-zsl-bmbt-leaf-write-never-submitted-confirmed]] (B548E404): evicting the cached
leaf and cold-reading STILL trips SIG1 → **skew is GENUINELY ON-DISK, reader fixes cannot
help.** `P60-BMBTWRITE owner=131` fired only 2× cluster-wide. `P61-BMBTSCAN` at
release/iflush shows `leafrecs==if_nextents cand=0 wrote=0` — the in-core leaf is
XBF_DONE-clean claiming durable, yet disk has N-1 → **the dirty leaf's logged change is
discarded / buffer marked DONE without a bio ever firing.** REFUTED: P62-RELOAD-FORK-SHRINK
(shrink fired 0×; reload state consistent). Suspected `_XBF_DELWRI_Q` collision (CLAUDE.md
design tension): freshly-allocated bmbt leaf on `pag_mxfs_alloc_buflist` with `_XBF_DELWRI_Q`
set → xfsaild's `xfs_buf_delwri_queue` returns false → XFS_ITEM_FLUSHING forever, and the
Phase-2 drain doesn't cover bmbt leaves.

[[sess62-zsl-leaf-buffer-lags-nextents-by-one]] (**663F1716**, SUPERSEDES the
never-submitted framing): builds confirm the bio DOES land — it just lands a SHORT leaf.
`P62-IFLUSH-FORCE ino=131 if_nextents=15 nheld=1 wrote=1` + `P60-BMBTWRITE ... numrecs=14`
→ the leaf buffer ITSELF is short (numrecs=14 while if_nextents=15); force-flushing it is
useless. Two sub-hypotheses: (1) post-split 2nd leaf (broot_lvl=1) never flushed/cached —
only leaf0(14) in this node's cache, the 15th record lives in an unflushed leaf1;
(2) in-core iext ahead of bmbt (SIG3). `mxfs_iflush_force_bmbt_durable` added but INEFFECTIVE.

### sess63 — leaf-write EIO fixed (FUA-passthrough), residual = in-core leaf reverts
[[sess63-zsl-bmbt-fua-fix-eio-gone-but-incore-leaf-reverts]] (**E277C0DA**): raw `dd`
of the platter (twice) confirmed the torn on-disk state is REAL (dinode di_nextents=N,
leaf numrecs=N-1 — recipe: dinode @ device byte 100771328, di_nextents @ +76 4B BE;
leaf device byte = 100704256 + leaf_daddr*512, numrecs @ +6 2B BE). `P63-INSERT-DESYNC`
(after xfs_btree_insert) NEVER fired → **leaf==iext at every insert**. `P63-TORN-FLUSH`
fired: `if_nextents=15 leafsum=14 comm=xfsaild` → the in-core LEAF is one behind the iext
skiplist AT flush. **FIX A (KEEP, works for its target):** route bmbt-leaf WRITES through
SCSI FUA passthrough — the plain REQ_OP_WRITE|REQ_META bio was intermittently `-EIO` on
the iSCSI/SCST stack (`P133-BMBT-RELFLUSH-ERR rc=-5`); in xfs_buf_submit, for multi-node
WRITE of `xfs_bmbt_buf_ops` call `mxfs_buf_write_fua(bp)` → **EIO eliminated, leaf writes
durable.** FIX B (added `xfs_bmbt_buf_ops` to `mxfs_buf_needs_fua_read`, KEEP-for-now):
did NOT regress this time, but SIG1 PERSISTS — reader FUA-reads leaf and still gets N-1
because the disk is durably TORN. **Residual root pinned: the in-core bmbt leaf reverts
N→N-1 AFTER the (consistent) insert, BEFORE the flush**; writer then durably flushes the
torn pair.

### sess64 — leaf-rebuild-at-iflush fix (biggest win); two residual faces unified
[[sess64-zsl-torn-dinode-leaf-never-14-incore-leaf-lags]] (**E6A40C95, KEEP** — proven
big win): `mxfs_iflush_force_bmbt_durable` (xfs_mxfs_dlm.c ~389, called from xfs_iflush
xfs_inode.c:4219 with ILOCK held, immediately BEFORE di_nextents is copied to the on-disk
dinode). For the SINGLE-LEAF case (broot_nrecs==1, level-0, extents loaded, leaf numrecs
!= if_nextents, if_nextents <= m_bmap_dmxr[0]): re-serialize the leaf's records straight
from the authoritative iext list (for_each_xfs_iext → xfs_bmbt_disk_set_all), set
`bb_numrecs = cpu_to_be16(cnt)` DIRECTLY (xfs_btree_set_numrecs is static/not visible).
Log `P64-LEAF-REBUILD`. **Result silent 1600→171, P59 152→5.** Two residuals:
(1) **nheld=0 torn path** — `P63-TORN-FLUSH leafsum=0 nheld=0`: leaf not cached at iflush
so rebuild finds nothing (~5 residual P59); (2) **Face-2 now dominant** (SIG3, 7 node
shutdowns/run) — must be fixed AT SOURCE because it fails mid-transaction before flush.

[[sess64-face2-leftcontig-desync-leaf-lags-iext-by-one]] (probe build B9C27147): Face-2
origin PROVEN — `P64-LEFTCONTIG-DESYNC ino=131 iext=15 leaf_numrecs=14 broot_nrecs=1` →
**in-core iext = N, bmbt leaf = N-1, single leaf**. A mkdir doing a LEFT_CONTIG merge
calls `xfs_bmbt_lookup_eq(cur,&old,&i)`; the leaf is missing the left-neighbor → i!=1 →
shutdown. UNIFIED ROOT for both faces: **the in-core bmbt LEAF buffer lags the authoritative
in-core iext tree by 1.** E6A40C95 reconciles only AT iflush (fixes Face A); Face B needs
the in-core leaf consistent DURING transactions. Two candidate origins of the lag not yet
separated: (a) a stale plain-bio READ DMA'd the older on-disk leaf over a checkpointed-clean
buffer (P61 guard only catches UNCHECKPOINTED mods — gap: checkpointed-clean-but-not-durable);
(b) xfs_btree_insert grew iext but not the in-core leaf. Fix options: broaden the guard to
refuse ANY disk read of a bmbt leaf with XBF_DONE owned by an EX-held inode (RISK: sess60
found evicting a loaded leaf reverts it), or reconcile-at-use in
xfs_bmap_add_extent_hole_real (rebuild leaf from iext, must be logged).

### sess65 — reframed as DLM-handoff coherency (Gemini×2 + GPT)
[[sess65-zsl-dlm-handoff-metadata-coherency-root]] (build 16520C7B; P65-LEAF-FABRICATE
INERT, nheld always ≥1). Fresh evidence of a **3-way divergence** on one node:
on-disk-leaf(14) / in-core-iext-tree(16) / if_nextents(15) — multiple owners concurrently
publish mutually-inconsistent (di_nextents,leaf) pairs. `P63-TORN-FLUSH if_nextents=15
leafsum=16` → the rebuild's `cnt==if_nextents` guard FAILED (iext tree walk yielded 16
non-null while if_nextents=15). GPT architectural reframe: **DLM EX serializes mkdir ENTRY
but NOT the full XFS metadata lifecycle** (CIL→AIL→iflush→bmbt writeback→local buffer-cache
inval→peer reload); N nodes = N independent buffer caches; the DLM must act like a
GFS2/OCFS2 glock (sync-demote on release + invalidate/reload on acquire) and doesn't fully.
Mechanism A: on EX ACQUIRE the reload refreshes if_nextents from the fresh dinode but a
STALE dirty/in-AIL cached bmbt LEAF SURVIVES eviction (`mxfs_dir_evict_bmbt_blocks` skips
dirty/in-AIL/pinned) → lazy xfs_iread_extents rebuilds iext from the stale leaf. Control-flow
fact: `P119-NONEX-FLUSH-SKIP` (xfs_inode.c:4144) runs BEFORE the force call — a non-owner
CANNOT write a stale leaf via the force; **the corruptor is an OWNER with a polluted iext.**
Fix direction: move correctness from xfs_iflush reconcile → **DLM HANDOFF** (EX release:
SCOPED synchronous destage of this inode + its bmbt leaf before unlock — whole-AIL push
DEADLOCKS, sess32/39; EX acquire: invalidate the stale leaf EVEN IF dirty/in-AIL via the
existing drain-the-pin-then-discard idiom). The single-dir-inode workload is adversarial;
sub-2×-native likely needs lock-stickiness/leasing (RULE-0 slowness is a separate FAIL).

### sess66 — write-side clobber proven; tenure-authority write gate built
[[sess66-zsl-bmbt-leaf-xfsaild-clobber-tenure-gate]] (**88688A48, BUILT, NOT TESTED**).
`P66-LEAFWRITE` (in xfs_bmbt_write_verify): every bmbt LEAF write for owner=131 has
**comm=xfsaild/sda**, and DIFFERENT nodes write DIFFERENT stale numrecs to the SAME shared
daddr (test3 writes 14, test4 writes 16 while a peer grew to 30). The dinode di_nextents
IS DLM-EX-gated (P119 xfs_inode.c:4144 + P17B epoch guard in xfs_iflush) so it advances to
the latest owner's count; the bmbt LEAF has an INDEPENDENT xfsaild/delwri path with **NO
EX gate**. Prior `mxfs_buf_xfsaild_skip_bmbt_write` only skipped when `i_dlm_mode==NL` — it
MISSED the re-acquired-EX-with-lingering-prior-tenure-BLI case (mode=EX). Three fixes:
(1) need_iread guard on `mxfs_dir_bmbt_invalidate_stale` (xfs_mxfs_dlm.c ~8010) — PROVEN
GOOD, eliminated P64-LEFTCONTIG-DESYNC entirely (invalidating while iext loaded reverted
the leaf away from authoritative iext); (2) drain-pin-then-evict for pin-only stale leaf;
(3) **TENURE-AUTHORITY write gate (the root-fix candidate):** new `mxfs_dir_bmbt_track(bp)`
stamps `bp->b_tenure_id = owner->i_mxfs_ex_grant_seq` at MODIFY time (hooked in
xfs_trans_log_buf for xfs_bmbt_buf_ops, multi-node); `mxfs_buf_xfsaild_skip_bmbt_write` now
ALSO skips+stales when `bp->b_tenure_id != ip->i_mxfs_ex_grant_seq` (leaf logged in a PRIOR
tenure = superseded, don't clobber peer). Mirrors the proven AG-meta b_tenure_id mechanism
(sess123/125). The modify-time epoch stamp is the correct discriminator (bmbt reads don't
stamp b_mxfs_dir_gen, so a gen-based gate would false-skip).

### sess67 — write-clobber theory REFUTED; root reframed to stale-cached READ
[[sess67-zsl-root-stale-cached-bmbt-leaf-not-write-clobber]] (build 88688A48 tested, then
probe build 3AC3BF09). The **P34B FUA-readback probe** (dirwr=1) is decisive:
`P34B-BMBT-STALEREAD ino=131 cached_recs=14 disk_recs=18 bflags=0x20` — the cached buffer
is CLEAN (XBF_DONE only, not pinned/dirty/delwri/in_ail) and BEHIND the platter; **the
on-disk leaf is CORRECT and matches di_nextents (disk_recs=18==if_nextents=18) — THE DISK
IS NOT TORN.** The reader walks the STALE CACHED leaf(14) → `ir.loaded=14 != if_nextents=18`
→ shutdown. This **REFUTES sess66's write-clobber theory** (88688A48 fails identically; the
LAST/durable write is correct; the tenure WRITE-gate attacks the wrong side) AND **REFUTES
a FUA-read fix** (`fua_disable=0` still fails — a CLEAN XBF_DONE buffer is returned with NO
I/O, so the FUA gate never engages). Actual root by elimination: the stale CLEAN-DONE cached
leaf SURVIVES the reload-time `mxfs_dir_evict_bmbt_blocks` eviction — WHY is open: (a) the
rhashtable owner-filtered walk MISSES it, (b) at evict time it was transiently
pinned/dirty/in_ail and the 50-iter/2ms unpin wait isn't enough, later settling clean-DONE,
or (c) a plain-bio re-read repopulated it stale and marked _XBF_FUA_FRESH. Built P67-BMBT-EVICT-ENTER
/ -SKIP probes (NOT yet observed under storm). **NOTE: host wedged at session end (RULE 2,
manual clyde reboot required) — iscsi_conn_cleanup D-state storm, stale SCSI PR.**

### sess73 — DECISIVELY re-rooted back to genuine ON-DISK inconsistency
[[sess73-zsl-ondisk-dinode-bmbt-inconsistent-writer-torn]] (build **64932978** =
55379AA2 + P73 diag). The **P70-DINO-RECONCILE** block (xfs_bmap.c:1274-1307) runs
UNCONDITIONALLY: it FUA cache-bypass re-reads THIS inode's on-disk dinode and adopts
`disk_nx` iff `disk_nx >= ir->loaded+num_recs`. **Corruption at xfs_bmap.c:1308 STILL
fired ⇒ the FUA-fresh ON-DISK dinode di_nextents was ALSO too low** relative to a
structurally-valid on-disk leaf (magic BMA3, bb_numrecs=0x13=19). ⇒ the on-disk
(di_nextents, leaf) pair is **GENUINELY INCONSISTENT ON DISK** — NOT reader staleness;
all read-side fixes (sess68 leaf-refresh, sess70 dino-reconcile) cannot help. This
**re-confirms sess60's writer-side torn release** and refutes the sess67 pure-stale-read
framing for this run. Likely mechanism (sess34): a node with a STALE-LOW cached dinode
does a mkdir and its release-drain iflush writes the stale-low di_nextents to disk,
REVERTING a peer's grow, while the peer's leaf (19 recs) stays → **dinode behind leaves**
(note: OPPOSITE polarity to the classic di>leaf — here di<leaf). `P61-CHOKEPOINT-SKIP-BMBT`
fired (a guard, not the fix). Two failure faces of the same ino=131 bug: (1) verify-HANG =
a LOCAL leaked i_lock (find wedges D-state in xfs_ilock down_write, NO owner thread;
unmounting the apparent holder did NOT free it → not a cross-node CAW orphan; sess132
leaked-ILOCK, site still unplugged; added P73-ILOCK-STUCK trylock+cond_resched detector,
which perturbs the wedge so it hit corruption instead); (2) DATA-LOSS =
"Structure needs cleaning" / `corrupt dinode 131 (btree extents)`, NO FS shutdown
(EFSCORRUPTED returned per-op). NEXT: instrument the dir DLM RELEASE / dinode iflush to
catch a di_nextents REGRESSION on disk and REFUSE to write a lower value than the current
on-disk dinode or the inode's own bmbt leaf sum (peer's grow must win).

## Net state at end of arc
- **KEEP builds/fixes:** 75C0C6AE (bmbt-child evict, 1600→105), 8E495999 (evict-gate on
  need_iread — do NOT evict a loaded leaf, it reverts), E6A40C95 (leaf-rebuild-at-iflush,
  1600→171 / P59 152→5), sess63 FIX A (bmbt-leaf write via SCSI FUA passthrough, kills the
  intermittent -EIO). sess66's need_iread guard on invalidate_stale (killed
  P64-LEFTCONTIG-DESYNC). Various always-on probes (P59-IREAD-MISMATCH, P60-BMBTWRITE,
  P61-BMBTSCAN, P63-TORN-FLUSH, P34B-BMBT-STALEREAD).
- **REFUTED (do NOT retry):** concurrent-EX (ex_pop=1); reader-FUA add alone (inert under
  fua_disable=1, and returns clean XBF_DONE with no I/O); xfsaild stale-reflush of an
  NL-held dir (P60 0×); NL-skip at bio chokepoint (P61 0×); bmbt read-over-logged guard as
  the revert vector (P61 0×); reload-fork-shrink (0×); sess66 tenure WRITE-gate as THE fix
  (refuted sess67 — but the disk was genuinely torn again by sess73, so write-side is NOT
  fully off the table).
- **The tension the arc never resolved:** different runs show BOTH "disk is correct, reader
  cache is stale" (sess67) AND "disk is genuinely torn" (sess60/61/62/63/73). Both are real;
  the true fix must couple the (dinode, bmbt-leaf) pair at the DLM handoff (sync-demote on
  release + invalidate-even-if-dirty on acquire, GFS2/OCFS2 glock semantics — sess65) AND
  keep the in-core leaf lockstep with the iext tree during transactions (Face-2). Slowness
  on this single-shared-dir workload is a SEPARATE RULE-0 FAIL (P138-WAIT 6.4s EX handoffs,
  sess50 STARVE family).
- Other ship-gate criteria FAIL throughout, untouched: fence_during_write (lost=400),
  rsync_paired (148%), posix_semantics_multi16 (>600s) — same hot-dir family.

## Infra invariants for this workload
16-node runs: `virsh -c qemu:///system destroy+start` ALL 16 SEQUENTIALLY before EVERY run
(backgrounded loops exit mid-way and leave stale mounts whose umount wedges D-state on SCSI
reservation conflict); verify uptime~0 & /proc/modules mxfs=0. Local /src/mxfs/mxfs.ko is
NFS-visible; the storm insmods it directly (no scp). Probes gated behind `dirwr=1` /
`mxfs.instr` module params (0644) — set via prep insmod or sysfs. Outer criterion `timeout`
must be ≥480s or it truncates into a fake INFRA fail. Platter ground-truth via raw `dd`
(recipe in sess63). Judge by per-signature dmesg, never the RESULT line.
