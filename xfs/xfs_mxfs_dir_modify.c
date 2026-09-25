// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- directory modification: reloads, shortform rebase, peer merges and epochs
 */
#define MXFS_TU_ID 13	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

int mxfs_dir_modify_target_flush = 1;	/* DEFAULT 1 (combo, see dir_owner_scan). DIAGNOSTIC: DEFAULT 0.  After the modify-path evict, SYNCHRONIZE CACHE the shared target so a peer's drained dirent (parked in the target write cache) reaches the platter before the post-evict FUA read.  Tests the FUA-platter-lag stale-RMW-base hypothesis. */
module_param_named(dir_modify_target_flush, mxfs_dir_modify_target_flush, int, 0644);

/* runtime toggle for the reliable LEAF-rebuild
 * (modify_refresh arm + createname rebuild).  Lets a run A/B-test whether the
 * rebuild's relog/read perturbs DATA-block coherency (test2 short readdir).
 * 1=on (default: rebuild fires once per cross-node tenure), 0=off. */
/* DEFAULT 0 (OFF).  PROVEN (instrumented, experiment B6F7AC64): firing the
 * rebuild caches a PEER's dir DATA blocks (xfs_dir3_data_read) which then go
 * stale on this node, so the cold readdir reads a SHORT data set (test2
 * readdir=100-117 vs 200) — a NEW divergence the rebuild introduced.  With the
 * rebuild OFF the DATA blocks stay coherent (readdir=200 both nodes) and the
 * leaf-hash hole is healed at READ time by mxfs_dir2_datascan_lookup instead
 * (no write-path perturbation).  Kept as an opt-in for future correctness work
 * on the on-disk leaf. */
/*  DEFAULT 1 — the leaf-hash-hole family (readdir OK,
 * lookup ENOENT; P21H-LEAFHOLE leaf_count missing ~half the fleet's hashvals,
 * dir_reuse@8/tcp r2 leaf-hash lookup_fail got=127) reproduced 1-in-5 on
 * v0.11.82 with this OFF and 0-in-3 (same pace, 101-102s) with it ON.  The
 * once-per-tenure union-only rebuild (see xfs_dir2.c consumption site) is the
 * sess26-designed countermeasure; every-create variants were the perturbing
 * ones, not this gating. */
int mxfs_dir_leaf_rebuild = 1;
module_param_named(dir_leaf_rebuild, mxfs_dir_leaf_rebuild, int, 0644);
MODULE_PARM_DESC(dir_leaf_rebuild,
	"reliably rebuild the dir LEAF hash index from coherent DATA blocks once per cross-node tenure; 0=off (default — perturbs data coherency), 1=on");
EXPORT_SYMBOL(mxfs_dir_leaf_rebuild);

/*
 * (PROVEN BY INSTRUMENT — tcp_dlm_scaling MODE B resurrection): refresh a
 * SHORTFORM directory's in-core base BEFORE a modify takes dp's ILOCK_EXCL.
 *
 * THE BUG: mxfs_dlm_dir_modify_refresh (called by xfs_remove/rename/create
 * AFTER they hold dp ILOCK_EXCL) only evicts DATA-fork dir blocks — a complete
 * NO-OP for a SHORTFORM dir, whose dirents live INLINE in the dinode.  And
 * those paths can NOT call mxfs_dlm_reload_inode because it needs i_lock EXCL
 * (down_write_trylock bails when the caller already holds ILOCK_EXCL).  So a
 * peer's committed dirent changes — signalled by MXFS_IF_DIR_RELOAD (DIR_MODIFY
 * heartbeat) with i_dlm_dir_gen advanced past loaded_gen — were NEVER adopted
 * before the shortform RMW.  The RMW then worked from the STALE in-core base
 * and durably RESURRECTED the peer's removed dirents (PROVEN:
 * P58-STALE-BASE-ADD add=[n1_rN.done] dir_gen=12 loaded_gen=3 reload_flag=1;
 * tcp_dlm_scaling leftover n1_rN nlink=1).
 *
 * FIX: the reader path mxfs_dlm_dir_consumer_refresh already consumes
 * MXFS_IF_DIR_RELOAD + reloads BEFORE xfs_lookup takes any ILOCK; mirror that
 * for the MODIFY paths by calling THIS helper with NO dp ILOCK held (before
 * xfs_trans_alloc*).  Use post_release=false so mxfs_dlm_reload_inode's
 * self-skip still PROTECTS our own un-checkpointed in-flight dir mods when no
 * peer actually modified (dir_gen == loaded_gen); it only adopts the on-disk
 * image when peer_modified_since_load (dir_gen > loaded_gen), where Invariant
 * #1 already made our prior tenure durable so disk is a strict superset.
 * No-op single-node / non-dir / flag-clear (no peer modify => no disk I/O).
 */
/* gate the CONTENT-level stale-shortform adoption.  Default OFF: the
 * count-based "disk ahead" test fired ~0x because the converter's in-core
 * shortform and the disk shortform are DISJOINT same-incarnation sets of
 * SIMILAR count (converter's own ~11 dirents vs rank1's ~11 incl node1_f1) —
 * a COUNT compare cannot detect that disk has a NAME (node1_f1) in-core lacks.
 * A correct fix needs NAME-SET comparison + a true UNION merge, but a blanket
 * union merge resurrects deletes on the delete-heavy 4/tcp tests, so
 * it must be epoch/tenure-scoped (design review).  Kept for reference/A-B. */
int mxfs_dir_adopt_block = 0;	/* reverted to 0 (was inert — in-core not shortform at modify; and full default-on stack regressed 2/tcp) */
/* REVERTED: dir_ex_grantgen_refresh (arm dir_ex_stale_refresh
 * on grant_gen advance) DELAYED the single-loss (round 11->19) but REGRESSED to a
 * DABUF_MAP_HOLE flood (rounds 20-21 readdir=0): dir_ex_stale_refresh re-reads LEAF
 * blocks (drain_evict + dir_gen-bump read-path) while reload(post_release=FALSE)
 * KEEPS the stale extent map -> refreshed-leaf + stale-map references a freed block
 * = !HOLE_OK shutdown cascade.  LESSON: the handoff base refresh must be
 * DATA-CONTENT-ONLY (never disturb leaf/extent-map under churn).  Next: data-only
 * targeted refresh (dir_addname_epoch_refresh, node.c) + fix the epoch/handoff
 * UNDER-FIRE at the dg_grant_ex source so it fires only on real handoffs. */
/* (instrumented): force a disk-superset extent-map adopt at the dir-modify
 * prelock when the monotonic DLM epoch shows a peer grew the dir since our base
 * loaded (disk di_nextents > in-core), EVEN under cached EX.  Prevents growing
 * the dir with a stale (too-small) extent map -> the allocator reusing a daddr
 * that already holds this dir's live block -> xfs_dir3_data_init zeroing it
 * (the PROVEN dir_reuse 4/8-node whole-block durable loss).  Default ON. */
int mxfs_dir_modify_extent_adopt = 1;	/* full per-block daddr compare implemented (P68-MAPDIVERGE), but it found maps AGREE at every modify-prelock (MAPDIVERGE=0) → the loss is NOT extent-map divergence at modify time but a pure data-block content RMW lost-update. Reverted to default 0 (FUA-read-per-modify is pure perf cost when it never fires). Code kept/gated for the relay. */
module_param_named(dir_modify_extent_adopt, mxfs_dir_modify_extent_adopt, int, 0644);
MODULE_PARM_DESC(dir_modify_extent_adopt,
	"adopt a peer's grown dir extent map before a modify (epoch-triggered FUA "
	"dinode check): 1=on (default), 0=off. Prevents the data_init double-alloc "
	"that zeroes a live dir block (dir_reuse_coherency 4/8-node durable loss).");
int mxfs_dir_modify_extent_reload;	/* DEFAULT 0 — TESTED, did NOT fire (P14-MODEXT-RELOAD=0×) and did NOT fix the 8-node create/lookup DABUF_MAP_HOLE (dir_reuse stayed 0/8). The epoch trigger (grant_epoch > valid_epoch) never matched for the non-SF dir. AND (dir_modify_extent_adopt P68-MAPDIVERGE=0) PROVED in-core extent maps AGREE with disk at modify-prelock time — so the DABUF hole is NOT modify-time extent-map staleness; the fresh-leaf/stale-map hypothesis is REFUTED for the create path. The hole's block-N origin needs INSTRUMENTATION (instrumented): log, at the xfs_dabuf_map invalid_mapping, where block N's reference came from (a stale LEAF re-read? an in-transaction xfs_trans_roll re-read? a genuinely orphaned daddr?) — do not guess. Kept gated-off as an inert reference. */
module_param_named(dir_modify_extent_reload, mxfs_dir_modify_extent_reload, int, 0644);
int mxfs_dir_epoch_convert_gate = 1; /* DEFAULT 1. when 1, a node about to modify a SHORTFORM dir whose dir epoch advanced reloads+adopts the peer's block0 BEFORE converting — serializes sf->block to ONE block0 (prevents the double-conversion that loses node1_f1). Part of the proven dir_reuse 4/tcp config. */
module_param_named(dir_epoch_convert_gate, mxfs_dir_epoch_convert_gate, int, 0644);
int mxfs_dir_block0_canon = 1; /* (3e02e7dd), PROVEN BY INSTRUMENT: 32/caw dir_reuse round-10 cluster meltdown — dir_epoch_convert_gate above is a RELATIVE staleness check (epoch advanced since my baseline) with a residual TOCTOU window under high concurrency (several nodes can pass it before any one's commit becomes visible to the others); this is an ABSOLUTE existence check (does a canonical block0 exist for this incarnation, full stop), published via the CAW slot's write-once dir_block0_fsb field (immediate at grant time, no disk-FUA/destage-timing dependency; durability guaranteed by Invariant 1 by the time any peer can observe it — see docs/canonical_block0_fix_plan.md). CAW-only. When 1, checked LAST (immediately before the actual conversion decision) so it closes gaps any earlier check in this function missed. */
module_param_named(dir_block0_canon, mxfs_dir_block0_canon, int, 0644);

int mxfs_dirop_sync_barrier = 1;
module_param_named(dirop_sync_barrier, mxfs_dirop_sync_barrier, int, 0644);
MODULE_PARM_DESC(dirop_sync_barrier,
                 "Synchronous parent-durability barrier on create/remove/"
                 "rename into peer-contacted dirs: 1=on (default), 0=off "
                 "(rely on demote-drain flush + destage kick)");

/*
 * (D-TMPFILE-CHURN-the budget rule-PERF-400, PROVEN BY INSTRUMENT + design-consult ruling):
 * the per-op parent publish above is gated per call site on
 *     !dp->i_mxfs_self_created || dp->i_dlm_dir_gen > 0
 * where the second clause ("also fire for a CONTENDED dir") was meant
 * to catch a shared dir.  MEASURED 2026-08-23 on a brand-new directory the
 * node had just created itself, in a private per-node churn with zero peer
 * interest: `P133-REMOVE durable=1 self_created=1 dgen=1` — i_dlm_dir_gen is
 * 1 from the dir's FIRST lock acquire, so the clause is true for every
 * directory that has ever been used and the v0.5.4 node-private carve-out
 * never applies.  ftrace: every unlink paid mxfs_dlm_dir_inode_durable =
 * xfs_log_force 0.63 + xfs_iflush_cluster 0.55 + sync bwrite 0.44 ms = 1.7 ms
 * of a 5.0 ms iteration (native XFS: 0.07 ms for the whole iteration).
 *
 * i_mxfs_self_created already IS the conservative "virgin local directory"
 * predicate the ruling asks for: created by this node this mount, and
 * cleared on ANY peer BAST (mxfs_dlm_bast_notify — a peer PR or EX request
 * both BAST the cached holder), on reload-from-disk and on reclaim.  A peer
 * can reach such a dir's dinode/dirents only by taking its inode DLM lock,
 * which BASTs us first; our release drain (__mxfs_dlm_dir_inode_durable at
 * the sd stage + dir data blocks, Invariant #1) then publishes everything
 * before the on-disk handoff.  So for a still-virgin dir the per-op platter
 * publish is redundant with the handoff drain.  Crash durability of the
 * un-forced transactions is the same as native XFS without fsync.
 *
 * dirop_virgin_skip=1: a self-created never-BASTed dir skips the per-op
 * publish regardless of i_dlm_dir_gen; dirop_virgin_skips_n counts how
 * often the clause WOULD have fired (the shadow counter the ruling
 * requires).  dirop_virgin_skip=0 = the 0.23.13 behaviour (A/B arm).
 */
int mxfs_dirop_virgin_skip = 1;
module_param_named(dirop_virgin_skip, mxfs_dirop_virgin_skip, int, 0644);
MODULE_PARM_DESC(dirop_virgin_skip,
                 "Skip the per-op parent publish for a self-created dir that "
                 "no peer has ever BASTed even when i_dlm_dir_gen>0: 1=on "
                 "(default), 0=legacy (gen>0 forces the publish)");
unsigned long mxfs_dirop_virgin_skips_n;
module_param_named(dirop_virgin_skips_n, mxfs_dirop_virgin_skips_n, ulong, 0444);
MODULE_PARM_DESC(dirop_virgin_skips_n,
                 "Shadow counter: per-op publishes skipped because the dir is "
                 "self-created+never-BASTed although i_dlm_dir_gen>0");

/*
 * The single gate for the per-op parent publish at xfs_create / xfs_remove /
 * xfs_rename.  Caller holds dp ILOCK_EXCL (so i_mxfs_self_created and
 * i_dlm_dir_gen are stable for the decision).
 */
bool
mxfs_dir_op_needs_publish(struct xfs_inode *dp)
{
	if (!mxfs_dirop_sync_barrier)
		return false;
	if (!dp->i_mxfs_self_created)
		return true;
	if (dp->i_dlm_dir_gen > 0) {
		if (!mxfs_dirop_virgin_skip)
			return true;
		/* dp ILOCK_EXCL serialises per dir; cross-dir races may lose a
		 * count — this is a shadow counter, not an invariant. */
		WRITE_ONCE(mxfs_dirop_virgin_skips_n,
			   READ_ONCE(mxfs_dirop_virgin_skips_n) + 1);
	}
	return false;
}
EXPORT_SYMBOL(mxfs_dir_op_needs_publish);

/* DEFAULT 0.  PROVEN FIX for the dir_reuse intra-block dir-slot
 * COLLISION (byte-exact: node7_f47.md overwrote node5_f46.md5 @ off=1280
 * because node7's node-format addname picked a slot its STALE in-core bestfree
 * still showed FREE).  At xfs_dir2_node_addname_int, before using an EXISTING
 * data block's bestfree to place the new dirent, gate on the RELIABLE master dir
 * epoch (mxfs_v5_dlm_inode_dir_epoch — advances on EVERY real cross-node handoff,
 * unlike the gen bump which is MISSED on rapid same-pair handoffs): if the block's
 * b_mxfs_dir_epoch lags the (master-synced) i_dlm_dir_valid_epoch, a peer modified
 * the dir since this block was last read coherently, so its bestfree is a stale
 * base.  Drop XBF_DONE on the ONE clean block + restart the search so the standard
 * read path FUA-refetches it coherently (bestfree then reflects the occupied slot).
 * Scoped to the single block being modified and only when CLEAN (never our own
 * dirty/in-AIL in-tenure work) — unlike force_coherent's blanket per-read refresh
 * which reverts not-yet-durable peer blocks (readdir got WORSE).  The
 * victim's add is already platter-durable at this point (sync RELFLUSH at its
 * release), so the refresh cannot lose data. */
int mxfs_dir_addname_epoch_refresh = 1;	/* DEFAULT 1.  Instrumented
		 * PROVEN (drc_phantom_diag, build 9473C7AD): the master dir epoch is
		 * RELIABLE (P64-MASTER-HANDOFF 93x, epoch monotone) but it was NEVER
		 * CONSUMED (P-FASTEX-EPOCH=0, dir_epoch_adopt off, this lever off) — so
		 * the only active signal was the EDGE-triggered handoff bit, which
		 * under-fires on the A->B->A->A re-grant pattern (P-DGEX handoff=0 all
		 * show owner==last_owner while the grantee's grant_gen jumped 19 = the
		 * lock DID change hands via other nodes; last_owner only tracks the
		 * IMMEDIATELY-prior owner so the bit reads false).  Result: node3's whole
		 * f2..f50 second-wave batch clobbered (readdir=750/800).  This lever
		 * consumes the LEVEL-triggered epoch at the addname modify site with the
		 * SAFE data-block-only refresh (drop XBF_DONE + restart on the ONE chosen
		 * block, keep-guard: never dirty/in-AIL/pinned/DELWRI) — NO fork adopt
		 * (avoids epoch_adopt shutdown), NO i_dlm_dir_gen bump (avoids
		 * DABUF_MAP_HOLE from leaf re-read vs stale extent map). */
module_param_named(dir_addname_epoch_refresh, mxfs_dir_addname_epoch_refresh, int, 0644);

/* DEFAULT 1.  The divergent-grow torn-map (DABUF_MAP_HOLE) root
 * proven by is BORN at xfs_dir2_shrink_inode freeing a NON-LAST (middle)
 * dir data block: xfs_bunmapi removes the block's extent but di_size is left
 * unchanged -> a GAP in the data-region extent map.  Harmless single-node (the
 * leaf bests no longer references it), but across a cross-node EX handoff a
 * peer's stale leaf still references the freed block -> durable hole -> FS
 * shutdown.  This is the UNIFIED root of dir_reuse 4/8 AND fence_during_write
 * 2/tcp (shared hot-dir rapid create+remove churn).  When set, the leaf/node
 * removename paths DO NOT free a middle data block under multi-node: the block
 * is left as a valid EMPTY data block, mapped, with its bests/free-index entry
 * kept all-free (so a later add reuses it).  No extent removed -> no gap -> no
 * tear.  When the block later becomes the directory tail it is freed normally
 * (di_size shrinks).  Inert single-node and for last-block frees. */
int mxfs_dir_keep_middle_block = 1;
module_param_named(dir_keep_middle_block, mxfs_dir_keep_middle_block, int, 0644);

/* DEFAULT 1.  Multi-node reused-inode CREATE race: xfs_dialloc
 * hands out an inode that is FREE cluster-wide in the inobt, but this node's
 * in-core copy is still XFS_NEED_INACTIVE (nlink=0) from its own recent rm whose
 * inactivation hasn't run yet.  Upstream xfs_iget_cache_hit returns -ENOENT
 * ("unlinked inodes cannot be re-grabbed"), which for a CREATE fatally cancels an
 * already-DIRTY xfs_create transaction -> Corruption of in-memory data ->
 * SHUTDOWN (the PROVEN dir_reuse -> fence_during_write/fault_netpartition/
 * tcp_dlm_scaling 2/tcp cascade).  When set, an IGET_CREATE on such an inode
 * flushes inodegc + returns -EAGAIN (retry) so the pending inactivation completes
 * and the inode recycles cleanly, instead of the fatal ENOENT.  Inert single-node
 * and for non-CREATE lookups. */
int mxfs_create_needinact_flush = 1;
module_param_named(create_needinact_flush, mxfs_create_needinact_flush, int, 0644);

/* DEFAULT 1.  The dir_reuse 4/8 residual SHUTDOWN is a bnobt
 * "double-free" in xfs_free_ag_extent: a block whose in-core inode extent map
 * is STALE (references a block a peer/prior incarnation already freed —
 * PROVEN not an allocator double-ALLOC by /; P3-EFREE-Q shows the
 * SAME inode incarnation freeing the SAME extent twice) is freed while it is
 * ALREADY in the free tree -> XFS_IS_CORRUPT -> xfs_defer_finish shutdown ->
 * cascades to the fault tests at 4/8.  When set, if the freed range is FULLY
 * contained in an already-free left-neighbour extent (genuinely already free
 * cluster-wide), SKIP the redundant free (no-op; blocks stay correctly free and
 * accounted) instead of shutting down.  Scoped to multi-node + full containment
 * only (partial overlap keeps the hard corruption — that would leak blocks).
 * This turns a catastrophic FS shutdown into a safe no-op for the stale-map
 * double-free; the residual single-dirent/data loss (stale map read) is a
 * separate, non-fatal problem. */
int mxfs_ag_skip_dblfree = 1;
module_param_named(ag_skip_dblfree, mxfs_ag_skip_dblfree, int, 0644);

/* DECISIVE targeted platter guard for the PROVEN intra-block
 * dir-slot collision.  At the addname's chosen byte offset (aoff) the in-core
 * bestfree says FREE, but a peer may hold a DURABLE dirent at aoff on the
 * platter that our cached block is missing (read-side staleness the lossy
 * epoch/gen failed to invalidate).  Unlike the random-sampled P28-PLATTER
 * full-block memcmp (which never reliably sampled the rare collision read),
 * this FUA-reads THIS daddr and checks ONLY the slot we are about to write:
 * if the platter has a LIVE dirent there (freetag != FREE_TAG) we are about to
 * clobber a peer -> the base is read-side stale.  =1 logs P28W-CLOBBER (probe);
 * =2 additionally refreshes the CLEAN block + restarts so the read path
 * FUA-refetches it coherently (fix).  Default 0.  Scoped multinode published
 * shared dir; one FUA read per addname (diagnostic cost, gate off in prod). */
int mxfs_dir_addname_platter_guard;
module_param_named(dir_addname_platter_guard, mxfs_dir_addname_platter_guard, int, 0644);

/* THE FIX — format-agnostic read-side staleness guard at dir
 * addname (mxfs_dir_addname_coherent_refresh, xfs_dir2_data.c).  PROVEN by the
 * P28W probe: a node holding dir EX serves a CLEAN cached dir DATA block that is
 * STALE vs the durable platter (the lossy TCP gen/epoch left it current-stamped:
 * dir_gen==loaded_gen, bufepoch==valid at the clobber), so its bestfree offers a
 * slot a peer durably filled -> use_free OVERWRITES the peer's dirent.  Before
 * use_free (block/leaf/node addname), FUA-read THIS daddr; if the platter is a
 * current valid data block of this dir and DIFFERS from the clean in-core buffer,
 * refresh the buffer IN PLACE from the platter so bestfree reflects the peer's
 * entry and use_free picks a real free slot.  Ground-truth (platter), so it does
 * NOT depend on the unreliable handoff/epoch.  CLEAN-only (never our own dirty
 * in-tenure work).  Cost = one FUA read per addname on a contended shared dir
 * (measured ~355s for dir_reuse 8/tcp, under the 480s budget).  Default 1. */
int mxfs_dir_addname_coherent = 1;	/* DEFAULT 1 — THE acquire-side half of the dir_reuse fix.  Before the first add into a CLEAN dir block, FUA-read the platter; if in-core != platter, invalidate+reread+restart so the free-slot search runs against the peer's current image → prevents the PROVEN intra-block free-slot DOUBLE-ALLOCATION (P13-COLLIDE: node7 placed node7_f8.md5 onto node8's durable node8_f8.md5).  set this 0 because it ALONE did not fix the loss — but that was BEFORE the platter-lag writer fix (dir_release_fua_write): back then the FUA reread hit the LAGGING LIO platter (stale), so it reread an image still missing the peer add.  NOW with dir_release_fua_write=1 forcing the platter current, the two are COMPLEMENTARY: writer makes the platter durable, reader rereads the current platter.  VALIDATED 8/tcp dir_reuse 7/8 PASS, 0 SINGLE 0 MASS (the only residual is a host-load TCP flap).  Per-add FUA cost only on the FIRST add into each still-clean block (the block goes dirty after, throttling it). */
module_param_named(dir_addname_coherent, mxfs_dir_addname_coherent, int, 0644);

void
mxfs_dlm_dir_modify_reload_prelock(struct xfs_inode *dp)
{
	struct xfs_mount	*mp;

	if (!dp)
		return;
	mp = dp->i_mount;
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;

	/*
	 * (design-consult consult, PROVEN tcp_dlm_scaling durable dirent
	 * RESURRECTION root): while THIS node already OWNS the dir lock in EX
	 * (cached until a peer BASTs it), its in-core dir fork is AUTHORITATIVE
	 * for the whole EX tenure — a peer cannot modify the dir.  A DIR_MODIFY
	 * reload signal that arrives mid-tenure (the evict-ring fires a FLOOD,
	 * frequently echoing our OWN modifications) must NOT trigger a reload +
	 * 3-way shortform merge from disk: under fua_disable the on-LUN image is
	 * our OWN not-yet-published PRE-modification state, so the union merge
	 * re-adds source dirents we JUST removed in-core (e.g. `mv n2_rN
	 * n2_rN.done` — n2_rN resurrected), and we later publish the corrupted
	 * fork (PROVEN: node2 P-SFMERGE ours+theirs UNION grows count while it
	 * holds EX; leftover survives drop_caches on both nodes).  The invariant:
	 * disk is authoritative ONLY at the not-owned -> EX ACQUIRE transition;
	 * in-core is authoritative WHILE owning EX.  At this pre-lock point a node
	 * about to RE-acquire after a peer handoff is NL (mode != EX) and DOES
	 * reload here (picking up the peer's committed changes); a node still
	 * caching EX skips.  Leave MXFS_IF_DIR_RELOAD set so the next genuine
	 * re-acquire (after we lose EX) honours it.
	 */
	/*
	 * (instrumented, PROVEN ROOT — 4-way logical-block0 SPLIT) BLOCK-FORMAT
	 * ADOPTION SERIALIZER.  dir_reuse_coherency 4/tcp durably loses node1_f1
	 * (the first dirent) because multiple nodes each materialize logical-block0
	 * at their OWN physical daddr: a node about to modify a dir it still holds
	 * in-core as SHORTFORM (LOCAL) re-converts shortform->block and allocates a
	 * SECOND block0, while disk is ALREADY EXTENTS (a peer converted+published).
	 * The inode extent[0] then flip-flops and rank1's block0 (with node1_f1) is
	 * orphaned (P62-DATAINIT-BLK0 + P62-REL-DIREXT).  Even when this node
	 * caches EX, a disk that reads block-format for the SAME incarnation while we
	 * are still LOCAL means our cached EX/fork is stale (a peer converted) — so
	 * adopt the peer's block layout BEFORE we re-convert.  FUA-read the dinode
	 * (no ILOCK held here: reload can take i_lock) and force a reload when disk
	 * is non-LOCAL but in-core is LOCAL for a matching di_gen.  This SERIALIZES
	 * the conversion to a single block0 (the proven fix per the evidence: once
	 * one block0 exists, the existing reload/adopt machinery converges).
	 */
	/*
	 * (instrumented) CONTENT-LEVEL stale-shortform-base fix.  PROVEN: the
	 * sf->block converter's in-core SHORTFORM base is MISSING node1_f1 while
	 * the disk shortform (rank1's published image) HAS it (P62-CRCONV: convert
	 * happens in-core LOCAL with disk ALSO LOCAL; P61-ADOPT-DISK fired 0 — a
	 * FORMAT compare cannot see a LOCAL-vs-LOCAL CONTENT gap).  The conversion
	 * then freezes the stale base and drops node1_f1.  Fix: FUA-read the disk
	 * dinode; if disk has MORE dir content for the SAME incarnation than our
	 * in-core shortform — either disk is non-LOCAL (peer already converted/grew,
	 * strictly ahead) OR disk is LOCAL with a higher sf entry count (peer added
	 * dirents we never adopted) — force a reload+merge BEFORE the modify
	 * converts.  GROWTH-ONLY (disk strictly bigger) so the additive shortform
	 * merge can only ADD the peer's dirents, never roll back our own work and
	 * never resurrect a delete (a delete shrinks disk, so disk-bigger is never a
	 * delete).  Fires even when we cache EX: disk being ahead while we hold EX
	 * means our cached fork is stale (a peer modified) and must be adopted.
	 */
	/*
	 * (instrumented, PROVEN: dir_reuse_coherency node1_f1 = DOUBLE sf->block
	 * conversion — round 2 trace: test1 AND test3 each convert ino=131 under
	 * EX, each allocating its OWN block0; later stale-base block0 RMWs drop
	 * node1_f1 and a node1_f1-less block0 wins).  EPOCH-GATED CONVERSION
	 * SERIALIZER: a node about to modify a SHORTFORM dir whose monotonic dir
	 * EPOCH has advanced beyond the epoch its base is coherent with means a
	 * PEER already modified (and, being past shortform capacity under the
	 * create storm, almost certainly CONVERTED) this dir since our base
	 * loaded.  The epoch is set in the DLM master at the peer's modify commit
	 * and delivered on our grant — reliable and immediate, unlike the disk-FUA
	 * format check below which loses the race when the peer's block0 has not
	 * yet flushed.  Force a disk-superset reload+adopt (post_release=true so
	 * the reload's epoch path adopts the peer's BLOCK image) BEFORE we run our
	 * own xfs_dir2_sf_to_block — so we add our dirents into the peer's existing
	 * block0 instead of allocating a SECOND one.  Our own pre-adopt shortform
	 * dirents are re-added by the create-path union-merge / pending replay.
	 * Same-incarnation only (epoch resets per incarnation).  Gated
	 * mxfs_dir_epoch_convert_gate (default off). */
	if (mxfs_dir_epoch_convert_gate && dp->i_ino != mp->m_sb.sb_rootino &&
	    dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		uint32_t ge = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
							  dp->i_ino);

		if (ge > dp->i_dlm_dir_valid_epoch) {
			mxfs_probe_ratelimited(
				"mxfs: P65-EPOCH-CONVGATE ino=%llu grant_epoch=%u valid_epoch=%u dlm_mode=%u gen=%u comm=%s — shortform dir, epoch advanced (peer converted); reload+adopt before our conversion\n",
				(unsigned long long)dp->i_ino, ge,
				dp->i_dlm_dir_valid_epoch, dp->i_dlm_mode,
				VFS_I(dp)->i_generation, current->comm);
			dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
			mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
			return;
		}
	}

	/*
	 * (3e02e7dd) (PROVEN BY INSTRUMENT — 32/caw dir_reuse round-10
	 * cluster meltdown): the epoch_convert_gate check above is a RELATIVE
	 * staleness signal (epoch advanced since MY baseline) with a residual
	 * TOCTOU gap under high concurrency: several nodes can each observe
	 * "epoch has not advanced past my baseline" and each proceed to
	 * convert independently before any one of their commits becomes
	 * visible to the others (proven live: node1_f1's dir data CRC-failed
	 * and the FS shut down at round 10 with epoch_convert_gate=1 already
	 * default-on).  This check is an ABSOLUTE existence check instead of a
	 * relative one: does a canonical block0 already exist for THIS
	 * incarnation, full stop — published via the CAW slot's write-once
	 * dir_block0_fsb field by whichever node converts first (see
	 * docs/canonical_block0_fix_plan.md, mxfs_dlm_caw_set_dir_block0).
	 * Available immediately at grant time (no disk-FUA/destage-timing
	 * dependency like the epoch signal or the mxfs_dir_adopt_block content
	 * probe below), and durability of the referenced block by the time any
	 * peer can observe it is guaranteed by Invariant 1 (no DLM unlock
	 * without a successful drain).  CAW-only; TCP already passes its
	 * criteria without this mechanism.
	 */
	if (mxfs_dir_block0_canon && dp->i_ino != mp->m_sb.sb_rootino &&
	    dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
		uint64_t canon_fsb = 0;

		if (mxfs_v5_dlm_inode_dir_block0(mp->m_mxfs_dlm, dp->i_ino,
						 VFS_I(dp)->i_generation,
						 &canon_fsb)) {
			mxfs_probe_ratelimited(
				"mxfs: P-BLOCK0-CONVGATE ino=%llu canon_fsb=%llu dlm_mode=%u gen=%u comm=%s — shortform dir, canonical block0 already published (peer converted); reload+adopt before our conversion\n",
				(unsigned long long)dp->i_ino,
				(unsigned long long)canon_fsb, dp->i_dlm_mode,
				VFS_I(dp)->i_generation, current->comm);
			dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
			mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
			return;
		}
	}

	/*
	 * gated (default 0): NON-shortform dir extent-map refresh.
	 * For a LARGE (LEAF/NODE, fmt != LOCAL) dir whose DLM epoch advanced since
	 * our base loaded (a peer added a data block), reload the inode HERE — at
	 * the pre-lock, no ILOCK held, so mxfs_dlm_reload_inode can take i_lock and
	 * rebuild the data-fork EXTENT MAP from disk.  The subsequent ILOCK-held
	 * mxfs_dlm_dir_modify_refresh evicts the data/leaf blocks (forcing a FRESH
	 * cold re-read that references the peer's grown block), but it canNOT reload
	 * the extent map; without this prelock reload the map stays STALE (missing
	 * the peer's block) -> xfs_dabuf_map returns a hole for the block the fresh
	 * leaf references -> !HOLE_OK EFSCORRUPTED shutdown (the 8-node create/lookup
	 * DABUF_MAP_HOLE storm).  Same fresh-leaf/stale-map root the readdir fix
	 * closed for the readdir path; this closes it for create/rename/remove.
	 */
	if (mxfs_dir_modify_extent_reload && dp->i_ino != mp->m_sb.sb_rootino &&
	    dp->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		uint32_t ge = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
							  dp->i_ino);

		if (ge > dp->i_dlm_dir_valid_epoch) {
			mxfs_probe_ratelimited(
				"mxfs: P14-MODEXT-RELOAD ino=%llu grant_epoch=%u valid_epoch=%u fmt=%u dlm_mode=%u — non-SF dir epoch advanced (peer grew); reload extent map before modify\n",
				(unsigned long long)dp->i_ino, ge,
				dp->i_dlm_dir_valid_epoch, dp->i_df.if_format,
				dp->i_dlm_mode);
			dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
			mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
			return;
		}
	}

	if (mxfs_dir_adopt_block && dp->i_ino != mp->m_sb.sb_rootino &&
	    dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		uint32_t len = BBTOB(dp->i_imap.im_len);
		void *tmp = (len && !(len & 511)) ? kmalloc(len, GFP_NOFS) : NULL;

		if (tmp) {
			uint64_t lba = (uint64_t)dp->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset;
			extern int mxfs_pal_scsi_read_fua_bdev(
				struct block_device *, uint64_t, void *, uint32_t);

			if (mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev,
						        lba, tmp, len) == 0) {
				struct xfs_dinode *dip = (struct xfs_dinode *)
					((char *)tmp + dp->i_imap.im_boffset);
				bool disk_ahead = false;
				int incore_cnt = -1, disk_cnt = -1;

				if (be16_to_cpu(dip->di_magic) == XFS_DINODE_MAGIC &&
				    be32_to_cpu(dip->di_gen) ==
					VFS_I(dp)->i_generation) {
					/* in-core shortform entry count */
					if (dp->i_df.if_data) {
						struct xfs_dir2_sf_hdr *ih =
							dp->i_df.if_data;
						incore_cnt = ih->count;
					}
					if (dip->di_format != XFS_DINODE_FMT_LOCAL) {
						disk_ahead = true;	/* peer converted/grew */
					} else {
						/* disk still shortform: compare counts */
						struct xfs_dir2_sf_hdr *dh =
							(struct xfs_dir2_sf_hdr *)
							XFS_DFORK_PTR(dip, XFS_DATA_FORK);
						disk_cnt = dh->count;
						if (disk_cnt > incore_cnt)
							disk_ahead = true;
					}
				}
				if (disk_ahead) {
					mxfs_probe_ratelimited("mxfs: P62-ADOPT-CONTENT ino=%llu incore_fmt=LOCAL incore_cnt=%d disk_fmt=%d disk_cnt=%d dlm_mode=%u gen=%u comm=%s — disk dir ahead, reload+merge before convert\n",
						(unsigned long long)dp->i_ino,
						incore_cnt, dip->di_format, disk_cnt,
						dp->i_dlm_mode,
						VFS_I(dp)->i_generation,
						current->comm);
					kfree(tmp);
					dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
					mxfs_dlm_reload_inode(dp,
						XFS_DIR3_FT_UNKNOWN, false);
					return;
				}
			}
			kfree(tmp);
		}
	}

	/*
	 * (instrumented, PROVEN ROOT — xfs_dir3_data_init zeroes a live dir DATA
	 * block, /62): the durable dir_reuse 4/8-node loss is a node growing
	 * the dir into a "new" logical block while its in-core data-fork EXTENT MAP
	 * is STALE (missing a block a peer already materialized on disk).  The
	 * allocator then hands back a daddr that already holds this dir's live
	 * block, and data_init ZEROES it -> whole-block durable loss (NOT a read-side
	 * stale-RMW: P60/P67 never fire; the get_buf/zero path bypasses the read
	 * coherency hooks).  EVEN A CACHED-EX HOLDER must adopt the peer's grown
	 * extent map BEFORE growing: under MHT batching a node yields+reacquires EX
	 * mid-wave (bast_pend), and if the reacquire reload kept our stale (smaller)
	 * map we double-allocate.  Level-triggered on the monotonic DLM epoch (cheap;
	 * no I/O when no peer modified): if our held grant's dir epoch exceeds the
	 * epoch our base is coherent with, FUA-read the disk dinode and, if disk has
	 * MORE data-fork extents than in-core for the SAME incarnation (peer grew the
	 * dir, strictly additive -> cannot roll back our work), force a disk-superset
	 * reload+adopt (post_release=true) BEFORE the modify's transaction starts.
	 * Runs with NO ILOCK held (pre-xfs_trans_alloc).  Gated default ON. */
	if (mxfs_dir_modify_extent_adopt && dp->i_ino != mp->m_sb.sb_rootino &&
	    (dp->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     dp->i_df.if_format == XFS_DINODE_FMT_BTREE) &&
	    !xfs_need_iread_extents(&dp->i_df) &&
	    /*
	     * ROOT FIX (instrumented, PROVEN run65 t2 169.654):
	     * this hook runs at modify-PRELOCK with NO ILOCK, so a CONCURRENT
	     * local thread's dir modification (t2: the block->leaf conversion,
	     * P34C 169.652) can be in flight — in-core is then legitimately
	     * AHEAD of disk (nx=2 vs 1; the dinode lands at release, Road B).
	     * The per-block compare read that as "diverged" and reload+adopted
	     * the STALE disk map over our own uncommitted grow (P68-PREEVICT
	     * shrink=1, OWNEVICT evicted=1) — the conversion's next block-0
	     * read then failed the data verifier (XDB3-under-XDD3, daddr 0x48)
	     * inside a dirty transaction => trans_cancel => SHUTDOWN => the
	     * whole cluster read the half-converted state and died (run65
	     * 7/8 nodes).  When OUR OWN inode item carries dirty / pinned /
	     * in-AIL state, the in-core fork is authoritative by definition —
	     * adopting disk can only roll back unlanded local work.  Skip.
	     */
	    !(dp->i_itemp &&
	      (dp->i_itemp->ili_fields ||
	       test_bit(XFS_LI_DIRTY, &dp->i_itemp->ili_item.li_flags) ||
	       test_bit(XFS_LI_IN_AIL, &dp->i_itemp->ili_item.li_flags))) &&
	    atomic_read(&dp->i_pincount) == 0 &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		/*
		 * DIRECT disk-vs-in-core comparison (the epoch gate is
		 * inert — valid_epoch is set == grant_epoch by every reload, so
		 * grant_epoch>valid_epoch is almost never true at modify time).
		 * FUA-read the disk dinode; if disk has MORE data-fork extents than
		 * in-core for the SAME incarnation, a peer grew the dir since our
		 * base loaded and our extent map is STALE (too small) — growing now
		 * would let the allocator reuse a daddr already holding this dir's
		 * live block (data_init double-alloc/zero).  Growth-only (disk
		 * strictly bigger, same di_gen) => disk is a strict superset =>
		 * post_release reload adopt cannot roll back our own work.
		 */
		uint32_t len = BBTOB(dp->i_imap.im_len);
		void *tmp = (len && !(len & 511)) ? kmalloc(len, GFP_NOFS) : NULL;

		if (tmp) {
			uint64_t lba = (uint64_t)dp->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset;
			extern int mxfs_pal_scsi_read_fua_bdev(
				struct block_device *, uint64_t,
				void *, uint32_t);

			if (mxfs_pal_scsi_read_fua_bdev(
				    mp->m_ddev_targp->bt_bdev,
				    lba, tmp, len) == 0) {
				struct xfs_dinode *dip =
					(struct xfs_dinode *)
					((char *)tmp + dp->i_imap.im_boffset);

				/*
				 * (instrumented, documented-but-never-
				 * implemented MERGE-adopt): the divergence is extent-map
				 * CONTENT (same nextents COUNT, DIFFERENT daddr per logical
				 * block) — two nodes each grew logical block N at their own
				 * AG-affine daddr, so a count-compare (old P67) is inert.
				 * Do a FULL per-logical-block daddr compare disk-vs-in-core
				 * for an EXTENTS-format dir: decode the disk inline extents
				 * and, for each, look up the same startoff in our in-core
				 * map; if ANY differs (startblock/blockcount) OR disk has a
				 * block we lack OR counts differ, our map diverged from the
				 * last committer's durable map (gap-B makes disk authoritative)
				 * → reload+adopt (post_release=true rebuilds i_df from disk)
				 * BEFORE we grow, so the allocator extends the SHARED map
				 * instead of re-materializing block N at a divergent daddr
				 * (the durable single-entry loss).  Same incarnation only.
				 * No ILOCK held (pre-xfs_trans_alloc); reload is safe. */
				if (be16_to_cpu(dip->di_magic) ==
					XFS_DINODE_MAGIC &&
				    be32_to_cpu(dip->di_gen) ==
					VFS_I(dp)->i_generation &&
				    dip->di_format == XFS_DINODE_FMT_EXTENTS) {
					uint64_t d_fl2 = be64_to_cpu(dip->di_flags2);
					uint32_t disk_nx = (d_fl2 & XFS_DIFLAG2_NREXT64) ?
						(uint32_t)be64_to_cpu(dip->di_big_nextents) :
						be32_to_cpu(dip->di_nextents);
					struct xfs_bmbt_rec *recs =
						(struct xfs_bmbt_rec *)
						XFS_DFORK_PTR(dip, XFS_DATA_FORK);
					bool diverged =
						(disk_nx != (uint32_t)dp->i_df.if_nextents);
					uint32_t k;

					for (k = 0; k < disk_nx && !diverged; k++) {
						struct xfs_bmbt_irec	dr;
						struct xfs_iext_cursor	ic;
						struct xfs_bmbt_irec	gr;

						xfs_bmbt_disk_get_all(&recs[k], &dr);
						if (!xfs_iext_lookup_extent(dp,
							&dp->i_df, dr.br_startoff,
							&ic, &gr) ||
						    gr.br_startoff != dr.br_startoff ||
						    gr.br_startblock != dr.br_startblock ||
						    gr.br_blockcount != dr.br_blockcount)
							diverged = true;
					}

					if (diverged) {
						mxfs_probe_ratelimited(
						    "mxfs: P68-MAPDIVERGE ino=%llu incore_nx=%llu disk_nx=%u dlm_mode=%u comm=%s — disk extent map differs (per-block daddr); reload+adopt before modify\n",
						    (unsigned long long)dp->i_ino,
						    (unsigned long long)dp->i_df.if_nextents,
						    disk_nx, dp->i_dlm_mode,
						    current->comm);
						kfree(tmp);
						dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
						mxfs_dlm_reload_inode(dp,
							XFS_DIR3_FT_UNKNOWN, true);
						return;
					}
				} else if (be16_to_cpu(dip->di_magic) ==
					XFS_DINODE_MAGIC &&
				    be32_to_cpu(dip->di_gen) ==
					VFS_I(dp)->i_generation &&
				    dip->di_format == XFS_DINODE_FMT_BTREE &&
				    be32_to_cpu(dip->di_nextents) >
					(uint32_t)dp->i_df.if_nextents) {
					/* BTREE: extents not inline; fall back to the
					 * count-grow heuristic (best-effort). */
					mxfs_probe_ratelimited(
					    "mxfs: P67-MODIFY-EXTENT-ADOPT(btree) ino=%llu incore_nx=%llu disk_nx=%u\n",
					    (unsigned long long)dp->i_ino,
					    (unsigned long long)dp->i_df.if_nextents,
					    be32_to_cpu(dip->di_nextents));
					kfree(tmp);
					dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
					mxfs_dlm_reload_inode(dp,
						XFS_DIR3_FT_UNKNOWN, true);
					return;
				}
			}
			kfree(tmp);
		}
	}

	if (dp->i_dlm_mode == MXFS_LOCK_EX)
		return;

	if (xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_RELOAD)) {
		dp->i_dlm_stale = true; dp->i_dlm_stale_src = 3;
		/* No ILOCK held here (caller is pre-xfs_trans_alloc): reload can
		 * take i_lock EXCL.  post_release=false keeps our own in-flight
		 * mods authoritative unless the peer genuinely advanced the gen. */
		mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, false);
		if (dp->i_dlm_stale)
			xfs_iflags_set(dp, MXFS_IF_DIR_RELOAD);
	}
}
EXPORT_SYMBOL(mxfs_dlm_dir_modify_reload_prelock);

module_param_named(dir_adopt_block, mxfs_dir_adopt_block, int, 0644);
MODULE_PARM_DESC(dir_adopt_block,
	"adopt peer's block-format dir layout at modify pre-lock when in-core is "
	"still shortform but disk is block (serialize block0): 1=on (default), 0=off");

/*
 * MODIFY-path sibling of mxfs_dlm_dir_consumer_refresh.  The reader
 * (lookup/readdir) refresh above runs with NO ILOCK held and takes
 * ILOCK_SHARED itself.  The dir-MODIFY paths (xfs_remove / xfs_rename /
 * xfs_create) already hold dp's ILOCK_EXCL via xfs_trans_alloc_dir, so they
 * MUST NOT re-lock — yet they are exactly the paths that previously RMW'd the
 * shared dir block from a STALE cached base across a DLM tenure boundary
 * (node re-acquired dir EX after a peer's committed delete, but its cached
 * dir DATA block still carried the peer's already-removed dirents; removing
 * its own entry and writing back RESURRECTED the peer's 35 deleted files —
 * the all-nodes-agree durable lost-update in unlink_visibility).  This variant
 * does the same gen-keyed whole-dir clean-block eviction but assumes the caller
 * holds ILOCK_EXCL, so the following RMW cold-reads the peer's durable image.
 * Undurable (this-node-pinned/in-AIL) blocks are still skipped — those are
 * intra-tenure local work with no peer to merge, never a lost update.
 */

/*
 * (design-consult design) — SHORTFORM tenure REBASE.
 *
 * The data-block evict above only refreshes dir DATA/LEAF blocks; for a
 * SHORTFORM directory the entries live in the inode data fork (i_df), which it
 * never touches.  PROVEN vector (P-CRNAME fmt=1 node4_f1 durable loss): a node
 * holding a STALE in-core shortform i_df from a prior DLM tenure adds its own
 * entry / converts sf->block writing ONLY its own entries, dropping a peer's
 * already-committed shortform entry.
 *
 * Fix: when the dir DLM tenure has ADVANCED (a peer modified the dir since we
 * last cached — dp->i_dlm_dir_gen != evicted_gen and gen!=0), coherently
 * plain-read the durable on-disk dinode (NOT the possibly-stale cached inode-
 * cluster buffer) and, if it is a VALID same-incarnation SHORTFORM dir that
 * DIFFERS from our in-core fork, REBASE (wholesale replace) our i_df shortform
 * data from it.  This is a REBASE, not a merge: Invariant #1 drained the prior
 * EX holder before it yielded, so the durable disk image is authoritative; any
 * divergent in-core shortform is stale and must be discarded.  Caller holds
 * ILOCK_EXCL (no concurrent fork access).  Not marked dirty (cache rebase, not
 * a logged change).  SAFE against self-revert: gated strictly on tenure-advance
 * (gen!=0 means a peer-driven reload happened, which only occurs after WE
 * released+drained, so our committed entries are already on disk) PLUS a
 * memcmp short-circuit (skip when disk == in-core).
 */
int mxfs_dir_sf_rebase = 1;	/* default ON */
module_param_named(dir_sf_rebase, mxfs_dir_sf_rebase, int, 0644);
int mxfs_dir_sf_rebase_ownskip = 1;	/* default ON. legacy plain-skip of rebase while dir holds un-checkpointed own work (only used when merge OFF). */
module_param_named(dir_sf_rebase_ownskip, mxfs_dir_sf_rebase_ownskip, int, 0644);
/*
 * ccloop c7ee71c6 sess19 (instrumented, BYTE-EXACT PROOF — fence_during_write @32/caw,
 * dir .fence_during_write ino=56623232, tests/logs/fdw_32caw_20260728_120403):
 * the wholesale REBASE below adopts the on-disk shortform image with NO test
 * that it is not OLDER than the coherent in-core fork.  Captured chain on
 * test27, all four prints within 4ms of each other, same inode, comm=mkdir:
 *
 *   P174-STALEGEN-ADOPT dir_gen=4 loaded_gen=3   (force disk adopt)
 *   P9-SFREFRESH  incore_bytes=114 disk_size=73
 *   P3-REFUSE-OLDER-DISK disk_chg=8 incore_chg=10 — keeping fork   (x2)
 *   P21-RB own_work=0 incore_cnt=8 disk_cnt=5 incore_bytes=114 disk_sz=73
 *   P61-ADOPT-CHK incore_sz=73 disk_sz=73         <-- fork REPLACED anyway
 *   P56-DIRWRITE vep=7 write=[node29 node30 node10 node20 hot node27]
 *
 * i.e. the reload path correctly REFUSED the older image (P3 time-travel
 * guard: same incarnation, di_changecount 8 < in-core i_version 10), and then
 * this rebase adopted that very image regardless, dropping the three names
 * (node25, node1, node24) that peers had committed at vep=4/5/6.  Every later
 * publish built on the poisoned base, so the three dirents were lost durably
 * and cluster-wide (parent nlink=35 => 33 subdirs, only 30 names on the
 * platter; the three children became unreachable).
 *
 * di_changecount is bumped by every logged modification and is written from
 * i_version at flush, and every dir modification is serialized under the dir
 * EX grant — so for the SAME incarnation it totally orders the dir's
 * modification history.  disk_chg < incore_chg therefore PROVES the on-disk
 * image is a snapshot of a point we have already moved past; adopting it can
 * only destroy newer state.  Refuse the rebase and keep the fork (the same
 * verdict, and the same predicate, the reload path already reaches).
 *
 * NOT a content union: a clean fork legitimately differs from a NEWER disk
 * image by entries a peer REMOVED, and unioning those back is the sess56
 * durable resurrection.  The changecount is what distinguishes "disk is
 * behind us" from "disk is ahead of us"; only the first case is refused.
 */
int mxfs_dir_rebase_verguard = 1;	/* default ON */
module_param_named(dir_rebase_verguard, mxfs_dir_rebase_verguard, int, 0644);

/*
 *  TORN-FORK TRIPWIRE (instrumented).
 *
 * xfs_idestroy_fork frees a LOCAL fork's if_data and NULLs it but deliberately
 * leaves if_bytes and if_format alone (upstream only destroys forks at inode
 * teardown, where nothing re-reads them).  MXFS destroys and rebuilds LIVE
 * directory forks on every adopt, so any path that destroys without completing
 * the repopulate leaves a live inode in the state
 *
 *      if_format == LOCAL  &&  if_data == NULL  &&  if_bytes > 0
 *
 * which xfs_ifork_verify_local_data cannot validate: the shortform verifier
 * gets a NULL image and returns a fault address, so EVERY flush of that inode
 * fails EFSCORRUPTED and the filesystem shuts down.  Captured on test6 during
 * tests/sf_mkdir_storm.sh (build 11348AC5, ino 60817544, if_bytes=148): 34711
 * identical P171-SFNULL + "Metadata corruption detected at xfs_dir2_sf_verify"
 * pairs, every one with rd_held=1 (xfsaild holding ILOCK_SHARED) and NO writer
 * in flight — so the torn fork is a COMMITTED PERSISTENT state, not a
 * destroy/repopulate window, and the mount ended in permanent EIO.
 * (tests/logs/sfstorm_20260728_131006/dmesg_test6.log.)
 *
 * P171 fires at the reader, far downstream, and by then the last-ILOCK-writer
 * stamp has been overwritten by the drain's re-log arm.  This tripwire fires at
 * the point the torn state becomes a DIRTY LOG ITEM — the step that makes it
 * permanent and flushable — and dumps the stack, which names the producer.
 */
void
mxfs_note_fork_tear(struct xfs_inode *ip, const char *site)
{
	struct xfs_ifork	*ifp;
	static atomic_t		p181n = ATOMIC_INIT(0);

	if (!ip)
		return;
	ifp = &ip->i_df;
	if (likely(ifp->if_format != XFS_DINODE_FMT_LOCAL ||
		   ifp->if_data != NULL || ifp->if_bytes <= 0))
		return;
	if (atomic_inc_return(&p181n) > 20)
		return;
	mxfs_probe("mxfs: P181-FORK-TORN ino=%llu site=%s if_bytes=%d mode=0%o dlm_mode=%d gen=%u comm=%s — LOCAL fork has if_bytes>0 with if_data==NULL; every flush of this inode will fail the shortform verifier\n",
		(unsigned long long)ip->i_ino, site, (int)ifp->if_bytes,
		VFS_I(ip)->i_mode, ip->i_dlm_mode, VFS_I(ip)->i_generation,
		current->comm);
	mxfs_probe_stack();
}
MODULE_PARM_DESC(dir_rebase_verguard,
		 "Refuse a shortform dir rebase when the on-disk image is "
		 "provably older than the in-core fork (di_changecount < "
		 "i_version, same incarnation).  1=on default");
/* non-perturbing rebase-decision counters (P21-RBSTAT). */
static atomic64_t mxfs_rb_fired, mxfs_rb_genbail, mxfs_rb_cohskip,
		  mxfs_rb_merged, mxfs_rb_adopted;
static atomic64_t mxfs_rb_verbail;
MODULE_PARM_DESC(dir_sf_rebase,
		 "Rebase a stale in-core SHORTFORM dir fork from the durable "
		 "disk image on a tenure-advanced modify (1=on default)");

/*
 *  instrumented INSTRUMENT (torn-adopt hypothesis).
 *
 * mxfs_dir_rebase_shortform replaces the in-core shortform data FORK from a
 * durable on-disk dinode image, but installs NOTHING from that image's CORE.
 * The fork and the core were written atomically as one dinode, and for a
 * directory the two are not independent: every mkdir bumps the parent's
 * di_nlink in the SAME transaction that adds the dirent.  Adopting the peer's
 * fork while keeping our cached core therefore yields a TORN inode — current
 * names, stale link count — and the next publish writes that stale link count
 * back over the peers' increments.
 *
 * Reproduced by tests/sf_mkdir_storm.sh (32 nodes, 8 rounds): round 8's parent
 * settles DURABLY at nlink=29 with 32 visible subdirectories on all 32 nodes
 * (5 link-count increments lost; re-read minutes later, still 29).
 *
 * This probe is DETECT-ONLY: it reports, at each adopt point, how our in-core
 * core fields compare with the image whose fork we are about to install.
 * disk_nlink > incore_nlink at an adopt PROVES the tear (we are about to keep
 * a link count that the image we trust for names says is too low).
 */
static void
mxfs_rebase_core_probe(struct xfs_inode *dp, struct xfs_dinode *dip,
		       const char *path)
{
	static atomic_t	p179n = ATOMIC_INIT(0);
	uint32_t	dnl = be32_to_cpu(dip->di_nlink);
	uint32_t	inl = VFS_I(dp)->i_nlink;

	if (dnl == inl)
		return;
	if (atomic_inc_return(&p179n) > 4000)
		return;
	mxfs_probe("mxfs: P179-REBASE-CORE-TEAR ino=%llu path=%s incore_nlink=%u disk_nlink=%u incore_chg=%llu disk_chg=%llu incore_sz=%lld disk_sz=%llu comm=%s — adopting the image's FORK while keeping our CORE\n",
		(unsigned long long)dp->i_ino, path, inl, dnl,
		(unsigned long long)inode_peek_iversion(VFS_I(dp)),
		(unsigned long long)be64_to_cpu(dip->di_changecount),
		(long long)dp->i_disk_size,
		(unsigned long long)be64_to_cpu(dip->di_size),
		current->comm);
}

static void
mxfs_dir_rebase_shortform(struct xfs_inode *dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_ifork	*ifp = &dp->i_df;
	void			*ict;
	uint32_t		icl;
	struct xfs_dinode	*dip;
	struct xfs_dir2_sf_hdr	*dsf;
	uint64_t		dsize;
	bool			own_work;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);

	if (!mxfs_dir_sf_rebase)
		return;
	/* Only the SHORTFORM (LOCAL) fork is handled here; block/leaf format
	 * is covered by the data-block evict + the write-side EX guard. */
	if (ifp->if_format != XFS_DINODE_FMT_LOCAL)
		return;
	/*
	 * NEVER rebase-over our OWN un-checkpointed work.  A node
	 * that just created a dirent (committed to the log, IN-AIL / PINNED, not
	 * yet checkpointed to the on-disk dinode) would have that create CLOBBERED
	 * by adopting the disk shortform (which lacks it).  PROVEN root of the
	 * tcp_dlm_scaling RENAME-REVALIDATE-MISS at dir_sf_mht_ms=100: the shared
	 * shortform dir's gen advances (peer touched it) between a node's own
	 * `create n2_rN` and its immediate `rename n2_rN` → mxfs_dlm_dir_modify_refresh
	 * calls this rebase → it adopts the peer's disk image MISSING our own create
	 * → the rename's src lookup ENOENTs → false clean-abort → 0 rounds (4/tcp
	 * test2).  Skip while we hold un-destaged own work; the peer's durable change
	 * is adopted on the NEXT refresh after our work checkpoints.  A clean PR/NL
	 * cacher (P43 case) has NO log item / is unpinned → still rebases, so
	 * this does NOT regress the clean-cacher-adopts-disk-shrink fix.
	 */
	own_work = xfs_ipincount(dp) > 0 ||
		   (dp->i_itemp &&
		    (test_bit(XFS_LI_IN_AIL, &dp->i_itemp->ili_item.li_flags) ||
		     test_bit(XFS_LI_DIRTY, &dp->i_itemp->ili_item.li_flags)));
	/*
	 * Legacy SKIP: only when the UNION merge below is disabled.
	 * A plain skip preserves our own work but loses a peer's concurrent
	 * shortform add (dir_reuse off-by-one).  The merge is the correct fix.
	 */
	if (own_work && !mxfs_dir_sf_rebase_merge && mxfs_dir_sf_rebase_ownskip)
		return;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	icl = BBTOB(dp->i_imap.im_len);
	if (!icl || (icl & 511))
		return;
	ict = kmalloc(icl, GFP_NOFS);
	if (!ict)
		return;
	if (mxfs_pal_bdev_read_plain_bdev(mp->m_ddev_targp->bt_bdev,
		(uint64_t)dp->i_imap.im_blkno + mp->m_ddev_targp->bt_sector_offset,
		ict, icl) != 0)
		goto out;
	dip = (struct xfs_dinode *)((char *)ict + dp->i_imap.im_boffset);
	if (be16_to_cpu(dip->di_magic) != XFS_DINODE_MAGIC)
		goto out;
	/*
	 * NON-PERTURBING instrumentation: atomic counters (no
	 * per-call printk — that hides the fast-handoff race; dump every 256
	 * fires).  Discriminates the rebase decision a re-acquiring node takes
	 * during the dir_reuse low-mht off-by-one: genbail (stale-cached
	 * incarnation) / cohskip (already-current) / merged / adopted.
	 */
	{
		long f = atomic64_inc_return(&mxfs_rb_fired);
		if ((f & 255) == 0)
			mxfs_probe("mxfs: P21-RBSTAT fired=%ld genbail=%lld cohskip=%lld merged=%lld adopted=%lld verbail=%lld\n",
				f, atomic64_read(&mxfs_rb_genbail),
				atomic64_read(&mxfs_rb_cohskip),
				atomic64_read(&mxfs_rb_merged),
				atomic64_read(&mxfs_rb_adopted),
				atomic64_read(&mxfs_rb_verbail));
	}
	/* Different incarnation on disk => freed/reused inode, not our dir. */
	if (be32_to_cpu(dip->di_gen) != VFS_I(dp)->i_generation) {
		atomic64_inc(&mxfs_rb_genbail);
		goto out;
	}
	/*
	 * TIME-TRAVEL GUARD (see the P178 dossier above the params):
	 * a same-incarnation disk image whose di_changecount is STRICTLY LOWER
	 * than our in-core i_version is provably a snapshot of dir state we
	 * have already moved past.  Both the wholesale adopt and the union's
	 * disk base would then revert peers' committed dirents that we already
	 * hold (the fence_during_write 3-dirent durable loss).  Keep the fork.
	 */
	if (mxfs_dir_rebase_verguard && dip->di_version >= 3 &&
	    be64_to_cpu(dip->di_changecount) <
			inode_peek_iversion(VFS_I(dp))) {
		static atomic_t p178n = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_rb_verbail);
		if (atomic_inc_return(&p178n) <= 2000)
			pr_warn("mxfs: P178-REBASE-OLDER-DISK ino=%llu disk_chg=%llu incore_chg=%llu disk_sz=%llu incore_bytes=%lld own_work=%d gen=%u comm=%s — home shortform older than in-core; rebase refused (would revert peers' committed dirents)\n",
				(unsigned long long)dp->i_ino,
				(unsigned long long)be64_to_cpu(dip->di_changecount),
				(unsigned long long)inode_peek_iversion(VFS_I(dp)),
				(unsigned long long)be64_to_cpu(dip->di_size),
				(long long)ifp->if_bytes, own_work ? 1 : 0,
				VFS_I(dp)->i_generation, current->comm);
		goto out;
	}
	/* Disk must ALSO be shortform; if it advanced to block format the
	 * data-block path handles it. */
	if (dip->di_format != XFS_DINODE_FMT_LOCAL)
		goto out;
	dsize = be64_to_cpu(dip->di_size);
	if (!dsize || dsize > (uint64_t)XFS_DFORK_SIZE(dip, mp, XFS_DATA_FORK))
		goto out;
	dsf = (struct xfs_dir2_sf_hdr *)XFS_DFORK_DPTR(dip);
	if (xfs_dir2_sf_verify(mp, dsf, (int64_t)dsize) != NULL)
		goto out;
	/*
	 * PER-FIRE log (rebase fires RARELY — only the shortform
	 * phase, <256/test — so a per-fire pr_warn is LOW-FREQUENCY and does NOT
	 * perturb the fast-handoff race the way dirwr's hot-path flood does).
	 * Logs the STALE-BASE signal: our in-core entry count vs disk's.  If
	 * incore < disk at a modify, our base is missing a peer's durable entry;
	 * the adopt/merge below must pull it in or our RMW clobbers it.  Capped. */
	{
		static atomic_t p21n = ATOMIC_INIT(0);
		uint8_t incnt = (ifp->if_data && ifp->if_bytes >=
				 (int)xfs_dir2_sf_hdr_size(0)) ?
				((struct xfs_dir2_sf_hdr *)ifp->if_data)->count : 0xff;
		if (atomic_inc_return(&p21n) <= 4000)
			mxfs_probe("mxfs: P21-RB ino=%llu own_work=%d incore_cnt=%u disk_cnt=%u incore_bytes=%lld disk_sz=%llu comm=%s\n",
				(unsigned long long)dp->i_ino, own_work ? 1 : 0,
				incnt, dsf->count, (long long)ifp->if_bytes,
				(unsigned long long)dsize, current->comm);
	}
	/*
	 * FIX-22 (a9a03929, run102 PROVEN) — strip OUR OWN current-tenure
	 * removes out of the disk image before ANY adopt/union below.
	 *
	 * The union arm treats every disk-only entry as "a peer's concurrent
	 * add", but with own_work the disk image can simply be OLDER than our
	 * in-core state (our own xfsaild landed a mid-tenure snapshot; our
	 * newest rename/rm has not destaged yet).  Then a disk-only entry that
	 * WE just removed is a ZOMBIE, and the union re-adds it — run102 t7:
	 * `mv n7_r49 n7_r49.done` at realns .289496, rebase-union at .294 re-
	 * imported n7_r49 from the .053-era platter image (P21-RB own_work=1),
	 * the rm then removed only .done, and the resurrected name went back
	 * out durably: the dlm_fairness 12-leftover ghost ratchet seeder.
	 * (The block-format drain-merge hit this exact ambiguity in /41
	 * and already solved it with the per-tenure removed-set; the SF union
	 * just never used it.)
	 *
	 * Gates: own_work only (we hold the modify path with undestaged mods —
	 * no peer can have modified this dir since those removes, so a
	 * removed-set ino match is definitionally OUR stale remove, never a
	 * peer's re-add), valid removed-set, and 4-byte-ino images only
	 * (dropping an entry must not change the SF ino width; i8count dirs
	 * do not occur on this geometry).
	 */
	if (own_work && dsf->i8count == 0 && dsf->count > 0 &&
	    dp->i_dlm_dir_removed && dp->i_dlm_dir_removed_n &&
	    mxfs_dir_remset_valid(dp) &&
	    dp->i_dlm_dir_removed_epoch == dp->i_dlm_dir_valid_epoch) {
		char		*sfbase = (char *)dsf;
		uint32_t	hdrsz = xfs_dir2_sf_hdr_size(0);
		char		*rd = sfbase + hdrsz, *wr = sfbase + hdrsz;
		char		*sfend = sfbase + dsize;
		uint8_t		z, in_count = dsf->count, zdropped = 0;
		char		zb[104];
		size_t		zo = 0;

		zb[0] = '\0';
		for (z = 0; z < in_count && rd < sfend; z++) {
			struct xfs_dir2_sf_entry *ze = (void *)rd;
			uint32_t esz = xfs_dir2_sf_entsize(mp, dsf,
							   ze->namelen);

			if ((char *)rd + esz > sfend)
				break;	/* malformed tail: stop compacting */
			if (mxfs_dir_was_removed(dp,
					xfs_dir2_sf_get_ino(mp, dsf, ze))) {
				zdropped++;
				if (zo < sizeof(zb) - 14)
					zo += scnprintf(zb + zo,
							sizeof(zb) - zo, "%.*s ",
							min_t(int, ze->namelen, 11),
							ze->name);
			} else {
				if (wr != rd)
					memmove(wr, rd, esz);
				wr += esz;
			}
			rd += esz;
		}
		if (zdropped) {
			static atomic_t p22n = ATOMIC_INIT(0);

			dsf->count -= zdropped;
			dsize = (uint64_t)(wr - sfbase);
			if (atomic_inc_return(&p22n) <= 2000)
				mxfs_probe("mxfs: P22-SFRB-ZOMBIE-SKIP ino=%llu dropped=%u zombies=[%s] disk_cnt=%u realns=%llu\n",
					(unsigned long long)dp->i_ino,
					zdropped, zb, dsf->count,
					(unsigned long long)ktime_get_real_ns());
			/*
			 * never trust surgical output — a
			 * compaction that broke early on a malformed tail
			 * leaves count over-claiming the kept bytes.  Verify
			 * the stripped image; on failure keep the in-core
			 * fork untouched (skip this refresh round entirely).
			 */
			if (xfs_dir2_sf_verify(mp, dsf, (int64_t)dsize) != NULL) {
				static atomic_t p14s = ATOMIC_INIT(0);

				if (atomic_inc_return(&p14s) <= 200)
					mxfs_probe("mxfs: P14-SFSTRIP-BAD ino=%llu cnt=%u dsize=%llu dropped=%u — post-strip image fails verify; refresh skipped\n",
						(unsigned long long)dp->i_ino,
						dsf->count,
						(unsigned long long)dsize,
						zdropped);
				goto out;
			}
		}
	}
	/* Already coherent? avoid churn and any self-revert no-op. */
	if ((uint64_t)ifp->if_bytes == dsize && ifp->if_data &&
	    memcmp(ifp->if_data, dsf, dsize) == 0) {
		atomic64_inc(&mxfs_rb_cohskip);
		goto out;
	}
	/*
	 * UNION MERGE: when we hold un-checkpointed own work,
	 * adopting the disk shortform wholesale would clobber our own just-added
	 * dirent(s) that are committed-to-log-but-not-checkpointed (disk lacks
	 * them).  A plain skip loses a PEER's concurrent add.  The correct state
	 * is the UNION: disk entries ∪ our in-core-only entries.  Build it into a
	 * temp buffer and adopt THAT instead of the bare disk image.  Only the
	 * matched-ino-width case is hand-merged; on width-mismatch or overflow we
	 * fall back to keeping our in-core fork (skip adopt — safe, peer entries
	 * picked up on the next refresh after our work checkpoints).
	 */
	if (own_work && mxfs_dir_sf_rebase_merge && ifp->if_data &&
	    ifp->if_bytes >= (int)xfs_dir2_sf_hdr_size(0)) {
		struct xfs_dir2_sf_hdr	*insf = ifp->if_data;
		uint32_t		maxsz = XFS_DFORK_SIZE(dip, mp, XFS_DATA_FORK);
		char			*merged;
		struct xfs_dir2_sf_hdr	*mh;
		struct xfs_dir2_sf_entry *iep;
		uint32_t		mlen = (uint32_t)dsize;
		uint32_t		merge_next_off = 0;
		int			i, added = 0;
		bool			bail = false;

		/* Only hand-merge matched ino width (both 4-byte or both 8-byte). */
		if ((insf->i8count != 0) != (dsf->i8count != 0))
			goto out;	/* keep in-core; adopt skipped this round */

		merged = kmalloc(maxsz, GFP_NOFS);
		if (!merged)
			goto out;
		memcpy(merged, dsf, dsize);
		mh = (struct xfs_dir2_sf_hdr *)merged;

		/*
		 * grafted entries MUST get FRESH data-block
		 * offsets.  Each sf entry stores the byte offset it will occupy
		 * in the eventual block-format data block; xfs_dir2_sf_to_block
		 * walks entries in offset order and places each at that offset.
		 * Copying an in-core entry's bytes WHOLESALE preserves its
		 * stale offset (assigned against a different dir state) which
		 * COLLIDES with the disk entries' offsets -> overlapping data
		 * entries -> xfs_dir3_data_verify metadata corruption + FS
		 * shutdown (PROVEN).  Re-assign each grafted entry a
		 * monotonic offset starting after the highest disk-entry end.
		 * When disk has NO entries we preserve the grafted entries'
		 * own (already-valid) offsets.
		 */
		{
			struct xfs_dir2_sf_entry *de = xfs_dir2_sf_firstentry(dsf);
			int k;

			merge_next_off = 0;
			for (k = 0; k < dsf->count; k++) {
				uint32_t eend = xfs_dir2_sf_get_offset(de) +
					xfs_dir2_data_entsize(mp, de->namelen);
				if (eend > merge_next_off)
					merge_next_off = eend;
				de = xfs_dir2_sf_nextentry(mp, dsf, de);
			}
		}

		iep = xfs_dir2_sf_firstentry(insf);
		for (i = 0; i < insf->count; i++) {
			struct xfs_dir2_sf_entry *dep;
			bool			found = false;
			int			j;
			uint32_t		esz;

			/* present on disk by name? */
			dep = xfs_dir2_sf_firstentry(dsf);
			for (j = 0; j < dsf->count; j++) {
				if (dep->namelen == iep->namelen &&
				    memcmp(dep->name, iep->name,
					   iep->namelen) == 0) {
					found = true;
					break;
				}
				dep = xfs_dir2_sf_nextentry(mp, dsf, dep);
			}
			if (!found) {
				struct xfs_dir2_sf_entry *gep;

				/* our in-core-only entry: graft onto merged */
				esz = xfs_dir2_sf_entsize(mp, insf, iep->namelen);
				if (mlen + esz > maxsz) {
					bail = true;
					break;
				}
				gep = (struct xfs_dir2_sf_entry *)(merged + mlen);
				memcpy(gep, iep, esz);
				/* Re-assign a fresh, non-colliding data offset (see
				 * comment above): only when disk had entries; an
				 * empty disk keeps the grafted entry's valid offset. */
				if (dsf->count > 0) {
					xfs_dir2_sf_put_offset(gep, merge_next_off);
					merge_next_off += xfs_dir2_data_entsize(
						mp, iep->namelen);
				}
				mlen += esz;
				if (mh->count == 255) {	/* sf count is u8 */
					bail = true;
					break;
				}
				mh->count++;
				if (mh->i8count &&
				    xfs_dir2_sf_get_ino(mp, insf, iep) >
				    XFS_DIR2_MAX_SHORT_INUM)
					mh->i8count++;
				added++;
			}
			iep = xfs_dir2_sf_nextentry(mp, insf, iep);
		}

		/*
		 * verify the union product before adopting.
		 * The graft loop walks the IN-CORE header's count over if_data
		 * — if that fork was already subtly desynced, the walk grafts
		 * heap garbage (zero-namelen entries) into an image that then
		 * publishes as the durable frankenstein (test4's count=7/six-
		 * entry wedge).  A bad product = keep the in-core fork.
		 */
		if (!bail && added > 0 &&
		    xfs_dir2_sf_verify(mp, (struct xfs_dir2_sf_hdr *)merged,
				       (int64_t)mlen) != NULL) {
			static atomic_t p14m = ATOMIC_INIT(0);

			if (atomic_inc_return(&p14m) <= 200)
				mxfs_probe("mxfs: P14-SFMERGE-BAD ino=%llu cnt=%u mlen=%u added=%d — union product fails verify; adopt skipped\n",
					(unsigned long long)dp->i_ino,
					mh->count, mlen, added);
			kfree(merged);
			goto out;
		}
		if (bail || added == 0) {
			kfree(merged);
			if (bail)
				goto out;	/* keep in-core */
			/* added==0: nothing of ours missing from disk; the
			 * disk image is a superset -> safe wholesale adopt. */
		} else {
			mxfs_rebase_core_probe(dp, dip, "union");
			kfree(ifp->if_data);
			ifp->if_data = NULL;
			xfs_init_local_fork(dp, XFS_DATA_FORK, merged,
					    (int)mlen);
			ifp->if_format = XFS_DINODE_FMT_LOCAL;
			dp->i_disk_size = (xfs_fsize_t)mlen;
			i_size_write(VFS_I(dp), mlen);
			kfree(merged);
			atomic64_inc(&mxfs_rb_merged);
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe("mxfs: P12-SF-MERGE ino=%llu disk=%llu merged=%u added=%d — union (disk ∪ own-uncheckpointed)\n",
					(unsigned long long)dp->i_ino,
					(unsigned long long)dsize, mlen, added);
			goto out;
		}
	}
	/* REBASE: adopt the peer's durable shortform wholesale. */
	mxfs_rebase_core_probe(dp, dip, "adopt");
	kfree(ifp->if_data);
	ifp->if_data = NULL;
	xfs_init_local_fork(dp, XFS_DATA_FORK, dsf, (int)dsize);
	ifp->if_format = XFS_DINODE_FMT_LOCAL;
	dp->i_disk_size = (xfs_fsize_t)dsize;
	i_size_write(VFS_I(dp), dsize);
	atomic64_inc(&mxfs_rb_adopted);
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("mxfs: P12-SF-REBASE ino=%llu newsize=%llu gen=%u evicted_gen=%u — adopted peer durable shortform\n",
			(unsigned long long)dp->i_ino, (unsigned long long)dsize,
			dp->i_dlm_dir_gen, dp->i_dlm_dir_evicted_gen);
out:
	kfree(ict);
}

void
mxfs_dlm_dir_modify_refresh(struct xfs_inode *dp)
{
	struct xfs_mount	*mp;
	bool			new_incarn;

	if (!dp)
		return;
	mp = dp->i_mount;
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;

	/*
	 * CONCURRENCY PROBE: log the DLM grant state at the start
	 * of every modify of the storm dir, with a WALL-CLOCK realns (NTP-synced
	 * across nodes).  Merge all nodes' P44-MODGRANT by realns: if two nodes'
	 * modify windows OVERLAP while BOTH believe they hold EX (mode=EX) — and
	 * especially if held=0 (cached EX but the actual grant moved to a peer,
	 * the stale-grant) — the loss is a DLM MUTUAL-EXCLUSION break, not a
	 * buffer-coherency gap (which would make every release/acquire fence inert,
	 * as PROVEN this session).  held = the ACTUAL grant; mode = cached belief.
	 */
	if (dp->i_ino <= 256 && unlikely(mxfs_instr_enabled || mxfs_dirwr_enabled)) {
		extern int mxfs_v5_dlm_inode_held(struct mxfs_v5_dlm *, uint64_t);
		int held = mxfs_v5_dlm_inode_held(mp->m_mxfs_dlm, dp->i_ino);
		static atomic_t p44mg = ATOMIC_INIT(0);
		if (atomic_inc_return(&p44mg) <= 200000)
			mxfs_probe("mxfs: P44-MODGRANT ino=%llu mode=%u held=%d exh=%u state=%u stale=%d epoch=%lu realns=%llu comm=%s\n",
				(unsigned long long)dp->i_ino,
				dp->i_dlm_mode, held, dp->i_dlm_ex_holders,
				dp->i_dlm_state, dp->i_dlm_stale,
				dp->i_dlm_epoch,
				(unsigned long long)ktime_get_real_ns(),
				current->comm);
	}

	/*
	 * ROOT FIX: coherent per-DATA-BLOCK content refresh BEFORE
	 * the modify's addname free-slot search, so a stale cached dir block can
	 * never make bestfree double-allocate a slot a peer already used (the
	 * proven 4/tcp dir_reuse loss).  Runs ahead of the lossy gen-skip below
	 * (gen is not a reliable cross-node signal).  Default OFF
	 * (mxfs_dir_coherent_modify); fires only when disk is provably ahead and
	 * never reverts our own committed-unwritten work.
	 */
	mxfs_dir_refresh_stale_data_blocks(dp);

	/*
	 * REFUTED: an unconditional pre-RMW FUA shortform compare-reload
	 * here did NOT fix the lost-update — under continuous local churn THIS
	 * node always carries un-checkpointed mods, so the helper's IN_AIL clean
	 * gate skips every time and the peer's change is never adopted.  Plus the
	 * extra FUA read added perf cost (dlm_fairness regressed).  The real fix
	 * is tenure-level (demote-for-peer + drain + reload-on-reacquire), see
	 * `docs/rulings/serialize-tenure-not-epoch.md`.  Reverted.
	 *
	 * (design review design-consult ABA fix): the old gen==0 / gen==evicted_gen
	 * short-circuits treated a freshly-created/reused dir (i_dlm_dir_gen==0)
	 * as "nothing cached to go stale".  FALSE under inode-number REUSE: the
	 * dir DATA cache is indexed by physical block (daddr), not by inode, so
	 * a peer can still hold the PREVIOUS incarnation's dir blocks at the
	 * same reused daddrs with XBF_DONE set (owner==ino verifier passes
	 * because the number was reused).  RMW'ing our dirent from that stale
	 * base durably clobbers the committer's just-added dirents (proven:
	 * rename_visibility, one node's renames invisible to ALL nodes incl.
	 * itself, ONLY on the first concurrent burst after a different test
	 * recycled these inodes; second run passes).  XFS bumps di_gen on every
	 * reallocation, so force a one-shot whole-dir clean-block evict whenever
	 * the on-disk inode generation differs from the one we last evicted for
	 * — guaranteeing the first RMW of a new incarnation cold-reads the
	 * peer's durable image regardless of the (collidable) i_dlm_dir_gen.
	 */
	new_incarn = (dp->i_dlm_dir_evicted_incarn != VFS_I(dp)->i_generation);

	/*
	 * SHORTFORM tenure-rebase.  Run BEFORE the (block-only)
	 * data-block evict and BEFORE the gen-skip fast path, but ONLY when a
	 * peer-driven reload has advanced the dir gen (gen!=0 && gen!=evicted)
	 * — never same-tenure, so we can never revert our own un-drained
	 * shortform work.  The helper itself also skips when disk==in-core.
	 */
	if (dp->i_dlm_dir_gen != 0 &&
	    dp->i_dlm_dir_gen != dp->i_dlm_dir_evicted_gen)
		mxfs_dir_rebase_shortform(dp);

	if (!mxfs_dir_force_evict &&
	    !new_incarn && dp->i_dlm_dir_gen == dp->i_dlm_dir_evicted_gen) {
		/* REVERTED: gating the whole-dir evict on epoch_advanced
		 * over-fired destructively under the storm (handoff on nearly every
		 * op -> evict+cold-read every modify -> exposed peers' non-durable
		 * in-flight entries -> MASS loss readdir=722/700 vs the single-dirent
		 * baseline).  The naive level-trigger lacks design review's quiesce / don't-
		 * publish-during-GRANTING / refresh-without-losing-in-AIL machinery.
		 * The MASS loss it exposed suggests a deeper Invariant-1 (drain-
		 * before-release) gap for dir DATA on the release side — investigate
		 * there next, not by force-evicting the reader. */
		/* (instrumented): a modify (create/rename/remove) that SKIPS
		 * the parent-dir refresh reads whatever dir blocks are cached.
		 * If a peer added a dirent (e.g. a concurrent mkdir of the same
		 * name) since our last evict, this RMW/existence-check uses a
		 * STALE base and misses the peer's entry -> directory-inode
		 * divergence.  Log the skip so a cross-node timeline shows a
		 * peer's create succeeding off a stale parent. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe("mxfs: P106-MR-SKIP ino=%llu gen=%u evicted_gen=%u loaded_gen=%u incarn=%u evicted_incarn=%u\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_dir_gen,
				dp->i_dlm_dir_evicted_gen, dp->i_dlm_dir_loaded_gen,
				VFS_I(dp)->i_generation, dp->i_dlm_dir_evicted_incarn);
		return;					/* fresh AND same incarnation */
	}
	/* with dir_force_evict on, fall through to the unconditional
	 * clean-block evict below even when the local gen looks unchanged — the
	 * gen is not a reliable cross-node "peer modified" signal. */

	/*
	 * arm the LEAF-rebuild for the FIRST modify of
	 * a fresh cross-node tenure.  A new incarnation (rm-rf+recreate reused
	 * the dir inode -> i_generation bumped) or an advanced dir_gen (a peer
	 * committed dirents) means this node's cached LEAF hash index may be
	 * stale; a node that RMW's + durably destages that stale leaf drops the
	 * peer's hashvals (the dir_reuse_coherency leaf-hash hole, readdir==EXP
	 * but lookup ENOENT).  Setting the flag here makes xfs_dir_createname
	 * reconstruct the leaf from the (now-evicted-coherent) DATA blocks ONCE
	 * per tenure (the flag is test_and_clear'd by the first create), so the
	 * destaged leaf carries every node's entries — without the every-create
	 * overhead that perturbed the reuse race.  Computed BEFORE the evict
	 * updates evicted_gen/incarn below.
	 */
	if (mxfs_dir_leaf_rebuild &&
	    (new_incarn || dp->i_dlm_dir_gen != dp->i_dlm_dir_evicted_gen))
		xfs_iflags_set(dp, MXFS_IF_DIR_LEAF_STALE);

	/* caller already holds ILOCK_EXCL — do NOT re-lock */
	if (mxfs_dir_evict_data_blocks(dp)) {
		dp->i_dlm_dir_evicted_gen = dp->i_dlm_dir_gen;
		dp->i_dlm_dir_evicted_incarn = VFS_I(dp)->i_generation;
	}
	/*
	 * DIAGNOSTIC (dir_modify_target_flush): after evicting the cached
	 * RMW base, issue SYNCHRONIZE CACHE to the shared target so its write
	 * cache (holding a peer's just-drained dirent) is destaged to the platter
	 * BEFORE the post-evict FUA read (which reads the platter, bypassing the
	 * target write cache).  If this turns dir_reuse_coherency PASS, the durable
	 * lost-update is a FUA-platter-lag stale RMW base (peer's release-drain
	 * landed only in the target write cache, not the platter the FUA read hits).
	 */
	{
		extern int mxfs_dir_modify_target_flush;
		struct xfs_mount *mp = dp->i_mount;
		/*
		 *  keep this call unconditional — it is
		 * the epoch CLOCK for the refresh-evict durability proof
		 * (P68-EVDECIDE compares b_epoch to m_mxfs_flush_epoch; a
		 * frozen epoch turns every evict into an undurable-skip ->
		 * stale-base RMW, proven at dir_reuse@8/tcp).  The helper
		 * itself now skips the physical SYNCHRONIZE CACHE when FUA
		 * reads are disabled (target cache IS the coherence point),
		 * so the per-modify cost is an atomic increment.
		 */
		if (mxfs_dir_modify_target_flush && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev)
			mxfs_blkdev_flush_epoch(mp);
	}
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("mxfs: P106-MR-EVICT ino=%llu gen=%u evicted_gen=%u incarn=%u new_incarn=%d\n",
			(unsigned long long)dp->i_ino, dp->i_dlm_dir_gen,
			dp->i_dlm_dir_evicted_gen, VFS_I(dp)->i_generation, new_incarn);
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P104-MODIFY-REFRESH ino=%llu gen=%u evicted_gen=%u incarn=%u new_incarn=%d\n",
			(unsigned long long)dp->i_ino, dp->i_dlm_dir_gen,
			dp->i_dlm_dir_evicted_gen, VFS_I(dp)->i_generation, new_incarn);
}
EXPORT_SYMBOL(mxfs_dlm_dir_modify_refresh);

/*
 * PROVEN-ROOT FIX (instrumented + design review) — adopt a peer's already-
 * committed dir FORMAT/CONTENT change before a modify RMW/conversion.
 *
 * PROVEN root of the dir_reuse_coherency durable node1_f* loss: a node holding
 * a STALE in-core SHORTFORM view of the shared dir re-converts shortform->block
 * (xfs_dir2_sf_to_block) and overwrites block0 with ONLY its own entries,
 * clobbering all peer entries already on disk (P42-SFCONV sf_count=11 +
 * P61-BLK0 core_node1=0 disk_node1=68).  The modify-path data-block evict
 * (mxfs_dlm_dir_modify_refresh) can't help — the staleness is the FORK FORMAT,
 * and the modify paths can't call mxfs_dlm_reload_inode because it takes
 * down_write(i_lock) and we already hold ILOCK_EXCL.
 *
 * Per design review: do the reload while holding the dir DLM EX but WITHOUT an active
 * transaction item for dp and without a dirtied fork — exactly the create/
 * remove/rename call site, where dp is ILOCK'd-but-not-yet-ijoined.  We hold
 * the DLM EX, so no peer can change disk while we drop the local ILOCK, run the
 * normal i_lock-taking reload (which adopts the peer's durable image and is
 * guarded against rolling back our own un-checkpointed work), and re-take the
 * ILOCK.  Triggered ONLY when a FUA dinode read shows disk is AHEAD of our
 * in-core fork for the SAME incarnation (di_gen match): face 1 = in-core
 * shortform but disk non-shortform (peer converted); face 2 = in-core
 * block/extents but disk grew (more extents / larger size = peer block->leaf
 * grow, the di_size!=blksize EFSCORRUPT shutdown class).
 *
 * Caller holds dp's ILOCK with `lock_flags` (e.g. EXCL|PARENT) and the dir DLM
 * EX, and dp is NOT yet joined to the active transaction.  Returns true if a
 * reload was performed (the lock was dropped + re-taken).
 */
bool
mxfs_dir_modify_adopt_disk_format(struct xfs_inode *dp, unsigned int lock_flags)
{
	struct xfs_mount	*mp = dp->i_mount;
	void			*tmp;
	uint32_t		len;
	uint64_t		lba;
	int			rc;
	struct xfs_dinode	*dip;
	uint16_t		disk_magic;
	uint8_t			disk_fmt;
	uint32_t		disk_gen, disk_nx, disk_nlink;
	uint64_t		disk_sz, disk_chg;
	bool			stale = false;
	extern int		mxfs_dir_modify_adopt_nlink;
	extern int		mxfs_dir_adopt_skip_held_ex;
	extern atomic64_t	mxfs_adopt_skip_held_ex, mxfs_adopt_read_held_ex;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	if (!S_ISDIR(VFS_I(dp)->i_mode) || dp->i_ino == mp->m_sb.sb_rootino)
		return false;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return false;

	/*
	 * (D-32NODE-SHARED-DIR-CREATE-PACE, ruling item 2): the FUA
	 * read below costs ~1 ms per create in a shared directory (rfr_ms 1.0
	 * in-tenure vs 0.2 private, where the dir_gen>0 gate at the call site
	 * already skips it).  It exists to catch a PEER's committed change to
	 * the dir inode.  A peer can only change it while holding the dir EX,
	 * and this node can only lose its EX through a path that bumps
	 * i_dlm_epoch (grant lost or marked stale).  So while we still hold
	 * EX, are not stale, the epoch and incarnation are the ones a previous
	 * clean check ran under, and the dir gen has not moved (a late
	 * DIR_MODIFY ring notification for a pre-tenure peer change re-arms
	 * the read, conservatively), the platter cannot be ahead of in-core:
	 * skip the read.  A demote or release, a stale mark, a reload, or an
	 * inode reuse all invalidate the recorded tuple by construction.
	 * Same-tenure only: the tuple is recorded only from a clean read
	 * taken while holding EX, never from a reload.
	 */
	/*
	 * 0.70.16: the dir gen is NOT part of the tuple.  Chain 141 leg A on
	 * 0.70.14 showed the skip engaging on 4 of 32 nodes with rfr_ms
	 * unchanged: peers' DIR_MODIFY ring notifications keep bumping
	 * i_dlm_dir_gen during our tenure for modifications made BEFORE it,
	 * and every bump re-armed the read.  Those modifications were drained
	 * to the platter before the peer released (invariant 1), so they were
	 * already in the image our clean read saw; a later notification of
	 * them says nothing new about the platter while we still hold EX.
	 */
	if (mxfs_dir_adopt_skip_held_ex &&
	    dp->i_dlm_mode == MXFS_LOCK_EX && !dp->i_dlm_stale &&
	    dp->i_dlm_adopt_ok_epoch != 0 &&
	    dp->i_dlm_adopt_ok_epoch == dp->i_dlm_epoch &&
	    dp->i_dlm_adopt_ok_incarn == VFS_I(dp)->i_generation) {
		static atomic_t p495s = ATOMIC_INIT(0);

		atomic64_inc(&mxfs_adopt_skip_held_ex);
		if (atomic_inc_return(&p495s) <= 20)
			mxfs_probe("mxfs: P495-ADOPT-SKIP ino=%llu epoch=%lu incarn=%u dir_gen=%u comm=%s — dir EX held continuously since the last clean adopt check; platter cannot be ahead, FUA inode read skipped\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_epoch,
				VFS_I(dp)->i_generation, dp->i_dlm_dir_gen,
				current->comm);
		return false;
	}
	if (mxfs_dir_adopt_skip_held_ex && dp->i_dlm_adopt_ok_epoch != 0) {
		/* 0.70.16: name the term that re-armed the read (capped). */
		static atomic_t p495n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p495n) <= 40)
			mxfs_probe("mxfs: P495-ADOPT-READ ino=%llu mode=%u stale=%d epoch=%lu ok_epoch=%lu incarn=%u ok_incarn=%u dir_gen=%u ok_dir_gen=%u comm=%s — tuple mismatch, FUA inode read taken\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_mode,
				dp->i_dlm_stale ? 1 : 0, dp->i_dlm_epoch,
				dp->i_dlm_adopt_ok_epoch,
				VFS_I(dp)->i_generation, dp->i_dlm_adopt_ok_incarn,
				dp->i_dlm_dir_gen, dp->i_dlm_adopt_ok_dir_gen,
				current->comm);
	}

	len = BBTOB(dp->i_imap.im_len);
	if (!len || (len & 511))
		return false;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return false;
	lba = (uint64_t)dp->i_imap.im_blkno + mp->m_ddev_targp->bt_sector_offset;
	rc = mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return false;
	}
	dip = (struct xfs_dinode *)((char *)tmp + dp->i_imap.im_boffset);
	disk_magic = be16_to_cpu(dip->di_magic);
	if (disk_magic != XFS_DINODE_MAGIC) {
		kfree(tmp);
		return false;
	}
	disk_gen = be32_to_cpu(dip->di_gen);
	disk_fmt = dip->di_format;
	disk_sz  = be64_to_cpu(dip->di_size);
	disk_nx  = be32_to_cpu(dip->di_nextents);
	disk_nlink = be32_to_cpu(dip->di_nlink);
	disk_chg = be64_to_cpu(dip->di_changecount);
	kfree(tmp);

	{
		/* 6000→300 — printk-storm DoS (see P82-ADD). */
		static atomic_t p61dx = ATOMIC_INIT(0);
		if (atomic_inc_return(&p61dx) <= 300)
			mxfs_probe("mxfs: P61-ADOPT-CHK ino=%llu incore_fmt=%d disk_fmt=%d incore_nx=%llu disk_nx=%u incore_sz=%lld disk_sz=%llu incore_gen=%u disk_gen=%u dlm_mode=%d comm=%s\n",
				(unsigned long long)dp->i_ino,
				dp->i_df.if_format, disk_fmt,
				(unsigned long long)dp->i_df.if_nextents, disk_nx,
				(long long)dp->i_disk_size, disk_sz,
				VFS_I(dp)->i_generation, disk_gen,
				dp->i_dlm_mode, current->comm);
	}

	/* same incarnation only: a different di_gen is the ABA path handled
	 * elsewhere (mxfs_dir_evict incarn_aba / reload reuse-adopt). */
	if (disk_gen != VFS_I(dp)->i_generation)
		return false;

	if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
	    disk_fmt != XFS_DINODE_FMT_LOCAL)
		stale = true;			/* face 1: peer converted sf->block */
	else if (dp->i_df.if_format == XFS_DINODE_FMT_LOCAL &&
		 disk_fmt == XFS_DINODE_FMT_LOCAL &&
		 disk_sz > (uint64_t)dp->i_disk_size)
		stale = true;			/*  face 1b, the
					 * /gap this function was
					 * disabled for -- a peer added a shortform
					 * entry we haven't adopted (SAME format on
					 * both sides, di_size alone reveals the
					 * content growth from the FUA read we
					 * already did; no extra I/O).  Without this,
					 * a later add that overflows shortform and
					 * self-converts via xfs_dir2_sf_to_block
					 * carries our STALE base into the new block,
					 * permanently dropping every entry we never
					 * adopted (proven: dlm_scaling@32 node's own
					 * just-logged mkdir vanishes across its
					 * parent's sf->block conversion). */
	else if (dp->i_df.if_format != XFS_DINODE_FMT_LOCAL &&
		 (disk_nx > dp->i_df.if_nextents ||
		  disk_sz > (uint64_t)dp->i_disk_size))
		stale = true;			/* face 2: peer grew the dir */

	/*
	 *  — FACE 3: peer added entries INSIDE an
	 * existing directory block.
	 *
	 * Every face above keys on the dir's GEOMETRY (format, extent count,
	 * di_size).  Once a directory is in block format, adding a name into
	 * space that already exists in block 0 changes NONE of them — the RMW
	 * base can be arbitrarily far behind the platter and this function
	 * reports "fresh".  That is the surviving loss class after the P184/P189
	 * fixes: 194 distinct (round, name) losses in run sfstorm_20260728_161929
	 * with the failure shape "whole mkdir gone" (entry and the parent's link
	 * bump together, 422 of 466 checks), i.e. a read-modify-write built on a
	 * stale base and published over the peer's newer image.
	 *
	 * di_nlink and di_changecount DO move on every add, and both arrive in
	 * the same read the faces above already paid for — so this costs one
	 * comparison, no extra I/O.  Same incarnation is already established.
	 */
	else if (mxfs_dir_modify_adopt_nlink &&
		 (disk_nlink > VFS_I(dp)->i_nlink ||
		  disk_chg > inode_peek_iversion(VFS_I(dp)))) {
		static atomic_t p190n = ATOMIC_INIT(0);

		stale = true;
		if (atomic_inc_return(&p190n) <= 4000)
			mxfs_probe("mxfs: P190-MODIFY-BASE-BEHIND ino=%llu incore_nlink=%u disk_nlink=%u incore_chg=%llu disk_chg=%llu fmt=%d disk_fmt=%d incore_sz=%lld disk_sz=%llu comm=%s — RMW base is behind the platter with identical geometry; adopting before the modify\n",
				(unsigned long long)dp->i_ino,
				VFS_I(dp)->i_nlink, disk_nlink,
				(unsigned long long)inode_peek_iversion(VFS_I(dp)),
				(unsigned long long)disk_chg,
				dp->i_df.if_format, disk_fmt,
				(long long)dp->i_disk_size, disk_sz,
				current->comm);
	}

	if (!stale) {
		/*
		 * a clean read taken while holding EX is the baseline
		 * the skip above compares against.  Recorded only under EX and
		 * not stale, so a read that raced a demote (mode already PR/NL)
		 * never seeds a tuple the next holder-tenure could match.
		 */
		if (dp->i_dlm_mode == MXFS_LOCK_EX && !dp->i_dlm_stale) {
			dp->i_dlm_adopt_ok_epoch = dp->i_dlm_epoch;
			dp->i_dlm_adopt_ok_incarn = VFS_I(dp)->i_generation;
			dp->i_dlm_adopt_ok_dir_gen = dp->i_dlm_dir_gen;
		}
		atomic64_inc(&mxfs_adopt_read_held_ex);
		return false;
	}

	mxfs_probe_ratelimited("mxfs: P61-ADOPT-DISK ino=%llu incore_fmt=%d disk_fmt=%d incore_nx=%llu disk_nx=%u incore_sz=%lld disk_sz=%llu gen=%u dlm_mode=%d comm=%s — reload stale fork before modify (peer converted/grew)\n",
		(unsigned long long)dp->i_ino, dp->i_df.if_format, disk_fmt,
		(unsigned long long)dp->i_df.if_nextents, disk_nx,
		(long long)dp->i_disk_size, disk_sz, disk_gen,
		dp->i_dlm_mode, current->comm);

	/*
	 * Drop the local ILOCK so the normal reload can take i_lock; we hold
	 * the dir DLM EX so no peer can mutate disk meanwhile, and dp is NOT
	 * joined to the active transaction here, so reloading its fork cannot
	 * corrupt a trans inode item (the iflush-corruption shutdown class).
	 * The reload's own dirty/in-AIL/pinned guard preserves any of our
	 * un-checkpointed work (in which case it skips — never a data loss).
	 */
	xfs_iunlock(dp, lock_flags);
	dp->i_dlm_stale = true; dp->i_dlm_stale_src = 4;
	mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
	xfs_ilock(dp, lock_flags);
	return true;
}
EXPORT_SYMBOL(mxfs_dir_modify_adopt_disk_format);

/*
 * — BLOCK-LEVEL DIRENT UNION-MERGE (the CONFIRMED fix for
 * 2/tcp crash_consistency, `docs/history/confirmed-staleflush-clobber-p17.md`).
 *
 * PROVEN root: under concurrent create into a shared block-format dir, a node
 * re-acquires dir-EX holding a cached dir DATA block that carries its OWN
 * un-written logged entries (undestaged) but is MISSING the peer's committed
 * entries; the acquire keep-guard refuses to discard the un-written work, so the
 * peer's entries are never adopted, and the node then durably flushes that stale
 * base over the peer's block -> durable lost update (P17-CLOBBER-DROP).
 *
 * Neither keep-stale nor cold-overwrite is correct (each loses one side).  The
 * fix is a UNION: read the peer's DURABLE image of every dir DATA block from the
 * shared LUN and, for each dirent present on disk but ABSENT from our in-core
 * dir, RE-ADD it via the normal xfs_dir_createname machinery (which handles free
 * space / leaf hash / nextents).  Names are node-disjoint (node1_* vs node2_*),
 * so the union is conflict-free and idempotent.
 *
 * Runs at the PRE-LOCK modify hook (NO outer transaction, NO ILOCK held), so
 * each re-add uses its OWN self-contained transaction — a createname failure
 * (e.g. ENOSPC) cancels a CLEAN private trans and can NEVER dirty + shut down
 * the caller's operation transaction (the dirty-cancel shutdown class).
 *
 * Gated behind mxfs.dir_merge (default OFF) until proven; correctness-validated
 * against tests/cc_blockdir_probe.sh with the P17 detector.  CAUTION: re-adds
 * are additive only — safe for create-only workloads (crash_consistency); a
 * peer DELETE could be resurrected, so do NOT enable for delete-heavy paths
 * without a gen/tombstone check.
 */
int mxfs_dir_merge_enabled;	/* default 0: OFF until proven */
module_param_named(dir_merge, mxfs_dir_merge_enabled, int, 0644);
MODULE_PARM_DESC(dir_merge,
	"block-dir peer dirent union-merge at modify pre-lock (additive): "
	"0=off (default), 1=on");

/* cheap per-block stale-block reconcile.  Unlike dir_merge (whole-dir
 * snapshot every tenure -> DLM-timeout, AND gated once-per-tenure so it misses
 * the lost entry), this FUA-reads ONLY the dir DATA blocks the acquire-evict had
 * to KEEP stale (in-AIL undestaged, flagged MXFS_IF_DIR_DATA_STALE) and re-adds
 * any peer dirent our in-core lacks, in the modify's own transaction, BEFORE the
 * RMW.  Runs only when a stale block was kept (rare) -> cheap.  Default 0. */
int mxfs_dir_stale_reconcile;
module_param_named(dir_stale_reconcile, mxfs_dir_stale_reconcile, int, 0644);
MODULE_PARM_DESC(dir_stale_reconcile,
	"per-block reconcile of kept-stale in-AIL dir DATA blocks at modify (additive): 0=off (default), 1=on");

/*
 * force new directories to BLOCK format at mkdir on a multinode mount,
 * eliminating the shortform->block format-TRANSITION race that is the PROVEN
 * root of the 2/tcp crash_consistency durable dirent lost-update
 * (`docs/history/root-narrowed-shortform-to-block-transition.md`: pre-grown-to-block
 * dirs lose 0/30, sf-start lose ~1/8).  A dir that is block-format from birth
 * never lives in shortform on the shared LUN, so two nodes can never race the
 * sf->block conversion (one keeping a stale shortform base and clobbering the
 * peer's block image).  Cost is one dir DATA block per mkdir (NOT per-create) —
 * cheap vs the perf-doomed per-create merge.  Gated OFF by default until proven.
 */
/*
 * DEFAULT ON.  Forcing new multinode dirs to BLOCK
 * format at mkdir eliminates the cross-node shortform->block CONVERSION
 * divergence that is the residual root of the dir_reuse_coherency 2/tcp data
 * loss: two nodes concurrently grow a FRESH shared dir from shortform and each
 * convert their own base to block (xfs_dir2_sf_to_block) independently, landing
 * the dir's LOGICAL block 0 at DIFFERENT physical blocks (node1 fsb15 / node2
 * fsb14) -> logical-block0 SPLIT -> cold verify orphans one block (readdir
 * shortfall + leaf-hash holes).  With the dir BORN block-format (single-node
 * mkdir conversion only), there is no concurrent conversion to diverge; both
 * nodes share the ONE creator-allocated block0 and the in-tree RMW coherency
 * (drain-before-release + acquire-reload/evict) keeps that single block0
 * consistent.  PROVEN: dir_reuse_coherency 2/tcp PASS (24 rounds, drc-FAIL=0,
 * zero same-incarnation double-conversions) with this ON, vs intermittent loss
 * with it OFF.  found force_block alone INEFFECTIVE, but on a 40-session-
 * older build whose block0 RMW coherency still clobbered; the intervening
 * fixes (per-AG drain, FUA-fresh reload, P43/P43B revert guards, ...) closed
 * that gap, so the conversion-divergence elimination is now the missing piece.
 * The mxfs_dir_should_force_block guard restricts this to multi-node DIR
 * shortform mkdir only (no single-node / non-dir impact).
 */
/*
 * (D-32NODE-SHARED-DIR-CREATE-PACE): P132-CREATE has decomposed the
 * cost of one create since, but only for DIRECTORY creates -- the
 * clock is started under `is_dir`.  The workload that sets the shared-LUN
 * create ceiling makes FILES, so the one probe that could attribute a create's
 * cost has never run on the path that matters.  Setting this to N > 0 starts
 * the clock for file creates too and prints any create whose total reaches N
 * milliseconds; 0 leaves directory-only behaviour exactly as it was.
 *
 * It is a threshold rather than a plain on/off because the measurement it
 * exists for runs 3200 creates across 32 nodes: printing every one of them
 * would add log volume to the very path being timed.
 */
int mxfs_create_cost_ms;
module_param_named(create_cost_ms, mxfs_create_cost_ms, int, 0644);
MODULE_PARM_DESC(create_cost_ms,
		 "print P132-CREATE for any create (file OR directory) costing "
		 "at least this many ms, with the pre-commit phase split into "
		 "trans-reserve / dir-DLM-acquire / dialloc; 0 = off, directory "
		 "creates only (default)");

/*
 * 0.75.47: lab reproduction knob for the cross-node create race.
 * The create-race loser branch of xfs_create (P127-EEXIST-LOSER) is reached
 * only when this node's VFS lookup returned negative before the peer's
 * create committed and the peer then took the directory's exclusive grant
 * first; the two are microseconds apart in one open(2), so a scheduled race
 * hit it once in 1000 attempts (D-0921, lap s525e).  Sleeping at the top of
 * xfs_create, after the lookup and before the directory is locked, widens
 * that window so a peer creating the same name inside it wins every time.
 * Regular-file creates on multi-node mounts only; 0 (default) = off.
 */
int mxfs_create_race_delay_ms;
module_param_named(create_race_delay_ms, mxfs_create_race_delay_ms, int, 0644);
MODULE_PARM_DESC(create_race_delay_ms,
		 "lab: sleep this many ms at the top of every regular-file create "
		 "on a multi-node mount, between the VFS lookup and the directory "
		 "lock, so a peer's create of the same name wins the race (0 = off)");

int mxfs_dir_force_block = 0;	/*  (2026-07-07) DEFAULT FLIPPED 1->0: force_block=1 forces shared subdir dirs into BLOCK format, making the single dir block (agbno9/AG) a hot cross-node RMW hotspot -> file-data/torn-RMW aliasing -> dir3 CRC -> FS shutdown -> 4/caw cache_coherency + zero_silent_loss FAIL 0/4 (PROVEN this session). force_block=1 was a WORKAROUND for the sf->block conversion race; that race is fixed by the ~30 dir_* coherence params since, so fb=0 (natural XFS shortform dirs, in-inode, no shared block) now passes ALL coherency tests: measured 4/caw 15/15 multi-node PASS + 2/caw 8/8 PASS at fb=0, no regressions. Old note: fb=1 ALONE gave 2/tcp 17/17; regression was fb=1+merge. */
module_param_named(dir_force_block, mxfs_dir_force_block, int, 0644);
MODULE_PARM_DESC(dir_force_block,
	"force new multinode dirs to block format at mkdir: 1=on (default), 0=off. "
	"Eliminates cross-node sf->block CONVERSION divergence (two nodes "
	"independently converting a fresh shared shortform dir -> logical block0 "
	"split -> durable dirent loss). sess44's feared regression (force_block keeps "
	"a dir BLOCK in-core while a peer converts it to SHORTFORM on disk -> "
	"P43B-overrides-P34D format divergence -> bnobt double-free shutdown) NO "
	"LONGER OCCURS: the sess49 P43 soundness gate (fmtrevert-skip gated on "
	"dfr_dirty || EX) lets a clean PR/NL cacher adopt a peer's durable shortform "
	"shrink. sess67 (ccloop 4cb2d0a2) PROVED on=1 -> full ./run.sh 2 tcp = 17/17 "
	"PASS (build 621FD271/EE5F752F), incl. dlm_fairness + cache_coherency. NOTE: "
	"force_block must run WITHOUT dir_merge=1 (merge alone caused sess65's "
	"corruption, NOT force_block).");

/* True when a freshly-created directory dp should be forced to block format. */
bool
mxfs_dir_should_force_block(struct xfs_inode *dp)
{
	struct xfs_mount *mp = dp ? dp->i_mount : NULL;

	if (!mxfs_dir_force_block || !mp || !mp->m_mxfs_dlm)
		return false;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return false;
	/* Only a freshly-initialized shortform dir (.,..) is convertible here. */
	return dp->i_df.if_format == XFS_DINODE_FMT_LOCAL;
}
EXPORT_SYMBOL(mxfs_dir_should_force_block);

void
mxfs_dir_merge_peer_blocks(struct xfs_inode *dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	struct mxfs_merge_ent	*ents;
	unsigned int		dir_blk_bb, blksize;
	void			*rb;
	int			nent = 0, i, added = 0, missing = 0;
	const int		MAX_ENT = 1024;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);

	if (!mxfs_dir_merge_enabled)
		return;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;
	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    dp->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;			/* shortform handled by sf_merge */
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	geo = mp->m_dir_geo;
	blksize = geo->blksize;
	if ((blksize & 511) != 0 || blksize == 0)
		return;

	rb = kmalloc(blksize, GFP_NOFS);
	if (!rb)
		return;
	ents = kvmalloc_array(MAX_ENT, sizeof(*ents), GFP_NOFS);
	if (!ents) {
		kfree(rb);
		return;
	}
	dir_blk_bb = XFS_FSB_TO_BB(mp, geo->fsbcount);

	/* Phase 1: snapshot the peer's DURABLE dirents from the shared LUN. */
	xfs_ilock(dp, XFS_ILOCK_SHARED);
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    xfs_need_iread_extents(&dp->i_df))
		goto unlock1;
	for_each_xfs_iext(&dp->i_df, &icur, &got) {
		xfs_daddr_t	ds, de, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		ds = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		de = ds + XFS_FSB_TO_BB(mp, got.br_blockcount);
		for (d = ds; d + dir_blk_bb <= de && nent < MAX_ENT;
		     d += dir_blk_bb) {
			uint64_t	lba = (uint64_t)d +
					mp->m_ddev_targp->bt_sector_offset;
			char		*blk = rb;
			__be32		magic;
			unsigned int	off, end;
			int		guard = 0, rrc;

			rrc = mxfs_fua_disable ?
			      mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize) :
			      mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize);
			if (rrc != 0)
				continue;
			magic = *(__be32 *)blk;
			if (magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
			    magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC)) {
				struct xfs_dir2_data_hdr   *hdr = (void *)blk;
				struct xfs_dir2_block_tail *btp =
					xfs_dir2_block_tail_p(geo, hdr);
				end = (unsigned int)((char *)btp - blk);
			} else if (magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
				   magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC)) {
				end = blksize;
			} else {
				continue;	/* leaf/free/node — no dirents */
			}
			/* owner must be this dir (skip a reused-daddr foreign
			 * block, an incarnation we must not adopt). */
			if (be64_to_cpu(((struct xfs_dir3_blk_hdr *)blk)->owner)
			    != dp->i_ino)
				continue;
			if (end > blksize)
				end = blksize;
			off = geo->data_entry_offset;
			while (off < end && nent < MAX_ENT && guard++ < 8192) {
				struct xfs_dir2_data_unused *dup =
					(void *)(blk + off);
				struct xfs_dir2_data_entry *dep;
				unsigned int	len;

				if (be16_to_cpu(dup->freetag) ==
				    XFS_DIR2_DATA_FREE_TAG) {
					len = be16_to_cpu(dup->length);
					if (len == 0)
						break;
					off += len;
					continue;
				}
				dep = (void *)(blk + off);
				if (dep->namelen == 0 || dep->namelen > 255)
					break;
				/* skip "." and ".." */
				if (!(dep->namelen == 1 && dep->name[0] == '.') &&
				    !(dep->namelen == 2 && dep->name[0] == '.' &&
				      dep->name[1] == '.')) {
					struct mxfs_merge_ent *e = &ents[nent++];

					e->inum = be64_to_cpu(dep->inumber);
					e->namelen = dep->namelen;
					e->ftype = xfs_dir2_data_get_ftype(mp,
									   dep);
					memcpy(e->name, dep->name, dep->namelen);
				}
				off += xfs_dir2_data_entsize(mp, dep->namelen);
			}
		}
	}
unlock1:
	xfs_iunlock(dp, XFS_ILOCK_SHARED);

	/*
	 * Phase 2: re-add every peer dirent missing from our in-core dir under a
	 * SINGLE ILOCK_EXCL tenure (— fixes the merge-v1 DLM-churn
	 * shutdown).  v1 took xfs_ilock(dp,ILOCK_EXCL) in its OWN fresh
	 * transaction PER entry; each ilock routes through mxfs_dlm_ilock and,
	 * under concurrent 2-node load, the peer can steal the cached dir-EX
	 * grant in the window between two entries' transactions, so the next
	 * ilock must re-acquire it via the DLM — and after dozens of such
	 * acquire/release cycles one acquire fails (rc!=0) → mxfs_dlm_ilock_begin
	 * force-shuts-down the FS (xfs_mxfs_dlm.c:8128 SHUTDOWN_CORRUPT_INCORE).
	 *
	 * Here we acquire dp ILOCK_EXCL exactly ONCE (one dir-EX DLM acquire,
	 * held continuously) and commit each re-add with xfs_trans_roll_inode,
	 * which __xfs_trans_commit(regrant=true)s the accumulated work, regrants
	 * a fresh full reservation, and re-joins dp WITHOUT releasing its ILOCK
	 * (xfs_trans_roll keeps held items locked).  ijoin lockflags=0 so the
	 * final commit/cancel never unlocks dp either — we own the lock and drop
	 * it explicitly.  The roll gives each createname a fresh tr_create
	 * reservation (sized for a full directory insert incl. block alloc), so
	 * accumulated-ENOSPC mid-merge cannot occur; a createname that still
	 * fails leaves a dirty rolled trans which we cancel (the prior entries
	 * are already durably committed by the preceding roll), isolated from the
	 * caller's create transaction.
	 */
	if (nent > 0) {
		struct xfs_trans	*tp = NULL;
		uint			resblks;
		int			err;

		resblks = XFS_DIRENTER_SPACE_RES(mp, MAXNAMELEN - 1);
		err = xfs_trans_alloc(mp, &M_RES(mp)->tr_create, resblks, 0,
				      0, &tp);
		if (err)
			goto out_free;
		xfs_ilock(dp, XFS_ILOCK_EXCL);
		xfs_trans_ijoin(tp, dp, 0);	/* lockflags 0: we own the ILOCK */
		for (i = 0; i < nent; i++) {
			struct mxfs_merge_ent	*e = &ents[i];
			struct xfs_name		name = {
				.name = e->name, .len = e->namelen,
				.type = e->ftype,
			};
			xfs_ino_t		cur = 0;

			err = xfs_dir_lookup(tp, dp, &name, &cur, NULL, NULL);
			if (err == -ENOENT) {
				missing++;
				err = xfs_dir_createname(tp, dp, &name,
						(xfs_ino_t)e->inum, resblks);
				if (err)
					break;		/* dirty: cancel below */
				added++;
			} else {
				err = 0;		/* present / benign */
			}
			/* Commit accumulated work + regrant a fresh reservation,
			 * keeping dp ILOCK_EXCL held (no DLM re-acquire). */
			err = xfs_trans_roll_inode(&tp, dp);
			if (err)
				break;
		}
		if (!err)
			err = xfs_trans_commit(tp);
		else
			xfs_trans_cancel(tp);
		xfs_iunlock(dp, XFS_ILOCK_EXCL);
	}
out_free:

	if (added && unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P17-MERGE ino=%llu snapshot=%d missing=%d re-added=%d\n",
			(unsigned long long)dp->i_ino, nent, missing, added);

	kvfree(ents);
	kfree(rb);
}
EXPORT_SYMBOL(mxfs_dir_merge_peer_blocks);

/*
 * block-dir union-merge folded INTO the caller's transaction, reusing
 * the create's ALREADY-HELD dir-EX grant — the ONLY merge path that avoids the
 * extra dir-EX DLM acquire that force-shut-down merge v1 (per-entry fresh txn)
 * and v2 (single-tenure xfs_trans_roll at pre-lock): under 2-node contention any
 * extra acquire on the hot dir inode TIMES OUT (rc=-110) →
 * mxfs_dlm_ilock_begin SHUTDOWN_CORRUPT_INCORE
 * `docs/history/merge-v2-single-tenure-refuted-dlm-timeout.md`.
 *
 * PROVEN root `docs/history/readside-ruled-out-writeside-clobber-confirmed.md`: the
 * durable dirent loss is purely WRITE-SIDE — a node durably writes an in-core
 * dir block missing the peer's committed entries (the acquire keep-guard kept an
 * undestaged-but-stale base it can neither drop nor write).  Read method (FUA vs
 * plain) is irrelevant; the release path's durability checks pass (the block IS
 * durable, just stale content).  The fix is a union: re-add the peer's durable
 * entries to our in-core dir so the create RMWs a union base.
 *
 * Caller contract (xfs_create, just after xfs_trans_ijoin(tp,dp,0) and BEFORE
 * xfs_dir_create_child): dp is ILOCK_EXCL held AND ijoin'd to tp; tp has
 * reservation headroom (resblks bumped) for up to max_ents extra dir inserts.
 * We take NO lock and NO transaction here.  The create's tp is already dirty
 * from xfs_dialloc, so a partial merge simply commits its entries with the
 * create; on ANY createname error we STOP (never escalate to a cancel — the
 * create owns commit/abort).  Names are node-disjoint so the union is
 * conflict-free; additive-only (safe for create workloads; a peer DELETE could
 * be resurrected — gate to additive paths).
 */
void
mxfs_dir_merge_peer_into_tp(struct xfs_trans *tp, struct xfs_inode *dp,
			    int max_ents)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	struct mxfs_merge_ent	*ents;
	unsigned int		dir_blk_bb, blksize;
	void			*rb;
	int			nent = 0, i, added = 0, missing = 0;
	int			MAX_ENT = max_ents;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);

	if (!mxfs_dir_merge_enabled || max_ents <= 0)
		return;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;
	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    dp->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;			/* shortform handled by sf_merge */
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    xfs_need_iread_extents(&dp->i_df))
		return;
	/*
	 * Perf gate (budget): only merge when a peer advanced this dir since our
	 * last whole-dir evict (the acquire refresh's mxfs_dir_evict_data_blocks
	 * advances i_dlm_dir_evicted_gen to i_dlm_dir_gen ONLY when it fully
	 * evicted — so gen != evicted_gen means a KEPT undestaged/stale block may
	 * exist = exactly when the union-merge is needed) OR a new inode
	 * incarnation.  Otherwise the in-core dir already reflects the peer's
	 * image and the full-dir snapshot read would be wasted on every create.
	 */
	/* INSTRUMENTED PROBE: is the once-per-tenure gate skipping the merge for
	 * the storm dir?  added=0 in P18 is ambiguous (gate-skip vs nothing-missing);
	 * this disambiguates.  ino<=256 + dirwr/instr gated, capped. */
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) && dp->i_ino <= 256) {
		static atomic_t pmg = ATOMIC_INIT(0);
		bool gate_skip = (dp->i_dlm_dir_evicted_incarn == VFS_I(dp)->i_generation &&
				  dp->i_dlm_dir_gen == dp->i_dlm_dir_evicted_gen);
		if (atomic_inc_return(&pmg) <= 600)
			mxfs_probe("mxfs: P-MERGEGATE ino=%llu gen=%u evgen=%u incarn=%u evincarn=%u decision=%s\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_dir_gen,
				dp->i_dlm_dir_evicted_gen, VFS_I(dp)->i_generation,
				dp->i_dlm_dir_evicted_incarn, gate_skip ? "SKIP" : "RUN");
	}
	if (dp->i_dlm_dir_evicted_incarn == VFS_I(dp)->i_generation &&
	    dp->i_dlm_dir_gen == dp->i_dlm_dir_evicted_gen)
		return;
	geo = mp->m_dir_geo;
	blksize = geo->blksize;
	if ((blksize & 511) != 0 || blksize == 0)
		return;
	if (MAX_ENT > 1024)
		MAX_ENT = 1024;

	rb = kmalloc(blksize, GFP_NOFS);
	if (!rb)
		return;
	ents = kvmalloc_array(MAX_ENT, sizeof(*ents), GFP_NOFS);
	if (!ents) {
		kfree(rb);
		return;
	}
	dir_blk_bb = XFS_FSB_TO_BB(mp, geo->fsbcount);

	/* Phase 1: snapshot the peer's DURABLE dirents from the shared LUN.
	 * Caller holds dp ILOCK_EXCL so the extent list is stable; no ilock. */
	for_each_xfs_iext(&dp->i_df, &icur, &got) {
		xfs_daddr_t	ds, de, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		ds = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		de = ds + XFS_FSB_TO_BB(mp, got.br_blockcount);
		for (d = ds; d + dir_blk_bb <= de && nent < MAX_ENT;
		     d += dir_blk_bb) {
			uint64_t	lba = (uint64_t)d +
					mp->m_ddev_targp->bt_sector_offset;
			char		*blk = rb;
			__be32		magic;
			unsigned int	off, end;
			int		guard = 0, rrc;

			rrc = mxfs_fua_disable ?
			      mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize) :
			      mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize);
			if (rrc != 0)
				continue;
			magic = *(__be32 *)blk;
			if (magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
			    magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC)) {
				struct xfs_dir2_data_hdr   *hdr = (void *)blk;
				struct xfs_dir2_block_tail *btp =
					xfs_dir2_block_tail_p(geo, hdr);
				end = (unsigned int)((char *)btp - blk);
			} else if (magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
				   magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC)) {
				end = blksize;
			} else {
				continue;	/* leaf/free/node — no dirents */
			}
			if (be64_to_cpu(((struct xfs_dir3_blk_hdr *)blk)->owner)
			    != dp->i_ino)
				continue;
			if (end > blksize)
				end = blksize;
			off = geo->data_entry_offset;
			while (off < end && nent < MAX_ENT && guard++ < 8192) {
				struct xfs_dir2_data_unused *dup =
					(void *)(blk + off);
				struct xfs_dir2_data_entry *dep;

				if (be16_to_cpu(dup->freetag) ==
				    XFS_DIR2_DATA_FREE_TAG) {
					unsigned int len = be16_to_cpu(dup->length);
					if (len == 0)
						break;
					off += len;
					continue;
				}
				dep = (void *)(blk + off);
				if (dep->namelen == 0 || dep->namelen > 255)
					break;
				if (!(dep->namelen == 1 && dep->name[0] == '.') &&
				    !(dep->namelen == 2 && dep->name[0] == '.' &&
				      dep->name[1] == '.')) {
					struct mxfs_merge_ent *e = &ents[nent++];

					e->inum = be64_to_cpu(dep->inumber);
					e->namelen = dep->namelen;
					e->ftype = xfs_dir2_data_get_ftype(mp,
									   dep);
					memcpy(e->name, dep->name, dep->namelen);
				}
				off += xfs_dir2_data_entsize(mp, dep->namelen);
			}
		}
	}

	/* Phase 2: re-add every peer dirent missing from our in-core dir into
	 * the caller's transaction (NO new lock, NO new trans).  Bounded by
	 * max_ents (== the reservation headroom the caller pre-reserved). */
	for (i = 0; i < nent; i++) {
		struct mxfs_merge_ent	*e = &ents[i];
		struct xfs_name		name = {
			.name = e->name, .len = e->namelen, .type = e->ftype,
		};
		xfs_ino_t		cur = 0;
		int			err;

		err = xfs_dir_lookup(tp, dp, &name, &cur, NULL, NULL);
		if (err != -ENOENT)
			continue;	/* present already / lookup error */
		missing++;
		err = xfs_dir_createname(tp, dp, &name, (xfs_ino_t)e->inum,
					 XFS_DIRENTER_SPACE_RES(mp, e->namelen));
		if (err)
			break;		/* stop cleanly; create owns commit */
		added++;
	}

	if (added && unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P18-MERGE-TP ino=%llu snapshot=%d missing=%d re-added=%d\n",
			(unsigned long long)dp->i_ino, nent, missing, added);

	/*
	 * PERF/DLM-TIMEOUT FIX: make the union-merge
	 * ONCE-PER-TENURE instead of once-per-create.  While THIS node holds the
	 * dir EX grant a peer CANNOT modify the dir, so the peer's durable image
	 * is stable for the whole tenure — re-snapshotting + merging on every
	 * create is pure waste, and (proven P29 run) the per-create full-
	 * dir plain-bio read slows create processing enough that BAST handling
	 * lags and a peer's readdir PR-acquire times out (rc=-110 CORRUPT_INCORE
	 * shutdown, the same class hit).  Once we have COMPLETELY merged
	 * the peer's snapshot (saw every entry — snapshot not truncated — and
	 * re-added every one that was missing), the in-core dir is a full union;
	 * advance i_dlm_dir_evicted_gen/incarn so the gate at the top of this
	 * function (and the modify-refresh evict) skip every subsequent create
	 * THIS tenure.  The gen re-advances on the next post-release re-acquire
	 * (slow-path bump), re-arming the merge for the next tenure.  Guarded on
	 * full completion so a reservation/MAX_ENT-truncated partial merge keeps
	 * re-running until the dir is fully unioned.
	 */
	if (nent < MAX_ENT && added == missing) {
		dp->i_dlm_dir_evicted_gen = dp->i_dlm_dir_gen;
		dp->i_dlm_dir_evicted_incarn = VFS_I(dp)->i_generation;
	}

	kvfree(ents);
	kfree(rb);
}
EXPORT_SYMBOL(mxfs_dir_merge_peer_into_tp);

/*
 * CHEAP per-block stale-block reconcile.  Folded into the caller's
 * create transaction (dp ILOCK_EXCL + dir-EX held, reservation headroom present
 * — same contract as mxfs_dir_merge_peer_into_tp).  Unlike dir_merge it does NOT
 * snapshot the whole dir (DLM-timeout) nor gate once-per-tenure (misses the lost
 * entry); it FUA-reads ONLY the dir DATA/BLOCK blocks the acquire-evict had to
 * KEEP stale (cached + in-AIL + undestaged = our committed-unwritten add on a
 * base a peer superseded on the LUN) and re-adds, via xfs_dir_createname (which
 * updates leaf/free coherently), any peer dirent our in-core lacks BEFORE the
 * RMW destages the stale base over it.  The peer's add is durable on the LUN by
 * now (it released EX -> publish-before-notify FUA-wrote+flushed it before we
 * could acquire).  Additive + idempotent (lookup-guarded) -> safe for the
 * create-only dir_reuse workload; a peer DELETE is never resurrected because a
 * deleted entry is absent from the disk image we read.  Gated dir_stale_reconcile.
 */
void
mxfs_dir_reconcile_stale_data_blocks(struct xfs_trans *tp, struct xfs_inode *dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	struct mxfs_merge_ent	*ents;
	unsigned int		dir_blk_bb, blksize;
	void			*rb;
	int			nent = 0, i, added = 0, missing = 0, stale_blk = 0;
	int			inc_miss = 0, not_done = 0, nextent = 0;
	const int		MAX_ENT = 1024;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);

	if (!mxfs_dir_stale_reconcile)
		return;
	/* Consume the flag unconditionally when enabled — if we cannot reconcile
	 * (shortform / extents not read) there is no stale DATA block anyway. */
	if (!xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_DATA_STALE))
		return;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;
	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    dp->i_df.if_format != XFS_DINODE_FMT_BTREE) {
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe("mxfs: P32-RECBAIL ino=%llu reason=fmt fmt=%d\n",
				(unsigned long long)dp->i_ino, dp->i_df.if_format);
		return;
	}
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    xfs_need_iread_extents(&dp->i_df)) {
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe("mxfs: P32-RECBAIL ino=%llu reason=iread_extents\n",
				(unsigned long long)dp->i_ino);
		return;
	}
	geo = mp->m_dir_geo;
	blksize = geo->blksize;
	if ((blksize & 511) != 0 || blksize == 0)
		return;
	rb = kmalloc(blksize, GFP_NOFS);
	if (!rb)
		return;
	ents = kvmalloc_array(MAX_ENT, sizeof(*ents), GFP_NOFS);
	if (!ents) {
		kfree(rb);
		return;
	}
	dir_blk_bb = XFS_FSB_TO_BB(mp, geo->fsbcount);

	/* Phase 1: snapshot disk dirents ONLY from cached in-AIL-undestaged
	 * (kept-stale) DATA/BLOCK blocks.  Caller holds dp ILOCK_EXCL. */
	for_each_xfs_iext(&dp->i_df, &icur, &got) {
		xfs_daddr_t	ds, de, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		ds = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		de = ds + XFS_FSB_TO_BB(mp, got.br_blockcount);
		nextent++;
		for (d = ds; d + dir_blk_bb <= de && nent < MAX_ENT;
		     d += dir_blk_bb) {
			struct xfs_buf		*dbp = NULL;
			struct xfs_buf_log_item	*bip;
			bool			is_stale;
			uint64_t		lba;
			char			*blk = rb;
			__be32			magic;
			unsigned int		off, end;
			int			guard = 0, rrc;

			/* reconcile EVERY cached DONE DATA/BLOCK block.  The
			 * v2 gen-filter (b_mxfs_dir_gen != i_dlm_dir_gen) was INERT —
			 * P31 fired 0× while the SKIP branch armed the flag ~192×/round:
			 * the flag-set condition (in-AIL/pinned kept-stale at acquire)
			 * and a per-block gen mismatch do NOT coincide (the block is
			 * re-read + re-stamped to dir_gen between the SKIP and this
			 * reconcile, so bgen==dir_gen here even though the block on disk
			 * carries a peer add we lack).  The reconcile is FUA-read +
			 * lookup-guarded re-add — fully idempotent — so scanning every
			 * in-core DATA/BLOCK block costs only cheap FUA reads on blocks
			 * that are already coherent, and reliably folds in the peer's
			 * durable add on the one that is not (the single-dirent loss). */
			if (xfs_buf_incore(mp->m_ddev_targp, d, dir_blk_bb,
					   XBF_TRYLOCK, &dbp) != 0 || !dbp) {
				inc_miss++;
				continue;
			}
			bip = dbp->b_log_item;
			(void)bip;
			is_stale = (dbp->b_flags & XBF_DONE) &&
				   (dbp->b_ops == &xfs_dir3_data_buf_ops ||
				    dbp->b_ops == &xfs_dir3_block_buf_ops);
			xfs_buf_relse(dbp);
			if (!is_stale) {
				not_done++;
				continue;
			}
			stale_blk++;
			lba = (uint64_t)d + mp->m_ddev_targp->bt_sector_offset;
			/* FUA read (NOT plain) — this cluster is a LIO target
			 * where plain bio reads are per-initiator-cached and STALE
			 * across nodes; the SCSI-FUA read pierces that cache for the
			 * coherent cross-node image (xfs_mxfs_dlm.c:17904, confirmed
			 * fua_disable=1 -> readdir 0/400).  Honor mxfs_fua_disable. */
			rrc = mxfs_fua_disable ?
			      mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize) :
			      mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize);
			if (rrc != 0)
				continue;
			magic = *(__be32 *)blk;
			if (magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
			    magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC)) {
				struct xfs_dir2_data_hdr   *hdr = (void *)blk;
				struct xfs_dir2_block_tail *btp =
					xfs_dir2_block_tail_p(geo, hdr);
				end = (unsigned int)((char *)btp - blk);
			} else if (magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
				   magic == cpu_to_be32(XFS_DIR3_DATA_MAGIC)) {
				end = blksize;
			} else {
				continue;
			}
			if (be64_to_cpu(((struct xfs_dir3_blk_hdr *)blk)->owner)
			    != dp->i_ino)
				continue;
			if (end > blksize)
				end = blksize;
			off = geo->data_entry_offset;
			while (off < end && nent < MAX_ENT && guard++ < 8192) {
				struct xfs_dir2_data_unused *dup =
					(void *)(blk + off);
				struct xfs_dir2_data_entry *dep;

				if (be16_to_cpu(dup->freetag) ==
				    XFS_DIR2_DATA_FREE_TAG) {
					unsigned int len =
						be16_to_cpu(dup->length);
					if (len == 0)
						break;
					off += len;
					continue;
				}
				dep = (void *)(blk + off);
				if (dep->namelen == 0 || dep->namelen > 255)
					break;
				if (!(dep->namelen == 1 && dep->name[0] == '.') &&
				    !(dep->namelen == 2 && dep->name[0] == '.' &&
				      dep->name[1] == '.')) {
					struct mxfs_merge_ent *e = &ents[nent++];

					e->inum = be64_to_cpu(dep->inumber);
					e->namelen = dep->namelen;
					e->ftype = xfs_dir2_data_get_ftype(mp,
									   dep);
					memcpy(e->name, dep->name, dep->namelen);
				}
				off += xfs_dir2_data_entsize(mp, dep->namelen);
			}
		}
	}

	/* Phase 2: re-add every snapshotted peer dirent missing in-core. */
	for (i = 0; i < nent; i++) {
		struct mxfs_merge_ent	*e = &ents[i];
		struct xfs_name		name = {
			.name = e->name, .len = e->namelen, .type = e->ftype,
		};
		xfs_ino_t		cur = 0;
		int			err;

		err = xfs_dir_lookup(tp, dp, &name, &cur, NULL, NULL);
		if (err != -ENOENT)
			continue;
		missing++;
		err = xfs_dir_createname(tp, dp, &name, (xfs_ino_t)e->inum,
					 XFS_DIRENTER_SPACE_RES(mp, e->namelen));
		if (err)
			break;
		added++;
	}

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("mxfs: P31-RECONCILE ino=%llu fmt=%d nextent=%d inc_miss=%d not_done=%d stale_blk=%d snapshot=%d missing=%d re-added=%d\n",
			(unsigned long long)dp->i_ino, dp->i_df.if_format,
			nextent, inc_miss, not_done, stale_blk, nent,
			missing, added);

	kvfree(ents);
	kfree(rb);
}
EXPORT_SYMBOL(mxfs_dir_reconcile_stale_data_blocks);

/*
 * (design-consult A-vs-B probe): called AFTER xfs_dir_create_child (our
 * dirent inserted into the in-core block, before commit).  For each cached
 * DONE dir DATA/BLOCK block, PLAIN-read the current on-disk image and count
 * disk dirents (by inumber) ABSENT from the in-core block.  disk_extra>0 here
 * = our RMW base was already STALE (mechanism A: a stale base was used, the
 * destage-time P-WMERGE is a CONSEQUENCE, not an ABA).  disk_extra==0 here but
 * >0 at the bio chokepoint = mechanism B (b_addr reverted / ghost buffer).
 * Read-only, gated dir_postrmw_probe.  Caller holds dp ILOCK_EXCL.
 */
int mxfs_dir_postrmw_probe_enabled;
module_param_named(dir_postrmw_probe, mxfs_dir_postrmw_probe_enabled, int, 0644);
MODULE_PARM_DESC(dir_postrmw_probe,
	"sess32 A-vs-B probe: after create RMW, log disk-extra dirents the in-core "
	"block lacks (proves stale-base-RMW vs writeback-ABA): 1=on");

void
mxfs_dir_postrmw_probe(struct xfs_inode *dp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_da_geometry	*geo;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	unsigned int		dir_blk_bb, blksize;
	void			*rb;
	int			nblk = 0, disk_extra_tot = 0;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);
	extern int mxfs_dir3_disk_has_extra_inum(struct xfs_mount *,
		const void *, const void *, uint32_t, bool, bool);

	if (!mxfs_dir_postrmw_probe_enabled)
		return;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;
	if (dp->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    dp->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	if (dp->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    xfs_need_iread_extents(&dp->i_df))
		return;
	geo = mp->m_dir_geo;
	blksize = geo->blksize;
	if ((blksize & 511) != 0 || blksize == 0)
		return;
	rb = kmalloc(blksize, GFP_NOFS);
	if (!rb)
		return;
	dir_blk_bb = XFS_FSB_TO_BB(mp, geo->fsbcount);

	for_each_xfs_iext(&dp->i_df, &icur, &got) {
		xfs_daddr_t	ds, de, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		ds = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		de = ds + XFS_FSB_TO_BB(mp, got.br_blockcount);
		for (d = ds; d + dir_blk_bb <= de; d += dir_blk_bb) {
			struct xfs_buf	*dbp = NULL;
			uint64_t	lba;
			__be32		magic;
			bool		icbf, dkbf;
			int		de_n, rrc;

			if (xfs_buf_incore(mp->m_ddev_targp, d, dir_blk_bb,
					   XBF_TRYLOCK, &dbp) != 0 || !dbp)
				continue;
			if (!(dbp->b_flags & XBF_DONE) ||
			    (dbp->b_ops != &xfs_dir3_data_buf_ops &&
			     dbp->b_ops != &xfs_dir3_block_buf_ops) ||
			    !dbp->b_addr) {
				xfs_buf_relse(dbp);
				continue;
			}
			icbf = (dbp->b_ops == &xfs_dir3_block_buf_ops);
			lba = (uint64_t)d + mp->m_ddev_targp->bt_sector_offset;
			rrc = mxfs_fua_disable ?
			      mxfs_pal_bdev_read_plain_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize) :
			      mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, lba, rb, blksize);
			if (rrc != 0) {
				xfs_buf_relse(dbp);
				continue;
			}
			magic = *(__be32 *)rb;
			dkbf = (magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC) ||
				magic == cpu_to_be32(XFS_DIR3_BLOCK_MAGIC));
			de_n = mxfs_dir3_disk_has_extra_inum(mp, dbp->b_addr, rb,
							     blksize, icbf, dkbf);
			nblk++;
			if (de_n > 0) {
				disk_extra_tot += de_n;
				mxfs_probe("mxfs: P-POSTRMW ino=%llu daddr=%lld disk_extra=%d in_ail=%d — STALE RMW BASE (mechanism A: peer dirent absent from in-core right after our addname)\n",
					(unsigned long long)dp->i_ino,
					(long long)d, de_n,
					(dbp->b_log_item &&
					 test_bit(XFS_LI_IN_AIL,
					   &dbp->b_log_item->bli_item.li_flags))
					 ? 1 : 0);
			}
			/* B-correlation: log this block's buffer identity +
			 * content-seq so a later P-WMERGE on the same daddr can be
			 * matched (same bp + same lseq => content reverted in place;
			 * different bp => ghost/duplicate buffer). */
			if (mxfs_dirwr_enabled || mxfs_instr_enabled)
				mxfs_probe("mxfs: P-POSTRMW-BP ino=%llu daddr=%lld bp=%px lseq=%u wseq=%u disk_extra=%d done=%d\n",
					(unsigned long long)dp->i_ino, (long long)d,
					dbp, dbp->b_mxfs_logged_seq,
					dbp->b_mxfs_written_seq, de_n,
					!!(dbp->b_flags & XBF_DONE));
			xfs_buf_relse(dbp);
		}
	}
	if (disk_extra_tot == 0 && (mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("mxfs: P-POSTRMW ino=%llu nblk=%d disk_extra=0 (in-core is a superset right after RMW -> if P-WMERGE later fires, mechanism B/writeback-ABA)\n",
			(unsigned long long)dp->i_ino, nblk);
	kfree(rb);
}
EXPORT_SYMBOL(mxfs_dir_postrmw_probe);

/* default OFF.  The pending-dirent replay alone cannot fix node1_f1
 * (the losing node observes the loss only at cold-read, with no transaction to
 * replay into — see `docs/history/replay-timing-gap-adopt-at-coldread-not-create.md`).
 * Kept (infrastructure) but gated off so baseline behavior is unchanged; the
 * next session enables it together with an extent-map-convergence adopt. */
int mxfs_dir_pending_enabled;
module_param_named(dir_pending, mxfs_dir_pending_enabled, int, 0644);

void
mxfs_dir_pending_add(struct xfs_inode *dp, const struct xfs_name *name,
		     struct xfs_inode *cip)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct mxfs_pend_ent	*arr;
	uint32_t		n, i;

	if (!mxfs_dir_pending_enabled)
		return;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode) || !cip)
		return;
	if (name->len == 0 || name->len > MXFS_PEND_NAME_MAX)
		return;

	/* Drop a list left over from a prior incarnation of this dir number. */
	if (dp->i_dlm_dir_pending &&
	    dp->i_dlm_dir_pending_incarn != VFS_I(dp)->i_generation)
		dp->i_dlm_dir_pending_bytes = 0;

	if (!dp->i_dlm_dir_pending) {
		dp->i_dlm_dir_pending =
			kmalloc(MXFS_PEND_MAX_ENTS * sizeof(struct mxfs_pend_ent),
				GFP_NOFS);
		if (!dp->i_dlm_dir_pending)
			return;
		dp->i_dlm_dir_pending_bytes = 0;
	}
	dp->i_dlm_dir_pending_incarn = VFS_I(dp)->i_generation;
	arr = dp->i_dlm_dir_pending;
	n = dp->i_dlm_dir_pending_bytes / sizeof(struct mxfs_pend_ent);

	/* Refresh an existing record for the same name (re-create after churn). */
	for (i = 0; i < n; i++) {
		if (arr[i].namelen == name->len &&
		    memcmp(arr[i].name, name->name, name->len) == 0) {
			arr[i].cino = cip->i_ino;
			arr[i].cgen = VFS_I(cip)->i_generation;
			arr[i].ftype = xfs_mode_to_ftype(VFS_I(cip)->i_mode);
			return;
		}
	}
	/* Bounded: once full, STOP adding so the OLDEST entries (e.g. node1_f1,
	 * the one that gets orphaned) are retained rather than evicted. */
	if (n >= MXFS_PEND_MAX_ENTS)
		return;
	arr[n].cino = cip->i_ino;
	arr[n].cgen = VFS_I(cip)->i_generation;
	arr[n].ftype = xfs_mode_to_ftype(VFS_I(cip)->i_mode);
	arr[n].namelen = (uint8_t)name->len;
	memcpy(arr[n].name, name->name, name->len);
	dp->i_dlm_dir_pending_bytes += sizeof(struct mxfs_pend_ent);
}
EXPORT_SYMBOL(mxfs_dir_pending_add);

void
mxfs_dir_pending_replay(struct xfs_trans *tp, struct xfs_inode *dp,
			xfs_extlen_t resblks)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct mxfs_pend_ent	*arr;
	uint32_t		n, i;
	int			did = 0;

	if (!mxfs_dir_pending_enabled)
		return;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!dp->i_dlm_dir_pending || !S_ISDIR(VFS_I(dp)->i_mode))
		return;
	if (dp->i_dlm_dir_pending_incarn != VFS_I(dp)->i_generation) {
		dp->i_dlm_dir_pending_bytes = 0;	/* stale incarnation */
		return;
	}
	arr = dp->i_dlm_dir_pending;
	n = dp->i_dlm_dir_pending_bytes / sizeof(struct mxfs_pend_ent);

	for (i = 0; i < n && did < MXFS_PEND_REPLAY_MAX; i++) {
		struct xfs_name nm = {
			.name = (const unsigned char *)arr[i].name,
			.len  = arr[i].namelen,
			.type = arr[i].ftype,
		};
		xfs_ino_t fino = 0;
		int err;

		/* dp ILOCK_EXCL is held by the caller (xfs_create, post-ijoin). */
		err = xfs_dir_lookup_locked(tp, dp, &nm, &fino);
		if (err == 0)
			continue;		/* already present (common) */
		if (err != -ENOENT)
			continue;		/* don't fight a real error */

		/* Re-add only the dirent.  The child inode still carries the
		 * nlink from its original create (the adopt replaced the dir
		 * fork, never touched the child), so do NOT bump nlink. */
		err = xfs_dir_createname(tp, dp, &nm, arr[i].cino, resblks);
		if (err == 0) {
			did++;
			pr_warn_ratelimited(
				"mxfs: P65-REPLAY dir=%llu re-added \"%.*s\" -> ino=%llu (dropped by stale-block0 adopt)\n",
				(unsigned long long)dp->i_ino,
				arr[i].namelen, arr[i].name,
				(unsigned long long)arr[i].cino);
		}
	}
}
EXPORT_SYMBOL(mxfs_dir_pending_replay);

/*
 * (design-consult design, `docs/history/session-98-gpt-fix-design.md`): RELEASE-side
 * PUBLISH-AND-DISCARD.  mxfs_dir_evict_data_blocks above only CLEARS XBF_DONE on
 * a durable cached dir block — but a cleared-DONE buffer STAYS in the per-node
 * buffer cache and on the AIL/delwri writeback path, so xfsaild can later
 * re-flush a SUPERSEDED in-core image over a peer's newer committed dirents
 * (the PROVEN P-DIRWR root: active-count oscillates because nodes' async
 * xfsaild destage in-core dir buffers 1-2 deletions behind a peer's already-
 * landed version).  Clearing DONE also leaves a re-dirty-able buffer that the
 * next EX acquire can RMW from a stale base.
 *
 * The fix design review prescribed: treat shared dir buffers as TENURE-LOCAL.  On release,
 * once the block is genuinely checkpointed to the shared target, xfs_buf_stale()
 * it.  XBF_STALE (a) drops _XBF_DELWRI_Q so no delwri/xfsaild walker will EVER
 * flush this image again, and (b) on relse removes the buffer from the cache
 * hash so the next acquire (fast OR slow lock path) is FORCED to cold-read the
 * peer's merged durable image.  This enforces coherency at the BUFFER level, not
 * the lock level — so fast-path EX grants (P-DIRFASTEX) become safe too.
 *
 * SAFETY (proven idiom, see the AG-meta walk + P79-INSTR note ~L7220): xfs_buf_
 * stale on an IN-AIL buffer removes its BLI from the AIL and DISCARDS the
 * committed update (a lost update).  So we ONLY stale a block that is durable:
 * clean, not pinned, not in-AIL, not delwri, DONE.  The release fence loop above
 * guarantees data_durable (incl. IN_AIL) before we get here, so by this point
 * the dir blocks ARE durable; we re-check per block and SKIP any that isn't.
 * Also: xfs_buf_stale does NOT clear XBF_DONE (v0.3.99/) — must force-clear
 * it, else xfs_buf_get reuses the staled buf without re-reading from disk.
 * Caller holds ip->i_lock (read) so the extent list is stable.
 */
/*
 * run14d: returns the number of blocks NOT staled (undurable skips +
 * trylock misses).  A nonzero return means the dir still has blocks whose
 * in-core image is ahead of disk — releasing now hands a peer a stale block
 * (the P99-STALE-SKIP → late-xfsaild-clobber lost-update).  The caller loops
 * flush→stale until this returns 0.
 */
int
mxfs_dir_stale_data_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	unsigned int		dir_blk_bb;
	int			nskip = 0;

	if (ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS)
		return 0;

	dir_blk_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

	for_each_xfs_iext(&ip->i_df, &icur, &got) {
		xfs_daddr_t	d_start, d_end, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		d_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		d_end = d_start + XFS_FSB_TO_BB(mp, got.br_blockcount);

		for (d = d_start; d + dir_blk_bb <= d_end; d += dir_blk_bb) {
			struct xfs_buf		*dbp = NULL;
			struct xfs_buf_log_item	*bip;
			bool			undurable;
			int			ierr;

			ierr = xfs_buf_incore(mp->m_ddev_targp, d, dir_blk_bb,
					      XBF_TRYLOCK, &dbp);
			if (ierr == -EAGAIN) {
				/*
				 * cached but LOCKED (write I/O in
				 * flight or another actor mid-update).  The
				 * silent skip here let the block's image
				 * survive on the releasing node's writeback
				 * path and clobber a peer's newer dirents
				 * after unlock (s36 iter1: test4 xfsaild/
				 * kworker writes at .737/.951 bracketing
				 * test3's hold).  Count it so the caller's
				 * flush→stale loop waits for the lock and
				 * stales the block before unlock.
				 */
				nskip++;
				if (unlikely(mxfs_dirwr_enabled ||
					     mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P36-STALE-LOCKED ino=%llu daddr=%llu\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d);
				continue;
			}
			if (ierr != 0 || !dbp)
				continue;	/* not cached => next read fetches */

			bip = dbp->b_log_item;
			undurable = (bip && test_bit(XFS_LI_DIRTY,
						     &bip->bli_item.li_flags)) ||
				    (bip && test_bit(XFS_LI_IN_AIL,
						     &bip->bli_item.li_flags)) ||
				    xfs_buf_ispinned(dbp) ||
				    (dbp->b_flags & _XBF_DELWRI_Q);
			/*
			 * !XBF_DONE alone is NOT a hazard — that is a
			 * block a prior pass already staled (DONE force-
			 * cleared) still findable via an extra hold.  It has
			 * no image that can flush, but counting it kept
			 * nskip > 0 and spun the caller's retry loop to
			 * exhaustion (380× done=0-only skips, 79× tries=500
			 * in s36 iter1).  Re-staling it below is idempotent.
			 */

			if (!undurable) {
				/* Durable + fully checkpointed: DISCARD it so
				 * xfsaild can never re-flush this image and the
				 * next acquire cold-reads the peer's block. */
				xfs_buf_stale(dbp);
				dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				dbp->b_mxfs_dir_gen = 0;
				if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P99-DIR-STALE ino=%llu daddr=%llu\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d);
			} else {
				nskip++;
				mxfs_probe_ratelimited("mxfs: P99-STALE-SKIP ino=%llu daddr=%llu dirty=%d in_ail=%d pin=%d delwri=%d done=%d\n",
					(unsigned long long)ip->i_ino,
					(unsigned long long)d,
					!!(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)),
					!!(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)),
					xfs_buf_ispinned(dbp),
					!!(dbp->b_flags & _XBF_DELWRI_Q),
					!!(dbp->b_flags & XBF_DONE));
			}
			xfs_buf_relse(dbp);
		}
	}
	return nskip;
}
int
mxfs_dir_drain_evict_data_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	unsigned int		dir_blk_bb;
	xfs_daddr_t		daddrs[MXFS_DIR_DRAIN_MAX];
	unsigned int		lens[MXFS_DIR_DRAIN_MAX];
	int			nd = 0;
	bool			overflow = false;
	bool			any_pinned = false;
	int			i;
	int			skipped = 0;	/* undurable blocks left cached */

	dir_blk_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

	/*
	 * BTREE-format dirs used to bail here,
	 * switching the acquire fence OFF the moment the shared storm dir
	 * grew past EXTENTS (the zsl quiet-dirent-loss + corrupt-dinode
	 * root).  The iext snapshot below works for a BTREE fork too once
	 * extents are in-core; only an unenumerable dir (BTREE, extents not
	 * yet read) is conservatively reported skipped.
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE) {
		/*
		 * evict stale cached bmbt CHILD blocks so the extent-map
		 * read (here or in the imminent xfs_create) cold-fetches children
		 * coherent with the freshly-reloaded bmbt root — without this a
		 * just-reloaded BTREE dir reads a stale cached child and shuts the
		 * FS down (corrupt dinode 131, btree extents).
		 *
		 * (instrumented, PROVEN by P60-RELAUDIT): evict ONLY when the
		 * in-core extent list is NOT loaded (need_iread).  Evicting a leaf
		 * while the iext tree IS loaded (need_iread=0) cold-re-reads the
		 * leaf buffer from its stale on-disk image, REVERTING it away from
		 * the authoritative in-core iext tree — measured iext=15 but
		 * leaf=14.  The next inode flush then writes di_nextents (from the
		 * iext tree) paired with the stale leaf, producing the on-disk
		 * dinode<->bmbt mismatch a peer reads as `ir.loaded != if_nextents`
		 * -> EFSCORRUPTED shutdown -> the zsl silent-loss cascade.  When the
		 * extents are loaded the iext tree is authoritative and there is no
		 * stale child to evict; the corruption only manifests while
		 * READING extents (need_iread=1), which this still covers.
		 */
		if (xfs_need_iread_extents(&ip->i_df)) {
			mxfs_dir_evict_bmbt_blocks(ip);
			return 1;	/* cannot prove coherent: skipped */
		}
	} else if (ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS)
		return 0;		/* shortform: no data blocks */

	/* Snapshot the dir-block daddrs + note whether any is pin-only.
	 *
	 * this raw down_read is where the 8/tcp
	 * round-12 cluster-wide create wedge parks (hung-task: dd D-state in
	 * mxfs_dir_drain_evict_data_blocks+0xf4, all 8 nodes, write holder
	 * EXITED = leaked i_lock EXCL — FACE-1, live-verified on test3).
	 * Use the forensic bounded-trylock waiter so the wedge NAMES the
	 * leaking down_write path (wr_last, note_lock'd since) instead
	 * of hanging silently.  Semantics preserved: still waits indefinitely
	 * (NO trylock-skip — that regressed 4-node 12/12 -> 0/4);
	 * bails only on FS shutdown, reported as skipped (=1) like the
	 * BTREE-not-read path so the caller does not advance evicted_gen.
	 */
	if (!mxfs_drain_ilock_read(ip))
		return 1;	/* shutdown while waiting: skipped */
	for_each_xfs_iext(&ip->i_df, &icur, &got) {
		xfs_daddr_t	d_start, d_end, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		d_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		d_end = d_start + XFS_FSB_TO_BB(mp, got.br_blockcount);
		for (d = d_start; d + dir_blk_bb <= d_end; d += dir_blk_bb) {
			if (nd >= MXFS_DIR_DRAIN_MAX) {
				overflow = true;
				break;
			}
			daddrs[nd] = d;
			lens[nd] = dir_blk_bb;
			nd++;
		}
		if (overflow)
			break;
	}
	up_read(&ip->i_lock);

	/* P-DE diagnostic (always-on, capped): which blocks does the acquire-side
	 * evict visit, and what disposition does each get?  The leaf lives at the
	 * high dir-logical offset so its daddr appears here only if the extent map
	 * has it; a stale-RMW leaf-hash loss means this evict failed to drop it. */
	{
		static atomic_t pde = ATOMIC_INIT(0);
		if (atomic_inc_return(&pde) <= 400)
			mxfs_probe("mxfs: P-DE-ENTER ino=%llu fmt=%d nd=%d gen=%llu loaded=%u\n",
				(unsigned long long)ip->i_ino, ip->i_df.if_format,
				nd, (unsigned long long)ip->i_dlm_dir_gen,
				ip->i_dlm_dir_loaded_gen);
	}

	/* Determine if a log force is warranted (any pin-only block cached). */
	for (i = 0; i < nd; i++) {
		struct xfs_buf		*dbp = NULL;
		struct xfs_buf_log_item	*bip;

		if (xfs_buf_incore(mp->m_ddev_targp, daddrs[i], lens[i],
				   XBF_TRYLOCK, &dbp) != 0 || !dbp)
			continue;
		bip = dbp->b_log_item;
		if (xfs_buf_ispinned(dbp) &&
		    !(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) &&
		    !(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) &&
		    (dbp->b_flags & XBF_DONE))
			any_pinned = true;
		xfs_buf_relse(dbp);
	}

	/*
	 * also force when the dir is STALE (a peer modified — gen
	 * advanced past what our blocks were loaded at).  The any_pinned scan
	 * above uses XBF_TRYLOCK and SILENTLY MISSES a block that is momentarily
	 * LOCKED (in-flight I/O completion / xfsaild / a peer drain), so a
	 * prior-tenure pin tail on the very block we must refresh goes
	 * undetected -> no log_force -> the bounded per-block drain below times
	 * out -> the stale pinned block is KEPT and RMW'd/served (the uv
	 * DIR-STALE-SKIP pin=1 lost-update).  A stale dir at acquire MUST get a
	 * coherent base, so checkpoint unconditionally here; gen-gated so an
	 * uncontended acquire (gen==loaded, e.g. rsync own-subdir) pays nothing.
	 */
	/*
	 * the any_pinned scan (XBF_TRYLOCK) SILENTLY MISSES a block that
	 * is momentarily LOCKED, and the gen gate is the LOSSY DIR_MODIFY evict-ring
	 * (dir_gen==loaded_gen here on EVERY drain_evict call — P-DE-ENTER PROVED it,
	 * because the ring drops messages on TCP AND the handoff reload sets
	 * loaded_gen=dir_gen).  So on a genuine cross-node handoff the checkpoint is
	 * NOT forced, the per-block bounded drain times out on a prior-tenure pin
	 * tail, and the stale pinned dir block is KEPT + RMW'd -> the residual
	 * single-dirent lost-update (dir_reuse 1-2/24).  The DLM master's prior-EX-
	 * owner handoff bit is the RELIABLE signal the gen never was: when a peer
	 * held EX since our last grant, our cached dir blocks are stale and MUST be
	 * driven to a coherent base.  Once-per-handoff-acquire, so the budget rule cheap. */
	if (any_pinned || ip->i_dlm_dir_gen != ip->i_dlm_dir_loaded_gen)
		xfs_log_force(mp, XFS_LOG_SYNC);

	/* Drain (bounded) + evict each clean block. */
	for (i = 0; i < nd; i++) {
		struct xfs_buf		*dbp = NULL;
		struct xfs_buf_log_item	*bip;
		bool			dirty, in_ail, pinned, delwri;
		int			w;
		int			irc;

		irc = xfs_buf_incore(mp->m_ddev_targp, daddrs[i], lens[i],
				   XBF_TRYLOCK, &dbp);
		if (irc == -EAGAIN) {
			/*
			 * cached but LOCKED — a LOCAL in-flight bio /
			 * xfsaild flush holds the buffer lock (buffer locks are
			 * per-node, so this is never a cross-node wait).  The OLD
			 * code SKIPPED it here, leaving a stale base for the imminent
			 * create/unlink RMW = the dir lost-update (dir_reuse
			 * leaf-hash hole / missing-contiguous loss).  Instead WAIT
			 * (bounded) for the in-flight I/O to drain so we evict a
			 * coherent block.  Safe to block: slow-path acquire / CAW
			 * poll process ctx.  After the bound, fall through to
			 * the old LOCKED-SKIP (a later acquire retries; loaded_gen
			 * kept back).  Companion to dir_pr_release_fast>=2 (broad
			 * release skip removed the masking that hid these LOCKED blocks).
			 */
			extern int mxfs_dir_acq_lockwait;
			int wl;

			for (wl = 0; wl < mxfs_dir_acq_lockwait &&
				     !xfs_is_shutdown(mp) && !xfs_is_unmounting(mp);
			     wl++) {
				msleep(2);
				irc = xfs_buf_incore(mp->m_ddev_targp, daddrs[i],
						   lens[i], XBF_TRYLOCK, &dbp);
				if (irc != -EAGAIN)
					break;	/* acquired (0) or gone (-ENOENT) */
			}
			{
				static atomic_t pdew = ATOMIC_INIT(0);
				if (atomic_inc_return(&pdew) <= 400)
					mxfs_probe("mxfs: P-DE-BLK ino=%llu daddr=%llu disp=LOCKED-WAIT iters=%d rc=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)daddrs[i], wl, irc);
			}
		}
		if (irc != 0 || !dbp) {
			/* -EAGAIN (still LOCKED after the bounded wait) = stale buffer
			 * left served; -ENOENT = not cached (a cold read fetches fresh). */
			if (irc == -EAGAIN) {
				static atomic_t pdel = ATOMIC_INIT(0);
				if (atomic_inc_return(&pdel) <= 400)
					mxfs_probe("mxfs: P-DE-BLK ino=%llu daddr=%llu disp=LOCKED-SKIP\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)daddrs[i]);
			}
			continue;
		}

		bip = dbp->b_log_item;
		dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
		in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
		pinned = xfs_buf_ispinned(dbp);

		/*
		 * sess97 ACQUIRE INVALIDATION FENCE (GPT design, design-consult).
		 * Wait out the async unpin tail for a pin-ONLY block, UNBOUNDED.
		 * The OLD 50-iter (~100ms) bound gave up (P-ACQ-DRAIN-SKIP) while
		 * the block was still pin-tailed, so the node KEPT a stale cached
		 * dir block and RMW'd its own create/delete onto it — clobbering a
		 * peer's concurrently-committed dirent (the proven sess96
		 * lost-update; the unlink_visibility "deleted file resurrected"
		 * residual: node B removes its dirent from a STALE base that still
		 * lists node A's already-removed dirent, resurrecting A's file).
		 * A pin-ONLY block (pinned && !dirty && !in_ail && DONE) is THIS
		 * node's own already-committed work whose CIL unpin tail just hasn't
		 * fired; xfs_log_force drives the commit, then we wait for the unpin
		 * so we can cleanly evict it (clearing XBF_DONE on a pinned buffer
		 * corrupts — sess64).  Runs off the CAW poll thread (slow-path
		 * acquire, process ctx), so blocking is safe.
		 * sess97 PERF REVERT: the unbounded variant (15000 iters +
		 * log_force every 16) caused a 5.5x unlink slowdown (28s→155s) by
		 * spinning on pin-tailed blocks under heavy concurrent-unlink CIL
		 * pressure, and it did NOT fix the unlink loss (that is a write-side
		 * handoff race, NOT this read/acquire path: DIR-STALE-SKIP=0,
		 * acquire-skips all benign).  Back to bounded (50 iters ~100ms);
		 * the single pre-loop log_force above drives the common case. */
		for (w = 0; w < 50 && pinned && !dirty && !in_ail &&
			     (dbp->b_flags & XBF_DONE) &&
			     !xfs_is_shutdown(mp) && !xfs_is_unmounting(mp); w++) {
			xfs_buf_relse(dbp);
			msleep(2);
			dbp = NULL;
			if (xfs_buf_incore(mp->m_ddev_targp, daddrs[i], lens[i],
					   XBF_TRYLOCK, &dbp) != 0 || !dbp)
				break;
			bip = dbp->b_log_item;
			dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
			in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
			pinned = xfs_buf_ispinned(dbp);
		}
		if (!dbp)
			continue;
		delwri = !!(dbp->b_flags & _XBF_DELWRI_Q);

		/*
		 * v0.5.2 (PROVEN BY INSTRUMENT, solo-rsync error-117 forensics): the
		 * sess101 "evict in-AIL/dirty/delwri too" policy below was
		 * justified by publish-before-notify (every committed dir
		 * change durable on the LUN before any peer gen bump).
		 * durable_signal is now PUBLISH-ONLY (no disk I/O), so a
		 * clean-but-in-AIL dir block's content exists ONLY in core +
		 * log redo — the platter still holds the previous write (or,
		 * on a re-mkfs'd LUN, the PRIOR INCARNATION's block:
		 * P-ACQ-DRAIN-EVICT ino=142 daddr=120 in_ail=1 followed by
		 * xfs_da_read_buf error 117 with the OLD fs UUID in the
		 * verifier dump).  Evicting it cold-reads that stale image.
		 * Use the same payload-LSN discriminator as the
		 * xfs_da_read_buf hook: an in-AIL buffer whose last mods are
		 * already destaged is safe to refresh; committed-unwritten
		 * work is skipped (the skip branch keeps loaded_gen back so
		 * the refresh retries after the AIL push).  The sess101
		 * lost-update cannot recur from this guard: a genuine peer
		 * modification implies WE released EX first, and the release
		 * drain (invariant #1) destages our blocks out of the AIL —
		 * at a true peer-modified acquire these conditions never hold.
		 */
		/* FIX-14 (PROVEN BY INSTRUMENT, run87 r2 node4 daddr
		 * 18840944): the in_ail gate on the undestaged check let a
		 * CIL-WINDOW buffer (committed md5 adds, in_ail=0, dirty=0,
		 * pin=0, delwri=0, lseq>wseq) be EVICTED on every acquire-fence
		 * pass (P68-EVDECIDE/P-DE-BLK EVICT fired per add); the next
		 * read re-DMA'd the pre-add platter over b_addr, so the wave's
		 * accumulated dirents vanished from the RMW base and the
		 * eventual destage wrote the reverted image — the md5-tail
		 * cluster-wide loss (runs 85/86/87 rounds 2/3/7/12).  Same
		 * idiom FIX-10 killed in xfs_dir2_data.c's P28C.  undestaged
		 * (lseq!=wseq || pinned) must be checked UNCONDITIONALLY. */
		if ((dbp->b_flags & XBF_DONE) && !pinned && !dirty && !delwri &&
		    !mxfs_dir_buf_is_undestaged(dbp)) {
			/*
			 * sess101 ROOT FIX (Gemini design-consult, reconciled the
			 * sess96/99 vs sess69 contradiction): EVICT in-AIL / dirty /
			 * delwri dir blocks too — only PINNED is a hard skip.
			 *
			 * The sess99 "aggressive acquire cold-read returns stale
			 * SCST content" regression PREDATED publish-before-notify:
			 * back then the releaser unlocked before its data fenced to
			 * the SCST media, so a cold-read genuinely raced an
			 * unflushed write.  publish-before-notify (xfs_bwrite +
			 * blkdev_issue_flush, EX held, post-commit) now fences every
			 * committed dir change to the LUN BEFORE a peer is told, so a
			 * plain cold-read reliably observes the durable image (sess69
			 * PROVED raw O_DIRECT reads are byte-identical across
			 * initiators = transport coherent).
			 *
			 * Therefore the OLD "!dirty && !in_ail && !delwri" guard was
			 * the lost-update SOURCE, not a safety net: a node acquiring
			 * EX during the concurrent create/delete storm kept its
			 * in-AIL cached block (its own committed-but-log-tail-pending
			 * work) and RMW'd that STALE base, durably DROPPING a peer's
			 * just-committed dirents (PROVEN: a node's own `rm` then
			 * ENOENTs a CONTIGUOUS RANGE of files it created, because a
			 * peer clobbered them from a stale base).
			 *
			 * SAFETY (Gemini): clearing XBF_DONE on a clean-but-in-AIL
			 * buffer is safe — the BLI stays attached, the AIL keeps the
			 * old LSN (whose data is already durable via
			 * publish-before-notify), the next read cold-fetches the
			 * peer's image, and this node's next modify re-logs the
			 * buffer (advancing the BLI).  We must NOT xfs_buf_stale()
			 * (drops the rhashtable entry while the AIL still refs it ->
			 * ghost/duplicate buf cache corruption).  We must NOT clear
			 * DONE on a PINNED buffer (sess64 corruption) — the bounded
			 * drain loop above already log_force'd + waited the pin tail;
			 * a still-pinned block is left for the next acquire.
			 *
			 * Leaf/node/freeindex blocks are covered automatically: this
			 * loop iterates EVERY block in the dir's data-fork extent map
			 * (data + leaf + free all live there), so a fresh data block
			 * is never merged against a stale leaf/free block. */
			dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			dbp->b_mxfs_dir_gen = 0;
			{
				static atomic_t pdev = ATOMIC_INIT(0);
				if (atomic_inc_return(&pdev) <= 600)
					mxfs_probe("mxfs: P-DE-BLK ino=%llu daddr=%llu disp=EVICT dirty=%d in_ail=%d delwri=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)daddrs[i], dirty, in_ail, delwri);
			}
		} else {
			/* Still PINNED after the bounded drain — clearing XBF_DONE
			 * on a pinned buffer corrupts.  Leave it; the
			 * caller must NOT advance loaded_gen past this so the next
			 * acquire/read re-attempts the evict once the pin tail
			 * fires. */
			skipped++;
			/* a LEAF block left stale here is the durable
			 * leaf-hash hole producer.  Arm the modify-path rebuild
			 * (mxfs_dir_rebuild_leaf_from_data) so the next dir RMW
			 * reconstructs the leaf hash index from the coherent DATA
			 * blocks rather than RMW'ing + destaging this stale leaf. */
			if (dbp->b_ops == &xfs_dir3_leaf1_buf_ops ||
			    dbp->b_ops == &xfs_dir3_leafn_buf_ops)
				xfs_iflags_set(ip, MXFS_IF_DIR_LEAF_STALE);
			/* a kept-stale DONE DATA/BLOCK block (NOT evict-invalidated)
			 * is the single-dirent-loss producer; its next RMW + async destage
			 * reverts the peer adds the stale base lacks.  Arm the modify-path
			 * per-block reconcile.  Broad (any DONE data/block reaching the skip)
			 * — the reconcile is idempotent (lookup-guarded), so a non-stale
			 * block costs only one cheap FUA read it then skips. */
			if ((dbp->b_flags & XBF_DONE) &&
			    (dbp->b_ops == &xfs_dir3_data_buf_ops ||
			     dbp->b_ops == &xfs_dir3_block_buf_ops))
				xfs_iflags_set(ip, MXFS_IF_DIR_DATA_STALE);
			{
				static atomic_t pdes = ATOMIC_INIT(0);
				bool is_leaf = (dbp->b_ops == &xfs_dir3_leaf1_buf_ops ||
						dbp->b_ops == &xfs_dir3_leafn_buf_ops);
				if (atomic_inc_return(&pdes) <= 600)
					mxfs_probe("mxfs: P-DE-BLK ino=%llu daddr=%llu disp=SKIP leaf=%d dirty=%d in_ail=%d pin=%d delwri=%d done=%d undestaged=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)daddrs[i], is_leaf, dirty, in_ail,
						pinned, delwri, !!(dbp->b_flags & XBF_DONE),
						in_ail ? mxfs_dir_buf_is_undestaged(dbp) : -1);
			}
		}
		xfs_buf_relse(dbp);
	}

	/* Overflow tail (rare large dirs): non-draining evict of clean blocks. */
	if (overflow) {
		down_read(&ip->i_lock);
		mxfs_dir_evict_data_blocks(ip);
		up_read(&ip->i_lock);
		skipped++;	/* conservative: not all blocks drained */
	}
	return skipped;
}
atomic64_t mxfs_rd_ino_real;	/* cold reads of real inode-cluster buffers */
atomic64_t mxfs_rd_ino_ra;	/* cold inode-cluster READAHEAD reads */
atomic64_t mxfs_rd_dir;		/* cold dir-block reads */
atomic64_t mxfs_rd_agmeta;	/* cold ag-meta (agf/agi/bnobt/...) reads */
atomic64_t mxfs_rd_other;	/* cold reads of any other buffer class */
atomic64_t mxfs_stale_ino;	/* xfs_buf_stale calls on inode-cluster buffers */

/*
 * (design review design-consult fairness design #3 — Minimum Hold Time):
 * the parent-dir inode-EX handoff storm.  When N nodes each unlink M files in
 * a SHARED directory, every unlink needs EX on the parent-dir inode; with no
 * minimum hold time a peer BAST releases our cached EX after a single op, so
 * the lock ping-pongs ~N*M times.  The CAW slot has no FIFO order among
 * waiters (a `waiters` bitmap + `yield_to` hint only), so the just-released
 * hot node re-wins the CAS while a node deep in backoff starves — one node
 * waited 123s > the 120s CAW timeout → ETIMEDOUT force-shutdown (the
 * unlink_visibility ship-gate failure).
 *
 * MHT batching: on a fresh inode-EX grant, stamp i_dlm_ex_acquire_ns.  If a
 * peer BAST arrives while we have held EX for < mxfs_inode_mht_ms, DEFER the
 * release (keep state CACHED so our own queued ops keep fast-pathing) and
 * schedule i_dlm_bast_dwork for the remainder of the window.  The holder
 * chews through all its queued unlinks in one tenure → ~N*M handoffs collapse
 * to ~N → no node can be starved past a few short tenures.  GFS2/OCFS2
 * glock "minimum hold time" pattern.  No on-disk/CAW-protocol change.
 * Default 300ms; 0 disables (immediate release, old behavior).
 *
 * raised the code default 50 -> 300.  Under the
 * dir_reuse_coherency 2/tcp churn (24 rounds of 200-file concurrent same-dir
 * create + rm-rf, reusing the dir inode/daddrs each round) the 50ms default
 * thrashed the parent-dir inode-EX handoff and the test exceeded its 300s
 * budget; 300ms batches each node's create wave into one tenure so the suite
 * fits the budget ("TIMING SOLVED via inode_mht_ms=300").  Prior
 * sessions ran the criterion with MXFS_EXTRA_MODARGS='inode_mht_ms=300' but
 * the canonical `./run.sh 2 tcp` uses module defaults — baking 300 in makes
 * the production config the tested one.
 */
int mxfs_inode_mht_ms = 300;
module_param_named(inode_mht_ms, mxfs_inode_mht_ms, int, 0644);

/*
 * 0.75.58 FILE EX TENURE FLOOR.  A regular file's EX tenure under a peer
 * BAST is kept for a short bounded window, exactly as a directory's is,
 * instead of being handed off at the very next operation boundary.
 *
 * MEASURED on the 2-node TCP rig (tests/peer_truncate_under_append_2node.sh
 * s537a-f, tests/append_contention_2node.sh s537g): with the file excluded
 * from the tenure floor, every syscall of the truncating peer — open,
 * ftruncate, close, stat — was its own cross-node hand-off, because the
 * appender's next operation took the grant back in the sub-millisecond
 * gap between them (~4-5 hand-offs per truncate, 51-107 ms), and the
 * alternating two-node line append handed the file off once every 1.2
 * appends (3096 BASTs for 4000 appends, 19.8 ms per append at ~13 ms per
 * hand-off).  The minimum-hold defer already applied to files
 * (mxfs_dlm_mht_defer_bast), but mxfs_dlm_dir_tenure_keep_delay returned 0
 * for anything that is not a directory, so the first op completion after
 * the BAST released the grant, and the acquiring-BAST batch arm was
 * directory-only too.
 *
 * The window is the file's own, shorter than the directory MHT: a peer
 * waits at most this long plus one release drain, and the holder batches
 * whatever it does in that time.  The quiet-age gate and the one-op
 * adaptive floor apply unchanged, so an idle holder still lets go at the
 * first >=grace idle sample.  0 disables (pre-0.75.58 behavior).
 */
int mxfs_file_ex_tenure_ms = 15;	/* 0.75.59: 30->15, A/B s538 (30) vs s539 (15): append batching unchanged at 0.1 ms/append, truncates 70-98 ms with a 248 ms tail -> 39-73 ms */
module_param_named(file_ex_tenure_ms, mxfs_file_ex_tenure_ms, int, 0644);
MODULE_PARM_DESC(file_ex_tenure_ms,
	"bounded EX tenure window for a regular file under a peer BAST, ms (op batching); 0=hand off at the next op boundary");

/*
 * The EX tenure window that applies to this inode: shortform dirs keep the
 * short window, other dirs the MHT, regular files their own.
 * Returns 0 when no floor applies.
 */
int
mxfs_ex_tenure_window_ms(
	const struct xfs_inode	*ip)
{
	extern int mxfs_dir_sf_mht_ms;
	umode_t m = VFS_I((struct xfs_inode *)ip)->i_mode;

	if (S_ISDIR(m)) {
		if (mxfs_dir_sf_mht_ms >= 0 &&
		    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL)
			return mxfs_dir_sf_mht_ms;
		return mxfs_inode_mht_ms;
	}
	if (S_ISREG(m))
		return mxfs_file_ex_tenure_ms;
	return 0;
}
/* per-format minimum-hold for SHORTFORM (LOCAL) dirs.  A
 * shortform dir's content is inline in the dinode → cross-node handoff is
 * coherent via the whole-inode reload (no separate leaf/data/extent blocks to
 * leave stale), so it does NOT need the long mht that masks the LEAF/BTREE-dir
 * coherency bug.  Low value lets a small high-churn shared dir (tcp_dlm_scaling)
 * hand off fast (fit 60s window) while large leaf/btree dirs (dir_reuse) keep
 * the full inode_mht_ms.  <0 disables (shortform dirs use the global mht). */
int mxfs_dir_sf_mht_ms = 40;	/* 100 = cache_coherency PASS 8/8 + tcp_dlm_scaling 8/8 worst ~39s (<60s window).  40 broke cache_coherency THEN (cross-node-read shortform dir needed more settle); 150 made tcp_dlm_scaling ~64s.  RE-TUNE after the bpend-consume fix: sf=100 forced 50-150ms IDLE coasts -> tds 71-75s FAIL; sf=2 + eager idle-release: tds 19.6s PASS at 4 NODES but 72s FAIL at 8 (per-syscall handoff bill scales with N, the 60s window does not).  SF-DIR TENURE FLOOR: the eager gates KEEP a tenure younger than this value across idle gaps (bast_pending stays set, MHT dwork serves the peer at expiry), so one tenure covers whole local create/mv/rm rounds instead of one syscall.  15ms passed STANDALONE (41.7s) but in-suite (17 tests, one shared module/FS instance) per-op time inflates ~2x (aged log tail-pushing etc.), rounds outgrow a 15ms tenure, batching collapses (~2-3 handoffs/round) -> 80-86s FAIL.  40ms re-covers the inflated round: iter r8 = 17/17 FULL PASS at 8/tcp, tds 17.3-30.9s (2x margin), cache_coherency 8/8 (the sf=40 sensitivity is gone on current reload machinery — whole-inode reload at SF handoff).  Worst-case peer wait = 40ms + one release drain (~13ms).  Block-format dirs keep inode_mht_ms=300 batching (dir_reuse create storms) and are NOT floored. */
module_param_named(dir_sf_mht_ms, mxfs_dir_sf_mht_ms, int, 0644);

/* tiebreak msleep-in-acquire was REVERTED — it cascaded dir_reuse/
 * fence/fault/soak to 12/17.  Self-demote skip is the kept tcp_dlm_scaling fix. */

/*
 * acquire-side LOCKED-block bounded WAIT (the dir_pr_release_fast>=2
 * "broad skip" coherency companion).
 *
 * dir_pr_release_fast=2 makes EVERY clean dir release cheap (skips the
 * release-side log_force/iflush drain), which PROVED fixes the
 * tcp_dlm_scaling upgrade livelock 4/4 — but it removed an INCIDENTAL masking
 * barrier: the release-side log_force used to drive xfsaild/delwri writeback to
 * completion, so few dir DATA blocks were still in-flight (buffer LOCKED) at the
 * next acquire.  Without it, mxfs_dir_drain_evict_data_blocks hits a momentarily
 * LOCKED stale block, XBF_TRYLOCK returns -EAGAIN, and the OLD code SKIPPED it
 * (P-DE-BLK LOCKED-SKIP) — leaving a stale base that the imminent create/unlink
 * RMWs, durably dropping a peer's dirents (the stale-block-RMW family:
 * dir_reuse leaf-hash hole / missing-first-contiguous loss).
 *
 * FIX: instead of skipping a LOCKED block, WAIT (bounded) for its in-flight I/O
 * to complete, then evict it coherently.  The LOCK is held by a LOCAL in-flight
 * bio / xfsaild flush (buffer locks are per-node), so the wait is bounded by
 * local I/O latency (a few ms) — NOT by any cross-node grant, so it cannot
 * starve a peer (this runs on the slow-path acquire / CAW poll process ctx where
 * blocking is safe —).  After the bound it falls back to the old
 * LOCKED-SKIP (safe: a later uncontended acquire retries, loaded_gen kept back).
 *
 * Value = number of 2ms poll iterations.  Default 60 (~120ms, matches the
 * pin-tail drain loop's bound).  0 = disabled (old LOCKED-SKIP behavior, for A/B).
 */
int mxfs_dir_acq_lockwait = 60;
module_param_named(dir_acq_lockwait, mxfs_dir_acq_lockwait, int, 0644);
MODULE_PARM_DESC(dir_acq_lockwait,
	"acquire-evict: 2ms iters to wait for a LOCKED in-flight dir block before skipping it; 0=skip immediately");

MODULE_PARM_DESC(inode_mht_ms,
	"inode-EX minimum hold time (ms) to batch same-node ops vs peer BAST; 0=off");

/*
 * sess-tcp (PROVEN BY INSTRUMENT root): bound the synchronous inode-inactivation
 * (xfs_ifree) drain.  A freed inode's cluster buffer can sit orphaned in the
 * AIL for ~60s while xfsaild is starved by a concurrent same-dir create storm.
 * The inactivation holds the AG as an active DLM holder across this drain, so a
 * peer's AG BAST is deferred for the whole wedge -> the peer's xfs_dialloc
 * times out (-ETIMEDOUT, 60s) -> concurrent create stall (posix_multi /
 * cache_coherency 2-node TCP). Cross-node dinode (mode=0) durability on an
 * actual peer AG handoff is enforced by the Phase-2 BAST drain pipeline
 * (invariant #1), so bounding the synchronous wait is safe. Default 200ms
 * (healthy inactivation lands in ~1-3ms); 0 = unbounded (old behavior).
 */
int mxfs_ifree_drain_ms = 200;
module_param_named(ifree_drain_ms, mxfs_ifree_drain_ms, int, 0644);
/*  eager per-ifree durability (force+drain+flush in the
 * sync-inactivation path) OFF by default — redundant since the Phase-2 drain
 * pipeline covers inode cluster buffers at every AG handoff; costed
 * 17-33ms/unlink on flush-honoring targets.  See xfs_inactive_ifree. */
int mxfs_ifree_eager_durable = 0;
module_param_named(ifree_eager_durable, mxfs_ifree_eager_durable, int, 0644);
MODULE_PARM_DESC(ifree_drain_ms,
	"max ms to synchronously drain a freed inode before deferring to the BAST drain pipeline; 0=unbounded");
/*  FIX-1 (instrumented, PROVEN via run_dir_reuse_coherency_
 * 20260725T140939Z ino 165): with the eager per-ifree chain off, the
 * immediate on-disk unlock at inactivation published the freed ino's slot
 * while the freed dinode (mode=0) was still CIL/AIL-only — the platter kept
 * the PRIOR (alive) incarnation, so a peer's acquire+reload in that window
 * certified a CORPSE as alive (test2 held PR on rmdir'ed dir 165 for 297s;
 * the whole fleet then ran round 1 inside the dead universe).  When 1
 * (default), the inactivation unlock is DEFERRED while the freed dinode is
 * undestaged: the grant stays CACHED and the release happens via a peer
 * BAST (bast_process durable loop, extended to freed inodes) or via
 * reclaim/evict (reclaim implies the dinode was flushed).  Invariant #1
 * applied to the inode's own cluster. */
int mxfs_inact_defer_unlock = 1;
module_param_named(inact_defer_unlock, mxfs_inact_defer_unlock, int, 0644);

/*
 * measurement lever (default 0): when 1, skip the FUA read for an
 * inode-cluster buffer whose containing AG this node owns EX (holders>0 ||
 * cached).  UNSAFE as a general fix — a peer can modify an already-visible
 * inode in our AG without owning the AG (e.g. cross-node rename touches the
 * file's inode), so a stale cached read can result.  For SOLO measurement of
 * the FUA-read perf ceiling (peers idle) ONLY.  The safe production form is
 * scoped to brand-new (XFS_INEW) inodes per the design review design-consult design.
 */
int mxfs_fua_skip_owned_inode;
module_param_named(fua_skip_owned_inode, mxfs_fua_skip_owned_inode, int, 0644);
MODULE_PARM_DESC(fua_skip_owned_inode,
	"diag: skip inode-cluster FUA read when this node owns the AG (UNSAFE)");

/*
 * PERF FIX: the per-inode cluster-stale in
 * xfs_iget_cache_miss/recycle stales the WHOLE 32-inode cluster buffer on every
 * individual inode cache-miss, so a readdir+stat or rm-rf of N inodes co-resident
 * in one cluster re-stales+re-FUA-reads that SAME cluster N times (PROVEN: only
 * 59 distinct inode-cluster daddrs but each FUA-re-read ~12×/round, rank1 rm =
 * ~900 inode FUA reads for 800 removes — 8/tcp dir_reuse straddles the 300s
 * budget on this thrash alone).  The stale exists to make a peer's
 * freshly-ALLOCATED inode visible (xfs_iget_check_free_state mode=0→ENOENT).
 * That allocation state is gated by the AG DLM lock (alloc/free can't happen
 * without it).  So when THIS node OWNS the AG (mxfs_buf_ag_owned_ex) AND the
 * cluster buffer is still _XBF_FUA_FRESH (we read it fresh and no BAST/stale
 * event cleared it since), no peer can have alloc'd/freed an inode in it → the
 * cached fresh buffer's allocation state is authoritative → the re-stale is pure
 * redundant work.  Skip it.  Content coherency is unaffected (handled separately
 * by the inode-DLM reload at ilock time).  Narrower & safer than the removed
 * broad "skip FUA when AG owned" (which skipped the FIRST read too,
 * serving genuinely stale data) — here we only avoid RE-reading a buffer we
 * already hold FUA-fresh under an exclusive AG tenure.
 */
int mxfs_inode_cluster_owned_skip = 1;
module_param_named(inode_cluster_owned_skip, mxfs_inode_cluster_owned_skip, int, 0644);
MODULE_PARM_DESC(inode_cluster_owned_skip,
	"skip redundant inode-cluster re-stale when AG-owned and buffer already FUA-fresh (perf, default on)");

/* gate the unpublished-dir FUA-skip fast path (xfs_da_read_buf).  When
 * a directory is UNPUBLISHED it has never had an on-disk DLM slot, so no peer
 * has ever reached it — its cached dir blocks are authoritative and the
 * cross-node dir-gen/FUA coherency machinery is pure waste (the dominant
 * residual rsync_paired cost).  Default 1 (on); set 0 to isolate. */
int mxfs_dir_unpub_skip = 1;
module_param_named(dir_unpub_skip, mxfs_dir_unpub_skip, int, 0644);
MODULE_PARM_DESC(dir_unpub_skip,
	"skip dir-block FUA coherency for unpublished (never-shared) dirs");

/*  (dlm_scaling 16/caw ROOT FIX): broaden the unpublished-dir
 * FUA-skip to a PUBLISHED dir that this node holds EX and that NO peer has ever
 * BAST'd (i_dlm_dir_contended==false).  MXFS caches the inode DLM lock: a dir EX
 * is released to NL ONLY on a peer BAST (which sets i_dlm_dir_contended sticky)
 * or on eviction (which resets the flag AND re-reads fresh at the next acquire).
 * There is no idle/per-op release.  So i_dlm_mode==EX && !i_dlm_dir_contended
 * PROVES the lock has been held continuously since a fresh acquire with zero
 * peer contention → no peer can have modified the dir blocks → the cached image
 * is authoritative and every cross-node FUA read of it is pure waste.  This is
 * STRICTLY stronger than the bare "i_dlm_mode==EX" that xfs_da_read_buf's comment
 * (correctly) rejected: that reject case was "released on a peer BAST then
 * re-acquired after a peer modify" — which sets i_dlm_dir_contended=true and is
 * therefore EXCLUDED here.  Additionally require i_dlm_dir_valid_epoch==0 (the
 * grant-carried cross-node handoff epoch, maintained on CAW): !contended catches
 * an IN-FLIGHT peer BAST, but valid_epoch==0 additionally proves NO peer handoff
 * has ever COMPLETED for this dir incarnation (closing the window where a peer
 * modified the dir while we were briefly at NL — e.g. the cache_coherency
 * concurrent-mkdir/create storm — without ever BAST'ing us).  PROVEN BY INSTRUMENT:
 * dlm_scaling's private per-node subdir did ~5000 SCSI-FUA reads/node of its OWN
 * single block (daddr=72), dropping the op-rate under the 50/s floor at 16 nodes.
 * Default 1 (on); 0 to isolate. */
int mxfs_dir_priv_ex_skip = 1;
module_param_named(dir_priv_ex_skip, mxfs_dir_priv_ex_skip, int, 0644);
MODULE_PARM_DESC(dir_priv_ex_skip,
	"skip dir-block FUA coherency for a published dir held EX with zero peer BASTs (provably private)");

/* iread-PR — see XFS_ILOCK_MXFS_PRIREAD
 * (xfs_inode.h) and xfs_ilock_data_map_shared.  The extent-map-load
 * ILOCK_EXCL escalation takes the cluster lock at PR instead of EX:
 * loading the iext tree only READS committed disk state (local EXCL
 * still serializes the in-core build).  Kills the post-adopt lookup
 * cluster-EX that starved 3x120s -> rc=-110 -> FS shutdown on 12/32
 * nodes in cache_coherency@32's read-only verify.  0 = pre-sess1
 * EX mapping (A/B). */
/*  — P194 measurement probe (see xfs_dir_lookup):
 * count directory operations that run on a base whose epoch does not match the
 * epoch stamped on the grant we hold.  Measurement only, no behaviour change.
 * This is the evidence for the design-consult design review prescription that the freshness gate
 * belongs at EX acquire, not at the conversion gate. */
/*  — `mxfs.create_baseline_trackers` REMOVED in.
 * It was proven dead code (P209 read 0 on every node of a full 32-node run) and
 * its block was additionally a latent sleep-in-atomic; see the deleted-block
 * comment in mxfs_dlm_grant_local_new.  A knob that cannot change behaviour is
 * worse than no knob — A/B "compared" two identical arms because of
 * it.  Its replacement is mxfs.creator_baseline_stamp, below. */

/*
 *  — CREATOR BASELINE STAMP AT PUBLISH.
 *
 * The knob above is PROVEN DEAD CODE (probe P209 read 0 on every
 * node of a full 32-node run): its block sits in mxfs_dlm_grant_local_new gated
 * on S_ISDIR(VFS_I(ip)->i_mode), but the only caller is xfs_iget_cache_miss
 * under XFS_IGET_CREATE, where the inode was allocated microseconds ago and
 * i_mode is still 0 (xfs_init_new_inode sets it later).  Even if it were
 * reached it would read 0 from the DLM, because at that instant the inode has
 * no slot at all (deferred publish) — and it would read it while holding
 * spin_lock(&ip->i_dlm_lock) over a query that takes a SLEEPING mutex
 * (caw_grant_meta_seq, dlm/dlm_caw.c:1120).  That block is removed with this
 * change; this knob replaces it at the point where the values actually exist.
 *
 * WHY THE SENTINEL IS A CORRECTNESS BUG, not just a missing optimisation
 * (mechanism completed by reading the CAW epoch rules):
 *
 *   caw_grant_epoch_update() (dlm/dlm_caw.c:872) advances a resource's
 *   dir_epoch on ANY EX/PW claim whose slot records a DIFFERENT node as the
 *   previous EX holder, and caw_tombstone_slot()/caw_claim_inherit_epoch()
 *   deliberately carry dir_epoch across an idle gap.  So a directory we create
 *   on a REUSED inode number inherits the DEAD incarnation's epoch lineage, and
 *   our own publish claim then BUMPS it (previous EX slot was some other node).
 *   That is exactly the captured signature — a freshly created, still EMPTY,
 *   self-created dir with grant_epoch=2 while our baseline reads 0:
 *
 *     P195-STALE-BASE-ALREADY-DIRTY ino=2097324 grant_epoch=2 valid_epoch=0
 *       grant_gen=14607 cached_gen=0 gen_moved=1 dirty_seq=1228
 *       ex_grant_seq=1228 self_created=1 baseline_unset=1 fmt=1 comm=mkdir
 *
 *   Every consumer of the baseline reads `master_epoch > i_dlm_dir_valid_epoch`
 *   as "a peer has published past my base".  With the baseline stuck at the
 *   never-set 0, that is PERMANENTLY TRUE for a directory this node created —
 *   and the P32E-DIREPOCH-FENCE (xfs_inode.c) then SKIPS EVERY FLUSH of that
 *   directory, including the release drain's.  mkdir(2) returns 0, the dirent
 *   is committed in-core, and no node ever writes it: D-SILENT-MKDIR-LOSS.
 *
 * WHY STAMPING AT PUBLISH IS SAFE (and stamping later is NOT).  The design review
 * Design-consult consult warns that copying the DLM's CURRENT epoch at an
 * arbitrary later moment LAUNDERS a peer update that happened while the inode
 * was visible.  The publish sites below are the instant this node takes the
 * FIRST REAL EX grant for an inode that was i_dlm_unpublished until then, and
 * the stamp additionally requires i_mxfs_self_created — which this tree's own
 * invariant (xfs_inode.h) defines as "created by this node and NO peer BAST has
 * ever arrived", i.e. no peer has so much as requested this inode's lock.  A
 * peer cannot have published without taking the lock, so there is nothing to
 * launder: the epoch we inherit describes a lineage that ended with the dead
 * prior incarnation, and our in-core image is the authoritative successor.
 *
 * Bitmask so the two baselines can be separated in a same-build A/B:
 *   bit 0 (1) — stamp i_dlm_dir_valid_epoch   (the P32E/P194/P195 baseline)
 *   bit 1 (2) — stamp i_dlm_cached_grant_gen  (the grant_stale_base evict gates)
 * 0 = pre-fix sentinels (negative control).
 *
 * SHIPS AT 0, AND HERE IS WHY — do not re-walk this.  MEASURED 2/caw, 50+
 * publishes per run across all three sites: the epoch read at publish time is
 * ZERO EVERY TIME (site=2 x19, site=3 x4, site=4 x2, all bep=0), because a
 * freshly created inode's slot has no handoff history yet.  Stamping 0 over 0
 * changes nothing, so this knob ALONE cannot fix anything — the sentinel is not
 * where the damage is.  The real defect is that the epoch the CONSUMERS later
 * read belongs to a PREVIOUS INCARNATION of the same inode number; that is
 * mxfs.dir_epoch_incarn_gate below, which is the fix that measured.
 *
 * What is retained unconditionally is P210-CREATOR-BASELINE, which counts
 * self-created directories reaching their first real EX grant REGARDLESS of any
 * knob.  That is the knob-independent exposure counter for the incarnation
 * gate's A/B: without it, an arm that passed because it never entered the state
 * would be indistinguishable from an arm that passed because the fix worked.
 */
/*
 *  — THE DIR EPOCH IS A PROPERTY OF THE INODE NUMBER,
 * NOT OF AN INCARNATION.  TRACE-PROVEN ROOT of D-SILENT-MKDIR-LOSS.
 *
 * Captured 2/caw, test2, one inode's full scoped window (ino 2099630):
 *
 *   119  P9-NLEDGE reset4create ino=2099630           <- incarnation A created
 *   126  P210-CREATOR-BASELINE site=2 bep=0           <- A published, epoch 0
 *   ...  P70-BP EXIT=full / P-DIRBAST ...             <- A handed off (epoch ->2)
 *   1363 EVICT-RING-FLAG incore_gen=2916713347 freed_gen=2916713348   <- A FREED
 *   1383 P9-NLEDGE reset4create ino=2099630           <- incarnation B created
 *   1410 P195-STALE-BASE-ALREADY-DIRTY grant_epoch=2 valid_epoch=0
 *          self_created=1 baseline_unset=1 comm=mkdir
 *
 * Incarnation B is BRAND NEW, created by this node, and at line 1410 it is
 * still i_dlm_unpublished — it has no DLM grant of its own at all.  The
 * grant_epoch=2 it reads comes out of the CAW grant_meta cache, which is keyed
 * by RESOURCE (the inode number) and still holds the value stored at
 * incarnation A's last grant; caw_tombstone_slot() and caw_claim_inherit_epoch()
 * (dlm/dlm_caw.c) carry dir_epoch across an idle gap ON PURPOSE, and
 * mxfs_dlm_caw_clear_inode_epoch's free-time reset is best-effort.
 *
 * So `master_epoch > i_dlm_dir_valid_epoch` is a CROSS-INCARNATION comparison —
 * the same invalid-comparison class proved for di_gen in
 * RELOAD-TYPEFLIP-STALE-SKIP.  And it is not merely noisy: it is permanently
 * TRUE for the new incarnation, so P32E-DIREPOCH-FENCE (mxfs.dir_epoch_flush_fence,
 * default 1) skips EVERY flush of that directory.  mkdir(2) returns 0, the
 * dirent is committed in-core, and no node ever writes it.
 *
 * Note the asymmetry this exposes: the CONSUMER of the baseline (P32E) ships
 * enabled, while the only maintainer that would advance it on a handoff
 * (mxfs.dir_epoch_adopt) ships DISABLED because proved enabling it
 * causes an AG double-free and FS shutdown.  A fence with no maintainer is a
 * fence that eventually refuses everything.  This gate fixes the comparison
 * rather than re-enabling the adopt, so none of regression is in play.
 *
 * mxfs_dir_epoch_superseded() is the single predicate both consumers use.
 * 0 = pre-fix (raw `>` compare), retained as the negative control.
 *
 * PAIRED A/B, ONE BUILD (0.11.242 C6D909C4133BA6731C55251), knob flipped at
 * runtime, fresh mkfs per arm, 2/caw, aged-mount reproducer
 * (prep -> crash_consistency dir_reuse_coherency fence_during_write
 *  fault_netpartition soak -> dirent_durability -> dirent_publish_integrity):
 *
 *   arm            dirent_publish_integrity   P195  P194  exposure  rebases
 *   gate=0 run1    FAIL 1/2  sbm=3               3     3        50        0
 *   gate=0 run2    FAIL 1/2  sbm=1               1     1        54        0
 *   gate=1 run1    PASS 2/2  sbm=0               0     0        53       19
 *   gate=1 run2    PASS 2/2  sbm=0               0     0        55       16
 *
 * "exposure" is P210-CREATOR-BASELINE, which counts self-created directories
 * reaching their first real EX grant and is deliberately NOT gated on this fix —
 * so the passing arm is provably entering the same state, not skipping it.
 * Every one of the 35 rebases was P211-EPOCH-REBASE with old_incarn != incarn,
 * e.g. "ino=2099632 cur_ep=2 old_ep=0 old_incarn=1838689591 incarn=403668081
 * comm=mkdir" — the baseline literally belonged to a dead incarnation.
 *
 * RESIDUAL, stated rather than hidden: i_generation is get_random_u32(), so
 * "same incarnation" is a 32-bit equality and carries a 2^-32 false-match, and
 * the never-established sentinel 0 would be indistinguishable from a live
 * generation that happened to be 0.  Same probabilistic caveat recorded
 * for the typeflip same-incarnation guard; it is not an ordering claim.
 */
int mxfs_dir_epoch_incarn_gate = 1;
module_param_named(dir_epoch_incarn_gate, mxfs_dir_epoch_incarn_gate, int, 0644);
MODULE_PARM_DESC(dir_epoch_incarn_gate,
	"qualify the dir-epoch staleness compare by the incarnation the baseline was established under; 0=pre-fix raw compare");

/*
 * Is the master's dir_epoch evidence that a PEER superseded this directory's
 * in-core base?  Answers for the CURRENT incarnation only.
 *
 * May re-base the baseline (that is the point), so callers must hold whatever
 * serialisation they already hold for i_dlm_dir_valid_epoch — the same tenure
 * protection its other write sites rely on; it is not covered by i_dlm_lock
 * anywhere in this file.
 */
bool
mxfs_dir_epoch_superseded(
	struct xfs_inode	*ip,
	uint32_t		cur_ep)
{
	extern int mxfs_dir_adopt_at_acquire;	/* defined just below */
	uint32_t		incarn;

	if (!mxfs_dir_epoch_incarn_gate)
		return cur_ep > ip->i_dlm_dir_valid_epoch;

	incarn = VFS_I(ip)->i_generation;

	/*
	 * (1) NO GRANT FOR THIS INCARNATION.  An unpublished inode has never
	 * been in the DLM under this incarnation, so anything grant_meta serves
	 * for its number was recorded by a previous one.  Nothing about our base
	 * can be inferred from it, and no peer can have published into an inode
	 * it cannot name.
	 */
	if (ip->i_dlm_unpublished) {
		static atomic_t p211u = ATOMIC_INIT(0);

		if (cur_ep > ip->i_dlm_dir_valid_epoch &&
		    atomic_inc_return(&p211u) <= 400)
			mxfs_probe("mxfs: P211-EPOCH-NOGRANT ino=%llu cur_ep=%u valid_epoch=%u incarn=%u comm=%s — unpublished incarnation; master epoch belongs to a previous one, not a supersession\n",
				(unsigned long long)ip->i_ino, cur_ep,
				ip->i_dlm_dir_valid_epoch, incarn,
				current->comm);
		return false;
	}

	/*
	 * (2) BASELINE FROM ANOTHER INCARNATION.  Re-base only when this node
	 * created the live incarnation and no peer has so much as requested its
	 * lock (i_mxfs_self_created, cleared by mxfs_dlm_bast_notify) — then no
	 * peer update exists to launder, which is the design review constraint.
	 * Otherwise leave the comparison exactly as it was: an inode we igot
	 * from disk is not ours to re-base.
	 */
	if (ip->i_dlm_dir_valid_incarn != incarn) {
		if (ip->i_mxfs_self_created) {
			static atomic_t p211r = ATOMIC_INIT(0);
			uint32_t old_ep = ip->i_dlm_dir_valid_epoch;
			uint32_t old_in = ip->i_dlm_dir_valid_incarn;

			ip->i_dlm_dir_valid_epoch = cur_ep;
			ip->i_dlm_dir_valid_incarn = incarn;
			/* Option B: an authority rebase carries the same
			 * self_created justification as the creator publish
			 * stamp — no peer update exists to launder, so the
			 * rebased pair is a VALID baseline (gen kept as-is). */
			if (mxfs_dir_adopt_at_acquire)
				smp_store_release(&ip->i_dlm_base_valid, 1);
			if (atomic_inc_return(&p211r) <= 400)
				pr_warn("mxfs: P211-EPOCH-REBASE ino=%llu cur_ep=%u old_ep=%u old_incarn=%u incarn=%u comm=%s — baseline belonged to a dead incarnation; re-based onto the live one\n",
					(unsigned long long)ip->i_ino, cur_ep,
					old_ep, old_in, incarn, current->comm);
			return false;
		}
		{
			static atomic_t p211f = ATOMIC_INIT(0);

			if (cur_ep > ip->i_dlm_dir_valid_epoch &&
			    atomic_inc_return(&p211f) <= 400)
				mxfs_probe("mxfs: P211-EPOCH-FOREIGN ino=%llu cur_ep=%u valid_epoch=%u valid_incarn=%u incarn=%u — cross-incarnation compare on an inode we did NOT create; left as-is\n",
					(unsigned long long)ip->i_ino, cur_ep,
					ip->i_dlm_dir_valid_epoch,
					ip->i_dlm_dir_valid_incarn, incarn);
		}
	}

	return cur_ep > ip->i_dlm_dir_valid_epoch;
}

/*
 * Stamp the dir-base coherence baseline as one released unit.  Call ONLY when
 * the base the fields describe is fully installed and final for this decision
 * point (reload install/keep, creator publish, authority rebase).  gg==0 means
 * "no grant-gen evidence at this site — keep the current value" (0 is also the
 * DLM's no-token answer, which must not overwrite a real cached token).
 */
void
mxfs_dir_base_stamp(
	struct xfs_inode	*ip,
	uint32_t		ep,
	uint32_t		gg,
	unsigned int		site)
{
	extern int mxfs_dirwr_enabled, mxfs_instr_enabled;

	WRITE_ONCE(ip->i_dlm_dir_valid_epoch, ep);
	ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;
	if (gg)
		WRITE_ONCE(ip->i_dlm_cached_grant_gen, gg);
	/* Publish the pair only after both stores are visible. */
	smp_store_release(&ip->i_dlm_base_valid, 1);
	atomic64_inc(&mxfs_b_stamp_n);
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P216-B-STAMP ino=%llu ep=%u gg=%u site=%u\n",
			(unsigned long long)ip->i_ino, ep, gg, site);
}

/* Clear the validity bit: the baseline can no longer vouch for the in-core
 * base (EX leaving this node / adopt in progress / phantom bail).  Pure store;
 * safe in any context. */
void
mxfs_dir_base_invalidate(
	struct xfs_inode	*ip,
	unsigned int		site)
{
	extern int mxfs_dirwr_enabled, mxfs_instr_enabled;

	WRITE_ONCE(ip->i_dlm_base_valid, 0);
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P216-B-INVAL ino=%llu site=%u\n",
			(unsigned long long)ip->i_ino, site);
}

/*
 *  — see the block comment at the retry loop in
 * xfs/xfs_dir2_readdir.c.  1 = the pre-sess28 unconditional 200x msleep(1)
 * retry, kept ONLY as the negative control for the A/B; it is a guaranteed
 * ~1.2 s per readdir on any directory flagged stale, because the reload it
 * retries can never take the write lock the caller is already holding for read.
 */
int mxfs_readdir_reload_retry_selfread;
module_param_named(readdir_reload_retry_selfread,
		   mxfs_readdir_reload_retry_selfread, int, 0644);
MODULE_PARM_DESC(readdir_reload_retry_selfread,
	"retry the readdir extent-map reload even when the caller holds ILOCK_SHARED and it can never land (1=pre-sess28 ~1.2s/readdir, 0=skip)");

/*
 * 0.84.4, TEST ONLY.  A leaf listing re-acquires the directory's cluster
 * lock once per data block; between blocks the cached grant makes that a
 * fast path unless a peer revoked it in the gap.  This sleep, taken with no
 * ILOCK held after each block of a watched directory (mxfs.watch_ino), makes
 * the gap wide enough for a peer's modify to land, so the per-block acquire
 * is a real request that a fault can meet — the shape the readdir arm of
 * tests/tcp_lockreq_blackhole.sh measures.  0 in production: never a sleep
 * on a listing.
 */
int mxfs_readdir_leaf_pause_ms;
module_param_named(readdir_leaf_pause_ms, mxfs_readdir_leaf_pause_ms, int, 0644);
MODULE_PARM_DESC(readdir_leaf_pause_ms,
	"test only: sleep between the data blocks of a leaf readdir of the watched directory (0=off)");

int mxfs_epoch_stale_op_probe = 1;
/*  — FRESHNESS GATE at the directory-operation boundary
 * (design-consult design review prescription).  When the base is not coherent with the epoch on
 * our grant AND this tenure has not already mutated it, adopt BEFORE running
 * the lookup, so a negative result cannot authorise a create against a
 * superseded base.  Default OFF until measured — P194 tells you how often it
 * would engage and P195 how often the unsafe (already-dirty) case arises. */
int mxfs_dir_lookup_freshness_gate;
module_param_named(dir_lookup_freshness_gate, mxfs_dir_lookup_freshness_gate, int, 0644);
MODULE_PARM_DESC(dir_lookup_freshness_gate,
	"adopt an epoch-stale dir base before the lookup that may authorise a create; 0=off (measure first)");

module_param_named(epoch_stale_op_probe, mxfs_epoch_stale_op_probe, int, 0644);
MODULE_PARM_DESC(epoch_stale_op_probe,
	"log P194 when a dir op begins on an epoch-stale base; 1=on (measurement only)");
module_param_named(ilock_map_recheck, mxfs_ilock_map_recheck_enabled, int, 0644);
MODULE_PARM_DESC(ilock_map_recheck,
	"re-test xfs_need_iread_extents after xfs_ilock and upgrade SHARED->EXCL if the DLM acquire hook reloaded the fork; 1=on");

int mxfs_iread_pr = 1;
module_param_named(iread_pr, mxfs_iread_pr, int, 0644);
MODULE_PARM_DESC(iread_pr,
	"extent-map iread ILOCK_EXCL takes cluster PR instead of EX (local-only exclusivity); 1=on");

/* sess1 (ccloop 46efd8b6) datascan gen-gate — see mxfs_dir2_datascan_lookup
 * (xfs_dir2_leaf.c) and i_mxfs_dscan_clean_key (xfs_inode.h).  The sess22
 * leaf-hash-hole heal ran the O(dir) authoritative data scan on EVERY
 * negative lookup of a multi-node dir: measured 459 read-IOs / ~112ms per
 * miss on the 640-entry cache_coherency rv/uv dirs (the scan's coherent
 * per-sector re-reads bypass the cache) — 640 misses/node = the dominant
 * verify cost after the ring/iread fixes.  With the gate, one no-hit scan
 * per (dir_gen, valid_epoch, loaded_gen) state proves the leaf ENOENT-
 * consistent; later misses at the same state trust the leaf.  Peer writes
 * move the epoch/gen (hole formation requires a peer write), and real fork
 * adopts reset the key sentinel, each re-arming exactly one scan.  0 =
 * pre-sess1 scan-every-miss (A/B). */
int mxfs_dscan_gen_gate = 1;
module_param_named(dscan_gen_gate, mxfs_dscan_gen_gate, int, 0644);
MODULE_PARM_DESC(dscan_gen_gate,
	"gate the per-miss dir datascan heal on coherency-state change; 1=on");

/* — the leaf-hash-hole heal as a whole (mxfs_dir2_datascan_lookup on
 * every multi-node ENOENT, mxfs_dir2_leafless_removename on a remove whose
 * name has no index entry).  Every hole the heal repaired on 2026-09-04 was
 * produced by the new-tenure retire of an undestaged log item, fixed in
 * 0.70.11; with the producer gone the heal is pure cost (an O(dir) cold data
 * walk per negative lookup — the largest single term of the 32-node shared-
 * directory create).  0 = index is authoritative, as in single-node XFS.
 * Default stays 1 until a full board and the crash chain pass with it off. */
int mxfs_dir_datascan_heal = 1;
module_param_named(dir_datascan_heal, mxfs_dir_datascan_heal, int, 0644);
MODULE_PARM_DESC(dir_datascan_heal,
	"heal a leaf-hash hole by scanning the directory's data blocks on ENOENT (and expunge data-side on remove); 0=trust the index");

/*  (dlm_scaling 32/caw ROOT FIX): extend the private-EX
 * FUA-skip to a SHARED dir this node holds at >= PR (protected-read) whose
 * cache no peer wants to modify (i_dlm_dir_want_ex==false).  PROVEN BY INSTRUMENT
 * (`docs/history/caw-32node-dlm-scaling-root-shared-ag0-reread.md`): at 32-node load every
 * node re-reads the ONE shared parent dir `.dlm_scaling` (AG0) ~100x/op — the
 * whole read storm that saturates the iSCSI target (~1319 cmd/s agg -> 41/s/node
 * < 50 floor).  dir_priv_ex_skip does NOT cover it: the shared parent is held at
 * PR (readers), not EX, and was BAST'd during setup (contended=true, valid_epoch>0),
 * so its EX-only gate never engages.  SAFETY: PR is incompatible with every WRITE
 * mode (CW/PW/EX) per the DLM matrix, so while i_dlm_mode>=PR no peer can be
 * modifying the dir (the i_dlm_epoch invariant: "while i_dlm_mode!=NL no peer can
 * have modified since the grant").  A peer that WANTS to modify must take EX,
 * which BASTs us (we hold >=PR) -> sets i_dlm_dir_want_ex=true -> skip disengages
 * -> we cold-reread.  The only staleness window (peer modified while we were
 * briefly at NL, no BAST) is closed on re-acquire by the valid_epoch grant-adopt
 * reload BEFORE this skip serves a read.  want_ex is cleared on each
 * fresh grant, so it reflects only EX BASTs since our current tenure.  Default 0
 * (off = ship behavior 9731510A) until validated at 32; flip after the coherency
 * family (cache_coherency/posix_multi/strong_consistency/zero_silent_loss/
 * dir_reuse) is re-confirmed GREEN at 4/16/32.  A/B: dir_shared_pr_skip=0 reverts. */
int mxfs_dir_shared_pr_skip;
module_param_named(dir_shared_pr_skip, mxfs_dir_shared_pr_skip, int, 0644);
MODULE_PARM_DESC(dir_shared_pr_skip,
	"skip dir-block FUA coherency for a shared dir held >=PR with no peer-wants-EX (kills the 32-node dlm_scaling shared-parent reread storm)");

/*  gate the P-DBLALLOC double-alloc detector (xfs_alloc.c).
 * That detector does ONE synchronous plain LUN read per DATA-fork allocation
 * (un-gated it so dir_reuse could run without instr).  Under dir_reuse
 * (~1600 allocs/round) and dlm_scaling that per-alloc read — issued while the
 * AGF buffer is held — serializes allocation through a ~1ms iSCSI round-trip and
 * ADDS reads to the very shared target whose saturation dlm_scaling measures:
 * a budget rule confound.  The double-alloc it caught is believed resolved (fb=0,
 * 4/caw coherency PASS).  Default 0 (off = no per-alloc read, clean timing);
 * set dblalloc_probe=1 to re-enable the detector for a fresh double-alloc hunt
 * (does NOT need instr=1, which hides the race). */
int mxfs_dblalloc_probe;
module_param_named(dblalloc_probe, mxfs_dblalloc_probe, int, 0644);
MODULE_PARM_DESC(dblalloc_probe,
	"enable the per-alloc P-DBLALLOC coherent-read double-alloc detector (heavy; default off)");

/* instrumented A/B gate for the scaling_curve 16-node
 * penalty: ftrace caller attribution showed ~890 of ~900 per-node disk-CAW
 * inode acquires during the 16-node disjoint-subdir rsync come from the
 * publish kworkers (mxfs_dlm_publish_dirs_work 558 + the BAST-side
 * publish_unpublished drain 333), not the syscall path — ≈14k CAW slot
 * claims cluster-wide competing with ~1.8 GB/s of data writes on the
 * shared LUN.  When 0, xfs_create does not queue the eager per-mkdir dir
 * publisher (the BAST-side drains and the ilock_begin backstop
 * remain — same correctness chain as files, slower first contended op).
 * Default 1 (eager publish on). */
int mxfs_publish_dirs = 1;
module_param_named(publish_dirs, mxfs_publish_dirs, int, 0644);
MODULE_PARM_DESC(publish_dirs,
	"eagerly claim on-disk CAW slots for fresh dirs via the per-mkdir "
	"async publisher (default 1; 0 defers to BAST-side publish)");

/*
 * — dir_reuse@16 WEDGE root fix.  The mxfs-ino-bast
 * workqueue is WQ_UNBOUND with max_active=0 (the ~512 unbound default).  Under a
 * 16-node hot-shared-dir storm the reclaimed-inode no-inode BAST path
 * (mxfs_dlm_noino_bast_work_fn) queues ONE work item PER BAST on the SAME hot
 * dir inode, so HUNDREDS of kworkers run concurrently, each issuing a
 * synchronous FUA read (read_slot) inside the on-disk unlock.  That EXHAUSTS the
 * block-layer request tags (PROVEN BY INSTRUMENT: 767 kworkers all D-state in
 * blk_mq_get_tag on test5, load 733, md5sum hung 302s) -> every FUA read blocks
 * -> the unlock cannot make progress -> self-reinforcing wedge.  Bounding
 * max_active caps concurrent bast FUA reads well under the device tag depth so
 * the block layer never saturates; the queued surplus drains in bounded batches
 * (and once the hot inode is unlocked, the rest hit the node_held==NL fast path).
 * 0 = kernel default (old unbounded behavior, for A/B).  Read at mount time.
 */
/*  ship default 32 (was 0/unbounded).  PROVEN needed at
 * 16 (dir_reuse wedge) AND 32 (posix_multi/strong_consistency EIO+starve with
 * ship-0 -> FAIL; with =32 -> PASS 32/32).  32 is well under the mpath tag depth
 * (non-binding at N<=32 node counts) yet bounds the 1000+-kworker storm. */
int mxfs_bast_wq_max_active = 32;
module_param_named(bast_wq_max_active, mxfs_bast_wq_max_active, int, 0644);
MODULE_PARM_DESC(bast_wq_max_active,
	"cap concurrent mxfs-ino-bast kworkers to avoid block-tag exhaustion under a hot-inode BAST storm (default 32; 0=kernel default/unbounded)");

/* instrumented detector gate: when 1, every multi-node inode
 * allocation reads the just-carved inode's COHERENT on-disk mode (plain bio) and
 * logs P-IALLOC-DBLALLOC if it is already LIVE (a peer owns it = same-chunk
 * inobt double-alloc).  Default 0 (one extra plain block read per alloc — keep
 * off for perf criteria; set 1 via sysfs for a cache_coherency repro). */
int mxfs_dbg_ialloc_dblcheck;
module_param_named(dbg_ialloc_dblcheck, mxfs_dbg_ialloc_dblcheck, int, 0644);
/*
 * (0.39.3, D-0351 containment): dialloc two-phase candidate
 * validation (docs/free-publish.md "Containment").  1 = validate every
 * clustered candidate's platter image before the inobt is modified
 * (default).  0 = the pre-containment allocator — A/B measurement knob for
 * tests/dialloc_disklive_inject.sh ONLY; never run a correctness campaign
 * with it off.
 */
int mxfs_dialloc_validate = 1;
module_param_named(dialloc_validate, mxfs_dialloc_validate, int, 0644);
EXPORT_SYMBOL(mxfs_dialloc_validate);

/*
 * instrumented INSTRUMENT — should the candidate validator keep running
 * after this mount's last peer leaves?
 *
 * mxfs_dialloc_two_phase() switches the D-0351/D-0946 containment off when
 * mxfs_v5_dlm_is_single_node() is true, and that is DYNAMIC membership: the
 * sole survivor of a departure answers yes.  Default 0 keeps the shipped
 * behaviour exactly; 1 keeps the validator running for a sole survivor so a
 * run can measure whether it refuses anything the shipped path would have
 * allocated over unchecked.  P951-VALIDATE-OFF-SOLE counts the other arm.
 */
int mxfs_dialloc_validate_sole;
module_param_named(dialloc_validate_sole, mxfs_dialloc_validate_sole, int, 0644);
MODULE_PARM_DESC(dialloc_validate_sole,
                 "Keep the dialloc candidate validator running for a sole "
                 "survivor: 0=shipped behaviour (default), 1=measure");
EXPORT_SYMBOL(mxfs_dialloc_validate_sole);
/*
 * 0.75.117 (D-0946): the candidate validator's treatment of a number whose own
 * free THIS node has not published yet.
 *   1 = REFUSE it transiently (default).  Its home dinode still carries our
 *       live predecessor image, and the create path's recycle gate reads that
 *       image, calls it corruption and cancels an ALREADY DIRTY transaction --
 *       which shuts the filesystem down.  The refusal happens before anything
 *       is dirtied, and mxfs_pubob_drive_publication provides the progress.
 *   0 = the pre-fix behaviour: allow it without reading the platter, on the
 *       inference that the live image at home must be ours.  This is the A/B
 *       CONTROL ARM for the defect and reproduces the shutdown; it exists so
 *       one build can carry both arms, and it must never be cleared for a
 *       correctness campaign.
 */
int mxfs_dialloc_pubpend_refuse = 1;
module_param_named(dialloc_pubpend_refuse, mxfs_dialloc_pubpend_refuse, int, 0644);
EXPORT_SYMBOL(mxfs_dialloc_pubpend_refuse);
MODULE_PARM_DESC(dbg_ialloc_dblcheck,
	"diag: detect same-chunk inode double-alloc at the allocation site");


/*
 * v6a phase 2 experiment (v0.3.130): lazy AG-DLM drain.
 *
 * Default 0 (eager drain — original v0.3.128 behavior).  When set to 1,
 * the per-trans drain in mxfs_ag_dlm_unlock is skipped if (a) the AG-DLM
 * grant is being kept cached AND (b) no peer BAST is pending.  In that
 * case the dirty AG metadata stays in the local delwri queue / xfs_buf
 * cache and is drained later by mxfs_dlm_ag_bast_work_fn (which already
 * does xfs_log_force + xfs_ail_push_ag_sync + blkdev_issue_flush before
 * the on-disk DLM release).
 *
 * Rationale: at every transaction commit, mxfs_ag_dlm_unlock decrements
 * holders to 0 (typical for create/mkdir transactions on a single AG)
 * and unconditionally drains pag_mxfs_alloc_dirty.  Each drain submits N
 * FUA writes and waits synchronously.  When no peer is contending, this
 * work is wasted — the BAST work fn would do the same drain at peer-
 * demand time.  The per-trans drain destroys metadata-create-heavy
 * cross-node throughput (v6a phase 1 measurement: even with read
 * amortization, T1 process kernel stack stuck in xfs_buf_wait_unpin
 * via mxfs_dlm_ag_drain_alloc_buflist via mxfs_ag_dlm_unlock).
 *
 * Correctness argument: the journal slot still records the transaction
 * (D15 per-node journal slots).  If our cached grant is force-revoked
 * (lease expire, cluster reconfig) before the BAST work fn drains, the
 * surviving peer replays our journal slot, applying the AG-meta
 * modifications.  So the eager drain is a perf optimization (avoid heavy
 * BAST drain), not a correctness requirement.  The lazy path preserves
 * correctness via journal replay.
 *
 * Risk: if peer's ACQ-FRESH fires WITHOUT triggering BAST on us (e.g.,
 * we missed BAST due to a bug, or we're declared dead and peer purges
 * us without our knowledge), peer reads stale on-disk AG metadata.
 * That's the failure mode the eager drain protected against.  Lazy
 * drain accepts this risk because (a) BAST should fire reliably, and
 * (b) journal replay covers the dead-node case.
 *
 * Phase 2 is gated by this knob so the change is reversible without
 * a code change.  Sess32 should A/B with eager vs lazy on the rsync
 * bench and on the canonical 5×256 stress harness.  If lazy passes
 * both, it can become the default in a later version.
 *
 * Per docs/v6-cache-architecture-proposal.md §11 (corrected H2 from
 * measurement).
 */
/*
 * gate for the sess20-35 diagnostic prints (P-*, MX-INSTR, H*).
 * Default 0 (off) — these per-op prints made metadata workloads ~100x
 * slower (failed perf criteria).  Pure logging; off-by-default is safe.
 */
int mxfs_instr_enabled;
module_param_named(instr, mxfs_instr_enabled, int, 0644);
MODULE_PARM_DESC(instr,
                 "Enable verbose per-operation MXFS diagnostic printk "
                 "(P-*/MX-INSTR/H*): 0=off (default), 1=on for debugging");

/*
 * (run14d): standalone gate for ONLY the dir-block write/read
 * content trace (P-DIRWR / P-DIRRD in pal/linux/xfs_buf.c and the dir
 * read verifiers).  mxfs.instr=1 turns on EVERY per-op print (~100x
 * slowdown, perturbs the races it should catch); this knob enables just
 * the two dir-block traces, cheap enough to leave on through a whole
 * cache_coherency run.
 */
int mxfs_dirwr_enabled;
module_param_named(dirwr, mxfs_dirwr_enabled, int, 0644);
MODULE_PARM_DESC(dirwr,
                 "Dir coherency probes: 0=off (default), 1=low-rate "
                 "write-side only (P133/P134 dinode+bmbt revert), "
                 "2=also per-IO content traces (P-DIRWR/P-DIRRD)");

/*
 * PROVEN (instrument step 2b): default ON.  On the SCST iSCSI target,
 * SCSI-FUA reads return the *un-destaged platter* image, which LAGS the
 * target's shared write-back cache where a peer's just-committed write
 * still lives.  So FUA reads are actively STALE here, producing both
 * metadata-corruption shutdowns (dialloc EFSCORRUPTED on a fresh-but-torn
 * AG inobt re-read; bnobt/SB/dir3 verify failures) AND ~45x slowness
 * (stale-read retries).  Disabling FUA routes reads through the coherent
 * shared cache.  Measured: rename_visibility 372s+SHUTDOWN -> 8s+no-shutdown.
 * Normal bio reads on a single shared SCST backstore are cache-coherent
 * across initiators, so cross-node freshness is preserved by buffer
 * invalidation, not by bypassing the cache.  0=use-FUA, 1=disable (default).
 */
int mxfs_fua_disable = 1;	/* sess6(ccloop 12e0d157): DEFAULT 1 for the SCST CAW-multipath target
				 * (criteria cluster: /dev/mapper/mpatha vendor CONFIRMED "SCST_FIO", all 32 nodes).
				 * On SCST every initiator shares ONE coherent write-back cache: a plain BIO read sees
				 * the coherent shared cache (fresh + fast), while a SCSI-FUA read PIERCES past it to the
				 * un-destaged platter (STALER + slower = the 32-node read-storm). PROVEN sess6: with
				 * fua_disable=1, cache_coherency/strong_consistency/dir_reuse @4 = 17/17 (incl the reuse
				 * cell no reload-skip fix could pass), and it clears the 32-node storm (FUA-reread
				 * dir-coherency is "fundamentally too slow at scale" per sess43/45/94). The sess14
				 * DEFAULT 0 was for the OLD /dev/sda LIO-ORG TCP cluster (per-initiator-cached, FUA
				 * REQUIRED) — a DIFFERENT target. A LIO target needs fua_disable=0; future work =
				 * auto-detect SCST vs LIO by SCSI vendor at mount. See ccmemory
				 * docs/history/caw-sess6-pivot-scst-confirmed-fua-disable-is-the-storm-fix.md. */

/*
 * (D-32NODE-SHARED-DIR-CREATE-PACE): skip the adopt check's FUA inode
 * read while the dir EX grant has been held continuously since the last clean
 * check (see the skip in mxfs_dir_modify_adopt_disk_format).  0 restores the
 * unconditional per-modify read for A/B.  The two counters are the census:
 * reads taken vs reads skipped, both only on the held-EX path.
 */
int mxfs_dir_adopt_skip_held_ex = 1;
EXPORT_SYMBOL(mxfs_dir_adopt_skip_held_ex);
module_param_named(dir_adopt_skip_held_ex, mxfs_dir_adopt_skip_held_ex, int, 0644);
MODULE_PARM_DESC(dir_adopt_skip_held_ex,
                 "Skip the per-modify FUA read of a directory's inode cluster "
                 "(mxfs_dir_modify_adopt_disk_format) while this node has held "
                 "the directory's EX grant continuously since the last read "
                 "that found the platter not ahead.  1=skip (default), 0=read "
                 "on every modify.");
atomic64_t mxfs_adopt_skip_held_ex = ATOMIC64_INIT(0);
atomic64_t mxfs_adopt_read_held_ex = ATOMIC64_INIT(0);
EXPORT_SYMBOL(mxfs_adopt_skip_held_ex);
EXPORT_SYMBOL(mxfs_adopt_read_held_ex);

int mxfs_dir_modify_adopt_nlink = 1;
EXPORT_SYMBOL(mxfs_dir_modify_adopt_nlink);
module_param_named(dir_modify_adopt_nlink, mxfs_dir_modify_adopt_nlink, int, 0644);
MODULE_PARM_DESC(dir_modify_adopt_nlink,
                 "Treat a directory whose on-disk di_nlink/di_changecount is "
                 "AHEAD of ours as a stale RMW base and adopt before "
                 "modifying, even when format/size/nextents are unchanged.  "
                 "1=on (default), 0=geometry-only (legacy).");
