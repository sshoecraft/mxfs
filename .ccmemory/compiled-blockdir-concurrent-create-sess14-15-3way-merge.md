---
name: compiled-blockdir-concurrent-create-sess14-15-3way-merge
description: sess14-15 crash_consistency root: block-dir concurrent-create durable dirent loss = reused-inode/daddr ABA; incarn-stamp fired 0x; 3-way SF merge fix…
metadata:
  type: project
tags: [compiled, crash_consistency, block-dir, aba-reuse, 3way-sf-merge, buffer-incarnation, tcp-dlm]
---

## Compiled: sess14-15 crash_consistency block-dir concurrent-create dirent loss

Central topic: across sess14 and sess15 the SOLE remaining `./run.sh 2 tcp`
ship blocker is **crash_consistency** — full suite is 15/16 (sess15) / 14-16
(sess14), everything else PASSes. crash_consistency PASSes standalone but FAILS
~50% in-suite (flaky, real). The failure is a **durable dirent LOSS in a
BLOCK-format shared directory under tight concurrent create**, and by end of
sess15 it is proven to REQUIRE inode/daddr REUSE (ABA). A separate write-side
shortform-dir *resurrection* face was fixed in sess14 by a 3-way SF merge; that
does NOT touch the block-dir loss.

### The two distinct dir faces (do not conflate)
- **Write-side SHORTFORM resurrection** (dlm_fairness `drained got=1`,
  tcp_dlm_scaling silent-loss): small churn dirs (create+mv+rm). A removed
  dirent (e.g. `n2_r6` on shared SF dir ino=17313886) gets durably STUCK on
  disk on BOTH nodes — a node RMWs a STALE shortform base still containing the
  entry and writes it back. Once durable, no read-side fix helps.
  [[sess14-PROVEN-writeside-shortform-resurrection-n2r6-stuck]]. FIXED by the
  3-way SF merge (below).
- **crash_consistency = BLOCK/LEAF-format dir**: 2 nodes each write 50
  O_SYNC data + 50 .md5 into ONE shared dir (=200 entries → block format).
  Concurrent. A test2 dirent (e.g. `node2_f49`, or a contiguous range
  node2_f15/f16) durably VANISHES from the LUN — test2 loses its OWN entry;
  the sidecar .md5 survives; +8s does not restore it (NOT eventual-consistency);
  drop_caches/pureLUN and test1-touch-dir-EX (direx) don't restore it. test1 is
  the clobberer (its block writes win). Contiguous creation-order names ≈ one
  dir DATA block's worth. SF merge does NOT apply (block dirs go through
  xfs_da_read_buf gen-invalidation + mxfs_dir_evict_data_blocks).
  [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]]
  [[sess14-merge-engages-writeside-cc-is-readside-blockdir]]

### The 3-way SHORTFORM merge (sess14 — SHIPPED, KEEP, write-side fix)
Convergent plan from sess9/12/13. Implemented in `xfs/xfs_mxfs_dlm.c`.
- New fields `void *i_dlm_dir_sf_base` + `uint32_t i_dlm_dir_sf_base_bytes`
  in `xfs/xfs_inode.h` (after i_dlm_dir_loaded_gen) = snapshot of the SF dirent
  image at last coherent disk sync = merge BASE. Freed in
  `xfs_icache.c xfs_inode_free_callback` / `xfs_inode_free`.
- `mxfs_sf_find()`, `mxfs_dir_sf_capture_base()`,
  `mxfs_dir_sf_3way_merge()` (a.k.a. `mxfs_dir_sf_merge_into`), takes i_lock
  EXCL (bounded trylock), builds merged SF per-name across base∪ours∪theirs:
  **ours!=base → keep OURS, else take THEIRS/disk**; adds peer-added names not
  in base/ours; assigns fresh sequential offsets; `xfs_dir2_sf_verify`;
  installs via `xfs_idestroy_fork`+`xfs_init_local_fork` iff changed; base
  advances to THEIRS. P-SFMERGE log on change.
- `mxfs_dir_sf_refresh_if_disk_differs` (xfs_mxfs_dlm.c:6293) REWRITTEN:
  removed early-return CLEAN gate; on differs → try merge FIRST (safe even when
  dirty, keeps our delta); fall back to clean-gated adopt-disk only when no
  base / SF-overflow / disk format changed.
- Also called from `mxfs_dlm_reload_inode` after `xfs_inode_from_disk`
  (re-applies our pre-reload delta so a reload no longer reverts our
  committed-not-durable dirents). Moving the call HERE (where
  P62-RELOAD-FORK-SHRINK fires) is what made P-SFMERGE actually ENGAGE — the
  sf_refresh-only build 917BE2AD had P-SFMERGE=0.
- `module_param sf_merge` default 1 (=on; 0 reverts at runtime).

Build progression (sess14): CF359E6C (baseline, 14/16) → **917BE2AD** (merge in
sf_refresh only — P-SFMERGE=0, didn't engage)
[[sess14-IMPL-3way-sf-merge-build-917BE2AD]] → **3017D9DF**
(merge ALSO in reload_inode — engages, P-SFMERGE fires on test2). Result:
dlm_fairness 6/6 (was flaky) — write-side face FIXED; KEEP. crash_consistency
still 3/6. [[sess14-HEAD-status]] Why safe vs sess9 refutations: keeps OUR
delta so a destage-lagging disk read can't revert our own rm; read-only-coherent
for untouched names; no forced DLM re-acquire so no starvation.

### sess15 ROOT of the block-dir loss — PROVEN by controlled experiment
The loss REQUIRES inode/daddr REUSE (ABA) **AND** tight back-to-back timing.
2×2 probe matrix [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]]
[[sess15-HEAD-status]] [[sess15-crash-consistency-is-sole-blocker-divergent-block]]:
- `cc_blockdir_probe.sh` (rm+recreate = REUSE, no gap) → LOSES <15 iter (fast).
- `cc_nogap_noreuse.sh` (unique dirs, no rm, no gap) → 40/40 CLEAN.
- `cc_minrepro.sh` (no reuse, per-iter dmesg-clear GAP) → 40/40 CLEAN.
- `cc_reuse_scoped.sh` (REUSE + ~1s gap) → 30/30 CLEAN (the gap lets the stale
  in-AIL buffer destage/settle, masking it).

So it is NOT a fresh-dir concurrent-RMW lost-update and NOT eventual-consistency
— it is an **ABA / reused-daddr cross-node cache-coherency bug**. When a dir
inode (and its data blocks at daddrs) is FREED and a new dir REUSES the inode
number and/or those daddrs, a peer still holds the PREVIOUS incarnation's dir
DATA block cached (XBF_DONE, daddr-indexed). The new incarnation's RMW reads
that stale buffer (no I/O since XBF_DONE) and writes back, dropping the new
dir's just-created dirents. crash_consistency fails IN-SUITE because earlier
tests (rsync_paired/dlm_scaling/etc.) free+realloc the inodes/daddrs it reuses.

**Exact loss signature (DIR-STALE-SKIP, xfs_da_btree.c ~3258, build B623A0F0):**
`DIR-STALE-SKIP ino=2517 blk=0 buf_gen=0 inode_gen=4 dirty=0 in_ail=1 pin=0
delwri=0 li_empty=1 has_bli=1 bli_flags=0x2` — a cached dir DATA block that is
stale (buf_gen=0 != inode_gen=4) but IN-AIL with
`mxfs_dir_buf_is_undestaged()`=true (b_mxfs_logged_seq != b_mxfs_written_seq),
so the read-path invalidation hook guard `(!in_ail || !undestaged)` PRESERVES
it → the create/RMW reads this stale base → drops the peer's whole block of
dirents. P-RELFLUSH (ino=131 build C10D1837) confirmed divergent-base:
SAME daddr=496 flushed by test1 with ONLY node1_f17..f23 and by test2 with ONLY
node2_f10..f14 — each node's in-core block holds only its own entries, last
writer wins. [[sess15-crash-consistency-is-sole-blocker-divergent-block]]

### sess15 fix attempt — buffer-incarnation stamp (IMPLEMENTED, fired 0×)
Design [[sess15-FIX-DESIGN-buffer-incarnation-stamp]]: the discriminator should
be inode i_generation (XFS bumps di_gen on every inode realloc); the dir3 block
header carries NO generation, so stamp it at the BUFFER level. Add
`uint32_t b_mxfs_dir_incarn` to struct xfs_buf, stamp = VFS_I(dp)->i_generation
on legitimate dir DATA reads/inits, and on cache-hit invalidate when
`b_mxfs_dir_incarn != current i_generation`, BYPASSING the dirty/in-AIL/
undestaged guard (a different-incarnation buffer's undestaged content belongs to
the FREED previous incarnation). Safety rule: incarn==0 (never-stamped) is NOT
treated as ABA so a missed stamp site can't discard live work.

Implemented (build **17DCD050**, deployed both nodes, dirwr=1)
[[sess15-incarn-fix-implemented-but-0-fire]]:
1. `b_mxfs_dir_incarn` at xfs/xfs_buf.h:240 (after b_mxfs_dir_gen).
2. xfs_da_btree.c xfs_da_read_buf ~3437: stamp unconditionally for DATA-fork
   dir reads.
3. xfs_da_btree.c read-hook ~3190: `incarn_aba = (incarn!=0 && !=i_generation)`
   added to invalidate trigger + bypasses in-AIL-undestaged keep-guard.
   P15-ABA-DIRINVAL log.
4. xfs_mxfs_dlm.c mxfs_dir_evict_data_blocks ~2010: same incarn_aba removes the
   `(in_ail && undestaged)` undurable term. P15-EVICT-INCARN-ABA log.

**RESULT: STILL LOSES (iter 16). P15-ABA-DIRINVAL=0 AND P15-EVICT-INCARN-ABA=0
on BOTH nodes** — incarn_aba was NEVER true. The i_generation discriminator did
NOT engage at the lost-update. Build KEPT (net-neutral, no regression, behaves
like B623A0F0=15/16). The fix MECHANISM (discard prior-incarnation buffer) is
right; the DISCRIMINATOR (i_generation) didn't match — find the right token.

### Why incarn_aba=0 — next hypotheses (sess15 handoff, RULE 4)
Candidates for why `b_mxfs_dir_incarn` is not `(!=0 && !=current i_generation)`:
(a) the reused dir inode's on-disk di_gen does NOT bump across rm+recreate (old
incarn == new i_generation — verify XFS di_gen behavior for dir reuse); (b) the
reading node's in-core VFS i_generation is STALE (iget cache-hit on a reused
inode# without gen refresh); (c) the stale buffer has b_mxfs_dir_incarn==0
(populated via a path bypassing the :3437 stamp — readahead,
xfs_dir3_block_read/xfs_dir3_data_readahead, xfs_trans_get_buf init); (d) the
loss is NOT a same-inode-reuse ABA at the dir-DATA read at all (DIR-STALE-SKIP
was a correlate). DECISIVE NEXT STEP: add b_mxfs_dir_incarn + VFS i_generation
to the DIR-STALE-SKIP log AND log them at P-RELFLUSH of the clobbering write;
reproduce; read the actual values. Also unresolved: xfsaild may flush the
lingering prior-incarnation in-AIL BLI onto the reused daddr regardless — may
need xfs_buf_stale/binval-style cancel, not just XBF_DONE clear.

### REFUTED this session-pair — do NOT re-chase
[[sess15-decisive-negatives-blockdir-loss]]
[[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]]:
- **Master DLM double-grant**: P-DOUBLEGRANT=0 (master-side single-clock,
  skew-proof detector), P-STALEMASTER-GRANT=0. The cross-node
  P106-EXGRANT/EXREL "overlap" (~4.5ms) was CLOCK SKEW. The gen-token
  double-grant fix (404BC55C) HOLDS.
- **Mastership flap**: P-STALEMASTER=0.
- **MHT batching window**: inode_mht_ms=0 still loses.
- **sf_merge as cause of the block loss**: sf_merge=0 still loses. The
  block↔shortform "format oscillation" in P105 traces was an INODE-REUSE
  artifact (low ino reused across iters), NOT a real single-dir reversion.
- **sf→block CONVERSION double-alloc**: P-H14-INSTR showed the converting node
  had the COMPLETE merged incore set at conversion (incore_names=[node1_f1-6
  node2_f1-5]); lost entries (f15/f16) are added AFTER conversion into block
  format → it's a block-format data-block RMW lost-update, NOT conversion, NOT
  shortform. (Supersedes the earlier "concurrent sf→block conversion
  double-alloc" framing in
  [[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]].)
- **clean-cached-stale-block**: module_param `dir_force_evict=1` (force
  mxfs_dir_evict_data_blocks on EVERY cross-node modify, not local-gen-gated)
  STILL loses — the clobber base is in-AIL undestaged, NOT clean; evict skips
  dirty.
- **CROSS-INODE daddr reuse / ABA owner-mismatch**: P15-ABA-DIRINVAL owner
  check fired 0× — the dir3 block owner (= inode number) always MATCHES =
  SAME-inode-number reuse, not cross-inode.

Earlier REFUTED (carried from sess9, do NOT repeat)
[[sess14-plan-merge-is-convergent-need-modeAB-evidence]]: relax P9 clean-gate /
drop IN_AIL skip (build 223CA589 → WORSE 27/30; IN_AIL skip is protective vs
destage-race); force slow-path when i_dlm_stale (build 58EB95A8 → STARVATION,
dlm_fairness got=7); di_changecount epoch discriminator (per-node i_version is
not a shared sequence — need atomic SHARED on-disk epoch or per-entry
provenance).

### GPT-5.5 consult direction (RULE 5)
[[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]]
[[sess15-HEAD-status]]: per-EPOCH (not per-op) authoritative reload on cross-node
acquire + ensure release drains the FULL inode metadata CLOSURE (every dir
data/leaf/free/bmbt buffer, not just the dinode AIL item) before setting
i_dlm_mode=NL; assert no dirty/pinned/in-AIL/delwri dir buffer remains at NL;
ABA-detect at read. Note the ROOT enabler: the cross-node free-invalidation gap
— a peer that cached a daddr never invalidates it when another node
frees+reallocs it (eviction-ring lossy on TCP; mxfs_v5_dlm_note_inode_freed /
note_dir_modified via disklock heartbeat, and mxfs_v5_dlm_inode_held is a NO-OP
on TCP). The buffer-incarn stamp was chosen as the cheaper sound path (fix the
symptom at read/RMW using authoritative per-inode i_generation) — but it needs
the right incarnation token, which sess15 did not yet find. Existing sess104 ABA
guard (i_dlm_dir_evicted_incarn != VFS i_generation in modify/consumer_refresh)
keys on the INODE and catches inode-number reuse but NOT daddr reuse where a
block freed from dir A is reallocated to dir B.

### Assets / harnesses (in-tree, KEEP — RULE 3)
Probes under tests/: `cc_blockdir_probe.sh` (FAST reuse repro, loses <15 iter —
KEY iteration tool), `cc_minrepro.sh` / `cc_nogap_noreuse.sh` /
`cc_reuse_scoped.sh` (the 2×2 reuse/gap matrix), `cc_df_capture.sh` (full-suite
+ dirwr detector capture, tallies churn fails + P-SFMERGE), `cc_dirvis_probe.sh`,
`cc_dirgrow_probe.sh` (P34C), `cc_doublegrant_probe.sh`, `cc_inode_timeline.sh`,
`tcp2_characterize.sh`, `reboot_cluster.sh 2` (virsh destroy+start BOTH before a
trusted run; test2 rmmod-busy is recurrent — umount -l + rmmod retry loop or
virsh reboot). Detectors (build B623A0F0/C10D1837/CE99583D, KEEP): de-ratelimited
P-RELFLUSH dumping `mxfs_dir_block_names()` per flushed daddr, P-H14 incore SF
name list, module_param dir_force_evict (default 1), P15-ABA-DIRINVAL owner
check (harmless, 0×). Gates: `mxfs.dirwr=1` enables always-on dir detectors
(P58/P62/P91/P104/P-SFMERGE/P-SFDIR-REVERT); `mxfs.instr=1` = 100× slow, HIDES
races — avoid.

### Build timeline
CF359E6C (14/16 baseline) → 917BE2AD (SF merge, 0-fire) → **3017D9DF** (SF merge
engages, dlm_fairness 6/6 FIXED, sess14 HEAD) → CE99583D / 3017D9DF / C10D1837 /
CD… instrumentation builds → **B623A0F0** (15/16, DIR-STALE-SKIP root proven) →
**17DCD050** (buffer-incarnation stamp, fired 0×, sess15 HEAD, KEEP net-neutral).
Cluster: test1 (192.168.120.114/.186) + test2 (.182), TCP transport. Criterion
`./run.sh 2 tcp` 100% NOT met; marker NOT written.
