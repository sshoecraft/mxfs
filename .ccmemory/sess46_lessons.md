---
name: sess46_lessons
description: sess46 (2026-06-02) — bnobt cross-node-free clobber localized to ACQUIRER stale-pristine AG buffer + frozen meta_gen; ruled out durability/medium/FUA; root = CAW concurrent-EX (claim-race or CAS). cache_coherency fails via shared-dir barrier hang.
metadata: 
  node_type: memory
  type: project
  originSessionId: 853907ba-efca-479d-9512-049b4237b3e5
---

# sess46 — bnobt clobber decisively localized; cache_coherency = shared-dir barrier hang

Build `9AF61DF252E5E8C86081513` = sess45 stable `5ED458EB` + gated diagnostics
P101, P102 ONLY (no functional change). Deployed test1-4, instr OFF, mounted.

## What cache_coherency actually fails on (fresh data, build 5ED458EB/9AF61DF2)
- 4 cluster tests on ONE mount. **cross_write_read PASSES standalone on a fresh
  mount**; fails only with carryover (inode reuse → stale cached type/size).
- **rename_visibility / unlink_visibility HANG on the test BARRIERS.** Barriers
  (tests/lib/cluster.sh) = marker files in a SHARED dir + `find|wc -l` poll.
  4-node concurrent shared-dir modify stalls them → 120s timeouts each →
  rename_visibility alone takes >300s and asserts fail. Load is ~0 (sleeping in
  CAW poll, not computing). dmesg: sense_key=0xe asc=0x1d MISCOMPARE storms
  (heavy CAW contention on the shared dir / its AG).
- Isolated 2-node shared-dir create+readdir+lookup is FAST + coherent
  (dirvis_probe.sh visible_after=0; shareddir_probe.sh 4-node create 80/80 <1.3s).

## PROVEN mechanism of the bnobt corruption (cross-node unlink/rename → EIO/shutdown)
FAST repro: reset4.sh 4; peers create files in their affine AGs; another node rm's
them (cross-node free). dmesg (P88 not instr-gated; P101/P102 need instr=1):
```
P101-INVAL-NOOP-PRISTINE agno=N daddr=.. bno numrecs=2 rec0=[9,k] buf_gen=1 pag_gen=1
P88 bnobt-WRITE-low-numrecs daddr=.. numrecs=1 rec0=[start=9 len=260906] disk_differs=1 buf_gen=1 pag_gen=1 fua_fresh=1
```
The ACQUIRER (freeing node) writes a PRISTINE whole-AG-free bnobt over the peer's
allocated V1. Its in-core AG bnobt buffer is stale-pristine; the read-coherency
hook `mxfs_ag_meta_invalidate_stale` NO-OPs because buf_gen>=pag_dlm_meta_gen
(both stuck at 1) → stale buffer served to xfs_free_ag_extent → clobber. P102
proved pag_dlm_meta_gen goes 0→1 once per AG then FREEZES (only fresh CAW acquire
[xfs_mxfs_dlm.c ~L2873] + post-acquire-lock cached path [~L2737] bump it; the
early cached fast-path [~L2658] and NESTED path [~L2648] do NOT). The cross-node
free re-enters NESTED/cached → no bump → stale reuse.

## RULED OUT this session (data) — do NOT re-chase
1. Peer write durability: aggressive owner flush (sync;sync;drop_caches;5s) before
   the free → clobber PERSISTS 8×; disk_differs=1 = V1 IS durable. NOT a destage gap.
2. Medium-vs-cache: raw `dd iflag=direct` first 64MB BYTE-IDENTICAL test1 vs test2
   → SCST target cache coherent across initiators.
3. FUA-reads-stale-medium: fua_disable=1 cluster-wide → clobber PERSISTS. The
   acquirer serves its in-core pristine buffer with NO device read (hook no-op).
(sess44 still valid: P96 node always holds own AG-DLM bit at modify; P89 cached
fast-path genuinely holds AG on disk.)

## ROOT (sharp next target): CAW transient concurrent-EX
Only thing consistent with "acquirer has pristine buffer + disk has peer's V1 +
both 'hold' the AG": two nodes transiently hold AG-DLM EX, masked by
`slot_appears_corrupt` auto-repair (dlm/dlm_caw.c popcount(holders_ex)>1 → zeroed
before mxfs_v5_dlm_ag_held checks). The CAS itself (caw_slot →
mxfs_pal_bdev_compare_and_write, SCSI COMPARE-AND-WRITE) is atomic; the likely
window is the SLOT CLAIM-RACE: AG locks for peer AGs are claimed on-demand
(rarely), so a node's first cross-node access can race the owner's first access and
both claim DIFFERENT slots (hash+linear-probe find_slot, dlm_caw.c ~L499) for the
SAME AG resource → two slots → both EX. Or a CAS/miscompare-retry window.
NEXT: dlm_caw helper to read the AG's slot RAW (no repair) + log
popcount(holders_ex) at the bnobt modify (xfs_alloc.c xfs_free_ag_extent /
xfs_alloc_fixup_trees). popcount>1 ⇒ concurrent-EX confirmed ⇒ fix find_slot
claim-race / CAS window in dlm_caw.c. Also log the slot INDEX chosen per AG per
node and assert one-slot-per-AG.

## diagnostics added (gated mxfs.instr, KEEP)
- P101: xfs_mxfs_dlm.c mxfs_ag_meta_invalidate_stale no-op branch — stale-pristine-served.
- P102: xfs_mxfs_dlm.c mxfs_ag_dlm_lock — acquire path + agno + meta_gen.

## tooling (tests/, persist)
- shareddir_probe.sh [N] — 4-node concurrent shared-dir create + cross-node rm =
  PRIMARY fast clobber repro. dirvis_probe.sh, rv_probe2.sh — isolated (pass).

## ⭐⭐⭐ sess46 LATE WINS (verified, KEEP)
1. **single_node_paired PASS at 104%** (≤105%). The 138% was multi-node-residue
   confound (sess44 right). Clean single-node mount → mxfs within 4% of XFS. FUA
   reads correctly gated off single-node (xfs_buf.c:1926). No code fix needed.
2. **dir-gen fix → rename_visibility from HANG+many-fails to FAST+1-2/240.**
   Build `9E6F5017FA9CE0E4820CA46`. Re-enabled sess43's gen-0 bump (it was
   A/B-disabled and never restored) in xfs/libxfs/xfs_da_btree.c (~L2872:
   `dp->i_dlm_dir_gen = 1` on first multi-node DATA-fork dir read). readdir/lookup
   use lock_flags=0 → bypass mxfs_dlm_ilock_begin → i_dlm_dir_gen stuck at 0 → the
   read-time dir-block invalidation hook (gated gen!=0) was SKIPPED → peers served
   stale cached dir blocks → missed new/renamed dirents → barrier-marker invisible
   → 120s barrier timeouts + asserts fail. After: dirent asserts (Old gone / New
   exists) all PASS, fast (~12s vs >300s hang). KEEP THIS FIX.

## ⛔ REMAINING cache_coherency failure (down to ONE root: di_size empty-content)
After the dir-gen fix, rename_visibility's only residual (1-2/240 assertions,
reproducible via cross_visibility→rename_visibility sequence, instr=0):
`Content preserved in node1_after_1: expected='content_1_1' actual=''` — peers read
a renamed file's content as EMPTY = di_size=0 inode read staleness.
DIAGNOSIS (sess46): the peer holds a CACHED PR grant on the REUSED inode number N
(from the earlier cross_visibility test where N was a different object). The
cached-mode fast path in mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c ~L1679: mode==PR &&
req==PR → take cached lock, NO reload) serves the stale cached inode (di_size=0).
getattr's ILOCK_SHARED hits this fast path → no reload. The peer's stale PR grant
was NOT invalidated when N was freed+reused (no BAST on free/reuse) so
i_dlm_stale=false. assert_file_exists ([ -f ]→stat→getattr) passes (mode correct)
but di_size stays 0 → cat reads empty. NOT a durability gap (barrier+2s settle
before read; sess46 proved metadata durable). ROOT = inode-reuse DLM coherency:
freeing/reusing inode N doesn't invalidate peers' cached grants on N (sess40
family). NEXT FIX OPTIONS: (a) on inode free (xfs_ifree) bump a per-inode gen or
release peer DLM grants; (b) getattr/open path: detect di_gen mismatch (cached
inode di_gen != disk) and force reload — needs a cheap check; (c) make node1's
EX-acquire-on-reuse reliably BAST peers' stale PR on N. Carryover-dependent
(needs inode-number reuse across the 4 tests).

## sess46 di_size residual — FINAL corrected finding + reverted attempts
Two in-IO-path fixes TRIED + REVERTED (do NOT repeat):
- getattr size==0 detect+reload (40B34C7C): P103 never fired in clean build; added
  cross_visibility flakiness from the EXCL upgrade. Reverted.
- iomap hole-within-size reload (53813959): ILOCK_EXCL in xfs_read_iomap_begin →
  DLM EX CAW poll (≤120s) → HUNG cross_visibility. Reverted.
LESSON: never take ILOCK_EXCL or call mxfs_dlm_reload_inode in the hot read/getattr
path (DLM EX blocks; reload needs i_lock write, can't hold ILOCK_SHARED).
**P104 detector (always-on, non-blocking, in build F1FA04C7) did NOT fire** → the
empty-content is NOT a stale extent-map/hole. It is **di_size==0 at the `cat` read**
(read returns early, 0 bytes → '') = READ-SIDE di_size staleness on a peer's file
(sess44/45 inode-cluster family). Narrow 4-node race (1-2/240; NOT reproducible
sequentially — manual create→read→free→reuse→read is coherent). NEXT: always-on
detector gated (multi-node && S_ISREG && in-core di_size==0) in xfs_vn_getattr AND
xfs_file_read_iter early-return logging in-core vs FUA-disk di_size → read-stale vs
writer-not-durable; then a SAFE non-blocking per-inode-sector re-read (no DLM CAW,
no ILOCK_EXCL) when disk>0 && in-core==0.

## ⛔⛔ sess46 FINAL: FIVE VFS-layer reload-triggers ALL FAILED → need DLM event-driven
The regular-file page-cache-invalidation-on-reload fix (xfs_mxfs_dlm.c ~L1553) is
correct but INERT — the stale inode's reload isn't triggered.  Five VFS-layer
triggers tried + reverted: (1) getattr size==0 EXCL+reload 40B34C7C (never fired);
(2) iomap hole EXCL+reload 53813959 (HUNG on DLM CAW); (3) open()-path reload
F3CA2903 (regressed cross_visibility); (4) per-read ILOCK_SHARED 5471F480 (PERF
WALL load~6); (5) di0-gated per-read ILOCK_SHARED 07B97DAF (only di0 sub-case +
barrier-timeout slowness → "cannot see file").  CONCLUSION: the trigger must be
EVENT-DRIVEN at the DLM layer — the owner's inode WRITE/RENAME (EX acquire) must
invalidate the inode on peers that hold it in-core WITHOUT a DLM grant (readdir/
lookup instantiate grant-less, so the EX BAST has no grant-holder to notify).
Needs a dlm_caw inode-invalidate broadcast OR grant-less-cache tracking. That's
the genuine remaining cache_coherency work.  DEPLOYED BUILD: `9E449D45` (dir-gen +
page-inval + P104; = 0FA2CB16 minus P105).  cache_coherency stays passed=2 failed=2.

## sess46 DEFINITIVE di_size root + partial fix (build 0FA2CB16, deployed)
P104 (read maps hole-in-size) AND P105 (read with in-core di_size==0) BOTH stayed
SILENT at the failing reads → the empty-content is a **STALE DATA PAGE** (page-cache
HIT, no iomap/disk read): di_size>0 + extent present, but the reading node's cached
page for the REUSED inode holds the prior lifecycle's content (zeros) → cat=''.
**ROOT of the root:** mxfs_dlm_reload_inode invalidated the page cache ONLY for
DIRECTORIES, never regular files. sess46 ADDED `else if (S_ISREG)
invalidate_inode_pages2` (xfs_mxfs_dlm.c ~L1553) — CORRECT but INERT: the reload
isn't TRIGGERED for the reused inode (reuse BAST lost on slot tombstone →
i_dlm_stale=false → cached-PR fast path serves stale without reload). cache_coherency
stays passed=2 failed=2 (rename+cwr fail identically). **NEXT (the ONE thing left):
trigger the reused-inode reload** — (a) free-time BAST peers off the inode, (b)
di_gen check on xfs_iget_cache_hit, or (c) cached-PR fast path honor i_dlm_stale +
cheap trigger. MUST be non-blocking (no ILOCK_EXCL/DLM-CAW in read path — those hung,
reverted 40B34C7C/53813959). Once triggered, the page-inval fix completes it.

## sess46 BUILDS
- `9E6F5017` = stable + dir-gen fix. `0FA2CB16` (DEPLOYED test1-4, instr OFF) =
  dir-gen fix + regular-file page-cache invalidation on reload + P104/P105 detectors.
  All KEEP. dir-gen: xfs/libxfs/xfs_da_btree.c ~L2872 `dp->i_dlm_dir_gen=1`;
  page-inval: xfs/xfs_mxfs_dlm.c mxfs_dlm_reload_inode ~L1553.

Criteria: single_node_paired now PASS (104%); cross_visibility/unlink dirent-coherent;
rename_visibility went hang→1-2/240 (only di_size empty-content residual);
cache_coherency still FAIL on that residual. State: /src/mxfs/state.md.
