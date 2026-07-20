---
name: sess44_lessons
description: "2026-06-02 sess44. Corrected the over-optimistic sess43 handoff: A0A86F31 SHUTS DOWN under basic 4-node load (SB-verify, bnobt overlap, DLM-timeout, NULL-deref). Made one safe fix (SB summary-counter clamp, build 8E87D691). Root-caused the dominant blocker: AG free-space lost-update from the in-AIL guard preserving a this-node-BEHIND bnobt buffer."
metadata:
  type: project
  originSessionId: f993c4e4-1ee7-4bcc-90cd-f3e050cb028c
---

# sess44 — corrected baseline + SB clamp fix + bnobt lost-update root cause

## ⚠️ The sess43 handoff ("clean 3/4, one architectural blocker") was OVER-OPTIMISTIC
A0A86F31 was clean only at IDLE. Under the REAL 4-node `cache_coherency` workload it
produces MULTIPLE shutdown classes (all reproduced this session, dmesg-verified):
1. **SB-verify CORRUPT_INCORE** — `xfs_sb_write_verify` (xfs_buf.c:1646). Lazy summary
   counters (icount/ifree/fdblocks) diverge per-node → `fdblocks>dblocks` → shutdown.
2. **bnobt free-space overlap** — `Internal error ltbno + ltlen > bno at xfs_alloc.c:2231`
   (`xfs_free_ag_extent`) → CORRUPT_INCORE shutdown. THE DOMINANT BLOCKER (see below).
3. **DLM-lock-unrecoverable** — `mxfs_dlm_ilock_begin:1808` force-shutdown when CAW inode
   acquire fails after retries under contention.
4. **NULL deref** — `xfs_dir2_sf_lookup+0x4b` (R12=0) under concurrent mkdir → reload-vs-
   lookup race on a shortform dir (if_data swapped under a walking lookup).
5. **mxfs_buf leak** on rmmod ("Objects remaining in mxfs_buf on __kmem_cache_shutdown").
`cache_coherency.sh` also TIMES OUT (EXIT=124, 880s) because it does 4 SEQUENTIAL
fresh_cluster_mounts (one per sub-test) — the mounts alone eat the 900s budget.

## ✅ FIX LANDED (build `8E87D691D646073D468A41B`, deployed test1-4, KEEP): SB summary-counter clamp
`xfs/libxfs/xfs_sb.c` `xfs_log_sb()` — after the lazysbcount recompute, in MULTI-NODE only,
clamp `sb_fdblocks<=sb_dblocks`, `sb_icount` into `xfs_icount_range()`, `sb_ifree<=sb_icount`.
Rationale: the lazy summary counters are per-node-private percpu counters seeded from the SB
at mount + advanced only by THIS node's deltas; a node freeing blocks/inodes a peer allocated
drives fdblocks past dblocks — BENIGN (the per-AG AGF/AGI is authoritative + the SB summary is
rebuilt from AGF on recovery, per the lazysbcount comment). Upstream ALREADY clamps ifree→icount
and uses `_positive` on fdblocks/frextents for this exact class; this extends the same defensive
clamp to the cluster fdblocks/icount case. Single-node untouched. **STATUS: plausibly correct,
NOT cleanly validated** — removing the SB-verify shutdown let the FS run PAST the summary symptom
and REVEALED the real disease (bnobt overlap #2 shuts down first). So they share a root: free-space
accounting corruption. Build OK (rc=0), tools unaffected (don't recompile xfs_sb.c).

## ⭐ ROOT CAUSE of the dominant blocker (bnobt overlap) — AG free-space LOST UPDATE
P15-INSTR (already in xfs_alloc.c:2231) PROVED it: test2/3/4 ALL corrupt **AG3 within ~83ms**.
bnobt shows ONE giant free extent `[24, 260915)` (len 260891 = agf_longest, agf_freeblks=260897
≈ pristine post-mkfs). Each node frees a 240-block extent (bno=280/776/1272) that is INSIDE that
free range → "already (partly) free". ⇒ 3 nodes allocated 240-blk inode chunks from AG3 but the
bnobt **reverted to nearly-all-free — every allocation lost**. Classic alloc-side lost update on
the bnobt under concurrent same-AG allocation (the test's shared dir + child inodes land in AG3).

### TWO hypotheses TESTED this session (RULE 4) — BOTH DISPROVEN
- ❌ **in-AIL guard preserves a this-node-BEHIND buffer — DISPROVEN by P77=0.** Theory was:
  `mxfs_ag_meta_invalidate_stale` (~L2257) preserves a gen-lagging in-AIL bnobt buffer on sess43's
  "in-AIL==this-node-ahead" assumption; an in-AIL buffer predating a peer's modify is BEHIND →
  preserved-stale → clobber. **But P77-INSTR (the in-AIL protect log) fired 0× on all 3 nodes during
  the corruption** → that branch was never taken. The lost update does NOT flow through the in-AIL
  preserve path. Do NOT "fix" the in-AIL guard — it's a dead end for this bug.
- ❌ **stall-abort drain — DISPROVEN.** `ag_bast_stall_iters=0` (unbounded drain, runtime param) on
  all 4 nodes → bnobt overlap STILL fires (ltbno=2/node).

### P85 DIAGNOSTIC (build `2B938526` = 8E87D691 + this probe): corruption is DURABLY ON DISK
Added `mxfs_ag_buf_disk_differs(p28_lbp)` at the xfs_alloc.c:2231 overlap (P28-INSTR). test1 hit it:
**`disk_differs=0 in_ail=0`** — in-core bnobt leaf MATCHES on-disk FUA-read. ⇒ the bad bnobt is
AUTHORITATIVELY ON DISK (not transient in-core staleness). A node committed a bnobt RMW on a STALE
BASE (missing a peer's alloc) and WROTE it to disk → clobbered the peer's alloc. Origin = a stale
bnobt READ AT ALLOC TIME (the free-time disk_differs=0 just observes the already-committed corruption).

### ⭐ CONCLUSIVE RULE-OUTS (build `2CC88731` = +P85/P86/P87 detectors) — the bnobt lost-update is NOT:
- **A CAW DLM split (P87=0, CONCLUSIVE).** Added post-CAS verify in dlm_caw.c: after every EX/PW grant
  CAS succeeds, re-read the slot and require `holders_ex == our bit` (popcount 1). `read_slot` →
  `mxfs_pal_bdev_read_prio` → `mxfs_scsi_read16_fua` (FUA, pierces to platter, NOT cached) = authoritative
  on-disk check. Fired 0× → EX grants persist exclusively; AG-EX serialization is CORRECT. The long-
  suspected sess26 "CAS-success-without-persist" is NOT happening here. (EXCL-VIOLATION=0, H22-repair=0.)
- **The read-coherency hook skipping a stale buffer (P86=0).** Logged EVERY stale-but-skipped AG-meta
  buffer (pinned/dirty/delwri/in_ail) in mxfs_ag_meta_invalidate_stale → fired 0×.
- **The in-AIL preserve path (P77=0).**
- **The release-drain skipping a pinned bnobt (P73 = 56-86× but ALL pin=0/bli=NULL = benign clean blocks).**
- **The cached AG fast-path** (pag_dlm_cached=true ⇒ we still hold the on-disk grant; BAST sets it false
  before unlock ⇒ no peer can have modified — safe by design).
- Corruption is DURABLY ON DISK (P85 disk_differs=0).

### Remaining SUBTLE surface (DLM correct + hooks clean + drain clean + on-disk durably corrupt):
(a) FUA-read-on-acquire returns pre-peer-change data despite the hook firing (storage/SCST FUA cross-
initiator gap specific to bnobt — but FUA works for inode/dir per cross_visibility PASS); (b) the failing
free is of an INODE EXTENT MAP wrongly pointing to free space (root in the inode bmbt, not bnobt — the
data-extent alloc recorded [bno,bno+len) in the inode but the bnobt removal was lost); (c) per-node
journal replay/checkpoint re-introducing a pristine bnobt block. NEXT decisive probe: instrument the
ALLOC-path bnobt read (cursor init / xfs_alloc_fixup_trees) with disk_differs + log pag_dlm_meta_gen and
the leaf b_mxfs_ag_gen — catch the stale base AT ALLOC time (the free only observes committed corruption).

### ⭐⭐⭐ ROOT CAUSE CONFIRMED (P88, build `23F83A35`): stale-pristine bnobt base from a durability window
P88 instruments the bnobt/cntbt WRITE path (log multi-node writes with numrecs<=1 = pristine). **test1
wrote daddr=4174648 (=0x3fb338, the EXACT block that then failed the overlap) with numrecs=1
rec0=[start=9 len=260906] = the mkfs-pristine whole-AG-free record.** Nodes actively WRITE BACK a pristine
V0 bnobt over the allocated V1. ROOT: the node's bnobt RMW is built on a STALE PRISTINE BASE — its
AG-meta FUA-read-on-acquire returned mkfs-pristine platter content because a peer's committed V1 bnobt
write was NOT platter-durable at read time (durability-ordering window). The invalidation hook DOES fire +
FUA-re-reads (P86=0, no skip), but the FUA read itself returns stale-pristine. P70=0 because the RMW is
LOCALLY self-consistent (pristine base → pristine result). The free later overlaps because blocks show free.

### ⭐ P88b FLIPPED THE FRAMING (disk_differs=1): V1 IS durable; node clobbers it with STALE V0
Added disk_differs to P88: at the numrecs=1 pristine write, FUA-reading the CURRENT on-disk content shows
**disk_differs=1 on EVERY clobber → the on-disk bnobt is V1 (allocated, DURABLE).** So it is NOT a write-
durability gap (V1 is on platter). It is READ-STALENESS / stale-writeback: the node modified a stale V0
bnobt base (its read at acquire returned V0) and wrote it over the durable V1. So sess43's P81 "make writes
durable" was NOT the actual gap (writes ARE durable). DISPROVEN this session too: P89 cached-fast-path
divergence (held-check fired 0×, reverted); and FUA coverage for bnobt IS present (mxfs_buf_needs_fua_read
→ mxfs_buf_is_ag_metadata = true for bnobt/cntbt/agf/agi/inobt/finobt; pag_dlm_fua_window NOT wired into
the read gate). So it is NOT missing-FUA-coverage either.

### TIGHTLY-BOUNDED remaining question (small surface) + decisive next probe
The stale V0 buffer is treated as FRESH (b_mxfs_ag_gen >= pag_dlm_meta_gen AND _XBF_FUA_FRESH set) so it is
neither invalidated nor FUA-re-read. Leading hypothesis: the **sess43 gen-stamp-on-fresh-read** (xfs_buf.c
~1553: stamps b_mxfs_ag_gen=pag_dlm_meta_gen after EVERY FUA read) LOCKS IN a stale read — if a node
FUA-reads V0 at the instant disk is V0 (a read-vs-peer-release-destage race: peer unlocked before its V1
hit the platter), the buffer is stamped gen-current+FUA-fresh; when disk later becomes V1 the buffer stays
V0 and is never refreshed → V0 RMW clobbers V1. Open: why doesn't the node's fresh AG-DLM acquire (bumps
pag_dlm_meta_gen → makes V0 gen-lagging → invalidate+FUA-reread V1) fire before the modify? **DECISIVE
PROBE: at the bnobt cursor read in the alloc/free path, log pag_dlm_meta_gen + buffer b_mxfs_ag_gen +
_XBF_FUA_FRESH + disk_differs.** If buffer is (gen-current + FUA-fresh + disk_differs=1) = masked-stale by
the gen-stamp → fix is to not stamp/trust a FUA read that races a peer's release (or invalidate AG-meta on
the node's OWN acquire even when gen-current, bounded). NOTE: unbounded drain (stall_iters=0) did NOT fix
it; sess43's release-time FUA-write (P81) was too slow — so the fix is on the READ/refresh side, not write.

### Refined fix direction (next session)
- The stale read is at ALLOC time, not free. Move the disk_differs probe to the ALLOC-path bnobt read
  (xfs_alloc cursor init / xfs_alloc_lookup) to catch the stale base when a node allocates.
- Most likely a PINNED/LOCKED bnobt leaf that the FUA-refresh hook (mxfs_ag_meta_invalidate_stale —
  XBF_TRYLOCK + !dirty/!pin/!delwri/!in_ail guards) CANNOT invalidate → node walks a stale leaf → RMW
  on stale base. sess42 already flagged this: "lazy gen invalidation can't refresh a pinned/locked
  buffer → used stale." The fix must guarantee the allocator's bnobt base reflects all peers' committed
  allocs before the RMW even when the leaf is pinned/locked (block alloc until refreshable, or
  force-drain/unpin the leaf on AG EX acquire).
- DLM serialization split still UNVERIFIED (CAW log looks serialized: register-waiter→wait-for-grant-done).

## Other measured criteria state (build 8E87D691, this session)
- **single_node_paired: 138%** (xfs 4031ms / mxfs 5563ms) — with peers FULLY torn down. Confirmed
  prior session's "216% is multi-node-residue" was PARTLY right (216→138 with peers down) but
  138% is a REAL single-node regression vs sess37's 85%. FUA reads + sync_iflush are gated off
  single-node, so the ~38% is elsewhere (suspect: 32MB log slice vs XFS 64MB → more log forces on
  metadata-heavy rsync; or DLM acquire overhead per inode/AG even single-node). Not yet root-caused.
- **rsync_paired: the "missing tool" failure is STALE** — `tools/mxfs_multinode_bench.sh` EXISTS now
  (created 2026-05-29). The criterion just needs a fresh run (will likely surface a real perf/corruption
  result, not a missing-tool error).
- 9 criteria recorded PASS but mostly stale (2026-05-29); will regress (dmesg_clean/wedged_unmount now
  FAIL given the shutdowns + Oops under load). 7 criteria NEVER measured (posix_semantics, zero_silent_loss,
  crash_consistency, fence_during_write, strong_consistency, scaling_curve, soak) — some need 16 nodes / 1h.

## ENV reminders
- SSH: `tools/mxfs_sshpass.sh <node> /tmp/.mxfs_pass '<cmd>'` (root via sshpass). Plain ssh fails (no key).
- MXFS_NODE_OFFSET=16 in cache_coherency.sh is DEAD (get_node_hostname ignores it) → targets test1-4 correctly.
- Reset: `MXFS_TESTS_DIR=/src/mxfs/tests bash tests/reset4.sh 4`. Reboot a wedged node: `virsh destroy/start`.
- Single sub-test: `MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster --test <T> --pass-file /tmp/.mxfs_pass --mount-point /mnt/shared`.
- Criteria definitively NOT met. Did not write the marker.
