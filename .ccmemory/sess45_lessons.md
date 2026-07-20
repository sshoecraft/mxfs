---
name: sess45_lessons
description: sess45 (2026-06-02) — di_size=0 cross_write_read root traced to atime-on-read EX clobber; node-affine inode alloc + atime-skip fix the di_size clobber; remaining wall is bnobt double-alloc + dir-block corruption under concurrent multi-file create.
metadata: 
  node_type: memory
  type: project
  originSessionId: e9e10da0-ffe3-4913-9f23-fa8640416bc6
---

# sess45 lessons (2026-06-02), build `3D36F352`

Continued the cross_write_read **di_size=0** blocker. User intervened: "stuck ~3
weeks, blown tens of millions of tokens — is the model capable / do we need something
different?" Honest answer given: model isn't the bottleneck; the loop has been
symptom-patching an architectural flaw (per-inode DLM over a shared inode cluster).
User chose **node-affine inode allocation** as the architectural direction.

## What was PROVEN (decisive, RULE-4 instrumented)
- **Isolated** write→sync→barrier→peer-read is fully coherent (`tests/dur_probe.sh`).
  The di_size=0 bug REQUIRES concurrency.
- **Write-side clobber** (P97): a node writes di_size=0 over an on-disk 1048576,
  `owned=1` (clobbered inode is in the flusher's `b_li_list`), `dlm_mode=5` (EX).
- **Trigger = atime-on-read** (P100 `dump_stack`): `filemap_read → touch_atime →
  xfs_vn_update_time → xfs_ilock(ILOCK_EXCL) → DLM EX → iflush stale di_size`. Reading
  a peer's file takes EX and flushes the reader's stale in-core inode, clobbering the
  peer's size to 0. (`rm`/xfs_remove is the other EX-on-peer path, but during cleanup,
  after the assertion.)
- **Inode cluster is entirely within one AG** → with node-affine, a cluster is owned
  by exactly one node. A node should never write a peer-AG inode cluster.

## DISPROVEN this session (don't re-chase)
- Read-staleness as PRIMARY: P98/P99 showed disk_di_size=0 at the read, but that was a
  CONSEQUENCE of the clobber, not a stale cache. (Overturns sess44's "read-side root.")
- Platter-vs-cache durability: `mxfs.fua_disable=1` (reads via bio, SCST shared cache)
  did NOT fix → not an FUA-read-vs-write-cache problem.
- Reload-clobber: `RELOAD-SIZE-DROP-SKIP` fired 0× → the reload path wasn't zeroing
  in-core. (Extended the guard anyway: dropped the `nblocks==0` requirement.)
- Pure atime: `noatime` alone cut clobbers 11→5 but didn't fix (rm path + residual).

## FIXES LANDED (build `3D36F352`, KEEP — all defensible)
1. **node-affine regular-file alloc** — `xfs_dialloc_pick_ag` (xfs_ialloc.c): multi-node
   regular files use `node_slot % maxagi`, not parent dir's AG. The cross_write_read
   TESTDIR is SHARED (created by one node); upstream parent-AG locality forced all
   nodes' files into one AG → one cluster → cross-node clobber.
2. **atime-on-peer-file skip** — `xfs_vn_update_time` returns 0 for an atime-only update
   of a regular file in a PEER's affine AG (helper `mxfs_inode_is_peer_ag`). Removes the
   dominant clobber trigger.
3. **getattr inode-DLM refresh** — `xfs_vn_getattr` takes ILOCK_SHARED (→DLM PR reload)
   before reading attrs (`mxfs_getattr_dlm_lock/unlock`).
4. **RELOAD-SIZE-DROP-SKIP** extended (drop nblocks==0).
- **RESULT**: `tests/cwr_probe2.sh` on a FRESH 2-node mount — concurrent write +
  cross-read (md5-first then stat) returns correct content AND size=1048576 both ways.
  **The basic di_size cross-read coherency is FIXED.**

## ⛔ REMAINING WALL (same as sess39-44): concurrent multi-file create corruption
Adding a `.md5` sidecar (2 files/node concurrently) trips:
- `bno + len > gtbno at xfs_alloc.c:2359` (bnobt double-alloc/overlap; P14-INSTR
  agno=1 bno=24 len=256 gtbno=32) → `xfs_defer_finish_noroll ... Shutting down`.
- `Metadata corruption at xfs_dir3_data_reada_verify block 0xc0` (shared-dir dir-block
  corruption under concurrent dirent add).
With node-affine (node1→AG0, node2→AG1), AG1 corruption is likely test2's OWN AG under
its own file+sidecar+dir load = possibly SINGLE-node bnobt RMW racing its own
dir-data-block alloc vs file-data alloc, NOT cross-node. NEXT: instrument the bnobt
ALLOC side (agbno chosen) vs FREE side + AG-DLM holder; fix the dir-block coherency
(sess37-39 dir-gen). Repro fast with `tests/cwr_probe2.sh` (file+sidecar variant).

## ⭐ POST-di_size: the remaining blocker is AG-meta (bnobt) durability race
After the di_size fixes, `tests/cwr_probe2.sh` (file+.md5 sidecar concurrent create)
still SHUTS DOWN with `ltbno+ltlen > bno at xfs_alloc.c:2244` (bnobt lost-update:
freeing [280,520) but bnobt shows [32,260915) still free → the allocation was lost).
- **NOT concurrent EX**: P15 `h_ex` is a HEX BITMAP (`%llx`), not a count. `h_ex=2`
  = 0x2 = bit1 = test2 holds EX; test1 sees it and registers-waiter. DLM mutual
  exclusion is CORRECT. (Do NOT chase concurrent-EX — sess44 lead 1 is CLOSED.)
- **It IS cross-node on the SHARED-DIRECTORY's AG**: node-affine isolates file
  INODES (node1→AG0, node2→AG1) but the shared TESTDIR's dir-data block lives in one
  AG that BOTH nodes modify (each adds its dirent) → cross-node AG-EX handoff on that
  AG → bnobt lost-update there. P14 shows the bnobt STALED at acquire (`verdict=
  STALED`); the FUA re-read returns a not-yet-durable pristine bnobt = the lost update.
- This is the documented sess42-44 **AG-meta durability-ordering** race: a releasing
  node's bnobt/cntbt/agf write must be PLATTER-DURABLE (destaged, not just in the SCST
  write cache) BEFORE the on-disk AG-DLM unlock, so the next acquirer's FUA-read sees
  it. Prior attempts: P81 release-FUA-write (too slow), P90 gen-bump (worse), P91
  FUA-write-through (no change). NEXT: verify the AG BAST/release path drains+flushes+
  blkdev_issue_flush the bnobt before unlock; make a FAST targeted destage of ONLY the
  dirtied bnobt/cntbt/agf blocks. OR reduce shared-dir AG contention (dir-data-block
  node-affinity?). The di_size work is DONE; this is the sole remaining cache_coherency
  blocker.

## Tooling added (tests/, persist per RULE 3)
`tests/cwr_repro.sh` (primary repro), `tests/dur_probe.sh` (isolated durability,
PASSES), `tests/cwr_probe2.sh` (concurrent; file+sidecar trips the corruption).
ENV: clean `/tmp/src*` on VMs (their `/` fills). Criteria NOT met; marker NOT written.

## ENV FIX (sess45): VM root disks grown 8G→28G (26G fs, 21G free)
test1-4 root LVs were 6.1G and FILLED by instr=1 P-log spam (kern.log 882M) →
spurious test failures (couldn't write /tmp sources → empty files looked like FS
bugs). User OK'd adding space. Grew live: `virsh blockresize testN vda 28G` then in
guest `growpart /dev/vda 3; pvresize /dev/vda3; lvextend -l +100%FREE
/dev/ubuntu-vg/ubuntu-lv; resize2fs ...`. Host (clyde) / has 233G free. If test5-16 /
test17-32 are brought up they have the SAME 6.1G root — grow them the same way before
heavy instr runs. Always vacuum logs (truncate /var/log/kern.log, journalctl
--vacuum-size=50M) between instr sessions regardless.

## ⭐⭐⭐ BREAKTHROUGH (sess45 cont): disk-fill was a HUGE confound + d_revalidate
After growing VM root disks (8→28G) so instr logs stop filling `/`:
- `tests/cwr_probe2.sh` (concurrent file+sidecar) went 8/8 OK — **the "bnobt corruption"
  was substantially a DISK-FULL artifact** (failed /tmp writes + metadata write failures
  on a full guest root manifested as "Structure needs cleaning"). NOT a pure mxfs bug.
- **cross_write_read PASSES 3/3** on 2 nodes with the di_size fixes.
- **2-node cache_coherency: ALL 4 sub-tests PASS** (cross_visibility, rename_visibility,
  unlink_visibility, cross_write_read).
- unlink_visibility was a STALE POSITIVE DENTRY (peer's unlink invisible: `ls` showed
  gone but `test -e` found it via cached dentry). FIX: re-enabled `s_d_op =
  mxfs_dentry_operations` (was disabled for perf) with a CHEAP node-affine gate in
  `mxfs_drevalidate` (xfs_super.c): POSITIVE dentry for OUR-own-affine-AG inode → skip
  (no parent DLM, dcache authoritative); NEGATIVE dentry → coordinated lookup (catches
  peer create = cross_visibility); PEER-AG positive → coordinated lookup (catches peer
  unlink/rename = unlink_visibility). This made 4-node cross_visibility go 124s→~12s
  (the slowness was the create-race visibility wait, now resolved) AND fast.
  ⚠️ FIRST attempt skipped negative-dentry revalidation → broke 4-node cross_visibility
  ("cannot see node1.txt"); RESTORED negative revalidation = correct.
- **4-node cache_coherency: passed=2 (cross_visibility, unlink_visibility), failed=2
  (rename_visibility 2/240, cross_write_read).** Both remaining failures =
  "peer reads writer's file content as EMPTY" for LOWER nodes (node1/node2), i.e. the
  di_size/content durable-before-visible race at 4-node concurrency (same family as
  cross_write_read, much reduced). NO corruption, NO shutdown, FAST (~12s/test).

## ⭐ NEXT (sess45 end / next session): the 4-node content-empty residual
rename_visibility fails 2/240: `Content preserved in node1_after_1: actual=''` on
peers — node1/node2's (rename-created, small-content) files read EMPTY on peers at
4-node concurrency. cross_write_read 4-node similarly. Root: durable-before-visible —
a peer reads a writer's file content before the writer's DATA is durable+visible. The
getattr DLM-PR-reload fixed SIZE coherency; the CONTENT (data pages / small inline
data) has a residual race. Investigate: does the peer's read-path IOLOCK-PR acquire
BAST the writer to flush its DATA (not just inode) before the peer reads? Is small
content inline (local-format) in the inode (covered by inode reload) or in a data
block (needs data-block durability)? Likely the writer's BAST flush must destage data
blocks before unlock, OR the peer must read data from disk not stale cache. Build
`5E279368` (di_size fixes + node-affine + cheap d_revalidate). 2-node green; 4-node 2/4.

## ⭐ 4-node cache_coherency residual ISOLATED: inode-number reuse carryover
cache_coherency.sh does ONE mount + 4 tests SEQUENTIALLY (cross_visibility,
rename_visibility, unlink_visibility, cross_write_read). Each test PASSES STANDALONE
on 4 nodes (rename_visibility 2/2 fresh). But run back-to-back, rename_visibility fails
1-2/240: consistently `Content preserved in node1_after_1: actual=''` (peers read
node1's FIRST renamed file as EMPTY = di_size=0). REPRODUCED: fresh mount → run
cross_visibility (PASS) → run rename_visibility (FAIL on node1_after_1).
ROOT = cross-node INODE-NUMBER REUSE: cross_visibility's `node1.txt` (lowest inode in
node1's affine AG0) is freed; rename_visibility's `node1_before_1` reuses that same
inode number; peers still hold a STALE cached in-core inode (di_size from
cross_visibility's use) for that number and a cached inode-DLM grant, so the peer's
read fast-paths (no reload) and returns the stale di_size=0. d_revalidate validates
NAME→ino (actual_ino==ip->i_ino, both reuse the same number) so it passes the dentry
but NOT the inode CONTENT/generation. The sess38/40 reuse fixes handle mode==0
(IRECLAIMABLE free→realloc); this is an ALLOCATED-inode generation-bump reuse the
peer doesn't detect. NEXT: on cross-node inode reuse, the peer must reload when the
on-disk i_generation differs from in-core (detect realloc), OR invalidate peers'
cached inode on xfs_ifree. Check xfs_iget_cache_hit generation check + whether the
read-path IOLOCK-PR acquire is a cached fast-path (no reload) for a peer-reused inode.
This is the SOLE remaining 4-node cache_coherency blocker (di_size clobber + dir
coherency + unlink all fixed; no corruption; ~12s/test).

## ⭐ CORRECTION: NOT inode-reuse (cross_visibility doesn't delete its files →
no inode freed → no reuse). The 4-node carryover failure (node1_after_1 read as
di_size=0/empty by peers, ONLY after cross_visibility ran first on the same mount) is
the di_size DURABLE-BEFORE-VISIBLE race — a peer reads node1's fresh rename-created
file before node1's inode (di_size) is durable+visible at 4-node concurrency. The
prior test's cache/timing state makes the race fire (standalone rename_visibility
passes 2/2 on 4 nodes). So the SOLE remaining cache_coherency blocker = the same
di_size durable-before-visible race, now intermittent (1-2/240) and only under
back-to-back 4-node load. The getattr ILOCK reload fixed the STAT path; the failing
read is `cat` (read path). NEXT: confirm whether the peer's `cat` read-path
(open→lookup iget, then read→IOLOCK-PR) actually forces an inode reload for node1's
file, or fast-paths on a cached grant; and whether node1's inode is durable when the
peer reads (instrument P98/P99 on the FAILING node1_after_1 read specifically). The
fix is likely: the read/open path must DLM-coordinate (reload) like getattr does, OR
node1's rename+sync must make the inode durable+peer-visible before the barrier.

## ⭐ FURTHER (sess45): residual is intermittent, P98/P99 do NOT fire
Reproduced carryover again: this time BOTH cross_visibility AND rename_visibility
failed (intermittent — earlier cross_visibility passed). Failing files vary
(node1_after_1, node3_after_2) — NOT always node1. CRUCIALLY: P98-GETATTR / P99-IGET
(di_size==0 detectors) did NOT fire on any peer during the failure. So the empty
`cat` content (`actual=''`) is likely NOT di_size=0 — more likely a transient
VISIBILITY/lookup race: the peer's `cat node1_after_1` momentarily ENOENTs (the rename
not yet visible) → cat fails → empty string. (d_revalidate should catch a stale
negative dentry, but the peer's FIRST lookup of after_N is in Phase 3 = cache-miss →
coordinated; so the window is elsewhere — maybe the rename's dirent isn't durable/
visible, or a brief lookup-vs-rename race.) NEXT: add a detector at the FAILING read —
log when a multi-node `cat`/open of a name returns ENOENT or 0 bytes for a peer-AG
file in a shared dir; correlate with the rename's dirent durability. The residual is
intermittent 1-2/240 under back-to-back 4-node load; standalone each test passes.
This is the LAST cache_coherency blocker (no corruption, no shutdown, fast ~12s).

## ⭐⭐⭐ TRUE ROOT of the 4-node residual: cross-node INODE REUSE (dir→file)
DECISIVE (rv_probe.sh + live inspect): the failing `cat node1_after_1` returns EISDIR
("Is a directory") while `stat` shows `regular file size=12 ino=131` on ALL nodes.
**`echo 3 > /proc/sys/vm/drop_caches` on the peer FIXES it** (cat then returns
content) → it is a STALE peer DCACHE/ICACHE, NOT on-disk. Mechanism: inode number
(e.g. 131) was a DIRECTORY (a churned barrier dir — the barrier mechanism creates/
deletes marker dirs between phases/tests → inode free+realloc), then REUSED as a
regular file (node1_after_1). Peers hold a stale cached in-core inode + dentry with
mode=S_IFDIR for ino 131; lookup/open returns the stale dir-inode → read → EISDIR.
The getattr fix reloads on STAT (shows regular) but the OPEN/READ path uses the stale
cached inode (lookup uses lock_flags=0, no DLM coordination → cache-hit returns stale).
So my earlier "NOT inode-reuse" correction was WRONG — it IS reuse, just dir→file
(mode change), driven by BARRIER-DIR churn, not the test's data files.
**THE FIX (next session): cross-node inode-reuse coherency.** A peer must detect that
a cached inode was reused (i_generation / di_mode changed on disk) and EVICT+
re-instantiate it (in-place mxfs_dlm_reload_inode is UNSAFE for a mode change — VFS
i_op/i_fop were set for the old type by xfs_setup_inode; must drop the inode and
re-iget). Options: (a) xfs_iget_cache_hit multi-node generation check (FUA-read di_gen;
mismatch → force reclaim/re-instantiate, like the sess40 IRECLAIMABLE reuse path but
for mode-change); (b) d_revalidate generation check (drop dentry AND evict inode on
gen mismatch); (c) coordinate xfs_ifree so peers drop the freed inode. This is the
SOLE remaining cache_coherency blocker (2-node green; 4-node only this intermittent
reuse-EISDIR). drop_caches workaround confirms it's purely a peer cache-invalidation
gap. NOTE: sess38/40 reuse fixes only handle mode==0 (free→realloc-same-type); this is
dir→file (type change) which needs eviction not in-place reload.

## ⭐⭐⭐ HONEST RE-ASSESSMENT (sess45 end): coherency is MULTI-FACET + intermittent
Quantified: 2-node cross_write_read = 2/3 PASS (1/3 intermittent FAIL). The failures
ROTATE through facets across runs:
  - di_size=0 (data read empty) — mostly fixed now (r3 data was correct 3937..).
  - dirent-not-visible (peer can't see a freshly-created .md5 sidecar: `No such file`)
    = directory-CONTENT visibility (peer's cached dir block missing the new dirent;
    first lookup reads it stale, xfs_lookup→xfs_dir_lookup(tp=NULL) does NOT acquire
    the dir DLM so no dir-gen reload).
  - EISDIR (inode-number reuse dir→file, stale peer inode mode).
ALL are the SAME architectural root in different costumes: **a peer trusts cached
metadata (inode size, inode mode, dir contents) it holds NO DLM grant on, and the
first uncoordinated access serves stale state.** Fixing one facet exposes the next.
This is why it's resisted for weeks — it's a CLASS, not a bug.
**DEADLOCK LEARNING: in-place inode reload during xfs_lookup (mxfs_dlm_reload_inode +
xfs_setup_iops under xfs_ilock(EXCL)) DEADLOCKS** (stat stuck in D-state, had to
virsh-reset 2 VMs). The detection (INODE-REUSE-DETECT, on-disk mode != in-core mode)
WORKS and is correct, but the in-place fix is unsafe — reuse needs EVICTION (drop stale
dentry → reclaim → recycle-reinstantiate), not in-place reload.
**HONEST FORECAST: point-fixes plateau.** The reliable fix is architectural: peers must
coordinate (DLM-acquire/validate) dir+inode metadata freshness on EVERY cross-node
access (GFS2 model — never cache grant-less), OR guarantee durable-before-visible on
every release. Both have a known perf tension (per-lookup DLM = barrier-timeout wall).
Build `F6C9DAAC` = `5E279368` (di_size+node-affine+atime-skip+d_revalidate fixes) +
detection-only INODE-REUSE-DETECT (instr-gated, no deadlock). Stable; 2-node ~2/3,
4-node 2/4. NOT a regression — the in-place-reload deadlock was reverted.

## ⭐ sess45 final: lookup-retry didn't help; durable-before-visible mechanism EXISTS but races
- Tried: xfs_lookup ENOENT-retry under dir ILOCK_SHARED (force dir-gen reload) to fix
  the .md5 dirent-visibility miss. RESULT: 5-run 3/5 PASS == 2/3 baseline (NO help) +
  adds a dir-DLM acquire to every ENOENT (could slow unlink_visibility's many `test -e`
  misses). REVERTED. The miss is durable-before-visible (peer's dirent not on the
  medium when we read), not a refreshable stale-cache.
- The dir-data durability mechanism ALREADY EXISTS: `mxfs_dir_data_durable` /
  `mxfs_dir_push_data_ags` (xfs_mxfs_dlm.c ~L82/135) run in the dir-inode BAST-release
  path (~L741) so a node makes dir DATA blocks durable before releasing on BAST. So the
  intermittent .md5 miss is a RACE WITHIN that path, not a missing flush. Candidates:
  (a) node1 doesn't hold the dir EX at node2's read time (released without BAST-durable),
  (b) the .md5 INODE's own durability (not the dir block), (c) node2 reads before
  node1's BAST-flush completes. NEXT: instrument the dir BAST-flush vs the peer read to
  find which; OR ensure the dir-DLM LAZY release (not just BAST) also runs
  mxfs_dir_data_durable + the new inode's durability.
- **Build F6C9DAAC is the stable head** (= 5E279368 di_size/node-affine/atime/d_revalidate
  fixes + instr-gated INODE-REUSE-DETECT; lookup-retry and in-place-reload REVERTED).
  2-node cross_write_read ~3/5; 4-node cache_coherency 2/4. No corruption/shutdown.
- **MARKER NOT WRITTEN.** Honest state: coherency is durable-before-visible (architectural,
  multi-facet, intermittent); point-fixes plateau; the di_size facet is fixed, the
  dirent/reuse facets remain as durable-before-visible races.

## ⭐ sess45 closing: durable-before-visible mechanism EXISTS — residual is a TIMING race
4-node cache_coherency this run: cross_visibility PASS, unlink_visibility PASS,
rename_visibility FAIL (1-2/240, content=''), cwr pending. The inode BAST-release path
(mxfs_dlm_bast_process) ALREADY does the full durable chain: filemap_write_and_wait
(L664) → invalidate_inode_pages2 (L666) → i_dlm_stale=true → blkdev_issue_flush destage
before unlock (L892/913, sess35 H26). So the 1-2/240 content-empty miss is NOT a missing
flush — it's a TIMING race: node2 reads node1's renamed file before node1's BAST-flush
completes, OR node1 isn't holding the inode DLM (released lazily) at node2's read so no
BAST fires and node2 reads stale. NEXT (fresh context): instrument the BAST-flush
completion timestamp vs node2's read timestamp for the FAILING node1_after_1 (P98/P99
+ a BAST-complete log), to confirm read-before-flush-complete vs no-BAST. If read-before-
flush: node2's PR-acquire must BLOCK until node1's BAST-flush fully completes (the grant
shouldn't be issued until the demote+flush is done). If no-BAST: node1's LAZY release
(not just BAST) must run the durable chain, OR node2's acquire must always BAST the
last-writer. 2-node now 5/5 on a clean cluster (di_size facet solid); 4-node 3/4.

## ⭐ sess45 closing-2: ilock_end is LAZY (no-BAST branch ruled out)
mxfs_dlm_ilock_end (xfs_mxfs_dlm.c:1898) only flushes/releases when
state==MXFS_DLM_ISTATE_BAST (a peer is waiting); otherwise it just decrements holders
and KEEPS the grant cached. So a writer holds its inode DLM cached after its op; a peer
read BASTs it → bast_process flushes (filemap_write_and_wait + blkdev_issue_flush
destage) THEN clears the grant bit, so the peer should acquire POST-flush. ⇒ the
"writer released without flush" branch is NOT the bug. The 1-2/240 residual is therefore
EITHER (a) a narrow BAST-flush-vs-grant timing window (peer's grant issued before
bast_process fully completes — check CAW grant ordering: does the waiter's CAS succeed
before the holder's flush finishes?), OR (b) the GRANT-LESS readahead cache: the peer's
iget of the renamed file hits an in-core inode instantiated via inode-cluster readahead
WITHOUT a DLM grant (so no BAST, no reload) — the same root as the di_size getattr issue
but for the read/content path. (b) is the more likely culprit and matches the
"peers cache metadata without a grant" theme. NEXT: instrument the FAILING peer read —
log whether the inode was a cache-HIT with i_dlm_mode==NL (grant-less readahead cache)
vs a fresh slow-path acquire; if grant-less-hit, force a DLM-coordinated reload on the
read path (like the getattr fix) for peer-AG regular files. Build F6C9DAAC stable.

## ⚠️ sess45 CORRECTION: 4-node cross_write_read STILL CORRUPTS (not just stale-read)
"No corruption" was 2-node-only. At 4 nodes, cross_write_read triggers
`xfs_inode_buf_verify` metadata corruption on inode blocks (0x1fda18, 0x5f8d48,
0x3fb3b0) → FS shutdown. This is the INODE-CLUSTER lost-update (P97 family) resurfacing
at 4-node concurrency: a node writes a stale/torn inode-cluster buffer that fails the
on-read verify. So the di_size fixes reduced it at 2 nodes but the inode-cluster
write-clobber + durable-before-visible STILL corrupts at 4-node scale. The honest 4-node
cache_coherency state: cross_visibility PASS, unlink_visibility PASS, rename FAIL
(1-2/240 stale-read), cross_write_read SHUTDOWN (inode-buf-verify corruption). So 4-node
is NOT 3/4-clean — cwr corrupts. The inode-cluster coherency (write a coherent cluster:
surgical per-inode write OR cluster-granularity DLM OR durable-before-visible on inode
release) remains THE core unsolved problem at scale, exactly as sess44 P97 found.

## ⭐ READY-TO-IMPLEMENT next fix: surgical per-inode inode-cluster write (gated)
The 4-node cross_write_read corruption = inode-cluster write-clobber (node writes whole
cluster buffer with a stale peer inode → xfs_inode_buf_verify fails → shutdown). THE FIX
(sess44-identified, now the confirmed central blocker): at the inode-cluster WRITE,
write ONLY this node's dirty inode sectors, never the whole cluster.
PRECISE PLAN (build on F6C9DAAC):
- Site: pal/linux/xfs_buf.c, in xfs_buf_submit, RIGHT BEFORE xfs_buf_submit_bio(bp)
  (after the P97 block ~L1775; the existing FUA-WRITE helper is mxfs_pal_scsi_write_fua_bdev,
  used at xfs_buf.c:1608 — mirror that, NO kmalloc, NO read = proven SAFE in submit per
  sess44 build 1F643C7C which did NOT hang).
- Gate: NEW module param `mxfs.surgical_inode_write` (default 0 → stable build unchanged).
  Only act when: param on, XBF_WRITE, multi-node, bp->b_ops==&xfs_inode_buf_ops (or _ra_ops),
  sb_inodesize>=512 && %512==0 (256B inodes share a sector → skip/fallback).
- Action: list_for_each_entry(lip,&bp->b_li_list,li_bio_list) for li_type==XFS_LI_INODE:
  iip=container_of(...,ili_item); off=iip->ili_inode->i_imap.im_boffset; isize=sb_inodesize;
  lba=bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset + off/512;
  mxfs_pal_scsi_write_fua_bdev(bp->b_target->bt_bdev, lba, bp->b_addr+off, isize).
  After all dirty inodes written: xfs_buf_ioend(bp); return;  (SKIP xfs_buf_submit_bio so the
  whole-cluster write — which carries stale peer inodes — never happens).
- Validate: mxfs.surgical_inode_write=1 + mxfs.instr=1; 4-node cross_write_read must stop
  the xfs_inode_buf_verify shutdown AND P97 INODE-CLUSTER-CLOBBER → 0; check no timeout
  (FUA-write per dirty inode is bounded). If di_size reads still wrong, that's the
  separate read-side/grant-less-cache path (getattr fix covers stat; read path needs the
  same). CAVEAT: surgical write leaves peer inode regions on disk untouched (correct), but
  the buffer's CRC covers the whole cluster — since we DON'T write the whole buffer (only
  sectors), peers' regions keep their own valid per-inode CRC; verify xfs_inode_buf_verify
  is per-inode not whole-cluster (it is — verifies each dinode). 
This is THE architectural fix for the inode-cluster facet; gate-off keeps it safe to land.

## ⭐ sess45 IMPLEMENTED: surgical per-inode write (build 5ED458EB, gated OFF)
Implemented the planned fix: pal/linux/xfs_buf.c xfs_buf_submit, just before the final
xfs_buf_submit_bio(bp) — when `mxfs.surgical_inode_write=1` (NEW param, default 0,
defined in xfs_mxfs_dlm.c), for a multi-node inode-cluster write it FUA-writes ONLY this
node's dirty inode sectors (b_li_list → ili_inode->i_imap.im_boffset, isize=sb_inodesize)
via mxfs_pal_scsi_write_fua_bdev, then xfs_buf_ioend + return (skips the whole-cluster
bio that would clobber peer inodes).  Falls through to normal submit if no inode written
or any FUA-write errors (correctness over optimization).  Gated OFF → stable build
(F6C9DAAC behavior) unchanged; build srcversion 5ED458EB.
VALIDATION LAUNCHED (background → /tmp/surg_test.txt, marker SURGDONE): deploys 5ED458EB,
sets surgical_inode_write=1 + instr=1, runs 4-node cross_write_read x3, reports
pass/fail + inode_buf_verify/shutdown count + P97 count.  EXPECTED if the fix works:
no inode_buf_verify shutdown, P97 INODE-CLUSTER-CLOBBER → 0, cwr passes (or only the
read-side di_size residual remains).  If it works, make it default-on (or wire it to
the inode flush path) and re-run full cache_coherency.  If it times out (per-inode FUA
cost) or doesn't fix, the alternative is cluster-granularity inode-DLM invalidation.
NEXT SESSION: read /tmp/surg_test.txt first.

## ⚠️ sess45 RESULT (re-recorded): surgical_inode_write=1 — PARTIAL/NO fix + SLOW
4-node cross_write_read, mxfs.surgical_inode_write=1 (build 5ED458EB): r1 PASS but r2
hit inode_buf_verify corruption (verify=1 on test2+test3) and ran 2+ min (slow, per-
inode FUA cost). So writing only this node's dirty inode sectors does NOT cleanly stop
the 4-node inode-cluster corruption AND is too slow. ⇒ the clobber is NOT solely the
whole-cluster write via this xfs_buf_submit path; corruption persists. NEXT: trace WHICH
write path produces the corrupt cluster when P97 fires (add a one-shot stack dump at the
inode_buf write); likely a non-b_li_list / readahead-writeback path, or a read of an
already-corrupt cluster. The better direction is CLUSTER-GRANULARITY inode-DLM
invalidation (on any peer inode modify, invalidate peers' cached cluster buffer) —
bounded cost, fixes both read-staleness and write-clobber. mxfs.surgical_inode_write
stays DEFAULT-OFF; stable head = F6C9DAAC. Param defined in xfs_mxfs_dlm.c; impl in
pal/linux/xfs_buf.c before final xfs_buf_submit_bio.

## ⭐ sess45 NEXT-EXPERIMENT (precise, for relay): characterize the verify-failure corruption
Surgical write didn't stop it ⇒ the corrupt inode cluster is NOT (only) written by this
node's whole-cluster flush. Two new hypotheses to discriminate FIRST (cheap):
1. READ of already-corrupt on-disk cluster (a peer wrote garbage) vs torn/transient
   in-core buffer: at the xfs_inode_buf_verify FAILURE, the kernel already dmesg-dumps
   "First 128 bytes of corrupted metadata buffer" — READ IT from the failing node's
   dmesg right after a 4-node cwr shutdown. Is it all-zeros (unwritten/torn), wrong
   di_magic (not 'IN'), a valid-but-wrong inode (stale incarnation), or random? That
   classifies it: all-zeros => inode-chunk init/alloc race (xfs_ialloc_inode_init via
   pag_mxfs_alloc_buflist not durable/coordinated); wrong-incarnation => reuse/clobber;
   random => torn write.
2. INODE-CHUNK ALLOCATION path: the corrupt block may be a FRESHLY-ALLOCATED inode chunk
   (xfs_ialloc_inode_init), not a flushed existing inode. Check if the failing block
   (0x1fda18, 0x5f8d48, 0x3fb3b0 last run) is in a just-allocated chunk. mxfs queues
   fresh cluster bufs to pag_mxfs_alloc_buflist with _XBF_DELWRI_Q|_XBF_MXFS_ALLOC_QUEUED
   (Phase-2 drained on AG release) — if a peer reads the chunk before this node's
   AG-release drains+destages it, peer reads uninitialized/garbage => verify fail.
DECISIVE INSTRUMENT: at xfs_inode_buf_verify failure (or in mxfs_buf read path for
inode_buf_ops), FUA-read the same block from the medium and log: in-core-corrupt vs
on-disk-corrupt, + first dinode magic/mode. on-disk-corrupt => a writer put garbage there
(alloc-init or clobber); in-core-only => transient read-vs-write. This single measurement
redirects the fix (durable inode-chunk-init-on-AG-release vs cluster coherency).
Build 5ED458EB deployed (surgical_inode_write default OFF). Cluster clean, 4 nodes.

## ⭐ sess45 refinement: alloc-time durable-before-visible (prime hypothesis for the dump)
mxfs_lazy_ag_drain defaults to 0 → AG-release uses the SYNC drain
(mxfs_dlm_ag_drain_alloc_buflist: xfs_buf_delwri_submit + blkdev_issue_flush destage).
So freshly-init'd inode chunks ARE destaged on AG release. ⇒ the async-no-flush path is
NOT the default culprit. PRIME HYPOTHESIS for the 4-node inode_buf_verify corruption: a
PEER reads an inode in a chunk the ALLOCATOR just created but has NOT YET AG-released
(chunk still in the allocator's pag_mxfs_alloc_buflist / delwri queue, not on platter).
Inode reads (xfs_lookup→iget, lock_flags=0) do NOT acquire the AG lock, so a peer can
iget+FUA-read an inode whose cluster is not yet durable → reads uninitialized/stale
platter → xfs_inode_buf_verify fails → shutdown. This is ALLOC-TIME durable-before-
visible (distinct from the flush-clobber the surgical write targeted — which is why
surgical write didn't help). CONFIRM via the corrupt-buffer dump: ALL-ZEROS / unwritten
= this (uninit chunk on platter). FIX options: (a) destage a new inode chunk before its
dirents become peer-visible (the create's AG-release already does, but the dirent can be
visible before release — need the chunk durable BEFORE the parent dirent is durable/
visible); (b) on a peer iget cache-miss of an inode whose cluster fails verify or reads
zeros, coordinate (acquire the AG or the allocator's inode-DLM to force the chunk drain)
then re-read; (c) make xfs_ialloc_inode_init FUA-write new chunks. Read /tmp/corrupt_dump.txt
(CZDONE) to confirm all-zeros before implementing. Build 5ED458EB, surgical_inode_write OFF.

## ⭐ sess45 latest: 4-node cwr fails with SIDECAR EMPTY cluster-wide (incl. writer)
This 4-node cross_write_read round: 3/3 FAIL, NO inode_buf_verify shutdown this time
(bad=0). Failure: "Node N verifies node4 integrity: expected='' actual='7ee9..'" for
ALL N including node4 itself → data_node4.md5 reads EMPTY even on its OWN writer node.
So NOT cross-node staleness — node4's own sidecar is empty/unreadable cluster-wide. This
is the inode-cluster corruption family WITHOUT a verify-shutdown: the small .md5 file's
inode/cluster is bad → reads empty everywhere. (The 1MB data inode is fine: actual md5
correct.) So the inode-cluster corruption sometimes → verify-shutdown, sometimes →
silent-empty-file. Both = the same inode-cluster write/init coherency root. CONFIRMS the
problem is inode-cluster integrity (di_size/content/whole-inode), NOT a pure cross-node
read race. The corrupt-buffer DUMP still needs capture (the verify-shutdown is rarer than
the silent-empty); re-run cwr 4-node a few times to catch a verify-shutdown and read its
"First 128 bytes" dump. Prime fix hypotheses unchanged: alloc-time durable-before-visible
(uninit chunk) OR inode-cluster write-clobber/merge. Build 5ED458EB (surgical OFF),
stable head F6C9DAAC. Cluster needs fresh mkfs (FS corrupt).

## ⭐ sess45 PRIORITY refinement: 4-node cwr DOMINANT failure is STALE-READ, not corruption
Dump-capture run: r1 fail=1 verify_hit=0 (stale-read, NO verify-corruption). So at 4
nodes, cross_write_read fails MOSTLY on stale-read (di_size empty / sidecar empty cluster-
wide / content empty), and the xfs_inode_buf_verify SHUTDOWN is the RARE case (caught
only intermittently). ⇒ RELAY PRIORITY: fix the 4-node STALE-READ first (it's the common
failure), not the rare corruption. The stale-read = grant-less-cache / durable-before-
visible read-side: a peer reads a writer's inode/sidecar before it's durable+visible, OR
reads its own grant-less cached copy. The getattr DLM-reload fixed STAT at 2-node but the
4-node read/content path (cat → open → read → IOLOCK PR acquire → reload) still returns
stale/empty intermittently. NEXT (relay): instrument the FAILING 4-node read — at the
peer's iget/read of the empty file, log cache-hit-vs-miss + i_dlm_mode + a FUA disk
di_size, to see if it's (a) grant-less cache-HIT (i_dlm_mode=NL, no reload) → force reload
on read for peer-AG inodes, or (b) durable gap (disk also empty) → writer durable-before-
visible. NOTE the sidecar-empty-on-OWN-node (node4 sees own data_node4.md5 empty) suggests
a WRITE/durability issue for small files, not just cross-node read. Build 5ED458EB stable.

## ⭐ sess45 CONFIRMED (data): 4-node cwr dominant failure = STALE-READ, corruption rare
Dump-capture run: r1/r2/r3 all fail=1 with verify_hit=0 (3/3 stale-read, ZERO verify-
corruption in 3 runs). CONFIRMS: the 4-node cross_write_read failure is overwhelmingly
the STALE-READ facet (di_size/content empty, incl. a node's own sidecar reading empty),
and xfs_inode_buf_verify corruption is RARE (secondary). ⇒ RELAY: focus the fix on the
4-node STALE-READ, not the corruption. This is grant-less-cache / durable-before-visible
on the READ+small-file-write path. The getattr DLM-reload fixed STAT at 2-node; the
4-node read/content path still returns stale/empty. The "own-node sidecar empty" is the
sharpest lead: node4 reads its OWN data_node4.md5 as empty → the small sidecar file's
in-core di_size is 0 at read (its create's di_size=33 didn't stick, OR a BAST-reload /
iflush_cluster clobbered it to 0). DECISIVE NEXT INSTRUMENT (relay): at the FAILING read
of an empty file, log {cache hit/miss, i_dlm_mode, in-core di_size, FUA-disk di_size,
RELOAD-SIZE-DROP-SKIP fired?}. Forks: disk!=0 in-core=0 => stale in-core (grant-less
hit; force reload on read for peer-AG); disk==0 => small-file write/durability gap. Build
5ED458EB stable; surgical_inode_write OFF. (verify-corruption dump still being hunted in
bg for completeness but is NOT the priority.)

## ⭐⭐⭐ sess45 DECISIVE (P98/P99 data): disk_di_size=0 EVERYWHERE → WRITE-side, not read-stale
4-node cwr, instr=1, P98-GETATTR + P99-IGET-HIT + P99-IGET-MISS on ALL 4 nodes at the
failing reads: UNIFORMLY incore_size=0 AND **disk_di_size=0**. Per the detector legend,
disk==0 => WRITER NOT DURABLE (the writer's di_size is genuinely 0 on the platter when
read), NOT a stale in-core cache (which would show disk!=0). P99-IGET-MISS (cache-miss,
fresh FUA disk read) ALSO sees disk=0 → confirms the medium has di_size=0. So the
4-node cross_write_read di_size=0 failure is the WRITE side: the writer's inode is 0 on
the platter — either never destaged OR clobbered to 0 (P97: a node flushes a stale
inode-cluster buffer with di_size=0 over the correct value). This RESOLVES the earlier
read-vs-write fork: it is WRITE-side. ⇒ RELAY FIX DIRECTION: ensure the inode-cluster's
di_size reaches the platter durably AND is not clobbered by a stale-cluster write — i.e.
inode-cluster write coherency / durable-before-visible on the WRITE/flush+release path,
NOT read-side reload (the getattr/d_revalidate read fixes can't help when disk itself is
0). The surgical per-inode write targeted this but was partial+slow; the clobber persists
because a node flushes its OWN inode with in-core di_size=0 (a reload set it 0, OR the
create's di_size update was lost before flush). NEXT: instrument WHY a node's in-core
di_size becomes 0 for a file it wrote 1MB to — log at xfs_iflush when writing di_size=0
for a regular file with the in-core history (was it reload-set? recently written?).
Then the symmetric guard (don't flush di_size smaller than disk for a reg file unless
truly truncated) OR fix the reload/lost-update that zeros in-core. Build 5ED458EB stable.
