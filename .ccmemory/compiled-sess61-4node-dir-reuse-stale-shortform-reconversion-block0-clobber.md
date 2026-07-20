---
name: compiled-sess61-4node-dir-reuse-stale-shortform-reconversion-block0-clobber
description: sess61 compiled: 4/tcp dir_reuse_coherency durable node1_f* loss = dirty stale block0 kept by drain-evict dirty-guard; grant_gen fix refuted.
metadata:
  type: project
tags: [compiled, sess61, dir_reuse_coherency, tcp-dlm, block0-clobber, dirty-keep-guard, grant-gen, shortform-reconversion]
---

## sess61 — dir_reuse_coherency 4/tcp durable node1_f* loss (compiled)

Central topic: the `dir_reuse_coherency` ship criterion (must pass 1/2/4/8 tcp
100%) fails only at **4 nodes over TCP DLM**. 1/tcp=16/16, 2/tcp=17/17 (sess58);
8/tcp never run. Representative baseline (diagnostic probes OFF): **~2/24 rounds
fail** (rounds 19-20). Peers (rank2/3/4) durably miss a `node1_f*` entry; **the
creator (test1) NEVER fails**. sess61 changes did not regress this baseline.
Root proven this session via RULE-4 direct evidence; the sess10 `grant_gen`
fast-path fix was implemented and REFUTED.

### Build progression (sess61)
- **55885EED** — PROVEN ROOT #1: stale in-core SHORTFORM re-conversion clobber.
- **289E7862 / A2C435A6** — `mxfs_dir_modify_adopt_disk_format()` (inode-fork
  format/nextents/size adopt) attempt — REFUTED, call is `if(0)` disabled.
- **E658513F** — P61-BLK0 buffer-level probe (bufgen/incarn/dirty/inail/pin).
- **75E5FD35** — handoff-point build, deployed, criterion NOT met.
- **7B1FF03F** — full sess10 `grant_gen` fast-path fix implemented; REFUTED
  (regressed to 16/24); harmful action GATED OFF behind `mxfs.dirwr` (default
  OFF) so baseline is restored. Infra + detection probe KEPT. Head build for
  next session; baseline ~2/24 NOT re-verified post-gating — VERIFY FIRST.

### Root cause — one bug, characterized at three depths
The mechanism is a **write-side stale-base RMW clobber**: an EX holder writes a
cached block0 whose content is BEHIND disk, overwriting peers' durable dirents.
The three memories below are progressively refined views of the SAME failure,
not three bugs.

1. **Fork-format face** [[sess61-PROVEN-ROOT-stale-shortform-reconversion-clobbers-disk-block-dir]]
   (55885EED, test4 r15): a node holding a STALE in-core SHORTFORM view re-converts
   sf->block via `xfs_dir2_sf_to_block`, materializing block0 with ONLY its own 11
   entries while disk is long since BLOCK format with 68+ entries (peers converted
   and grew). Decisive trace: `P42-SFCONV ino=131 sf_count=11 dlm_mode=5`,
   `P60-SFCONV-BASE node1f_cnt=0 has_node1_f1=0`, `P61-BLK0 core_node1=0
   disk_node1=68`. The conversion erases the disk block dir → node1_f1..f50
   durably lost on ALL nodes. Architectural constraint (in code): the MODIFY paths
   (`mxfs_dlm_dir_modify_refresh`, xfs_mxfs_dlm.c ~2852) only evict cached dir DATA
   blocks; they do NOT reload the inode fork because `mxfs_dlm_reload_inode` does
   `down_write(i_lock)` which SELF-DEADLOCKS under the held ILOCK_EXCL. So modify
   reaches `xfs_dir2_format` / `xfs_dir2_sf_to_block` with a stale fork. Two faces
   from this one gap: stale BLOCK->LEAF map → di_size!=blksize EFSCORRUPTED
   shutdown (sess57), and stale SHORTFORM → re-conversion clobber (this loss).

2. **Content/data-buffer face (dominant steady face)** [[sess61-REFINED-content-level-stale-block0-buffer-RMW-clobber]]:
   the fork-adopt attempt `mxfs_dir_modify_adopt_disk_format()` (called in
   xfs_create at xfs_inode.c ~1492; FUA-reads dinode, drops+reloads if in-core
   fork fmt/nx/size is behind disk for same di_gen) was REFUTED — P61-ADOPT-CHK
   shows `incore_fmt=2 disk_fmt=2` on 100/100, never gen-mismatch, never
   disk-ahead. Under EX the inode METADATA is never behind disk. The actual
   staleness is CONTENT-LEVEL in the cached DATA block buffer: create-time
   (comm=dd, dlm_mode=5) P61-BLK0 shows `core_node1=0 disk_node1=76` (in-core
   block0 EMPTY while disk has peer dirents). The node RMWs that stale buffer and
   writes it back, clobbering `node1_f1` etc. At VERIFY (PR) the block reads
   coherent (core==disk) via the sess60 readdir gen-bump — damage is already
   durable. The node does NOT re-convert here (P61-ADOPT-CHK never shortform), so
   the shortform-reconversion of face 1 was a faster-timing face; the steady
   dominant face is a stale cached EXTENTS block0 buffer.

3. **Buffer-level DECISIVE** [[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]]
   (E658513F): the clobbering in-core block0 buffer is **dirty=1, bufgen=0,
   inail=0, pin=0** while inode `i_dlm_dir_gen=20/24/34`. So `bufgen(0) <
   i_dlm_dir_gen` — the MXFS tenure-gen mechanism ALREADY FLAGS the buffer stale,
   but the dirty-protection guard KEEPS it (dirty/pinned/in-AIL kept to protect
   own un-checkpointed work). The buffer is EMPTY of node1 entries (core=0) while
   disk holds 63-88 at the SAME daddr, same incarnation, DISJOINT content
   (node4's own entries vs peers' node1 entries). Each node independently
   MATERIALIZED block0 (data_init/conversion) from its own base; last writer
   wins on disk. P60-LBMAP ("daddrs agree, not a split") was about the EXTENT
   MAP; the CONTENT at that shared daddr DIVERGES per node = the sess36/sess42
   divergent-block0 root, now characterized at the buffer level at 4 nodes.

### The exact code gap [[sess61-FINAL-dirty-keep-guard-in-drain-evict-is-the-gap]]
`mxfs_dir_drain_evict_data_blocks` (xfs/xfs_mxfs_dlm.c:3736; called on slow-path
EX reacquire ~10266 AND from the fast-path stale-refresh ~9781) evicts a cached
dir block (clears XBF_DONE → next read FUA-refetches disk) ONLY when (line ~3983):
```
(dbp->b_flags & XBF_DONE) && !pinned && !dirty && !delwri &&
(!in_ail || !mxfs_dir_buf_is_undestaged(dbp))
```
A **DIRTY** block is NOT evicted — it is KEPT and served to the RMW. Same
dirty-keep guard as `mxfs_dir_evict_data_blocks` (~2382). The code's stated
assumption (comment ~3978) — "a genuine peer modification implies WE released EX
first, and the release drain (Invariant #1) destages our blocks out of the AIL,
so at a true peer-modified acquire these conditions never hold" — IS VIOLATED
here: a dirty content-behind-disk block0 (bufgen=0) exists at acquire. sess41
added an evict-side refresh, but it only handles a block kept for being
in-AIL-CLEAN-undestaged (FUA-compares, drops XBF_DONE if disk has strictly more
live dirents); it SKIPS dirty/pinned/delwri. GPT-5.5's invariant: dirty
CURRENT-tenure buffers are protected, but dirty OLD-tenure (bufgen < dir_gen)
buffers are corruption and must NOT reach disk.

Three candidate origins of the dirty-stale block0 (open): (a) release-drain did
not destage/clean it; (b) it became dirty after acquire via an EARLIER create in
the same wave that RMW'd a stale base; (c) a conversion/grow `data_init`
materialized block0 empty on a stale base (bufgen=0 = freshly init'd, never
tenure-stamped) — most consistent with the bufgen=0 observation.

### Refuted this session (do NOT repeat)
- Logical-block-0 SPLIT (sess42): P60-LBMAP — all nodes resolve dir logical-0 to
  the SAME daddr, same i_gen, same nextents. Extent maps agree.
- Read-side stale-serve: at verify (PR) block0 core==disk; the sess60 readdir
  gen-bump keeps read/PR path coherent. P34-TRYLOCK-STALE / DIR-STALE-SKIP /
  P60-GENMATCH-STALE all ~0 on read path.
- Double sf->block conversion as a distinct bug: P42-SFCONV i_gens all DISTINCT
  per node — one converter per incarnation.
- Inode-FORK staleness / `mxfs_dir_modify_adopt_disk_format()`: fork fmt/nx/size
  never behind disk under EX (P61-ADOPT-CHK). Helper KEEP disabled or delete;
  never fires.
- Logical-block split / read-side stale-serve / double-grant: double-grant
  already fixed earlier in dlm.c gen-token.

### The grant_gen fix — implemented and REFUTED
[[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]] laid out sess10's
plan: the dir-EX fast path trusts only `i_dlm_dir_gen`, which is bumped by the
LOSSY async DIR_MODIFY eviction-ring (`note_dir_modified`) that drops messages
on TCP — so the fast path serves a stale base. Plan: use the reliable per-grant
`grant_gen` as the "lock changed hands" token. Implemented in full (7B1FF03F,
[[sess61-grant-gen-fix-REFUTED-overfires-need-peer-owner-signal]]):
`mxfs_dlm_grant_gen(ctx,res)` in dlm/dlm.c(+.h), `mxfs_v5_dlm_inode_grant_gen`
in v5_mount.c(+.h) (TCP-only, 0 on CAW), `i_dlm_cached_grant_gen` in
xfs_inode.h, cached on slow-path grant (~10225), compared on fast-path serve
(~9639) forcing dir_ex_stale_refresh + i_dlm_dir_gen++ on mismatch
(P61-GG-FASTSTALE).

RESULT: REGRESSION. The check FIRED (5-13x/node) but failures went ~2/24 →
**16/24 (r3-r20), nodes_pass=0/4**. WHY: `lk->grant_gen = dlm_next_gen(ctx)` is
assigned on EVERY waiter→GRANTED promotion (dlm/dlm.c:624), including BENIGN
SAME-NODE re-grants (MHT release+reacquire churn with no peer between). So
grant_gen is a monotonic per-grant-episode counter, NOT a clean "handed to a
PEER" signal. The check OVER-FIRES on ordinary same-node re-grants, forcing the
heavy evict+fork-rebuild far more often than the lossy ring — and the forced
cold refresh hits the sess100 hazard (returns a stale image MISSING this node's
own just-committed-not-yet-published change) → drops own work → mass failures.
sess10's premise ("grant_gen changes only when the lock changed hands") is
FALSE. Action gated OFF behind `mxfs.dirwr`; infra + P61-GG-FASTSTALE probe kept.

Refined signal needed: not "our grant_gen changed" but "a node OTHER THAN US
held EX between our grants". Options: (1) master tracks per-resource prior EX
owner, exposes a `peer_ex_epoch` bumping only when a DIFFERENT node gets EX
(needs local mirror to learn peer grants — on TCP only via BAST). (2) KEY
INSIGHT: a real cross-node handoff REQUIRES this node to receive a BAST and
RELEASE, so its next acquire is a fresh SLOW-PATH grant where the slow-path
reload already adopts disk and re-sets the cached gen (fast path would then
MATCH, no false fire). So the real question: in the failing case, is the
clobbering RMW on a FAST path that skipped the slow-path reload, or does the
slow-path reload itself fail to adopt the peer's block0 DATA? Strong lead:
`mxfs_dlm_reload_inode` stales the INODE-CLUSTER buffer but does NOT evict the
dir DATA-block buffers; `mxfs_dir_drain_evict_data_blocks` runs on the slow path
(~10221) but KEEPS the dirty bufgen=0 block0 — so even a correct slow-path
reacquire keeps the dirty stale block0. The fix belongs in the DATA-block evict.

### A vs B — which layer (must resolve before the real fix)
[[sess61-HANDOFF-state-and-next-steps]] frames the fork: for an EX holder's
in-core block0 to be behind disk, either **A** (stale cached/own buffer: node
released EX, peer grew disk, node reacquired but its dirty/in-AIL block0 was
never refreshed — fixable in dir/DLM-acquire layer) or **B** (TCP DLM
double-grant: two nodes held dir-inode EX concurrently, peer grew disk while
this node held EX with its dirty buffer — no dir-layer fix works; sess49 flagged
TCP double-grant residual). The buffer being dirty=1 (uncommitted) at reacquire
while disk advanced leans toward B but is not conclusive. The CAW detector
`mxfs_v5_dlm_inode_ex_count` returns ex_pop=0 on TCP (CAW-only) — USELESS for
TCP double-grant. NEXT must add a TCP-DLM-grant-path EX-overlap detector: at the
TCP master/grant assert ≤1 EX owner per inode resource with monotonic
grant/release cookies, OR stamp a per-EX-grant epoch on the inode and assert at
first buffer-dirty that block0 was validated under the current epoch.

GPT-5.5 fix design (once A/B known): if **A**, tenure-cookie invariant — never
let a dir buffer be dirtied unless it was read/init under the CURRENT EX tenure;
at EX (re)acquire, before the modify trans dirties block0, invalidate+reread
stale CLEAN buffers; a stale DIRTY buffer is an invariant violation. Do NOT
union-merge dir2 blocks (breaks leaf hash/bestfree). Do NOT rebuild the inode
fork mid-transaction (iflush-corruption shutdown class). Do NOT blindly drop a
dirty buffer joined to the live trans. Preferred: PREVENT block0 being
materialized/dirtied on a stale base — guard MATERIALIZATION in
`xfs_dir3_data_init` / the sf->block + block->leaf grow for logical block 0 of a
multinode dir: FUA-check disk; if disk already holds a valid same-incarnation
populated dir block at that daddr, ADOPT disk (read it in) instead of zeroing
(sess36/sess42 lineage). Or force block0 drain-then-reread at a genuine
peer-handoff reacquire (post_release, dir_gen advanced) at a safe point (no
active trans), NOT keep it. If **B**, fix the TCP DLM grant to enforce EX
exclusivity — no dir-layer fix will work.

Also needed: a lock-held-safe inode-fork reload for the modify path (caller
holds ILOCK_EXCL) — a `reload_locked` variant that re-reads the dinode and
rebuilds the data fork WITHOUT re-taking i_lock, triggered when modify-refresh
(or the top of `xfs_dir2_sf_to_block`) detects disk di_format/di_gen shows a
peer already converted/grew this incarnation past our in-core shortform. Safe in
the sf-stale case (conversion is the first modify, no own un-checkpointed mods
yet).

### Instrumentation / ops (in tree)
- P61-BLK0 (xfs/libxfs/xfs_da_btree.c after block0 read): in-core vs FUA-disk
  node1 count + bufgen/incarn/dirty/inail/pin + ex_pop. Per-read FUA perturbs
  timing (amplifies ~2/24 → 15/24) — GATED behind `mxfs.instr`; run
  `mxfs.instr=1` to diagnose, OFF for representative runs.
- P61-ADOPT-CHK / P61-ADOPT-DISK, P60-LBMAP (xfs_mxfs_dlm.c / xfs_da_btree.c).
- P61-GG-FASTSTALE (grant_gen fast-path), gated behind `mxfs.dirwr` (OFF).
- Per-failure dmesg snapshot: tests/suite/dir_reuse_coherency.sh dumps dmesg →
  `/root/drc_fail_r${round}_rank${R}.dmesg` on failure (KEEP — ring wraps fast).
- P-DIRFLUSH capped at 40 (xfs/libxfs/xfs_inode_buf.c, noise cut).
- `mxfs_dir_modify_adopt_disk_format()` call in xfs_create/xfs_inode.c is `if(0)`
  disabled (REFUTED) — can delete.
- Repro: `./run.sh 4 tcp dir_reuse_coherency`; completion marker `=== done:` in
  the run log (NOT pgrep). Reset between runs: `virsh -c qemu:///system
  destroy+start test1-4` (device-busy otherwise). `pr_warn(4)` does NOT reach
  console at default loglevel 4.
- RULE-0/PERF: ~13s/round × 24 ≈ 312s vs 300s TEST_TIMEOUT — even a fully
  coherent run risks timing out near round 24; a per-round cost cut is also
  required, not just correctness.

### Immediate next-session checklist
1. VERIFY baseline: `./run.sh 4 tcp dir_reuse_coherency` on 7B1FF03F should be
   ~2/24 (grant_gen action gated OFF) — NOT re-verified this session.
2. Add the TCP-DLM EX-overlap detector to settle A vs B decisively.
3. If A: instrument WHY the dirty content-behind-disk block0 exists at acquire
   (bufgen, incarn, BLI lsn vs written_seq, last logger, whether a release-drain
   ran since the peer's grant) — likely origin (c), materialization on a stale
   base; fix at materialization (adopt disk block0) or force safe
   drain+reload at genuine peer-handoff acquire. If B: fix the TCP DLM grant.
