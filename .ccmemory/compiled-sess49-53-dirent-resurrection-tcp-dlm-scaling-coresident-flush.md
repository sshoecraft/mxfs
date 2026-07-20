---
name: compiled-sess49-53-dirent-resurrection-tcp-dlm-scaling-coresident-flush
description: sess49-53: cache_coherency P43 fix, dir-EX upgrade livelock, durable dirent resurrection via stale SF flush + merge-union; criterion NOT met (4/5).
metadata:
  type: project
tags: [compiled, dlm, dirent-resurrection, tcp-dlm-scaling, cache-coherency, shortform-dir, release-durability, iunlink]
---

# sess49-53 — dirent resurrection, TCP DLM scaling, and co-resident shortform-dir flush

Central thread across sess49-53 (ccloop `8ddb16a2`, criterion = full `./run.sh 2 tcp`
reliably **17/17**): the last MXFS ship blocker collapsed from the 90-session
`cache_coherency` read-side bug (FIXED sess49) into a `tcp_dlm_scaling` /
`dlm_fairness` cluster of dir-coherency faults on a *shared hot directory* under
concurrent create+rename+rm churn: a symmetric PR→EX dir-upgrade livelock (FIXED),
an iunlink corruption shutdown (patched, suspect), and a **durable dirent
resurrection** that is still open at sess53 end. Best reliability reached: **4/5**
on plain defaults. Marker NEVER written through sess53.

Two-node LIO rig fact (kills a wrong sess48 premise): storage is **LIO fileio over
`/home/steve/disk.img`, ONE instance on clyde, virtio-scsi to both VMs = ONE coherent
host page cache** (`emulate_write_cache=0`). No per-initiator/SCST read cache — never
chase SCST/FUA for coherency on this rig. DLM mode enum: `0=NL 3=PR 5=EX`.

## sess49 — cache_coherency FIXED (build DBA88871)

`./run.sh 2 tcp` hit **17/17** for the first time; `cache_coherency` standalone 10/10,
`dir_reuse_coherency` 2/2. Root of the 90-session blocker was a **read-side guard
misfire**, not storage ([[sess49-ROOT-cache_coherency-uv-is-P43-fmtrevert-guard-misfire]]).
The `unlink_visibility` (uv) subtest: test1 reader saw node2's last 10 deletes because
its in-core dir inode was a **stale BLOCK fork** while the LUN held the correct
SHORTFORM image (proven by `echo 3 > drop_caches` → count 0, size 6). The
`P43-DIR-FMTREVERT-SKIP` guard (`xfs_mxfs_dlm.c` ~6837 + P43B snapshot ~7112), built
in sess43 for `dir_reuse` (CREATE-only, dirs only grow), refused node2's durable
block→shortform shrink and pinned the stale block fork forever.

FIX (KEEP, DBA88871): a **soundness gate** on P43/P43B — keep the in-core block ONLY
when authoritative: `dfr_dirty` (pincount>0 || ili_fields || IN_AIL) OR
`dfr_grant_held = (i_dlm_mode == MXFS_LOCK_EX)`; else fall through and adopt the disk
shortform (`P43-ADOPT-PEER-SHRINK`). Must be **EX-only**, not `mode!=NL`: the acquire
path sets `i_dlm_mode=PR` *before* the reload, so `mode!=NL` still flagged a PR reader
authoritative → ~15% flake. A PR holder cannot have unshared writes, so a PR copy
differing from durable disk is stale and must adopt. EX-gate = identical behavior to
the old guard for EX holders (no `dir_reuse` regression). Oracle: `uv_disktruth2.sh` +
`drop_caches` reproduces the divergence in ~1 iter.

The sess49 residual was then fully traced ([[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]]):
`tcp_dlm_scaling`/`dlm_fairness` "drained got>=1" leftover dirent, durable (survives
`drop_caches` on both nodes = write-side resurrection, not read-side). Both tests pass
STANDALONE, fail IN-SUITE = cumulative-churn contamination. sess49 diagnosis blamed a
**TCP DLM double-grant**: a dropped/un-honored TCP BAST leaves stale cached
`i_dlm_mode==EX`, both nodes RMW the shortform fork, one resurrects the other's removed
dirent; the read-side coherent fix `mxfs_dir_sf_refresh_if_disk_differs`
(`xfs_mxfs_dlm.c:8176`) + `mxfs_dir_sf_3way_merge` can't save it when the peer's removal
isn't yet destaged. Verification impossible on TCP because `mxfs_v5_dlm_inode_held` is a
NO-OP (returns 1). Fast repro: `tests/tcp/repro_rename_drain.sh 150 8`. **This
double-grant theory was later REFUTED in sess50** (`P106-STALE-EX` fired 0×,
`P-DOUBLEGRANT`=0).

## sess50 — resurrection root = fast-path SF-merge re-add (build E67385C9)

FIX B (KEEP) killed the resurrection at its real source ([[sess50-ROOT-resurrection-is-fastpath-sfmerge-readd-FIX-B]]):
the durable dirent came from the **cached-EX FAST PATH** (`i_dlm_state==CACHED`,
`peer_mod=0`) where the SF 3-way merge re-added the node's *own* async-destaged-then-
removed shortform dirent (theirs-loop "in theirs !ours !base") — NOT a DLM double-grant.
On a continuous-hold fast path the in-core fork is authoritative (a peer modify needs EX,
which BASTs us off CACHED), so it must NOT adopt lagging disk. Fix (`xfs_mxfs_dlm.c`
~9018): gate `mxfs_dir_sf_refresh_if_disk_differs` behind global `int
mxfs_sf_fastpath_adopt = 0` (default 0 = fix). Fast-path re-adds → 0/0; `./run.sh 2 tcp`
17/17 once. (Note: forgot the `module_param_named` for A/B; global default works.)

New residual surfaced: `tcp_dlm_scaling` **slowness/stall** — a single dir-EX handoff
stalls ~60s then fails (`rounds exp=150 got=45`, `within window`>60s). `mxfs_dlm_lock`
retries 60×1000ms on `-ETIMEDOUT` (`dlm.c:1389`), so one unrecovered stall blows the
whole window. Suspected sess13/33 cross-resource inode-EX↔AG-DLM deadlock or a
lost-message handoff; worse in-suite (`tcp_dlm_scaling` runs last, 16 prior tests churn
the LUN).

## sess51 — tcp_dlm_scaling root = symmetric PR→EX dir-upgrade livelock

PROVEN via 5+ min of live thrash dmesg ([[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]]):
NOT the cross-resource deadlock. bash `open(O_CREAT)` does `lookup(dir PR)` then
`create(dir EX)`; mxfs caches the PR (holds till BAST), so create is a PR→EX **upgrade**.
Both nodes cache PR + both want EX → the master's upgrade path (`dlm/dlm.c:2574`
CONVBLK-DENY, inode-scoped) DENIES with `-EDEADLK` and does NOT bast the conflicting
holder. The loser (P109, `xfs_mxfs_dlm.c:9370`) drops PR→NL **through the full
bast_process drain pipeline** (`mxfs_dlm_dir_inode_durable` → `mxfs_inode_cluster_durable`:
log_force SYNC ~2s + iflush_cluster + blkdev_flush) and re-requests → re-collides. The
~2s clean-PR-release drain (pure waste: PR is read-only, nothing dirty) is the amplifier.
Signature on `/mnt/shared` root dir ino=128: `P-CONVBLK-DENY` / `EDEADLK` /
`P35-DIRHONOR` / `P62-RELOAD-FORK-SHRINK` cycling every ~6s. The `mxfs_inode_mht_ms=300`
MHT defer only engages when WE hold EX — useless here since the loser holds PR.

sess51 tried three release-skip widths of skipping `mxfs_dlm_dir_inode_durable` on a
provably-clean release (`held_mode!=EX && xfs_inode_clean && !in_ail && pin==0`), param
`mxfs_dir_pr_release_fast` (0=off, 1=self-demote-only DEFAULT, 2=broad-all-clean),
captured held-mode at entry, `P51-REL` always-on log:
- **BROAD skip** (FFC0DA1D): `tcp_dlm_scaling` 4/4 PASS (EDEADLK hundreds→1-2, drain
  2000ms→1-3, TDS-LEFTOVER=0, 0 shutdowns) — but EXPOSED `dir_reuse_coherency` +
  `rsync_paired` ~17% fail each. The clean-release log_force was an **incidental
  coherency-masking barrier**; removing it un-masks the sess37/40 stale-block-RMW family
  on BLOCK/LEAF dirs ([[sess51-dir-reuse-exposed-by-durability-skip-stale-block-race]]).
- **SELF-demote-only** (build D50912EB): `dir_reuse`/`rsync` SOLID; `tcp_dlm_scaling`
  intermittent (~1 fail/3). BEST BASE. Skips durability only on a P109 self-demote
  (EDEADLK recovery), tracked by new `i_dlm_self_demote` flag in `xfs_inode.h` (set ~9472,
  read+cleared at bast_process entry) ([[sess51-FIX-narrowed-self-demote-durability-skip-17of17]]).
- REFUTED: shortform-gate (skip clean release when dir `if_format==LOCAL`, 3FCCA8B7) BROKE
  `dir_reuse` 0/2 (its vulnerable phase IS sf→block growth); msleep node-slot tiebreak in
  EDEADLK recovery (0C21541E) CASCADE 12/17 (msleep in DLM acquire too disruptive).

Core tension recorded: `tcp_dlm_scaling` needs clean-PR peer-handoff releases CHEAP;
`dir_reuse` needs them DRAINED (masking) — SAME code path. The masking `dir_reuse` needs
is for pending **dir-data-block writeback** (`xfs_inode_clean` checks only the inode, not
data blocks). The exposed sess37 stale-block race: read hook (`xfs_da_btree.c` ~3101) and
acquire-evict (`mxfs_dir_drain_evict_data_blocks` ~3603) both use `XBF_TRYLOCK` and SKIP a
LOCKED (-EAGAIN) stale dir block (in-flight self delwri/AIL writeback) → RMW on a stale
base durably drops a peer's dirents. Read-side cannot block (deadlock: holds inode DLM,
starves peer grant); acquire-side blocking is documented-safe (sess97) but risky. Also
noted: `force_block=1` is a regression (sess44 — breaks `dlm_fairness`+`cache_coherency`
via BNOBT double-free), `mxfs_dir_force_block` stays 0.

## sess52 — option B (broad-skip + acquire-side lockwait), residual = dir-fork-revert DABUF shutdown

Option B (build C16AAEAC → D67776EC, KEEP): `dir_pr_release_fast=2` broad release-skip +
NEW acquire-side LOCKED-block bounded-wait `mxfs_dir_acq_lockwait=60` in
`mxfs_dir_drain_evict_data_blocks` (~3605) ([[sess52-FIX-broad-skip-plus-acquire-lockwait-optB]],
[[sess52-residual-is-dir-fork-revert-DABUF-shutdown-cascade]]). FIXES the livelock (EDEADLK
hundreds→~4) AND `dir_reuse` slowness (round 18@3min vs 24@6min). Reliability **3/5** —
runs 2,3 failed on a SHUTDOWN, not a livelock (acquire-wait fired 0×; the LOCKED race is
rare, the wait is cheap insurance).

The real residual: **dir-inode FORK REVERT → DABUF-hole shutdown → cascade**. A reload
reverts the in-core dir fork to the invalid state `{di_format=EXTENTS/BTREE, nx=0,
size>0}` (format says data blocks, extent map empty); then `xfs_create`/`xfs_remove` maps
a dir block → `xfs_dabuf_map` HOLE (`xfs_da_btree.c:2814`, `!(flags &
XFS_DABUF_MAP_HOLE_OK)`) → EFSCORRUPTED → dirty `xfs_trans_cancel` → `Corruption of
in-memory data (0x8) Shutting down` → node1 FS down → whatever create/rm-heavy test runs
next fails 0/2 (fence_during_write, rsync_paired, tcp_dlm_scaling, soak). Pre-existing
sess45/77/80 DABUF-map-hole family, ~40% intermittent, node1-LOCAL (node2 had zero
NXSHRINK). Two decisive sub-cases:
- **GEN MISMATCH freed-reuse** (run 2, subdir ino=8928577, incore_gen=3555416468 vs
  disk_gen=65196620, disk freed mode=0): reload adopted a freed *different-incarnation*
  image in-place → `P-RELOAD-IOPS-REWIRE new_mode=00`. Two complementary guards (KEEP):
  **P52-RELOAD-FREEDREUSE-DIR-SKIP** (~6841, before the sess116 P116 guard) on the raw
  cached `dip`, and **P52-FRESHSRC-FREEDREUSE-DIR-SKIP** (~7295, inside the P34D FUA-fresh
  adopt block) on the `fresh` image — run-4 proved the corrupting adopt was the P34D
  FUA-read `fresh` image, not raw `dip`. Both skip when disk reads FREE (`di_mode
  S_IFMT==0`) for a live in-core `S_ISDIR` with a *different* `di_gen` (proves different
  incarnation, so P116's "peer freed THIS inode" assumption is wrong). Build progression:
  CE9B0FD4 (+guard 2) = 3/4; **D67776EC** (+guard 3) is the sess52 HEAD.
- **SAME-incarnation root revert** (run 3, ino=128, gen=0): `P32-IFLUSH-NXSHRINK
  incore_nx=0 disk_nx=1 incore_size=312 disk_size=4096 dlm_mode=5 comm=rm` — node1 (EX)
  flushed a shortform in-core over a block on-disk image (root reverted block→shortform),
  orphaning the data block; a later `xfs_remove` mapped it → DABUF. NOT yet fixed.
  Candidates: extend `P33-DIRGROW-REVERT-SKIP` (~6940) to keep in-core when
  `i_dlm_mode==EX` even if clean (under EX disk can't be legitimately smaller); OR the
  GPT-5.5 Step-4 fork-flush fence in **`xfs_iflush_cluster`** (`xfs_inode.c:5393`
  continue-skip loop, NOT `xfs_iflush` which force-shuts-down on error) — "no stale
  in-core fork may ever reach the on-disk dinode." Step 4 UNIMPLEMENTED. The
  `P32-IFLUSH-NXSHRINK` detector (`xfs_inode.c:4852`) is the right SIGNAL but log-only.

## sess53 — plain defaults + P52 = 4/5; option B overturned

BREAKTHROUGH ([[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]]): the criterion
config is **PLAIN `./run.sh 2 tcp`, pure defaults** (`dir_pr_release_fast=1`,
`sf_merge=1`) on build **D67776EC** (option-B code present but default 1 = sess51 narrow
self-demote-only) **+ the P52 freed-reuse guards**. Option B (`=2`) was WRONG — it CAUSED
`tcp_dlm_scaling` failures (iunlink/`trans_cancel:1061` shutdowns + leak). Why plain works
now but not in sess52: the P52 freed-reuse guards fixed `dir_reuse`'s gen-mismatch face, so
`=1` now passes BOTH `dir_reuse` AND `tcp_dlm_scaling`. `dir_acq_lockwait=60` and
`dir_pr_release_fast=1` are already code defaults; option B's only delta (`=2`) hurts. DO
NOT pass `MXFS_EXTRA_MODARGS`.

With defaults, `tcp_dlm_scaling` had **two intermittent faces** (the other 16 tests reliable
every run):

**Face 2 — iunlink corruption shutdown, PATCHED (idempotent-iunlink), now SUSPECT.**
`xfs/xfs_iunlink_item.c xfs_iunlink_log_dinode`: when `old_ptr==next_agino &&
i_next_unlinked==next_agino` (rapid free→reuse→free advanced buffer+in-core to the item's
next_agino; only the captured `old_agino` is stale, chain already correct) → **idempotent
no-op** instead of force-shutdown. Validated firing (P53-IUNLINK-IDEMPOTENT h1/h2,
shutdown=0). BUT ([[sess53-CRITICAL-idempotent-iunlink-may-mask-real-unlinked-list-corruption]])
build 21C36EEA p2 shutdown on node1: `xfs_inactive_ifree: xfs_ifree returned error -117`,
`Found unrecovered unlinked inode 0x39a in AG 0x4` — a genuine AGI `di_next_unlinked`
chain corruption at ifree, NOT the precommit mismatch. Hypothesis: the no-op MASKS a real
unlinked-list corruption under rapid free→reuse→free on a shared dir's child inodes
(multi-node AGI/unlinked-bucket coherency); the precommit check was catching a REAL bug and
the no-op defers the crash to ifree. Consider REVERTING and root-causing the chain
corruption. `P53-IUNLINK-MISMATCH` diag (`old_ptr/old_agino/i_next_unlinked/uncp`) still in
tree. Net reliability of 21C36EEA: p1=16/17 (leak), p2=14/17 (this shutdown + cascade) — NOT
clearly better than the D67776EC baseline (4/5, leak-only, no shutdowns).

**Face 1 — durable dirent RESURRECTION, STILL OPEN (~1/5). THE blocker.** node2's rename
SOURCE dirent (`n2_rN`, sometimes a burst) survives durably on both nodes after
`drop_caches`. GPT-5.5 consult (RULE 5) gave the invariant, and two fixes landed (KEEP, in
86DDB26D / 21C36EEA) ([[sess53-HANDOFF-ex-gate-clean-adopt-merges-suppressed-leak-now-pure-disk]]):
"**Disk is authoritative ONLY at EX-acquire boundaries; in-core is authoritative WHILE
owning EX.**"
  1. **EX-tenure reload suppression** (`mxfs_dlm_dir_modify_reload_prelock` ~2646):
     `if (dp->i_dlm_mode==MXFS_LOCK_EX) return;` — no mid-tenure disk→in-core reload while
     owning EX.
  2. **clean-adopt at acquire** (reload merge ~7746/7323): run `mxfs_dir_sf_merge_into` only
     when `!xfs_inode_clean(ip)`; a CLEAN inode ADOPTS disk (no union of a stale prior-tenure
     image).
These SUPPRESSED the SF merges (sfmerge=0 both nodes) — the merge resurrection vector is
CLOSED — but the leak PERSISTS as **pure on-disk resurrection**.

The multi-node mechanism ([[sess53-dirent-resurrection-multinode-stale-flush-plus-merge-union]],
[[sess53-residual-durable-dirent-resurrection-stale-dir-flush]]): node2 does
`mv n2_rN n2_rN.done`; the leftover is the SOURCE name. **node1 stale-FLUSHES** the whole
shortform dinode carrying `{n2_rN}` (a removed source dirent it still had cached, because the
`EVICT-RING-DIRMOD` DIR_MODIFY signal is asymmetric/lossy — node1 gets ~0 DIR_MODIFY) →
durable on the LUN; **node2 then 3-way SF-merges** and UNIONS its in-core `{n2_rN.done}` with
the stale disk `{n2_rN}` (`P-SFDIR-REVERT incore_cnt=2 disk_cnt=1`, `P-SFMERGE 1+1→2`). Reads
are coherent (single host page cache), so the bad image is genuinely on the LUN. Decisive
proof ([[sess53-FINAL-residual-is-release-durability-race-with-churn]], build 21C36EEA):
`dirwr=1` run — node2 `P-SFREL-VERIFY ino=8930275 incore_size=25 disk_size=20 STALE-DISK`
(after node2's release flush, disk is BEHIND in-core); `mxfs_inode_cluster_durable` retries
25× while `incore_size` OSCILLATES 35→40→20 — the dir is churned by LOCAL ops concurrently
DURING the flush, so the flush chases a moving target and intermittently lands a superseded
image (`clean=1 in_ail=1 rerr=0`, `P51-REL drain_ms=0`).

REFUTED across sess53 (do NOT repeat): **`sf_merge=0`** (adopt-disk on reload) — still leaks
AND REGRESSES `fence_during_write`; proves the merge is one vector but disabling it alone
can't fix a disk that's already stale from the flush; KEEP `sf_merge=1`. **DIRGEN-BUMP**
(bump `i_dlm_dir_gen` on every release, 99EBB950, gated on fua_disable) — does NOT regress
cache_coherency/cross_write_read under fua_disable=1 but does NOT fix the leak (resurrection
is a background/false-sharing flush + peer merge, not acquire-time modify); revert. **option
B (`=2`)** — unreliable. **DIRAHEAD-overlay** (added under fua_disable ~5349) — never fired on
the leak, DORMANT/unproven, consider revert. warm-FS repeat driver INVALID (node2
`trans_cancel:1061` crash cascades).

sess53 end state: build 21C36EEA (= D67776EC + P52 + idempotent-iunlink + EX-gate +
clean-adopt), plain defaults, ~4/5. **Marker NEVER written.** Two independent residuals gate
reliable 17/17: (a) release-side shortform durability race — the stale FLUSH; and (b) the
suspect unlinked-list corruption face-2. NEXT (per handoffs): fix
`mxfs_inode_cluster_durable` to quiesce local modifiers and loop the durable flush until
`P-SFREL-VERIFY` reads DURABLE (disk==incore) before releasing EX; OR make dir
reload-on-ACQUIRE reliable via a DLM grant-epoch / shared on-disk dir epoch (not the lossy
evict-ring) so node1 never flushes a stale fork; OR implement the GPT Step-4 fork-flush fence
in `xfs_iflush_cluster`. Baseline to beat if sess53 code is reverted: **D67776EC (plain
defaults + P52, no sess53 changes) = 4/5, leak-only, no shutdowns.** Repro:
`PLAIN=1 bash tests/tcp/fg_one_run.sh <lbl>` (~540s, reboots, ~1/5 fails).

## Build progression (chronological)
- **DBA88871** (sess49) — P43/P43B EX-gate soundness gate; cache_coherency FIXED; 17/17 once.
- **E67385C9** (sess50) — Fix B `mxfs_sf_fastpath_adopt=0`; resurrection root fixed; residual = handoff stall.
- **FFC0DA1D** (sess51) — broad release-skip `dir_pr_release_fast=2`; fixes livelock, exposes dir_reuse.
- **D50912EB** (sess51) — narrow self-demote-only release-skip; BEST BASE, dir_reuse/rsync solid.
- **C16AAEAC → CE9B0FD4 → D67776EC** (sess52) — option B + acq-lockwait + P52 guards 2 & 3.
- **B9258412 / 86DDB26D / 21C36EEA** (sess53) — D67776EC + P53 diag + EX-gate + clean-adopt + idempotent-iunlink; plain defaults; 4/5.

## Standing lessons
- Slowness/stall IS a test failure (60s handoff blows the window); `mxfs_dlm_lock` 60×1000ms retry means one stall fails the whole round.
- `xfs_inode_clean` checks only the inode, NOT dir-data blocks — a "clean" release/flush can still be publishing a superseded shortform image.
- The evict-ring DIR_MODIFY signal is asymmetric/lossy (node1 gets ~0) — do not rely on it for reload triggers; use a DLM grant epoch or shared on-disk dir epoch.
- Under EX the on-disk image cannot be legitimately smaller/older than in-core; a reload that shrinks/reverts the in-core fork under EX is always wrong.
- A guard tuned for one path (P43 create-only-grow, P116 peer-freed-this-inode) misfires on the opposite path (unlink shrink, freed-different-incarnation) — gate on real authority (EX-held / dirty / gen-match), not on format or mode!=NL.
