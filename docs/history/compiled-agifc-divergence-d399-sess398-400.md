<!-- D-399 AGI-freecount/btree divergence: sess398 regression, sess399 root+fix design, sess400 fixes landed 0.23.11-13, verified clean. -->
## D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399 — sess398-400

### sess398: relog-gate false-veto fix (0.23.8→0.23.9), then a bad regression
0.23.8's 6-lap board went 24/24 PASS, but the na (P146V-NOAUTH-REFUSE) detector fired 24-43x/node:
the relog-authorization gate vetoed legitimate same-gen repairs under a verified EX because it
keyed on sticky `i_dlm_icd_refused`, clearable only by a real destage write. No functional loss
(all rows still PASS) but wrong. Fixed in 0.23.9: authority now requires `rawmode>=EX &&
(!foreign || i_mxfs_self_created)`. Added detector P-RELFLUSH-NOTENURE.

0.23.9 then regressed hard. `tests/tmpfile_churn.sh` (the O_TMPFILE + linkat(AT_EMPTY_PATH)
version — first real exercise of the stacked create-item + iunlink-INSERT-item tmpfile path
under injection) hung at rc=124 on ~22 nodes. Every subsequent lap failed fleet-wide:
dir_reuse_coherency 0/32, dirent_durability 0/32, rsync_paired 28/32, all with EUCLEAN
("Structure needs cleaning", -117) — first hit was `P-DIALLOC dp=159 err=-117`, preceded 4s
earlier by a `P383-HOME-VS-OWED` fence-abandoned-publication storm. Two hypotheses left open
at session end: H1 tmpfile churn corrupted AGI/inobt state; H2 the re-enabled P146V relogs
(now landing again, ul>0) broke inobt/AGI. Session also produced two harness fixes still in
use: `os.link()` on `/proc/self/fd/N` hits EXDEV on ext4 and mxfs alike (not a defect) — use
`linkat(fd,"",AT_FDCWD,name,AT_EMPTY_PATH)`; and MXFS allocation is node-affine (files land in
the node's affine AG, dirs rotate), so any inode-reuse repro must mkdir until a dir lands in
the freed inode's AG before creating files in it.
`docs/history/docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`
`docs/history/docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`

### sess399: root found, then proven — un-tenured AGI writers
H1 confirmed. The `-117`s were `XFS Internal error i != 1 && j != 1` at
`xfs_ialloc.c:1918` (`xfs_dialloc_ag_finobt_near`): AGI said `agi_freecount==1` with no
matching finobt record. Platter dump (tools/mxfs_agi_dump.py) showed the AGI, inobt root and
finobt root all stamped with one LSN but disagreeing on count — the AGI count itself is wrong
by ±1, not a leaked/lost inode. A +1 ghost permanently blocks creates in a full AG (dialloc
only grows a chunk when `freecount==0`); a -1 ghost trips `P-DIFREE-CORRUPT` → shutdown. Only
the two node-owners of each doubly-owned AG (AG = node_slot % 25) ever hit it.

Mechanism, chased via new instrumentation (`mxfs_agifc_audit`, `mxfs_agifc_mod`,
`mxfs_agifc_release_audit`, all landed 0.23.10): at a fresh AG acquire, the AGI buffer's BLI
was still in the AIL from this node's *own prior tenure*. The read-hook's in-AIL protect kept
it, on the sess43/sess103 premise that "in-AIL AG-meta is always this-node-ahead of the peer" —
false once an in-AIL buffer survives a release. The stale image's `freecount` differed from the
freshly-read leaves; the next RMW (difree) published the wrong count forward permanently.

Then proven to the exact writer: `xfs_dir_add_child()` (O_TMPFILE linkat completion,
xfs_dir2.c:1557) and the rename-whiteout path (xfs_dir2.c:2010) both call
`xfs_iunlink_remove()` with **no `mxfs_ag_dlm_lock`** — unlike `xfs_iunlink` (insert) and the
ifree path, which are tenured. (The xfs_iunlink comment claiming "the REMOVE side is already
coordinated" is wrong for these two callers.) Full chain: tenure ends AGI==leaves → release
drains → the un-tenured linkat REMOVE logs the AGI with no drain owed → its BLI stays in the
AIL → peer's tenure allocates → this node's next acquire preserves the stale in-AIL AGI →
first audit sees a 1-count mismatch against fresh leaves → RMW + release republishes the wrong
count. Single-owner AGs drift too, against their own stale image.

Repro (no injector needed): `tests/agifc_churn_experiment.sh <label> pernode 0 200 32`. Fix
plan (GPT/the design-consult rule reviewed, landed next session): (1) bracket `xfs_iunlink_remove` in both
callers with the same AG-DLM shape as `xfs_iunlink`; (2) defense-in-depth — the release drain
should wait for AIL *removal* of the tenure's AG-meta BLIs, and the read-hook in-AIL protect
should require `b_tenure_id == current tenure`; (3) keep `P-IUNL-RM-NOTENURE` as a precondition
alarm. GPT flagged an AG(inode)→AG(dir) vs existing AG(dir)→AG(inode) lock-order question —
resolved as a pre-existing hazard mitigated by trylock/hold-nothing-while-blocking, not a
global ascending-order invariant.
`docs/history/docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`
`docs/history/docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`

### sess400: fixes landed 0.23.11-0.23.13, verification clean
- Fix 1 (0.23.11): AG-DLM bracket around `xfs_iunlink_remove` in `xfs_dir_add_child` and the
  rename-whiteout path, same shape as `xfs_iunlink`. Cut mismatches from 65/2810 to 0/39.
- Fix 2 (0.23.12): the residual 39-41 mismatches were `pagi_freecount` off by ±1 at
  `agi_btenure=0` — a fresh acquire clears `AGI_INIT` but only `xfs_ialloc_read_agi` rebuilt
  `pagi`; `xfs_iunlink`/`xfs_iunlink_remove`/`xfs_difree` use plain `xfs_read_agi`. Fixed by
  making `xfs_read_agi` rebuild `pagi` whenever `AGI_INIT` is clear.
- Layer 2 (0.23.12): `P-AGMETA-PRIORTENURE-UNDESTAGED-INAIL` alarm in the read-hook protect
  branch — a prior-tenure in-AIL clean/unpinned/undestaged AG-meta buffer is now itself an
  invariant violation, logged (escalate to shutdown only if proven silent otherwise).
- Fix 3 (0.23.13): `xfs_link` pre-acquires the source inode's AG when `nlink==0` (same
  pattern `xfs_rename` already used for `wip`) — needed because Fix 1's bracket could otherwise
  block holding both ILOCKs against a peer-held AG.

Verification E6-E10 (pernode/shared × inj0/inj20 + final 0.23.13 pernode): every run
`am=0 ar=0 nt=0 ptu=0`, 32/32 clean unmount, chk per-AG AGI==inobt==finobt. Oracle lesson:
`chk_mxfs` on a *live* LUN is invalid for a currently-held AG — inobt/finobt can land its
buffers up to 15s apart even at the same LSN; use `AGIFC_UMOUNT=1` (32-way umount, ~1s) for a
trustworthy read. 6-lap d385 board on 0.23.13 was the pending step to close D-399 FIXED AND
VERIFIED.

Side finding, filed as its own defect: `D-TMPFILE-CHURN-RULE0-PERF-400` (the derived-budget rule violation,
not correctness) — pernode tmpfile churn runs 3.0-4.3s/200-iter vs native 0.01-0.02s; the
shared-dir shape didn't even finish inside a 6s budget (EX ping-pong). Breakdown: median
iter 7.5ms, close→inactivate→ifree accounts for 56% (3.5ms) because close() runs synchronously
through ifree and the churn reuses the same inode every iteration; p90 15ms, tail spikes to
640ms.
`docs/history/docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`
