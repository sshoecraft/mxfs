<!-- TCP 2-node campaign sess528-534 (0.75.46-0.75.58): D-0920/D-0921 closed F&V; D-0922 truncate-pace root-caused across 6 fix iterations, still OPEN. -->
TCP 2-node campaign, sess528-534, builds 0.75.46-0.75.58. Continuation of
`docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`. Three defects: D-0920
(stale fork publish), D-0921 (create-race EEXIST leaks to userspace),
D-0922 (truncate-under-hot-appender pace, the bulk of the campaign).

## D-0920 — stale cluster slot on iflush fork copy (closed sess528)

Proven from the s527f detector on 0.75.45 (heal=0): test1 xfsaild flushed
inode 8388909 with a stale in-core fork (adopted from a private platter
read after a peer release) over a smaller on-disk extent; test2 read a
16-byte zero hole (P104-READ-HOLE-IN-SIZE, 89/200 files empty). Root:
`xfs_iflush_fork` only copies a fork into the staged image when it's
logged, so an unlogged-but-changed fork on an adopted-stale inode never
gets republished.

Root proof and fix design:
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`.
Fix 0.75.46 (`xfs/xfs_inode.c`): `mxfs_iflush_fork_publish` always memcpys
the re-encoded in-core fork into the staged image when it differs on an
unlogged fork; `iflush_fork_heal` module param removed. Closed F&V in
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`:
laps s528a (prep) + s528b (NOPREP), 200 rounds each, 0 empty files either
node vs 89 empty/178 validation failures on 0.75.45.

## D-0921 — create-race EEXIST returned to userspace (closed sess528)

Design (`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
`xfs_create`'s cross-node create-race loser branch
(`xfs/xfs_inode.c` ~2778-2812) returns `-EEXIST` after orphaning its own
allocation. For `open(O_CREAT)` without `O_EXCL` the VFS hands that EEXIST
straight to userspace — a POSIX violation, since a non-exclusive create
racing an existing file should just open it. Root proven in
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`:
a stress artifact's `multipage_file.txt` was missing exactly its B1
record, correlated 1:1 with one `P127-EEXIST-LOSER` line on test2 at
phase start.

Fix 0.75.48 (`pal/linux/xfs_iops.c` `xfs_vn_create`): on `-EEXIST` when
`!excl` on a multinode mount, return `-ESTALE` instead (VFS's
`do_filp_open` retries `path_openat` once with `LOOKUP_REVAL` on
`-ESTALE`, landing on the winner's inode with correct `O_TRUNC`/perm
handling). Do NOT instantiate the winner directly from create —
`FMODE_CREATED` would skip `O_TRUNC` and `acc_mode`. Closed F&V in
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`:
armed laps s528h/i (losers reached, `open_errors=0`, all files complete)
vs 0.75.47's s528g (3 losers, 3 failed opens); unarmed + append laps also
PASS.

Harness fixes along the way (in `tests/concurrent_create_race_2node.sh`
and `tests/append_contention_2node.sh`): added `CREATE_DELAY_MS` /
`A_LEAD_MS` knobs to force losers reliably (only 1-3 losers per 100
rounds even armed); fixed REC-arm record padding (`tr` escape was being
eaten by ssh, causing NUL padding — replaced with `printf` width) and
read-back verification (base64 -w0, plus an on-node-vs-read-back md5
assertion) — see
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`.

2/tcp board on 0.75.48 came back 25 PASS / 0 FAIL
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`),
established the chunking recipe used for the rest of the campaign:
showstat elapsed sums to split rows into two `run.sh` chunks (~538s +
~330s), which skips prep when the marker already matches 2/tcp.

Side finding this era: `dino_clobber_check=1` (a FUA-verify-every-write
probe for D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY) fired once
(`P-DINO-CLOBBER#1`, ino 8388737) under the concurrent-create workload —
traced to a FREE-image slot with no in-core inode, which the existing
"free, not logged" partial-write mask legitimately suppresses; the probe
ran *before* that mask so it couldn't distinguish masked from landed.
Moved post-mask in the same 0.75.49 change described below
(`P-DINO-CLOBBER-MASKED` vs `P-DINO-CLOBBER`), after which repeat laps
showed 0/0 — see
`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`.

## D-0922 — truncate-under-hot-appender pace (filed sess527h, still open at relay)

Filed from s527h: truncate under a concurrent hot appender measured
167-236 ms against a 100 ms bound. Root-caused and fixed across five
build iterations; every fix closed one mechanism and exposed the next.

**Iteration 1 — terminal-defer loop (0.75.49).** Root
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
`mxfs_dlm_bast_process`'s P244 terminal-defer path reset state to CACHED
on every drain, which re-admitted the hot writer's fast path ~100us
later and re-triggered the same BAST — a live loop. Compounded by a flat
1s `MXFS_LOCK_ACQUIRE_WAIT_MS` retry cadence once the peer's relab
backoff (P279) hit its 1s cap. Fix: capture `pend` at BAST entry; if it
advanced during the drain (`live_commit`) for a regular file with
`file_yield_on_demote`, stay in BAST state (park admissions, wake on
release) and re-fire the dwork at delay 0 instead of falling back to
CACHED + relab backoff.
Result (`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
P279 and LKTIMEOUT both went to 0, but truncate pace was unchanged
(119-220 ms) because `truncate -s 0` is actually FOUR cross-node
hand-offs (open PR, ftruncate EX, close EX, stat PR), each costing
30-50 ms — the 100 ms bound had implicitly assumed one hand-off.

**Iteration 2 — immediate re-fire, DISPROVED (0.75.50).** Tried
`mod_delayed_work(...,0)` to force instant re-arm on live-commit.
Truncate walls unchanged (240/138/227 ms) and append throughput
regressed 4.5x (18.4 ms/append vs 4.1 ms on 0.75.49) because the
immediate re-fire destroyed the accidental hand-off batching the old
coalesced dwork gave for free
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`).
Reverted to `queue_delayed_work(0)` (coalesces onto any pending arm) in
0.75.51; added a stage-timing breakdown to P244/P138
(`t_us a b b1 b2 c c1 c2 d`, b1=settle, b2=dir flush, c1=filemap
write-and-wait, c2=invalidate_inode_pages2) to localize the remaining
~120 ms outlier.

**Discovery — MHT batching mechanism and c1 hypothesis (0.75.51).**
0.75.51 measurements
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`)
pinned the ~120 ms-per-lap outlier to stage c1
(`filemap_write_and_wait`) every time; ~63 ms outliers to stage b
(settle + AIL drain + coalesced flush). Documented the batching lever:
`mxfs_dlm_mht_defer_bast` holds an EX grant in CACHED under
`inode_mht_ms` (300 ms default; `dir_sf_mht_ms`=40 for dir shortform)
before releasing, but BASTs that arrive while the holder is
ACQUIRING bypass the MHT entirely (`P35-ACQBAST-HONOR`) — which is
exactly the truncate/appender ping-pong shape, so the appender was
never getting batched.

**Iteration 3 — c1 root: AG remaster park with flat sleep (0.75.53).**
Proven with a purpose-built stack watchdog
(`mxfs_drain_wb_watch_ms`, 0.75.52) that dumped the drain kworker's stack
on a slow `filemap_write_and_wait`
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
the c1 stall was the appender's extent-allocation path
(`xfs_bmapi_convert_delalloc` → `xfs_alloc_vextent_iterate_ags` →
`mxfs_ag_dlm_trylock`) blocking on an AG whose DLM ledger page was mid
remaster (`P-TAUTH-REMASTER-PARKED`/`-RX`), and the retry wrapper
(`mxfs_dlm_lock_retries`, `dlm/dlm.c`) slept a **flat 100 ms** per retry
regardless of how soon the handoff actually completed (a sess423
"handoff cadence" artifact). Two such parks per truncate lap explained
the two ~225 ms truncates.
Fix: change the flat 100 ms retry sleep to exponential backoff starting
at 4 ms, doubling, capped at 100 ms.

**Iteration 4 — stage-order root (0.75.54).** Proven
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`)
via a merged two-node timeline (`tools/timeline_2node.py`, new this
session): every P244 live-defer correlated with `xfs_setfilesize`
committing under ILOCK_EXCL from the ioend *after* the drain's settle
stage (b) had already run — the drain order was (a: log_force+alloc
drain), (b: settle+log_force+ail_drain+coalesced flush), (c:
filemap_write_and_wait+invalidate), so page writeback in stage c
re-dirtied the inode (size/unwritten conversion) after stage b had
already flushed it, triggering a fresh defer. Fix: move stage c before
stage b. Result
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
P244 count dropped to 0 in every capture (was 10-12/lap), truncates
mostly 73-97 ms, 21/24 laps under the 100 ms bound; remaining tail
(103-113 ms) traced to a ~28-32 ms AG hand-off (grace 11 + drain 7 +
flush/unlock 8), broken down further by a new
`P12-AGREL-STAGES`/`mxfs_ag_bcache_pin_census` instrument (0.75.55).

**Iteration 5 — AG release fixed sleeps removed (0.75.56/0.75.57).**
Found two unconditional sleeps in the AG-unlock path
(`xfs_trans_ail.c`'s `xfs_ail_push_ag_sync_bounded`: `msleep(10)` every
prepass regardless of pin state; a `msleep(3)`+second log-force always
run post-COMMIT). 0.75.56 removed the forced prepass sleep; 0.75.57 made
the post-COMMIT settle conditional on a nonzero pin census
(`P12-AGREL-PINNED`, which then never fired in practice). AG release
dropped from ~11-15 ms to 5.4-8.9 ms; 17/18 truncate laps under bound
(one 107 ms)
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`).
Remaining-tail root: each of the truncator's four syscalls (open,
ftruncate, close, stat) is its own separate cross-node hand-off because
the appender grabs the lock back in the gap between them — plus 4-6
`P-CONVBLK-DENY` events per lap where the DLM master denies a PR→EX
upgrade outright (forcing a full self-demote + fresh EX request) because
an existing GRANTED PR entry stays visible to `lk_is_holder` during the
upgrade attempt. PR→EX convert-queue redesign (queue the converter, BAST
the conflicting holder, deny only a genuine second converter) parked as
a later item — the existing CONVERTING state hides the converter from
`lk_is_holder`, so it can't be reused as-is.

**Iteration 6 — file tenure floor, regressed the tail (0.75.58).** Root:
`mxfs_dlm_dir_tenure_keep_delay` returned 0 for non-directory inodes, so
the very first `ilock_end` after a BAST released immediately, and
`P35-ACQBAST-BATCH` was dir-only — files got no batching floor at all.
Fix: `file_ex_tenure_ms` knob (default 30 ms, 0 = old behavior) plus
`mxfs_ex_tenure_window_ms(ip)` used consistently in
`mxfs_dlm_mht_defer_bast`, the tenure-keep-delay helper (now covers
`S_ISREG`), the dwork quiet-age gate, and the P35 batch arm.
Result — append improved dramatically (0.1 ms/append vs 19 ms; basts
dropped from thousands to single digits) but truncate got a **new**
248 ms tail
(`docs/history/docs/history/docs/history/compiled-tcp-2node-truncate-pace-campaign-sess528-534.md`):
the truncator's *own* new tenure floor held its inode EX for the
full window while it was itself blocked waiting on the AG — a P5D
pre-wait deferred-BAST drain got converted into CACHED+bast_pending by
the now-REG-aware `dir_tenure_keep_delay`, releasing only after the
window elapsed (~27 ms), and every later truncator syscall then had to
wait out the appender's 30 ms window again. Net: a truncate pays
2-3 whole tenure windows instead of one.

**State at relay (sess534 END, unresolved).** A grind chain (s539a-i)
was in flight sweeping `file_ex_tenure_ms` = 15 then 10 on both nodes
(restoring 30 at the end) to find a value that keeps append batching
without stacking multiple full windows onto a truncate. If that chain
died mid-run, the knob may be stuck at 15 or 10 — check
`/sys/module/mxfs/parameters/file_ex_tenure_ms` on both nodes before
resuming. Next fix identified but not yet built: the P5D pre-wait
release (at the `mxfs_trans_drain_inode_unlocks` site,
`xfs_mxfs_dlm.c` ~43285) must bypass the tenure floor entirely — a
holder about to block on the AG gets nothing from holding tenure, so a
per-inode/task flag should force `dir_tenure_keep_delay` to 0 and the
dwork quiet-age gate to release immediately while that flag is set.
D-0922 was still OPEN at relay — the fix chain closed every root found
so far but the tenure-floor side effect reopened the pace bound, and
the 2/tcp board had not yet been run on 0.75.58.

## Cross-cutting tooling/traps from this campaign

- `tools/timeline_2node.py` — merges per-node event logs into one causal
  timeline; clock skew between test1/test2 varies per lap (5-22 ms
  observed) and must be derived per-lap from a known causal pair
  (P7S→P7B or P138→P74-GRANT), never assumed constant.
- The harness's dmesg capture greps for `mxfs` only, which silently
  drops raw kernel stack-dump frames — pull unfiltered `dmesg` from the
  node directly when using a stack-watchdog instrument.
- `P-SFS` (xfs_setfilesize) print is capped at 1500 lines per boot —
  truncate laps hit it, append laps rarely do.
- `tests/cluster_slot_clobber_2node.sh` was missing its executable bit
  going into this campaign; fixed in-flight by a rig-runner chmod.
