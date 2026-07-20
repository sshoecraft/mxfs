---
name: compiled-ccloop46ef-dirreuse16-32-ladder-sess1-8
description: Compiled ccloop46ef sess1-8: chase of 16/32-node CAW dir_reuse/cache_coherency ladder — roots found/fixed, 16/caw complete, sess8 regression open.
metadata:
  type: project
tags: [compiled, ccloop46ef, dir_reuse, caw, 16node, 32node]
---

# Compiled: ccloop46ef sess1-8 — 16/32-node CAW dir_reuse/cache_coherency ladder chase

Central topic: driving `criteria.json`'s 1/2/4/8/16/32-node CAW ladder to 100% PASS.
The ladder was stuck on `cache_coherency@32`, `dlm_scaling@32`, `crash_consistency@32`,
and `dir_reuse_coherency@16/32` through a chain of distinct corruption/wedge/perf
mechanisms in the mxfs dir-EX tenure, CAW slot-release, and buffer-completion layers.
Each session's root theory was tested against the ladder and either confirmed-and-fixed
or refuted by the next session's evidence — refutations are called out explicitly below,
they are not additional standing theories. Sessions 1-7 are ccloop run `46efd8b6`; sess8
(last entry) runs under a **different** ccloop id (`12e0d157`, session `33136bc8`) doing
the same cache_coherency@32 chase — treat its scoreboard as the most current, and note it
shows @32 in worse shape than sess7 left it (see "Current state" at the end).

## sess1 — tenure-floor concept born; two unrelated root fixes proven

Entering state: 1/2/4/8 caw 17/17, 16 caw 16/17 (dir_reuse unrun), 32 caw all failing/unrun.
Two independent root causes proven via RULE-4 chains on `diag_rv_replay` 32-node
[[AAA-ccloop46ef-sess1-TWO-ROOT-FIXES-evictring-ireadpr]]:

1. **Stale-HB evict-ring replay** — disklock.c's HB monitor scan used a plain (non-FUA)
   cacheable read; a stale read makes peer `head_seq` appear to jump backward, replaying
   already-consumed DIR_MODIFY/INODE_FREE ring entries. Each replay bumps `i_dlm_dir_gen`
   and arms `MXFS_IF_DIR_RELOAD` — non-idempotent for the counter. Measured 6 spurious
   dir_gen bumps/reloads-per-second on a *pure-read* verify with zero writers. Fix:
   monotonic consume guard (`(int32_t)(h - last_evict_seq) > 0`), `evict_seen` reset at
   `fire_dead`. Param `evict_ring_monotonic=1`.
2. **iread-EX starvation → shutdown** — first lookup after a dir-fork unload escalates
   `ILOCK_EXCL` for `xfs_need_iread_extents`; `xfs_ilock` mapped *any* ILOCK_EXCL to
   cluster EX, so 12+ nodes contended dir EX against 20 PR-cyclers and hit
   `-110`/shutdown. Fix: `XFS_ILOCK_MXFS_PRIREAD` bit (xfs_inode.h `1u<<6`) tags the
   iread escalation; it maps to cluster PR instead (local EXCL kept for the iext build).
   Param `iread_pr=1`.

Both landed at build `87E860C4`, chained with a `dscan_gen_gate` fix (neg-lookup dscan
cost) to `DDB9E83B` → cache_coherency@32 PASS 32/32. A **dir-EX tenure floor**
(`dir_ex_tenure_floor`, batches back-to-back same-node dir ops under one EX grant) was
then added at `0BD98E9E` to fix crash_consistency@32 (PASS 32/32) but **regressed
cache_coherency+dlm_scaling@32 to 0/32**: the full-window floor let 31 waiters pile on a
hot slot, triggering the pre-existing orphan-release-abort loop into a stranded on-disk
EX (no in-core holder anywhere, every node polling `rc=-110`). Converted to a **sliding
grace** (`dir_ex_batch_grace_ms=25`: hold min(25ms, window-remaining) per op-end) at
build `30E6BF7F`, untested at session end
[[AAA-ccloop46ef-sess1-FOUR-FIXES-scoreboard]]. This tenure-floor/grace design is the
seed of nearly every mechanism chased through sess2-6.

## sess2 — dir_reuse@16 launch mechanics; sliding-grace regression triaged to 3 distinct causes

`dir_reuse_coherency@16` needs its own launch discipline: downward ladder transitions
(32→16) leave extras (test17-32) mounted; relaunching before power-cycled nodes finish
booting cascades into mass teardown timeouts. Fixed by: force power-cycle all extras,
wait for SSH on sentinels before relaunch, never re-launch immediately after a
power-cycling run [[AAA-ccloop46ef-sess2-LAUNCHED-dirreuse16]].

Trio run on `30E6BF7F` (25ms grace): crash_consistency PASS 32/32 (grace preserves the
batching win), but cache_coherency 0/32 and dlm_scaling 0/32 with **no strand, no
rc=-110** — a different failure mode than sess1's. Two mechanisms found in this session,
one of which sess3 later disproved as *the* driver:

- **Torn-publish clobber** (real, but crash-dependent — later shown non-general): a node
  PANIC mid-tenure lands dir *block* content (Phase-2 drain writes) without the *dinode*
  (fmt/size/nextents) landing, because P15-REL-ABORT drains-then-aborts before
  fencing/NL. A later EX holder reading the stale-SF dinode re-converts SF→block at the
  *same daddr*, overwriting the crashed node's block content
  [[AAA-ccloop46ef-sess2-PANIC-torn-publish-clobber-chain]]. Real bug (crash-recovery
  gap, no foreign-journal-replay of a dead peer's slice), but **sess2's own next probe
  showed 0/32 failures recur on runs with zero panics** — so this is *not* the primary
  driver of the trio regression, just a real secondary hazard.
- **Victim-node EIO family** (the actual per-run driver): 1-3 nodes/run go mount-wide EIO
  mid-rv-phase with `P9-ICD-FAIL` on SF-parent inodes (`imap_to_bp` returns `-EIO` for
  6s, 1500 tries) and NO "has been shut down" message — an unlogged shutdown-equivalent.
  Refuted in this chase: panic-as-driver, node1_before_1-as-clobber, slot-table ghosts
  across mkfs (all 1814 slots carry one `vol=FNV1a(sb_uuid)`), PR-fence as blocker
  (sg_persist keys all present) [[AAA-ccloop46ef-sess2-STATE-victim-node-EIO-family-and-AB-plan]].
  A/B confirms: `dir_ex_tenure_floor=0` restores cache_coherency@32 to pass — the tenure
  machinery (floor+grace, dwork releases) is the *enabler*, hitting SF-parent dirs (e.g.
  `ino=131` = `.cache_coherency`) that stay SF forever and get EX-hammered by every
  subdir op. Build `6CFAB18E` adds an ICD MIDLOOP discriminator probe (plain-read rc,
  magic, shutdown-flag) to localize the EIO source precisely
  [[AAA-ccloop46ef-sess2-END-icd-eio-probe-built-6CFAB18E]]. Also fixed this session:
  node-root-disk-full fabricating fake victim failures (log triplication), serial
  console capture wired to all 32 VMs, run.sh prep power-cycle parallelized.

## sess3 — corruption chain traced to shutdown-on-rename; cold-iget hypothesis raised

The MIDLOOP probe resolved: victims die in the **rename** phase hitting
`P14-DABUF-HOLE` (leaf/free references a dablk missing from the in-core map) or `i != 1`
in `xfs_bmap_del_extent_real` → EFSCORRUPTED → dirty `xfs_trans_cancel` →
"Corruption of in-memory data... Shutting down filesystem" → per-mount EIO. This *is*
the sess2 EIO death (`shutdown=1` confirmed) — not silent, just missed because artifact
collection used `journalctl -k` which rotates in ~85s under probe volume; fixed to
collect `dmesg -T` first
[[AAA-ccloop46ef-sess3-STATE-corruption-chain-traced-and-3-fixes]]. Three hygiene fixes
landed in build `FF5E7827` (v0.10.7): (1) bmbt FUA-write gate bypass — sess63's routing
of bmbt writes through `mxfs_buf_write_fua` returned *before* the sess66 tenure gate ran,
letting stale leaves republish unlogged; fixed by moving the gate before the FUA write
plus a read-stamp (`mxfs_bmbt_read_verify` → `mxfs_dir_bmbt_track`) so fresh reads count
as current-tenure; (2) never-adopt-older guard (benign, fired 0×); (3) confirmed dinode
write stream sound, platter consistent at rest via `chk_mxfs`.

**floor=1 (default) = 0/32 always; floor=0 = effective PASS** — this A/B is the session's
load-bearing fact, re-confirmed on the fix-laden build. Hypothesis raised (not yet
tested): reader-side **cold-iget adopts a lagging home dinode** while cached leaf
structure is from a newer era, composing a torn view without any torn platter. Probe
(iget_age_ms) built into build `9C813539`, untested at session end
[[AAA-ccloop46ef-sess3-END-build-9C813539-next-steps]].

## sess4 — cold-iget refuted; P15H reap-storm proven+fixed; platter-torn proven then refuted as decoder bug

`iget_age_ms` came back 10-25 **seconds** on every victim's hole — dir inode was
long-lived in-core, not freshly adopted. **Sess3's cold-iget mechanism is dead.**

Actual root for this window: **P15H strand-reap storm**. Under floor=1 batching, a
granted-but-unconsumed mirror can legitimately sit for seconds (poll abandons,
ACQUIRE_WAIT retries ≤6s), but the sess15-H2 strand detector reaped after only 4×25ms
(100ms) — 45 reaps on one inode in 35s across 23 nodes — occasionally racing a
just-promoted consumer and clearing the fresh EX bit *after* the consumer's verify
passed, producing a phantom-cached-EX "dark branch" that ran concurrent, unpublished ops
whose renames were then lost when read back mixed with the real chain
[[AAA-ccloop46ef-sess4-P15H-REAP-STORM-root-and-fixes]]. Also found: a CAW-path hole
where `p_rel_gen==0` fell into unconditional legacy unlock (unanchored wire CAS on a
possibly-evicted meta bucket). Fixes in build `DD94481C` (v0.10.9): strike threshold
4→280 (~7s, above every legitimate unconsumed window); `P6ZC-REL-NOANCHOR` skips wire
unlock entirely when CAW+`p_rel_gen==0`; forensics around the anchored unlock.

Mid-session, a **separate-looking mechanism** was chased and ultimately also folded into
decoder tooling, not a real corruption: `P-HOLE-DISK`/PLATTER-SCAN was silent because
`mp->m_bsize` is FSB-in-basic-blocks (=8), not bytes — every raw probe read EINVAL'd all
of sess3+sess4 up to the fix. Once fixed, run `072239Z` (build `1A48257A`) showed
`DISK_MAPS_WANT=0`/`refs_into_holes=2` — **"PLATTER-TORN, WRITER-side"** — attributed to
"stale-base RMW laundering" (a tenure's first modify of a bmbt child it never re-read
that tenure RMWs prior content, then re-stamps the tenure id, defeating the sess66
content-blind gate forever after)
[[AAA-ccloop46ef-sess4-PLATTER-TORN-PROVEN-laundering-hunt]]. **This PLATTER-TORN verdict
was itself REFUTED at end of session**: build `91A7D62B`'s `P70-REL-AUDIT` (post-unlock
raw FUA readback, da3-magic-aware) showed `refs_into_holes=0` on all 36 audits — writers
and platter fully exonerated. The earlier "torn" reads were **decoder artifacts**: the
scanner misdecoded a da3 interior NODE block (living in the leaf-dablk region) as a leaf,
producing constant ghost refs (`ghost_db=16384,16384`). Both decoders were fixed to check
LEAF1/LEAFN magic. "Stale-base RMW laundering" as a corruption mechanism is therefore
also refuted (its detector, `P67-STALE-BASE-RMW`, fired once and benign)
[[AAA-ccloop46ef-sess4-END-writers-exonerated-readskip-next]]. Remaining failure at
session end: `cache_coherency@32` still 0/32, but now traced to a stale *reader-cached
buffer* (walker follows a leaf entry to a legally-freed data block against a fresh map) —
last unaudited layer flagged for sess5: read-time dir-buffer invalidation is skipped for
dirty/pinned/in-AIL buffers per a sess12 guard, so local reads can serve stale images
even though writes are protected.

## sess5 — uv-ghost chain solved; datascan-corruption solved; i!=1 narrowed (theory later refuted in sess6)

Two independent bugs fully solved this session
[[AAA-ccloop46ef-sess5-uv-ghosts-solved-i-ne-1-hunt]]:

1. **uv "none remain" ghosts**: create-wave leaf wars manufacture leaf-hash holes (dirent
   present in data blocks, absent from leaf); `rm` on a hole-name ENOENTs at leaf lookup,
   the whole unlink txn aborts, `rm -f` swallows the error, file survives as a *leafless*
   ghost that `ls`/readdir still counts. Fix (v0.10.18): `mxfs_dir2_leafless_removename`
   — on removename leaf-ENOENT, scan data blocks for the exact name, expunge data-side,
   return success so unlink completes.
2. **Datascan corruption storm**: datascan + leafless-remove read data blocks with
   `flags=0`, so legal sparse holes (post-shrink) tripped `XFS_DABUF_MAP_HOLE_OK`
   checks and raised EFSCORRUPTED storms that killed the mv wave. Fix (v0.10.19): pass
   `HOLE_OK` in both, and gate the P14-DABUF-HOLE probe to `!HOLE_OK` (most P14 storms
   were benign readdir holes, not real corruption).

Remaining blocker: `i != 1` in `xfs_bmap_del_extent_real` during rename dir-block free
(bmbt lookup misses an iext entry) → EFSCORRUPTED → shutdown → that node's renames
invisible cluster-wide. A discriminator (`P75-BMBT-DEL-MISMATCH`, build `3FA53AF8`) was
built to distinguish "LUN==cache ⇒ iext stale" from "LUN!=cache ⇒ stale cached bmbt
leaf" — result landed the session's END memory
[[AAA-ccloop46ef-sess5-END-P61-skip-eats-bmbt-commits-fix-design]]: **samelun=1 every
time** (cached content == LUN; the committed op is simply missing from the leaf, not a
stale-cache read). Traced to `P61-CHOKEPOINT-SKIP-BMBT` (xfsaild write skip when dir not
EX) fake-clean-ioend'ing a write whose committed image never reached the LUN, then the
evict machinery discarding the true in-core buffer because its guards (clean,
"destaged") were satisfied by the lie — next re-read loads the pre-commit leaf while the
iext (still in-core) reflects the real, unpublished commit. Fix design proposed but
**not yet proven**: at the P61 skip, if content differs from LUN, mark the buffer
undestaged (`b_mxfs_logged_seq++`) instead of lying, so the next EX tenure's release
fence lands it.

## sess6 — sess5's P61 theory REFUTED; real root = mid-tenure reload racing the write cache; iversion-frozen fix landed; dir_reuse@16 wedge chain opened (memory-clobber theory later refuted in sess7)

**Sess5's "P61 skip eats committed bmbt updates" is refuted.** A tripwire
(`P77`, both skip sites) showed every differs-from-LUN skip had `lseq==wseq` *before* the
mark — i.e. never-logged, struct-recycled republish images, not eaten commits. Applying
sess5's proposed fix (v0.10.24: bump lseq + scan-undestaged) made things *worse*
(late-republish of stale leaves under later EX) and was reverted (v0.10.25, print-only)
[[AAA-ccloop46ef-sess6-MIDTENURE-RELOAD-root-and-evidence]].

Across 6 builds this session the evidence converged on the true root: **mid-tenure
reload/decode races the LIO write cache**. While a node holds EX and has modified the
dir this tenure, its own dinode+leaf writes are cache-resident (LIO drops FUA writes);
any reload path that force-reads the platter (a cluster-buffer pierce, or the P34B leaf
compare) sees pre-write state and adopts/regresses one side of
`(dinode, iext, leaf)` against the others → `i!=1` or `ir.loaded!=if_nextents`
divergence. A genuine tenure *start* is safe (prior holder's release flushed); the bug is
reload happening *mid*-tenure. Along the way: `di_changecount` was found **frozen** under
storm (upstream only bumps iversion on log-item clean→dirty *transition*; under
continuous dirty the item never leaves AIL so cc never advances), making every
cc-equality reload gate vacuous — real bug, fixed (v0.10.26): force one
`inode_inc_iversion` per CORE-logging tx on mxfs multi-node mounts. Verified cc now
climbs. A completion-barrier design (P3B, v0.10.25) and a P3B-REFLUSH-after-late-work fix
(v0.10.27) were both tried and **did not close** i!=1 (P3B-REFLUSH fired 0×, refuted as
the path). The fix shape identified for sess7 to try: in `mxfs_dlm_reload_inode`, if
`i_dlm_mode==EX && i_mxfs_dirty_seq == i_mxfs_ex_grant_seq` (dirtied *this* tenure), skip
the destructive fork/dinode adopt. A partial attempt this session (P34B tenure-AHEAD
skip, v0.10.28) made the *measured* failure count worse (169 fails/3 dead vs the
sess5-end baseline of 54-56/1 dead) — flagged as possibly needing to bisect back toward
the sess5-end build if the full mid-tenure-skip doesn't collapse it.

Separately, `dir_reuse_coherency@16` was run for the first time this session and failed
0/16 with a chain **provisionally attributed to a one-shot memory clobber**: `ino=131`
(shared test dir) showed `h_ex` frozen at `0x320` for 900+s with garbage neighbor fields,
suspected as a small-buffer overflow in shortform-dir merge/adopt memcpy; plus a
`P36-MHT-REARM` unbounded 8ms-forever spin holding an iget ref, feeding an unmount inode
leak, feeding post-rmmod bio-completion oopses into unloaded module text
[[AAA-ccloop46ef-sess6-END-dirreuse16-clobber-agenda]]. **This memory-clobber theory is
refuted in sess7** — see below; `h_ex=0x800` was a live bitmask (node_bit 11), not
corrupted memory.

## sess7 — dir_reuse@16 root PROVEN and fully fixed (3 stacked bugs); 16/caw board COMPLETE 17/17; 32/caw cache_coherency+dlm_scaling PASS

Three stacked root causes, each proven by live kcore/kprobe debugging on test9/test1,
each fixed, ladder re-measured after each fix:

1. **broot-bytes stale-field oops → node wedge → cluster starvation** (v0.10.31, build
   `70EA513F`). `xfs_idestroy_fork` frees `if_broot` and NULLs it but leaves
   `if_broot_bytes` stale after a reload/adopt rebuilds a live fork from an extents-format
   disk image (same landmine class as the documented `if_data`/`if_bytes` bug). The next
   extents→btree conversion's `xfs_bmap_broot_realloc` sees `new_size==old_size`, takes
   the no-op path, and returns the NULL `if_broot` — `xfs_bmbt_init_block` writes to
   NULL+4 → **kernel NULL-write oops**, killing the `dd` creator task *in place* while it
   holds the dir's VFS `i_rwsem`/`i_lock` and `i_dlm_ex_holders=1` forever (verified via
   `/proc/kcore` scan: rwsem owner = dead-task slab address). Every subsequent dir op
   parks; the on-disk CAW slot freezes `h_ex` with `waiters` set — **this is the exact
   signature sess6 mis-attributed to memory clobber; it is a live bitmask on a wedged
   node, not corruption**
   [[AAA-ccloop46ef-sess7-ROOT-broot-bytes-oops-and-wedge-chain]]. Fix A: zero
   `if_broot_bytes` in `xfs_idestroy_fork` + `P80-BROOT-TORN` heal guard at
   `xfs_bmap_broot_realloc` entry. Fix B (containment): `i_dlm_dwork_strikes` counter,
   strikes out at 2500 (~20s continuous busy), drops the leaked iget ref instead of
   spinning forever.
2. **bmbt release-fence blind spot → stranded leaf → manufactured CRC storm** (v0.10.32,
   build `D0A20A10`). Fix A/B eliminated all oopses/wedges/panics (16/16 nodes alive), but
   exposed: the release fence's undestaged-detection required `XBF_DONE`, so a
   peer-BAST modify-evict clearing `XBF_DONE` mid-tenure made a real durable delta
   invisible to the fence — EX handed away with the delta unlanded. The stranded buffer
   then flooded chokepoint/FUA skip arms at ~40Hz forever, and sync reads verified the
   *dirty in-core* image against a CRC only ever stamped at write time, manufacturing
   perpetual `EFSBADCRC` (LUN itself was verified valid by raw O_DIRECT read+crc32c)
   [[AAA-ccloop46ef-sess7-FIX-CDE-bmbt-stranded-leaf-v01032]]. Fix D (root): drop the
   `XBF_DONE` requirement from the undestaged-detection predicate (keep only
   `!XBF_STALE`). Fix C (heal): reconcile at the skip site — same-as-LUN → certify
   destaged; differs+undestaged → `P81-BMBT-SUPERSEDED-DROP` (loud loss accounting) +
   certify + `xfs_buf_stale` (implements the sess66-promised "stale it" that was never
   built); differs+clean → stale. Fix E: `b_mxfs_inplace_read` flag skips `verify_read`
   on in-core-authoritative completions.
3. **Stale `b_iowait` completion token → perpetual CRC on one node** (v0.10.33, build
   `7395C3EC`). Fix C/D/E took the failure from 0/16 to 15/16 (one rank stuck on
   `readdir=0/1600`, forever `EFSBADCRC`). Root, proven via kprobe caller resolution +
   `watch_daddr`/kcore + `block:block_bio_queue` tracing: real bios *were* queued, but
   `xfs_buf_iowait` returned early because `b_iowait.done==1` **at rest** (stale
   completion token from an earlier emulated ioend or a readahead-steal `XBF_ASYNC` flip)
   — iowait's wait-loop then CRC-verified pre-DMA content forever
   [[AAA-ccloop46ef-sess7-STALE-IOWAIT-TOKEN-v01033]]. Fix: `reinit_completion` on the
   `b_iowait` at sync `xfs_buf_submit` entry (safe — submitter holds the buffer lock, so
   any pre-existing token is provably stale). Also found and fixed in passing: Fix-E was
   being defeated by a double-`__xfs_buf_ioend` call (arm consumed the in-place flag,
   iowait's second pass re-verified) — pairing fixed so the arm's ioend clears `XBF_READ`.

**Milestone**: `dir_reuse_coherency@16` PASS 16/16 (run `174235Z`) →
`16/caw` board **COMPLETE 17/17**; `1/2/4/8/16 /caw` all 17/17
[[AAA-ccloop46ef-sess7-MILESTONE-16caw-COMPLETE-17of17]]. Re-running the 32-node trio on
`v0.10.33` with *no additional changes*: `cache_coherency@32` PASS 32/32 (run `181910Z`),
`dlm_scaling@32` PASS 32/32 (run `182945Z`) — both cured incidentally by the v0.10.31-33
fix stack. Session ended with `dir_reuse_coherency@32` **RUNNING** (pid 2828039, run
`183952Z`, r2/24 healthy, CRC=0/P81=0/OOPS=0), the last remaining ladder gap
[[AAA-ccloop46ef-sess7-END-drc32-RUNNING-last-ladder-gap]]. Build `v0.10.33`
(`7395C3ECCCDD5B07DE5A2EB`) deployed cluster-wide.

## sess8 — DIFFERENT ccloop id (12e0d157); cache_coherency@32 regressed again; new root found (unrelated to sess1-7's fixes)

This memory runs under ccloop `12e0d157` / session `33136bc8`, not `46efd8b6` — likely a
later, separate resumption of the same ladder-completion goal. Its scoreboard shows
`32/caw` **worse than sess7 left it**: cache_coherency FAIL, crash_consistency FAIL,
dlm_scaling PENDING, dir_reuse PENDING (16/caw still 16/17, dir_reuse PENDING — i.e. this
session's view does not show sess7's 16/16 dir_reuse PASS reflected, suggesting either a
stale scoreboard read or state drift between the two ccloop runs — worth reconciling
first thing next session)
[[AAA-sess8-cachecoh32-ROOTS-reload-identical-landed-neg-lookup-dscan-next]].

Two fixes landed, build `944B0EAB292DFC5433AC12A` (`96C5CF1F` + 2 param-gated fixes,
both default ON): `reload_skip_identical` (skip fork destroy/from_disk when disk dinode
is provably identical by cc/gen/mode/fmt/nx/size — kills an identical-adopt EX
rotation loop, fired 11985×/run) and `dir_ex_verify_caw` (extends an existing TCP-only
held-verify check to CAW; fired only 1×/run, so **phantom-EX is refuted** as the tear
source — kept anyway, cheap).

New leading hypothesis for cache_coherency@32's current failure (test dies specifically
in `rename_visibility`'s verify phase, which never completes within budget): **block-format
dir layout divergence ping-pong** — block-format dirs have no 3-way merge (only
`mxfs_dir_sf_merge_into`, shortform-only). A node with committed-but-not-yet-destaged
rename mods self-skips the reload adopt (the sess36 guard, required to not lose its own
delta), keeps its *whole* in-core layout, and its later release republishes that layout
wholesale — clobbering a peer's disk-merged layout. Last-writer-wins at the whole-layout
level, so divergence is structural under concurrent block-dir grow/shrink; masked at
≤16 nodes by MHT batching + fewer racers. **Not yet proven** — next session's step 1 is
to instrument tear *formation* during the rename phase (watch first
`INCONSISTENT-AT-RELEASE`, which node kept which layout) before picking a fix direction
(release-side re-iread-after-drain vs. adopt-side re-apply vs. preventing divergence
birth by forcing dir grow/shrink under freshly-verified EX+map).

## Current state / what the next session should pick up

- Confirmed root-caused and fixed, all landed in tree (do not re-chase): stale-HB
  evict-ring replay, iread-EX-vs-PR mapping, dscan gen-gate cost, dir-EX
  tenure-floor/sliding-grace mechanics, P15H strand-reap storm (threshold+anchor fixes),
  decoder da3-NODE-misread-as-leaf artifact, uv leafless-ghost removename, datascan
  HOLE_OK corruption, iversion-frozen-under-storm, broot_bytes stale-field oops,
  bmbt release-fence XBF_DONE blind spot + skip-site reconcile, stale `b_iowait`
  completion token.
- Explicitly refuted, do not re-propose without new evidence: cold-iget-adopts-lagging-home
  (sess3, refuted sess4); PLATTER-TORN writer-side / stale-base-RMW-laundering (sess4,
  refuted same session — decoder bug); "P61 skip eats committed bmbt updates" (sess5,
  refuted sess6 — real root was mid-tenure reload racing the LIO write cache, and P34B's
  partial fix attempt made things worse); ino=131 memory-clobber theory for dir_reuse@16
  (sess6, refuted sess7 — was a live wedge/bitmask from the broot-bytes oops, not
  corrupted memory); phantom-EX as the sess8 tear source (fired 1×/run, refuted by its own
  new verify check).
- Open at the end of sess7 (ccloop 46efd8b6): `dir_reuse_coherency@32` result unknown —
  was RUNNING at handoff, never confirmed PASS/FAIL in these memories.
- Open at the end of sess8 (ccloop 12e0d157, later/parallel run): `cache_coherency@32`
  and `crash_consistency@32` both FAILing again on a *new* mechanism (block-dir layout
  divergence, unproven), `dlm_scaling@32`/`dir_reuse@32` PENDING. First action: reconcile
  why this session's scoreboard shows 16/caw dir_reuse PENDING when sess7 (46efd8b6)
  recorded it PASS 16/16 — determine if this is genuinely a different/reset environment
  or a stale board read, then instrument tear formation per sess8's plan.
- Reusable tooling built along the way, still in tree: `scripts/rv_marker_harvest.sh`,
  `scripts/live_marker_harvest.sh`, `scripts/setup_serial_capture.sh`,
  `scripts/caw_slot_dump.py`, `scripts/diag_rv_replay.sh`, `scripts/coord_bar_watch.sh`,
  `scripts/diag_rv_verify_ab.sh`, `scripts/node_disk_hygiene.sh`, the kcore
  `findino.py`/`rdring.py` inode-DLM-state dumpers, `watch_daddr` buffer-pointer probe,
  netconsole-to-clyde panic capture. Standing gotchas: always window kernlog greps to run
  start; `/home/steve/disk.img` buffered reads on clyde alias stale page cache — always
  `iflag=direct`; `tools/mxfs_sshpass.sh` flattens quoted script args, never pass complex
  inline scripts through it; kill stale ccloop predecessor claude sessions at session
  start.
