---
name: compiled-caw-v06x-4node-dirent-loss
description: Compiled v0.6.4/v0.6.5 CAW 4-node dirent-loss fix chain: phantom cached-EX, grant_seq prebump, epoch-consume, acq_epoch, block-for-life → 17/17.
metadata:
  type: project
tags: [compiled, caw, dirent-loss, cache-coherency, dlm, 4node, v0.6.x]
---

# CAW 4-node dirent-loss fix chain (v0.6.3→v0.6.5), ccloop 186320ae, sess2→sess5

Central topic: on 4-node CAW (`/dev/mapper/mpatha`, SCST fileio backing), a create+mv+rm
storm against a single shared directory randomly lost one node's dirent adds/renames for
EVERYONE — surfacing as `cache_coherency` uv/rv/cv, `mmap_coherency`, and `posix_multi`
failures. The loss migrated between tests run-to-run (~100% of 4-node runs hit one).
Terminal symptom: deleted dirents survive on disk pointing at freed inodes → `P26-IGET-FAIL
err=-2` (t2/3/4 "pass" by failing the stat; only test1 stat FAILs). Repro loop throughout:
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 4 caw
precond_readiness cache_coherency`. Fixed across five distinct root causes; four builds.

## Root cause 1 — phantom cached EX / dual-writer (sess2, [[caw-phantom-cached-ex-dirent-loss-rootcause]])
`dirland=1` completion-ring (`dland_dump` → `P-DLAND d= o= s=<fnv> n= t=<realns>`) proved
**two nodes RMW the same dir block interleaved** (daddr=8372968, uv ino 10485888, ~60ms,
t1 climbing count 66..90 while t4 climbs 67..89) — two uncoordinated RMW streams; final image
drops the loser's latest adds. `P106-STALE-EX cached_mode=EX on_disk_held=0` fired 61× at
window start: the dir-EX fast path (`xfs_mxfs_dlm.c` ~16990-17080) verifies the on-disk CAW
slot via `dir_ex_verify_held` but was **PROBE-ONLY** — it logged P106 then served the phantom
cached EX anyway. `P108-REACQUIRE` (idle-only, gated pin==0 && holders==0 && 1000ms throttle)
can never act inside an active storm. **Genesis (µs trail, t1 ino 10485888):** BAST unlock's
CAS-EAGAIN retry re-reads the slot, sees OUR just-re-granted bit, and CLEARS it — releasing a
grant a concurrent LOCAL slow-path acquire took 1.6ms earlier (`P106-EXREL`→`P106-EXGRANT`
gen=4→`P106-STALE-EX held=0`). In-core keeps CACHED-EX; disk is released → dual-writer.
Interim defense: `dir_ex_revalidate=1` (sess51 knob, `xfs_mxfs_dlm.c:4860`) diverts every
published !self_created dir EX-modify to authoritative slow-path re-acquire.
Red herrings eliminated: lseq/wseq=0 (SUBMIT-time snapshot, not broken accounting); "log I/O
error -52" bursts (benign per-iteration prep_fs PR-CLEAR on dying prior mount); `P26-LKFMT
fmt=1` is BLOCK not shortform (XFS_DIR2_FMT: SF=0, BLOCK=1); tombstone epoch-inherit clean.
Trap: `dirwr=1` must be an insmod modarg, NOT `mxfs.dirwr=1` (silently dropped).

## Root cause 2 — grant_seq not bumped before bit-add CAS (sess4 FIX A, build 3AAFAEEF, [[caw-v064-prebump-epochconsume-fixes]])
The offense side of RC1. In `dlm/dlm_caw.c` every slow-path grant did `caw_slot CAS →
caw_check_exclusion → caw_verify_grant_persisted (FULL SCSI READ, ms) → caw_grant_meta_store
(seq bump)`. The fresh holder bit was live on disk for ms with `grant_seq` un-bumped, so a
concurrent unlock's `find_slot` saw the bit, passed entry/in-loop/last-instant seq checks, and
CAS-cleared the NEW tenure (proof: iter12 test2 ino=133 EXGRANT@.538467 → STALE-EX held=0
@.539723, 1.26ms; abort fired on test1's parallel instance where the store had landed;
CAW-DUP-SLOT=0). **Fix:** `caw_grant_seq_prebump(ctx,resource)` immediately before EVERY
holder-bit-adding `caw_slot` (waiter-promote, fresh-claim, compat-add, convert up/down,
flush_held_to_disk ×2). Failed-attempt bumps are safe-direction (spurious unlock abort →
BAST re-arm self-heals). Result: `P106-STALE-EX = 0` across all iterations; the abort now
fires where clears used to slip.

## Root cause 3 — CAW acquire consumed no freshness signal (sess4 FIX B, build BD8746D8, [[caw-v064-prebump-epochconsume-fixes]])
The uv dangling-dirent proper. Dir-shrink storm → test4's EX grants consumed NO freshness:
the P63 one-shot handoff bit is ~80% lossy, and the P65 level-triggered epoch was OBSERVE-ONLY
(`mxfs_dir_epoch_adopt=0` since the sess49 8/tcp regression). test4 `valid_epoch` froze @14
vs cluster 27 → `P68-EVDECIDE` kept the stale dir block (b_epoch==stale valid_epoch) → every
unlink re-logged the stale 18-entry image → release-drain durably resurrected node2_file28 →
block→sf conversion crystallized it → dirent→freed inode. `disk=[node2_file28]` confirmed by
`P56-RELOAD-MERGE` on all 4 nodes; two independent block→sf conversions (t4 ~:19.93, t2
~:19.99) = divergence smoking gun. **Fix:** at the P65 gate (`xfs_mxfs_dlm.c` ~13645), on
CAW + post_release + epoch!=valid, set `genuine_handoff=true` when SELF-CLEAN (pin==0 &&
!ili_fields && !in_AIL) — the sess49-regressing config (TCP + dirty grow) excluded on both
axes. `genuine_handoff` drives P33/P43 guard bypass + P68-PREEVICT + adopt + valid_epoch
stamp (~15190). Validation: v064b iters 1-7 PASS 4/4, STALE-EX=0; **iter8 TIMEOUT(240s)** —
test1 wedged mid-uv, harness virsh-destroyed it, volatile journal lost the evidence (wedge
cause UNKNOWN, not attributed to the fix; 7 clean fast iters argue against adopt-storm; a
PRE-EXISTING `mxfs_ili` slab leak on rmmod-after-log-error-shutdown noted on t2). Mitigation:
persistent journald on test1-4 + `scripts/klog_tail.sh` clyde-side collectors (`/tmp/klog_testN.log`).

## Root cause 4 — dual-representation divergence, and why valid_epoch can't gate (sess4 hunt, build 9C634772 → sess5 fix CD7D3E62)
Deep forensics ([[caw-uv-single-dirent-leak-hunt]], run 003620Z) proved the residual family
is **two on-disk representations of one dir with no serialization**: during the 120-unlink
storm ONE node (t3) crosses the block→sf threshold first and converts IN-CORE early; from then
t3's removals edit the INODE CORE (sf) while peers keep editing the BLOCK (daddr=2376). t3
wrote nothing to 2376 post-conversion (P35E silent; ~129 correct P11-FLUSH-CLEANSKIP). t1's
later EX tenures cold-read the STALE block (still carrying node3_file20/21, which lived only in
t3's sf core) and release-drain RE-ASSERTED them (crc=03b70f75 nent=18→14→13, comm=rm). The
block-side resurrect is the DOMINANT leak, not the dinode revert: **`surgical_inode_write=1`
(per-dinode FUA sectors) was REFUTED as sole fix** (run 005227Z still lost node2_file26+node3_file26,
ino=156, TWO entries) — it may be a needed ingredient but did not stop the family. Eliminated
this session: phantom-EX as uv cause (0 STALE-EX in failing runs; Fix A holds), split-slot
(32-bit FNV, all home, 0 dups), b_epoch stamp fraud, eviction-never-runs (P4O evict=1 fires),
systemic lineage divergence, FUA transport staleness (SCST fileio shares backing page cache),
P34F self-ahead early-return. **Why valid_epoch cannot serve the acquire gate:** modify/evict-path
hooks legitimately sync valid_epoch UP to master epoch mid-tenure for buffer stamping + prior-tenure
evicts (`xfs_mxfs_dlm.c` 5318/5342 + libxfs read hooks `xfs_da_btree.c:3575`,
`xfs_dir2_leaf.c:1156`, `xfs_dir2_node.c:2090`, `xfs_dir2_data.c:2224`), erasing the acquire
gate's lag with no adopt having run → stale dir-block base survives handoffs. **Fix
(CD7D3E62, [[caw-v065-acq-epoch-fix]]):** new `ip->i_dlm_dir_acq_epoch` (xfs_inode.h, after
i_dlm_dir_valid_epoch, init 0). The P65 CAW gate (~13655) now compares `dir_grant_epoch !=
i_dlm_dir_acq_epoch` (TCP still uses valid_epoch, `>`). acq_epoch advances ONLY at the reload
coherence point (~15245, immediately before the guaranteed `xfs_inode_from_disk`, no bail
between); keep-stale early returns (P43-FMTREVERT-SKIP) leave it lagging so the gate re-fires
next acquire = true level-trigger. Verification: **13/13 consecutive PASS** (prior fail rate
1-in-2..5), P65-EPOCH-ADOPT firing 347/iter on test1 (adopt=1 clean=1, multi-epoch skips like
grant=55 acq=53 caught), 0 P106-STALE-EX, 0 P43-FMTREVERT-SKIP. Instrumentation fix same build:
`P136-DIRINO-WRDONE` (`pal/linux/xfs_buf.c` ~1584) was SKIPPING LOCAL(sf)-format dir dinodes —
the sess4 "nobody wrote sf" hole was an artifact; now logs ALL dir dinode images with fmt=/gen=.

## Root cause 5 — full closure to 17/17 (sess5, build 656E89B4, [[caw-v065-fix-chain-4caw-17of17]])
`dlm_fairness` storm (create+mv+rm per round, 4 nodes, one dir) kept re-minting ghost families
(n2_r15 mv-ENOENT adopt-empty; n4_r10.done / n2_r1 / n3_r1 stale-tenure destage clobber inside
test3's gen-27 tenure; block→sf conversion crystallizing ghosts). FIVE fixes, each RULE-4 proven:
1. **acq_epoch** (as RC4) → cache_coherency 13/13+.
2. **P106-STALE-EX-BAIL** (`mxfs_dlm_ilock_begin` ~17700): phantom cached-EX serve (on-disk
   slot not ours) now demotes to NL + `goto restart` slow re-acquire. Gates: !unpublished,
   pin==0, state==CACHED, no demoter, <3 laps. (This finally converts RC1's probe-only path
   into behavior.)
3. **P5R-TRANSREFRESH** (`xfs_da_btree.c` honor hook ~3280): a stale_pending dir block joined
   to OUR OWN clean trans (trylock can never win) → in-place FUA refresh under the trans lock
   (magic+CRC verified). Handles mid-trans-yield → peer-modify → re-acquire.
4. **P-ICD-TENURE-REFUSE** (`mxfs_inode_cluster_durable` ~4290): destage-time slot verify
   (every 32nd lap) refuses cluster write from a dead tenure; PLUS sticky `i_dlm_icd_refused`
   honored by the reload sf-merge gate (`!xfs_inode_clean || icd_refused`) so a
   ghost-retired-clean inode MERGES instead of wholesale-adopting (wholesale adopt reverted
   committed renames). Cleared only at real-write success exit.
5. **Block-format-for-life** (`xfs_dir2_sf.c` block_to_sf suppress under multinode+force_block)
   + **`xfs_dir_block_isempty`** (`xfs_dir2.c`, tp-aware, at rmdir + rename-target checks):
   shared dirs never re-enter shortform, killing the sf-ghost machinery (RC4's dual-representation)
   entirely. Empty-block-dir rmdir via `xfs_dir3_block_read` + `xfs_dir2_block_sfsize count==0`.
   The precond "unlink/cleanup" FAIL on all nodes was the block-isempty gap.
Also: P136 instrumentation cap was 1200 (3/4 nodes blind ~40s before window) → raised to 60000
+ fmt/gen fields + LOCAL dinodes no longer skipped (had been EXTENTS/BTREE-only). **Result: 4/caw
ALL 17 PASS on 656E89B4** (chunked sequential runs, same build).

## Standing traps / environment notes for future sessions
- P142 slot dump: hex/self are node-BIT masks (t1=0x1 t2=0x2 t3=0x4 t4=0x8).
- EXREL/EXGRANT rapid cadence (rel_gen +2..4 per 10ms) is NORMAL under storm.
- CLOCK TRAP: never compare raw monotonic stamps cross-node; derive per-node offset from
  same-line realns pairs. HASH TRAP: the C fnv1a is 32-BIT.
- P35E `names[]` truncates at ~16 entries and kernlog spans PREVIOUS iterations (same
  ino/daddr reused per mkfs) — always window by realns/run start.
- SCST mxfs device: fileio `/home/steve/disk.img o_direct=1 async=1 wt=0` — ack-after-AIO-complete;
  read-pass-write NOT proven, but SCST fileio shares the backing page cache (FUA transport
  staleness ruled out as a cause).
- run.sh FAIL artifacts: `/tmp/run_<test>_<RUNID>`; PASS runs keep nothing.
- Progress ladder: 1/caw + 2/caw = 17/17 PASS; 4/caw = 17/17 on 656E89B4; 8/16/32 pending.
  posix_multi was the last non-cache_coherency 4/caw gap (3/4) before the RC5 chain.

## Build progression
3AAFAEEF (FIX A prebump) → BD8746D8 (v064b, +FIX B epoch-consume) → 9C634772 (v0.6.4 prebump +
epoch-consume + P141/P142 probes, sess4 head) → CD7D3E62 (v0.6.5 acq_epoch, 13/13) → 656E89B4
(v0.6.5 five-fix chain, 4/caw 17/17).
