---
name: sess49-8tcp-root-is-durable-dir-delalloc-extent-tear
description: sess49(ccloop): 8/tcp dir_reuse FAILS deterministically (node6 round7) via DABUF_MAP_HOLE — durable dir extent-map GAP (leaf refs block 1, map=[blk0,…
metadata:
  type: project
---

## sess49 (ccloop) — 8/tcp dir_reuse: deterministic DABUF_MAP_HOLE shutdown = durable dir extent-map GAP

### State / criteria
Criteria: get 1/2/4/8 tcp dir_reuse working 100%. dir_reuse MINNODES=2 so **1/tcp is N/A** (correctly skipped, ran=0). **2/tcp + 4/tcp PASS** (recorded, confirmed). **8/tcp = the blocker (FAIL 0/8 every clean run this session).** Marker NOT written.

### Build state at handoff: srcversion 1E2B906C
= original behavior + NEW instrumentation/levers (all safe, original semantics preserved):
- `mxfs_dir_delalloc_tripwire(ip, site)` (xfs_mxfs_dlm.c, decl in .h): scans a dir data fork for DELAYSTARTBLOCK, dumps extents+stack on first 8 hits. Called at: xfs_dir2.c dir2_grow_inode, xfs_mxfs_dlm.c post_from_disk, xfs_da_btree.c dabuf_map_hole. **Fired 0× all runs** → the in-core fork has NO persistent delalloc (the -2 seen in the FIRST polluted-VM run was transient/not reproduced clean).
- `mxfs_dir_handoff_adopt` param **DEFAULT 1** (= original). A/B lever for the P63-HANDOFF genuine_handoff edge bit.
- `tests/tcp/drc_reliab_iter.sh <N>`: clean virsh destroy+start all N VMs, set console_loglevel=4 (QUIET_CONSOLE=1, drops the pr_warn flood off the serial console — keeps it in dmesg), run.sh N tcp dir_reuse_coherency, prints ITER_RESULT. ~8-10min/iter; one foreground bash call each.

### THE FAILURE (clean-reboot reproducible, ~deterministic)
**node6 (rank6) fails at round 7 (~90-160s uptime)**; node6 readdir=0 thereafter, all other 7 nodes readdir=719→700/800 (missing node6's ~81-100 dirents). Failure mode VARIES per run: (a) DABUF_MAP_HOLE cascade shutdown (1300-1700 hole hits, node EIO), or (b) pure node-isolation (node6 declared dead after 40s "did not reconnect", NO corruption). (b) is downstream of (a): node6's FS shuts down → peers declare it dead → its work lost.

### PROVEN ROOT (RULE 4): durable dir extent-map GAP, NOT delalloc, NOT handoff, NOT reader-reload
`P14-DABUF-HOLE ino=131 fmt=2 nextents=3 disize=12288 dir_gen==loaded_gen(=20/35/65) i_gen==evicted_incarn(same incarnation) comm=dd`, irecs `[00] br_startoff 1 br_startblock -1` (HOLE). disize=12288 = 3 logical blocks (0,1,2); nextents=3 = [block0, block2, LEAF] with a **GAP at block 1**, but the LEAF hash index references block 1 → xfs_dabuf_map !HOLE_OK → EFSCORRUPTED shutdown. This is the classic sess20 reuse-stale-leaf / dir extent-map divergence (the ~130-session "durable lost-update" core). The dir (ino 131) is rm-rf+recreated each round (reused inode/daddrs); a block allocated+leaf-referenced is LOST from the map across the cross-node EX churn, leaving the gap.

### REFUTED this session (do NOT repeat)
1. **Reader-side reload guard** (keep in-core on same-incarnation EXTENTS→EXTENTS shrink): built 5A6EF12E, fired 1889× keeping in-core, STILL 0/8 — test1 shut down with P33/P62 fired 0× (fresh-load hole). REVERTED.
2. **genuine_handoff / P63-HANDOFF is the cause**: gated OFF via mxfs_dir_handoff_adopt=0 → P63-HANDOFF fired 0× → DABUF_HOLE STILL fired 1375-1672× → REFUTED. (Param kept, default restored to 1.)
3. **In-core delalloc extent**: tripwire fired 0× → the fork has no persistent delalloc; the hole is a plain missing extent (-1), a real map GAP.
4. gen-coupling (dir_gen>loaded_gen): refuted AGAIN (always equal at the hole; sess15 already refuted).

### NEXT (RULE 4) — attack the durable map-GAP creation (write side)
The dir map ends up [blk0, GAP@blk1, blk2, leaf] while the leaf references blk1. Either (a) blk1 was allocated+leaf-linked then its EXTENT was lost from the map (a stale iflush / reload wrote a map missing blk1's extent over the good one), or (b) two nodes diverged on the map across an EX handoff (sess24/39/42 double-alloc family: node A puts blk1 at one daddr, node B's map omits it). DECISIVE PROBE: at the hole, FUA-read the on-disk dinode + dump BOTH in-core AND on-disk extent lists for ino 131 (prove disk-torn vs in-core-torn). Then either (1) GPT consult #1: release-side force-complete ALL dir-fork buffers incl LEAF so leaf+map+dinode are one consistent durable image at unlock; or (2) GPT guardrail #4: at the hole site, reload extent map + retry instead of shutdown (lock-inversion: xfs_da_read_buf holds ILOCK-shared, reload needs EXCL — needs an EAGAIN-retry plumbed to a non-ILOCK caller).
sess22's KEEPER build (1FE2C2DA, pre-genuine_handoff) had **ZERO shutdowns** (144/145 or PASS) via reorder-remove + rebuild-hole-skip — current build REGRESSED to cascade; consider diffing what re-introduced it (no git; reason from P-signatures).

### Heavy instrumentation flood (RULE 0 concern)
60k-148k dmesg lines/run (P68-EVDECIDE/P-DIRIFLUSH/P64-N1F1/FUA-COUNT/P26-DSCAN ungated pr_warn + 1300+ DABUF alerts). Contributes to slowness + node isolation. Gating the worst behind mxfs_instr would clean the signal + may reduce mode-(b). Not done this session (mechanical, risk).

See [[sess48-DECISIVE-loss-is-reader-extentmap-staleness-not-writer]] [[sess47-GPT-consult-leaf-coherence-invariant-and-design]] [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]] [[sess22-build-1FE2C2DA-reorder-plus-holeskip-144of145-noshutdown]].
</body>
