---
name: sess27-HANDOFF-head-state-and-next-step
description: sess27(ccloop) HEAD/HANDOFF: dir_reuse 8/tcp loss PROVEN = intra-block dir-slot COLLISION (clobberer's addname picks the victim's just-filled offset;…
metadata:
  type: project
---

## sess27 HEAD — where the next session starts

### CRITERIA: 1/2/4/8 tcp dlm 100%. NOT MET. Sole blocker = 8/tcp dir_reuse_coherency (~50% flaky dirent loss). 1/2/4 tcp green.

### Build/config: tree+deployed=**965BDBD3** (keeper). Working modargs (NOT default): `dir_gen_per_handoff=1 dir_modify_extent_adopt=1`. Cluster CLEAN.

### THE PROVEN MECHANISM (byte-exact, this session's breakthrough) — [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]]
INTRA-BLOCK DIR-SLOT COLLISION. Round-7 daddr=10466208 off=1280: node5 adds+flushes node5_f46.md5 @ off=1280 (P11-DATALOG+POSTADD+RELFLUSH show it present); 14ms later the block shows node7_f47.md @ off=1280 and node5_f46.md5 GONE. node7's addname picked the EXACT slot node5 had just filled → overwrote it. node7's free-space accounting (data-block bestfree, or node-format FREE/freeindex bests[]) was STALE (listed off=1280 free). Same root as sess11 ("dirent bytes logged then vanish"), still live.

### WHY it evades detectors (reconciles all sess27 refutations)
node7 RMWs a base whose DATA-block content lacks node5's add but whose **gen MATCHES** (dir_gen==loaded_gen) — so the read-path invalidation (xfs_da_btree.c:3176, runs under EX for published dirs; owned_ex = i_dlm_unpublished only, NOT "holds EX") does NOT fire (b_gen==dir_gen), DIR-STALE-SKIP needs gen-mismatch, P60-GENMATCH-STALE skips in-AIL blocks. The node5→node7 handoff FAILED to bump node7's dir_gen → node7's stale block served as fresh. WRITE-SIDE (slot physically overwritten on platter); force_coherent/fua_write/release_invalidate/dirskip/MHT all REFUTED (don't address the gen-not-bumped slot pick).

### THE FIX (next session, RULE 4):
ROOT = the cross-node handoff (node5→node7) did not bump the clobberer's i_dlm_dir_gen, so its cached data block (b_gen==dir_gen) is served stale and its bestfree offers the occupied slot. Make handoff detection RELIABLE so the clobberer refreshes the data block (and the node-format FREE/freeindex block) before its addname slot-pick.
1. PROVE: instrument xfs_dir2_data_use_free / xfs_dir2_node_addname_int slot-pick (ino<=256): log chosen (daddr,off) + whether a live dirent ALREADY occupies that off (collision caught in the act) + the block's b_mxfs_dir_gen vs dp->i_dlm_dir_gen at pick time. Confirm gen==gen (missed handoff) at the collision.
2. FIX options: (a) make P63/FASTEX handoff detection fire on the missed handoff (check why node7's gen didn't bump — master dg_shadow epoch for ino=131 not advancing on the rapid node5→node7 grant? see dlm.c dg_grant_ex epoch + [[sess23-NEXT-hypothesis-node-format-freeblock-coherency]]); (b) at addname slot-pick on a multinode shared dir, if the block is clean and the dir had ANY handoff since the block's last read, force a coherent re-read of the data block + FREE block before xfs_dir2_data_use_free. NOT an unconditional per-acquire gen bump (would re-read own in-tenure clean blocks = lose work).
3. Do NOT: union-merge blocks (corrupts allocator), unconditional gen bump mid-tenure.

### Refuted this session (don't repeat): dir_release_invalidate=1, inode_mht_ms=600, dir_release_fua_write=1, force_coherent=1, dirskip=1 — all still FAIL. Read-side/durability/eviction/timing knobs don't touch it. See [[sess27-DECISIVE-loss-is-write-side-force-coherent-doesnt-help]] [[sess27-REFUTED-four-mechanisms-residual-is-undetectable-content-lostupdate]].

### Tooling (tests/tcp/): drc_catch3.sh (dirwr=1+DRC_STREAM NFS→drc_cap/stream_rankN.log, ring-immune, clears stale markers), drc_catch2.sh, drc_passrate2.sh. run.sh forwards MXFS_TEST_ENV. The dirwr probes P11-DATALOG/P11-POSTADD/PRELOGF/P-RELFLUSH dump block dirent-name lists — invaluable, reuse them.
