---
name: sess69-ondisk-proof-durable-lostupdate
description: sess69 HARD PROOF: unlink_visibility = durable WRITE-side lost-update. Raw O_DIRECT dir-block identical across initiators (transport coherent); on-di…
metadata:
  type: project
---

# sess69 (ccloop run 29df431e) — DEFINITIVE on-disk proof of the unlink_visibility root

Build EC07F422 (= sess97 99635EAD code). cache_coherency 2/4 this run (unlink +
cwr fail; cwr is variance per sess94). Focused on unlink_visibility.

## METHOD (RULE-4, no code change) — tests/uv_disktruth.sh
Reproduced the shared-block-dir concurrent-unlink divergence (test3=test4=19,
test1=test2=0). Then read the dir's data block RAW via `dd iflag=direct` on
multiple initiators, and PARSED it.

## PROOF (airtight)
1. **Transport is COHERENT**: raw O_DIRECT bytes of the dir block (XFS-daddr
   10436672; device skip = xfs_data_offset/512 + daddr; xfs_data_offset @ byte 88
   of mxfs_ondisk_super) are BYTE-IDENTICAL across initiators (test3 vs test2).
   → per-initiator/SCST stale-read hypothesis (B) REFUTED.
2. **On-disk content is WRONG (durable lost-deletion)**: block magic = XDB3
   (XFS_DIR3_BLOCK_MAGIC, 4096-byte block format). Leaf tail @ bs=4096:
   **count=122 (120 files + . + ..), stale=101 → active=21 = 19 files + 2**.
   Data-entry parse independently found the SAME 19 active `node*_file*` entries.
   → the disk DURABLY retains 19 deletions that were supposed to be removed.
3. Nodes showing 0 (test1/test2) hold the correct-INTENT but NON-durable in-core
   state; nodes showing 19 (test3/test4) read the (wrong) durable disk.

## VERDICT: durable WRITE-side lost-update (confirms sess82-97 framing with proof).
A node flushed a dir-block image built on a STALE BASE, durably clobbering 19 peer
removals. My mid-session "read-side staleness" detour was WRONG — corrected by the
raw parse (disk genuinely = 19, so cache-shows-0 nodes are the stale ones).

## MECHANISM — narrowed, not yet pinned
This run's dmesg: **ex_pop=1 everywhere** (EX properly serialized; concurrent-EX
REFUTED, matches sess52). **0 harmful acquire-skips** (P-ACQ-DRAIN-SKIP on the dir
all had done=0 = benign already-invalidated; none done=1). test2: 1× P87-CAW-SPLIT.
So WITH proper EX serialization + working acquire-evict + coherent transport, a
stale-based image still got durably written. Remaining live hypotheses:
- (a) **dir FORMAT-TRANSITION lost-update**: as 120→few entries, dir collapses
  node→leaf→block (xfs_dir2_leaf_to_block etc.); the consolidation READS data/leaf
  blocks and rewrites one block. If any source block is stale-cached (gen-matched
  but content old), deleted entries get resurrected into the new block + flushed.
  The acquire-evict runs once at acquire, before the multi-block reshape reads.
- (b) release/acquire HANDOFF ORDERING: B re-reads before A's release-flush lands.
  (Release fence uses synchronous xfs_bwrite before unlock; sess68 Check-5 refuted
  early-unlock for the inode-BAST path — but the reshape path may differ.)

## NEXT (the decisive instrument nobody has built — GPT/sess68 both wanted it)
Trace every dir-block WRITE submission for the test dir: node, daddr, EX-held?,
active-entry-count being written, caller (removename vs reshape vs xfsaild). On
failure, the LAST writer of the surviving block + its active-count pinpoints
reshape-stale vs handoff-ordering. Then fix the proven cause.

INFRA: tests/uv_disktruth.sh reproduces in ~2-5 iters; leaves divergence LIVE (no
cleanup) so you can raw-read disk truth. Parser: /tmp/parsedir.py (XDB3, bs=4096).

## UPDATE (later sess69): leaf_to_block RESHAPE hypothesis REFUTED
Gemini (RULE-5) hypothesised the carrier is a stale LEAF block consolidated during
xfs_dir2_leaf_to_block. Built **E06FDBC3** = EC07F422 + always-on probe **P69-L2B**
in xfs/libxfs/xfs_dir2_block.c::xfs_dir2_leaf_to_block (logs ino, dlm_gen, active=
count-stale, LEAF+DATA daddr/b_mxfs_dir_gen/in_ail/pin). Deployed 4 nodes. Repro'd
WORSE divergence (t1=0, t2=t3=t4=45; poker-EX reads 45 => 45 durable). **P69-L2B
fired 0× on ALL nodes** => dir still LEAF format at 45 entries, NO reshape. The
lost-update is in the NORMAL leaf-format removename path, NOT reshape. REFUTED.

## SHARPENED ROOT (sess69 end): SILENT stale leaf/data block (gen matches, content stale)
This run dmesg: ONLY ex_pop=1 — NO P87-CAW-SPLIT, NO dup-slot/CLAIMRACE, NO
DIR-STALE-SKIP, NO harmful P-ACQ-DRAIN-SKIP(done=1). Yet 45 durable lost. So the
stale block is SILENT: b_mxfs_dir_gen == i_dlm_dir_gen (passes the xfs_da_read_buf
lazy hook) but content stale. The gen HOLE: i_dlm_dir_gen bumps + evict run ONLY on
the SLOW-PATH acquire (xfs_mxfs_dlm.c ~L3122-3167). A FAST-PATH dir EX re-acquire
(cached compatible lock, returns BEFORE the L3037 slow path) does NO gen-bump, NO
evict => stale cached leaf/data served as fresh, RMW'd, flushed = durable clobber.

## NEXT (concrete)
1. PIN the fast-path hole: instrument the fast cached-lock return in
   mxfs_dlm_ilock_begin (before L3037) — log dir EX fast-grants (ino/mode/gen).
   Reconcile the paradox: a peer modifying needs EX => must BAST us => our
   re-acquire should be SLOW (gen bumps). So either the BAST/release path failed to
   bump-gen/evict, OR a true fast-path-after-stale window exists. Pin which.
2. OR finally build the WRITE-submission trace (GPT sess97 + sess68 wanted it,
   STILL unbuilt): every dir-block write -> node-slot, daddr, magic(data/leaf),
   active-count, dir-EX-held?, in_ail/pin, caller. Last writer of surviving block
   pinpoints the bad write directly, mechanism-agnostic. THIS is the highest-value
   next instrument.
3. FIX candidates (Gemini + user "own format OK"): pull-based on-disk per-dir epoch
   checked cheaply on dir reads (sidesteps gen-only-on-slow-acquire + CAW BAST
   unreliability); OR make EVERY dir EX acquire (incl fast-path) bump gen + evict
   for multi-node-shared dirs. Guard perf (the won 104%).
Build E06FDBC3 (P69-L2B probe) harmless to keep (ratelimited, reshape-only path).
Related: [[sess97_lessons]] [[sess68-check5-result-unlink-base-staleness]] [[mxfs1-vs-v5-not-mirror-images]]
