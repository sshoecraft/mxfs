---
name: sess47-uv-pintail-relax-REGRESSES-shared-medium-lacks-superset
description: sess47 REFUTED: relaxing the read-hook pin guard for pin-tail blocks REGRESSES uv 1/2→0/2 (data loss) — the shared LUN does NOT hold the superset, so…
metadata:
  type: project
---

## sess47 — pin-tail read-hook relaxation REFUTED + uv root refined

### Final KEEP build: CD292C045FDB4E8EDA0DE18 = baseline EF006296 + TWO net-positive fixes ONLY (no probes, pin-tail relax reverted):
1. **undestaged-DONE release flush** ([[sess47-FIX-release-flush-undestaged-DONE-dir-block]]): mxfs_dir_data_durable + mxfs_dir_flush_data_blocks now also land XBF_DONE-but-lseq!=wseq dir blocks.
2. **stale-triggered acquire log_force**: mxfs_dir_drain_evict_data_blocks does xfs_log_force(SYNC) when `i_dlm_dir_gen != i_dlm_dir_loaded_gen` (not just the trylock-missable any_pinned scan).
Net: clean full `./run.sh 2 tcp` reached **16/17** (best); crash_consistency + dir_reuse + (sometimes) cache_coherency + tcp_dlm_scaling all pass in various runs. DIR-STALE-SKIP path eliminated for crash_consistency/dir_reuse.

### REFUTED THIS SESSION (do NOT retry): relaxing the read-hook pin guard (xfs_da_btree.c:3228) to evict a PIN-TAIL block (pin=1 but list_empty(b_li_list) && !dirty && !in_ail) → **uv REGRESSED 1/2 → 0/2 (BOTH nodes fail = data loss)**. PROVES: the shared LUN does NOT hold the superset, so clearing XBF_DONE discards test1's undestaged (wseq=0) deletes and the cold-read returns a NON-superset. **The fix is WRITE-SIDE (get both nodes' dir mods onto the shared LUN), NOT read-side refresh.**

### uv ROOT (refined, PROVEN via always-on probes, build CD292C045):
- uv reads from CACHE (no drop_caches). ASYMMETRY: node2 (LAST modifier) has the superset IN-CORE → PASSES. test1 (earlier modifier) holds a stale pinned in-core block missing node2's later deletes → FAILS (`uv none remain got=10`).
- test1 DID release the dir (P35-DIRHONOR=3, always-on) and got evict-ring=9, DIR-STALE-SKIP=10. P-TCPEX-REACQ=0/P108=0 (NOT phantom-EX).
- The failing block (DIR-STALE-SKIP): pin=1 li_empty=1 dirty=0 in_ail=0 **wseq=0** (NEVER written to the shared LUN) lseq=250. It is a post-evict cold-read buffer that test1 re-modified and holds (no release).
- mxfs_dirskip_enabled=0 (NL-skip OFF, so P47-NLSKIP-UNDEST=0 — NOT the wseq=0 producer). The release drain P47-RELDISP showed block 0 nflush=1 (my fix DID fire) so the release attempts the bwrite — yet a later cold-read instance is wseq=0 and stale.
- CORE DILEMMA: test1's in-core block has test1's deletes (only in-core+log, wseq=0) AND is missing node2's deletes; the shared LUN has neither node's full superset reliably. Lazy lock caching (inode_mht_ms=300) + async EVICT-RING gen + per-op-destage banned (v0.5.1, 60s/8.7k-rsync RULE-0) = the merge dilemma.

### NEXT-SESSION DIRECTIONS (write-side, since read-side refuted):
- (A) ensure a node's dir mods reach the shared LUN before it releases the GRANT to a peer, AND the peer's acquire cold-reads — i.e. make the release-drain bwrite ACTUALLY land + be visible cross-node (verify fua_disable=1 isn't hiding the peer's write behind a per-initiator SCST read cache; sess21 FUA existed for exactly that). Test: when uv fails, raw-read /dev/sda block-0 daddr to see if the LUN has the superset (if YES → read-side eviction is the fix after all, but must NOT lose own undestaged; if NO → write-side).
- (B) strict-serialization-on-contention: disable lazy EX caching for a contended dir so each modify destages+releases (GFS2 model) — perf risk on tcp_dlm_scaling.
- (C) block-level dirent MERGE.
### SEPARATE roots still open: crash_consistency = reg-file .md5 EMPTY content on peer (sess39/45 family, passes 3/3 STANDALONE = mostly CONTAMINATION in-suite); tcp_dlm_scaling = xfs_iunlink_item_precommit corruption → __xfs_trans_commit:890 shutdown (AGI unlinked-list, pre-existing sess45). [[sess47-FIX-release-flush-undestaged-DONE-dir-block]] [[sess46-UNIFIED-ROOT-pinned-shared-dir-block-merge-dilemma]]
