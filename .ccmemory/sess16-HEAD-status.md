---
name: sess16-HEAD-status
description: sess16 HEAD: 2/tcp crash_consistency = dir DATA/leaf-block same-incarnation concurrent-RMW lost-update (dinode resolves correctly to block nx=3; gen-…
metadata:
  type: project
---

## HEAD sess16. `./run.sh 2 tcp` = 15/16, crash_consistency SOLE fail. Marker NOT written. Cluster on 171D846C (== 17DCD050 15/16 baseline + gated diagnostics only: P16-RELEASE, P35E-names, enriched P62 gens, lseq/wseq). Functional fallback 17DCD050.

## FINAL REFINED ROOT (RULE 4, exhaustively instrumented this session): crash_consistency durable loss = **dir DATA/leaf-block concurrent-RMW lost-update on the SAME inode incarnation**. PROVEN via P36-DINO-WR: both nodes' FINAL dinode writes for ino 131 are block fmt=2 nx=3 size=8192 — the DINODE format resolves CORRECTLY to block; the dir has 3 data blocks. The 5 lost md5 entries live in a dir DATA/leaf block, dropped by a concurrent RMW from a stale base. The gen-differ-by-1 (incore 648 vs disk 649) seen at P62 was a CORRECT inode-reuse incarnation switch (adopting the fresh empty new dir) — a RED HERRING for this loss. Reuse (rm-rf + re-mkdir each iter, di_gen+1) only supplies the tight fresh-shortform-restart timing; the actual clobber is same-incarnation data-block RMW.

## MECHANISM: mxfs_dir_evict_data_blocks (modify-path, ~2043) SKIPS an in-AIL undestaged data block (keep-guard) so the RMW reads a stale base missing the peer's entries → durable drop. The acquirer's OWN block is in-AIL undestaged from its prior tenure (drain/BLI-lifecycle gap).

## ELIMINATED this session (do NOT retry): (1) read-side discard of in-AIL undestaged dir buffers when buf_gen<gen → xfs_dir3_leaf_read_verify CRC CORRUPTION (fresh leaf/free/node blocks are also in-AIL undestaged buf_gen=0). (2) shortform->block upgrade-adoption → reduced loss but CORRUPTS (xfs_dir3_block_read: adopted block dinode whose DATA BLOCK not yet durable). (3) FASTEX peer_modified shrink-refuse → 0× fire (losing adoptions are post_release/incarnation-switch). (4) format-blind self-skip / inode-reuse-incarnation framings → red herrings (dinode resolves correctly).

## THE FIX (GPT demote-drain [[sess16-gpt-architecture-demote-drain-by-lock-ownership]], the only sound path): on dir EX RELEASE, drain by LOCK OWNERSHIP — guarantee NO dir data OR leaf block dirtied under this lock is left dirty/pinned/delwri/in-AIL-undestaged (logged_seq!=written_seq) before unlock; write data/leaf blocks BEFORE the dinode; order home writes before unlock (blkdev_issue_flush). On EX ACQUIRE, invalidate cached dir blocks + reread. The existing sess97 release fence (xfs_mxfs_dlm.c ~3758) drains data-fork blocks but evidently leaves a block in-AIL-undestaged at handoff under concurrent leaf-format create — strengthen it to cover ALL dir blocks (data+leaf) by lock ownership and assert none in-AIL-undestaged before unlock (P16-RELEASE-DUMP already dumps this — extend the assert). CANNOT be shortcut on the read/evict side (corrupts). 

## REPRO: tests/cc_blockdir_probe.sh (per-iter dmesg-clear + ino capture; FOREGROUND `timeout 280`; ino 131 reused; fails <15 iter, 2-11 entries). P36-DINO-WR/P133-DIRINO-WR fire for ino<=256 dirs. test2 rmmod-busy on redeploy → virsh -c qemu:///system destroy+start test2 (~15s); verify BOTH srcversions. Clear stale ccloop .output via `find <tasks-dir> -maxdepth 1 -name '*.output' -delete` (NEVER rm+glob [[feedback-never-rm-glob-variable-path]]). [[sess16-DECISIVE-gen-differs-by-one-reuse-aba]] [[sess16-PARTIAL-sfblk-upgrade-adoption-needs-datablock-durable]]
