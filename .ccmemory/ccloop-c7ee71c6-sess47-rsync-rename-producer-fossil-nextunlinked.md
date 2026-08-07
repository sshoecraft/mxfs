---
name: ccloop-c7ee71c6-sess47-rsync-rename-producer-fossil-nextunlinked
description: sess47: rsync-rename producer NEW SIGNATURE decoded — cluster-buffer revert fossilizes di_next_unlinked (P53 forensics complete); P143 fence gap = xf…
metadata:
  type: project
---

# rsync-rename producer — sess47 breakthrough (ring: test2:/root/transcommit_incore_1785706689.dmesg)

## The event (0.11.375, aged cycle 3, t=1094)
`P53-IUNLINK-MISMATCH ino=0x3e00118 old_ptr=0x117 old_agino=0xffffffff next_agino=0x116` → xfs_inode_verifier_error → `Corruption of in-memory data (0x8) at __xfs_trans_commit` → test2 withdrawal. THREE mismatches in 3s (0x1ae/0x179/0x118, three DIFFERENT cluster chunks, agno 31); first two old_ptr==next_agino → absorbed by P53-IUNLINK-IDEMPOTENT no-op (sess53's masking warning CONFIRMED live). P217 rename containment: ZERO lines — new surface entirely.

## Decoded mechanism
- t=840: P82-REM ino=65011992 (agino 0x118) mid-list remove, next was 0x117; iunlink item logs NULL-clear into cluster buffer; committed.
- The clear REVERTED: buffer/media regressed to pre-write image (di_next_unlinked=0x117 fossil). P220-EPOCH-LEDGER-OPEN at shutdown: pend=39 dur=38 flush=38 — ONE committed change never made it home.
- Reuse-create rewrote the CORE via inode-item flush (dip_gen==i_gen — same-incarnation proof) but di_next_unlinked is NOT in the logged core → fossil laundered under a current-gen dinode.
- t=1094 re-unlink insert precommit: expected old=NULLAGINO, buffer=0x117, next=0x116 → not idempotent-safe → fatal.
- Idle 847→1089 (249s) with nothing flushing the obligation ⇒ the revert likely happened by ~847 (inode-DLM release pipeline window, P70-BP/P-BP-EXIT-KEEP at 840.5-847.3) — nothing left dirty to destage.

## Class map (do not re-derive)
- P61-BIO-OVER-LOGGED-BMBT (pal/linux/xfs_buf.c ~9925): PROVEN fix refusing disk read over uncheckpointed bmbt leaf.
- sess122: SAME refusal on AGI was PROVEN HARMFUL (shared-grain; in-core not authoritative) — reverted. Inode clusters are shared-grain like AGI (32 dinodes, peers update siblings) ⇒ refusal is NOT the fix shape; per-slot merge (cf. P56-CORESIDENT-DIR) or fence/destage-enforcement are.
- P143-AGMETA-FLUSHREAD fence + pag_mxfs_meta_wr_epoch (xfs_buf.c 1475/2282): covers agf/agi/agfl/bnobt/cntbt/inobt/finobt ONLY — **xfs_inode_buf_ops UNFENCED** (mxfs_agmeta_ops at 2234).
- di_next_unlinked offset 0x60 in v3 dinode → IS in corruption dumps' 128 bytes.

## Next (armed in 0.11.376)
Report-only probes: P-INOCL-COLDREAD (cluster cold read inside unflushed window, new pag inocl wr-epoch) + P-INOCL-BIO-OVER-LOGGED (read submit over uncheckpointed cluster buffer, NO refusal). Lap the aged protocol (producer rate: 3 events in 1 lap when hot). Then GPT fix-shape consult with probe verdicts.
