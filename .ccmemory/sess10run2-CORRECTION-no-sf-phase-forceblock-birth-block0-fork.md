---
name: sess10run2-CORRECTION-no-sf-phase-forceblock-birth-block0-fork
description: sess10 CORRECTION: storm dir converts SF→block AT MKDIR (empty, force_block; P42-SFCONV sf_count=0 comm=mkdir, t1/rank1 only). dir_reuse r3 loss = bi…
metadata:
  type: project
---

# sess10 late correction — dir_reuse round-3 face

## Evidence (chain-r8 artifact /tmp/run_dir_reuse_coherency_20260703T202423Z)
- Round 3, readdir=395/400, missing node2_f1 node3_f1 node3_f2 node4_f1 node4_f2; verify-time DIRDUMP: in-core==platter (168/142/87) — durable loss during create wave.
- P-SFDIR-REVERT: 0 on all nodes (detector requires fmt==LOCAL at reload; dir is never LOCAL post-mkdir).
- P42-SFCONV/P60-SFCONV-BASE: storm-dir conversion fires at MKDIR with sf_count=0 (empty), comm=mkdir, rank1/t1 only → force_block-style pre-conversion; block0 exists from birth (round-3 block0 daddr=4718600, reused).
- So the r3 victims are BLOCK-format adds erased from block0's birth-era lineage — same class as r8-round-13 archaeology (post-conversion block0 fork), NOT an SF-phase loss. dlm_scaling's quota-0 (SF parent .dlm_scaling) remains a genuinely SF-format face; fence hot-dir leak = SF remove-resurrection likely.

## Round-3 signature (2 independent repros: iter7 + chain-r8, both round 3)
Round 1-2 clean, round 3 loses peers' FIRST 1-2 adds from block0. Round 3 = second reuse of the dir's ino+daddr set (fresh mkfs → r1 fresh, r2 first reuse, r3 second). Something in the SECOND reuse cycle leaves a stale-lineage block0 image/buffer that wins over peers' earliest adds. Suspects: cached prior-incarnation buffer at the reused daddr on a PEER (incarn_aba guard should catch — didn't), or the converter's fresh block0 image racing with peers' first adds via stale platter (peer's fresh iget reads platter before rank1's conversion image lands durable — peers' adds then RMW pre-conversion garbage? their reads verify magic though...).

## NEXT-SESSION DECISIVE MOVE
The chain (suite4_s10r9..r13 logs in scratchpad 2eca429b) keeps reproducing ~1/2-1/4. To pin the round-3 block0 fork: run STANDALONE dir_reuse ARMED (MXFS_WATCH_ARM=1, default helper modargs watch_ino=1) — the per-round arming makes P13-LADD/P11-DATALOG (placements with names+aoff), P49-STALEBASE (RMW-time platter walk), P-DIRWR (uncapped content CRC per destage), P10-RDBLK fire for the storm dir. Armed runs never failed yet (7×) — if 6+ more armed passes, use HYBRID: arm ONLY P-DIRWR+P13-LADD (cheap, no per-op platter reads) via a new watch level (watch arming but P49/P13-COLLIDE gated off — e.g. skip when mxfs_dirwr_enabled==0 add level check) to keep timing near-natural. The money question per RULE 4: which node wrote block0's final image missing the 5, and what base did it read (P-DIRWR crc timeline + placements).

## Ledger note
i_mxfs_lastrel_* stamped only in bast_process sd stage; P-SFDIR-REVERT prints it (no fire yet). For the block0 face the analogous need is per-BUFFER last-write provenance — P-DIRWR when armed covers it.

## Chain status at relay: r8 done (16/17, dir_reuse 0/4 as above), r9-r13 pending. Marker NOT written.
