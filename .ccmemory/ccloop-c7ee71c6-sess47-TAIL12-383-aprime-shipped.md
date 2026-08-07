---
name: ccloop-c7ee71c6-sess47-TAIL12-383-aprime-shipped
description: sess47: 0.11.383 fleet = A-PRIME IMPLEMENTED (mount-level iunlink store: record@precommit, retire@home-write, overlay@both installs w/ CRC+gen-match)…
metadata:
  type: project
---

# 0.11.383 (75DC83AA76309BE1DEC9E19) — A-prime live fleet-wide

## Implementation (per GPT ruling, TAIL8)
- xfs_mount.h: m_mxfs_iunl_{lock,list,count} (mount-scope — survives reclaim/teardown, the proven requirement).
- xfs_mxfs_dlm.c (~before mxfs_defer_reap_init): struct mxfs_iunl_rec {ino, gen, next_agino, daddr, boffset}; mxfs_iunl_store_record (insert/update by ino; ENOMEM loud), mxfs_iunl_store_retire_range (home-write completion for [daddr,daddr+bblen)), mxfs_iunl_store_overlay (magic check, GEN MATCH else P-IUNLSTORE-GENDROP+drop, value differs → overlay 4 bytes + xfs_dinode_calc_crc + P-IUNLSTORE-OVERLAY). Init/purge wired into defer_reap_init/destroy.
- xfs_iunlink_item.c precommit: record after log_buf (VFS gen, next_agino, bm_bn, im_boffset).
- pal/xfs_buf.c: retire at inode-cluster write completion (inocl stamp site); overlay at BOTH installs — read_map cold fill (TAIL10's pinned vector) and coherent_reread_verify candidate pre-install.

## Verified on deploy
reap repro CLEAN ×2 scenarios; matrix 9/9; zero P-IUNLSTORE-* warns (record/retire cycle silent by design).

## PROOF PROTOCOL (relay continues)
Aged soak cycles (lap → idle 250s → lap → matrix → sweep). Success signals: P-IUNLSTORE-OVERLAY firing (defense catching real stale images — each one a prevented fossil) with **P53-IUNLINK-MISMATCH = 0** across ≥8 cycles incl. burst + idle-gap windows. Producer rate was ~1/5-6 cycles (2 fatals + 2 idempotent waves over ~11 cycles on 377-382). Any P53 WITH 383's store live ⇒ record/retire lifecycle gap (e.g. write completion path not taken for some destage flavor — check evict-ring/journal-replay writes retire too) — ring first, then audit retire coverage.
Then: D-RSYNC-RENAME-361 promotion decision, finding-B/AGI arms stay armed, icluster + FOREIGN-REPLAY campaigns per END memory.
