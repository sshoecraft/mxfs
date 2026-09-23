---
name: trap-the-sess575-rulings-missing-base-stable-primitive-already-exists-as-images-replayed-plus-homeflush
description: D-FOREIGN-SLICE-INTENTS-ABANDONED (sess610): the sess575 ruling's BASE_STABLE is already in the tree as the IMAGES_REPLAYED milestone preceded by P22…
metadata:
  type: project
tags: [D-FOREIGN-SLICE-INTENTS-ABANDONED, recovery, design, item5]
---

# Do not rebuild BASE_STABLE; build increments 3b/3c

Read this session (sess610) for the abandoned-intents defect, 2 nodes / TCP:

- The sess575 Astra ruling (docs/rulings/foreign-slice-intents-efi-completion-base-stable.md)
  names BASE_STABLE ("victim base images replayed and durable; never re-replay") as the
  missing primitive. It exists: xfs/xfs_log.c does `blkdev_issue_flush` after a clean
  shadow replay (`P226-FR-HOMEFLUSH`, sess462 STOP-SHIP 1) before the durable
  `IMAGES_REPLAYED` CAS, and xfs_mxfs_dlm.c skips the slice replay when the descriptor
  is at or past that stage ("descriptor already at stage ... skipping the slice replay").
- What exists beyond it: census + RECOVER/QUARANTINE split (xfs_mxfs_icensus.c), the
  obligation record + list (dlm/recov_obl.c, written only next to a TERMINAL outcome via
  mxfs_v5_dlm_recovery_publish_refusal_obl), receipt + proof formats (dlm/recov_obl_done.c,
  no callers), ladder gates (disklock.c refuses OBLIGATIONS_DONE unconditionally,
  refuses GRANTS_RELEASED over an open record).
- What does not exist (grep confirmed 2026-09-13): MXFS_RECOV_F_CENSUS_ZERO, the
  publication/purge guard, RECOVERY_INSTALLING/RECOVERY_EXCLUSIVE, a recovery credential,
  recovery_advance_obl_done, OBLIGATION_FREEZE_LOST/SPARSE outcomes, any completion
  transaction, any OPEN (non-terminal) record publication.
- Full spec: docs/dlm-protocol.md "Item 5 — real EFI completion" (increments 3a/3b/3c) and
  docs/rulings/item5-inc3-4-completion-takeover-stopship.md (10 stop-ships). The
  verdict flip must be the LAST edit of one change set.
- Measured consequence on 2/tcp (tests/d_intents_2tcp_open_efi.sh s610h): the survivor
  keeps the sole-survivor Write-Exclusive gate after a terminal refusal (dependency
  cleared, gate never restored), so the returned victim's mount is refused
  (P-PRKEY-PUBLISHED rc=-52 UNATTRIBUTED) and the cluster is stuck at one node with the
  victim's AG answering EIO. On a 2-node cluster that WE gate is itself a cluster-wide
  writer guard the completion can lean on.
- The AG acquire path (xfs_mxfs_dlm.c ~44700-45200, nested fast path admits ANY local
  caller when pag_dlm_holders > 0) is where the recovery-exclusive credential check goes.
