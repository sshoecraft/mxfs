---
name: ccloop-c7ee71c6-sess33-inodegc-authority-verified-P234-zero
description: P234 source counter: dirty-at-NL/PR = 0 strict (287-288); inodegc authority class VERIFIED covered by sync-inactive policy — audit + measurement, not…
metadata:
  type: project
---

# sess33 — inodegc/orphan authority class: VERIFIED covered (no new machinery)

## The audit (GPT closure criterion 1)
GPT's D root fix (sess32 ruling) assumed upstream-style DEFERRED inactivation
mutating without cluster authority. MXFS multinode does NOT defer:
`xfs_icache.c` ~3925-4010 — when `m_mxfs_dlm && !single_node &&
journal_info==NULL`, inactivation runs SYNCHRONOUSLY at final iput (P25
sync-inactive path, adopted for the AGI-bucket recycle race at v0.3.59).
xfs_inactive → xfs_ilock(ILOCK_EXCL) → full DLM admission = the
"reacquire authority before dirty" design, structurally. The deferred
worker path survives ONLY the nested-AGI case (xfs_iunlink_reload_next
irele inside AGI-held trans, journal_info!=NULL) and its later
xfs_inactive re-admits identically. ISTALE inodes cannot create core
obligations at all — `ASSERT(!xfs_iflags_test(ip, XFS_ISTALE))` in
xfs_trans_log_inode.

## The measurement (closure criterion 3, first source counters)
P234-LOG-NOEX at the pend++ stamp site (xfs_trans_inode.c): counts every
publication obligation stamped while i_dlm_mode != EX. Buckets
lognoex_nl / lognoex_pr in the P220 release-barrier dump.
- 0.11.287 first lap (dd+zsl+crash @32): pr=0 everywhere; nl=0-2/node, the
  ONLY attributed firer = `caller=mxfs_dlm_bast_process` — the pipeline's
  OWN P146V clean-but-unlanded re-log (legitimately at NL, lands its own
  write; obligation=0 at every unlock proves it).
- 0.11.288 flag-gated the two pipeline re-log arms (P146V + P182 relmerge)
  via `i_mxfs_pipe_relog` (set/clear around the tiny-trans sites; init at
  the DLM-field block): **lognoex_nl=0 lognoex_pr=0 STRICT** across
  dd+zsl on 8 sampled nodes. Tripwire is permanent, default-on.

## What remains for D-RELEASE-BARRIER-OPEN closure (GPT criteria)
(2) deterministic race injection, (4) extended stress with mask on,
(5) reacquired-tenure drain cleanliness, (6) pace, (7) 5-point fault
matrix. Criterion 3's remaining counters: stage-at-NL (P222 exists),
ISTALE-attach-without-authority (class-X analysis says mask-covered
lossless; EX gate excludes ISTALE until it has an authority class).
