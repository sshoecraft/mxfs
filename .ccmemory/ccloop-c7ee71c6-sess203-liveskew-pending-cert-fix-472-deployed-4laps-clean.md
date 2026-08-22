---
name: ccloop-c7ee71c6-sess203-liveskew-pending-cert-fix-472-deployed-4laps-clean
description: sess203: LIVESKEW pending-window fix (GPT c-strengthened+b) landed 0.11.472 (sv 9EF804271D01AA283D14131), deployed 32/caw, 4 rsync laps PASS; both mo…
metadata:
  type: project
---

# sess203 — pending-transition certificate fix for the LIVESKEW/precommit shutdown

## GPT ruling (gpt-5.6-sol, full text in sess203 transcript)
Reject blanket (a). Adopt **(c) strengthened**: per-inode pending-transition
certificate {old, next, valid} published at item creation with release
ordering BEFORE the caller advances i_next_unlinked. Overlay decision:
- skew explained (cert.old==record && cert.next==incore) → graft (P-IUNLSTORE-PENDGRAFT)
- image already == cert.next → accept, no graft (P-IUNLSTORE-POSTSTATE)
- unexplained → refuse (LIVESKEW, kept, now prints cert telemetry)
Plus **(b) narrow precommit backstop**: at old_ptr mismatch, if
mxfs_iunl_store_fossil_match (ino+gen+daddr+boffset, committed==old_agino)
AND own cert matches this item → P-IUNL-PRECOMMIT-FOSSILFIX, repair via the
normal transition instead of EFSCORRUPTED shutdown. All new probes are
standing alarms (absorbed events = an install site is leaking).

## Implementation (0.11.472, sv 9EF804271D01AA283D14131)
- xfs/xfs_inode.h: i_mxfs_nu_cert_{old,next,valid} after i_next_unlinked.
- xfs/xfs_icache.c:424ff: init.
- xfs/xfs_iunlink_item.c: publish in xfs_iunlink_log_inode (wmb-fenced,
  P-IUNL-CERT-STACKED if already valid — AGI buf lock guarantees single
  outstanding transition); clear in xfs_iunlink_item_release (on precommit
  path this runs under cluster buf lock, same lock all overlay sites hold);
  backstop with goto apply into the normal transition.
- xfs/xfs_mxfs_dlm.c: mxfs_iunl_store_fossil_match (after query_print);
  overlay LIVESKEW block rewritten with 4-case decision.
Reader ordering: incore → rmb → valid → rmb → old/next. Trans-cancel path
leaves incore advanced with cert cleared — accepted (dirty cancel = shutdown).

## Verification so far (NOT yet RULE-6 sufficient)
prep_cluster 73s; 4 rsync_paired laps same fs, ALL PASS 32/32 (vs 0.11.471:
lap2=2 fail, lap3=3 fail+shutdown incl the P53 fatal, lap4=3 fail). Fleet
survey 13:15-13:18Z window: ZERO LIVESKEW/P53/PENDGRAFT/POSTSTATE/FOSSILFIX/
shutdown. Caveat: cert machinery never FIRED (window not hit) — this is
no-recurrence, not mechanism-exercised. test4 dmesg still holds the 12:43Z
sess202 incident lines; filter surveys by timestamp.

## Ledger
Added: D-IUNL-LIVESKEW-REFUSES-PENDING-WINDOW-GRAFT-471 (critical, Mode A,
fix pending verification) + D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-
UNKNOWN (critical, Mode B — rsync rc!=0, no kernel probes, errno still
uncaptured; did not recur in the 4 laps). 73 entries, 29 open.

## Next
More overwrite laps (8-10) to either exercise PENDGRAFT or beat the .471
failure cadence; Mode B errno capture on recurrence; board chunks 3-5 on
.472; then #1 F4 obligation registry (sess197 ruling).
