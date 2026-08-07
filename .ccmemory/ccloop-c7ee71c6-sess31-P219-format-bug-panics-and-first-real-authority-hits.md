---
name: ccloop-c7ee71c6-sess31-P219-format-bug-panics-and-first-real-authority-hits
description: P219 print had %s-vs-integer bug: every fire PANICKED the node (sess30's mystery deaths). Fixed 0.11.269; first 13 REAL no-authority publishes captur…
metadata:
  type: project
---

# sess31 — P219's format-string bug killed its own nodes; first real captures

## The bug (fixed in 0.11.269)
`pal/linux/xfs_buf.c` P219-LOGGED-NO-AUTHORITY print passed
`(unsigned long long)ip->i_mxfs_pub_stage_ns` in the position where the format
had `comm=%s` — vsnprintf walked a ~1.78e18 nanosecond timestamp as a char*:
GP fault (non-canonical 0x18c74...), panic in xfsaild context, node reboots.
Two prior panics with the identical 0x18c74... signature exist in
test20's serial log (one at t=76256s on a session-12 build, one at t=134s on
0.11.268). CONSEQUENCES:
- Session 12's "nodes died with no visible error" was partly THIS (P219 fired →
  panic → counters wiped by reboot). All past `noauth=0 stale_tenure=0` counter
  harvests carry SURVIVORSHIP BIAS.
- The serial logs are root-only; unprivileged reads look empty (sess30 trap).
- Fix: added the missing `stage_ns=%llu` before `comm=%s`. A tree-wide compile
  sweep (`make 2>&1 | grep "char \*"`) shows no other %s-vs-integer mismatch.
  The remaining -Wformat width warnings (%d vs long long) are value-truncation
  only — varargs slots are 64-bit on x86-64, no crash, but probe VALUES lie.

## First surviving P219 captures (0.11.269 fix-arm run, 13 events, 7 nodes)
All: `staged=1 stale=1 stage_epoch=2 now_epoch=3 epsrc=14516` — epoch ADVANCED
between xfs_iflush staging and xfsaild submit; the LAST bump site was
xfs_mxfs_dlm.c:14516 ("v0.5.1: grant lost — invalidate epoch-stamped dentries").
Two classes:
- `dlm_mode=0 stage_mode=5 img_nl=0 img_mode=100600` — xfsaild WRITING A FREED
  INODE'S IMAGE AT NL, staged under a dead EX (test2, test26#2). The
  cluster-write-reverts-freed-inode corruption class from sess29, logged-slot
  variant (GPT remaining-work item 2).
- `dlm_mode=5 relflush=1 img_nl=1 stage_mode=0` — submitted under EX during the
  release drain, but stamp says staged at NL/epoch2: attach-without-restamp
  suspected.

## The unresolved contradiction (next step)
Same module load: `epoch_ends≈4200/node, epoch_flushing=0` — NO epoch bump ever
ran with XFS_IFLUSHING set, yet 13 staged images were published after the epoch
moved. Leading resolution: ATTACH-WITHOUT-RESTAMP paths — the ISTALE attach in
xfs_ifree_cluster (xfs_inode.c:4849 sets IFLUSHING and attaches WITHOUT calling
xfs_iflush, so `i_mxfs_pub_stage_epoch` keeps an ancient value), and possibly
drain resubmits of an already-staged buffer. So P219 `stale=1` conflates
(a) genuinely lost tenure between stage and submit with (b) stamp older than
the attach. Discriminators already in the print: dlm_mode/relflush/img_nl.
NEXT: split the predicate (restamp at ISTALE attach, or record attach-time
epoch separately), then re-measure; the `dlm_mode=0 img_nl=0` class is the one
that can corrupt (freed-image write at NL) — decide skip-vs-hold with GPT
(logged slots cannot simply be dropped; that loses committed changes — see the
P219 design comment in xfs_buf.c).
