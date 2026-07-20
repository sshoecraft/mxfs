---
name: AAA-ccloop7251-sess4-grantseq-clock-crash-fix
description: sess4 pt2: iclus grant_seq coherency clock = genuine_handoff for routed files (crash_consistency stale-extent root) + reload-skip; full 8/cawd batter…
metadata:
  type: project
---

# grant_seq: the ICLUSTER coherency clock (build CEB811BC1551663A1B0A8A1)

## The crash_consistency root (RULE-4 proven)
Failing shape: reused-ino REG file rewritten 8KB O_SYNC by its creator; every
foreign reader served the PREVIOUS incarnation's extents (wrong md5, right
size class). Chain: reader held a stale in-core shell from earlier churn →
slow-path grant → mxfs_dlm_reload_inode(post_release=true) → keep-stale gates
`(dirty||grant_held) && !genuine_handoff` → routed files can NEVER raise
genuine_handoff (no per-inode grant_gen/dir_epoch — P63/P65 arms are per-inode
+ dir-only) AND sc_grant_held (redirected to cluster granted_mode) is TRUE →
in-core kept "authoritative" → stale served forever. Repro REQUIRES ino churn
before the test on the SAME mount (fresh-prep runs pass trivially — beware
false A/B greens; validated on a 24-round-drc-churned mount, arm fired 230×).

## The mechanism
- ic->grant_seq++ on every NL→granted disk claim (only window a peer could
  have held EX). Accessor mxfs_iclus_grant_seq(mp, ino).
- ip->i_dlm_iclus_seen_seq: stamped at reload/adopt; also captured-before/
  stamped-after at the hot ilock_begin post-grant reload site.
- reload TOP-OF-FUNCTION arm (NOT the S_ISDIR block — first attempt died
  there, fired 0×): routed && !unpublished && seen!=cur && SELF-CLEAN
  (P65 ea_self_clean discipline: pin==0 && !ili_fields && !IN_AIL — a dirty
  self + forced adopt would sess49-revert own state) → genuine_handoff=true,
  stamp seen=cur. Marker P-ICLUS-HANDOFF.
- Acquire-site skip: routed && !i_dlm_stale && seen!=0 && seen==cur → skip
  reload entirely (cluster held continuously ⟹ no peer write possible).

## Battery state @8/cawd knob=1 (all PASS)
dir_reuse 24-round 509s calibrate (≈21s/round — same as 6-round 124s rate;
budget 120s @6r still ~4s over), cache_coherency 13-21s, posix_multi 10s,
zero_silent_loss 3-5s, crash_consistency 7-15s (incl. churned-mount repro),
mmap_coherency 1s. Perf levers left for drc: create-phase dir-EX rotation
(P138 56ms/BAST × MHT), rm/barrier 6s, EDEADLK dance frequency (allocation
steering would kill most).
