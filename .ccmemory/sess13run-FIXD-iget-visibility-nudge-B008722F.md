---
name: sess13run-FIXD-iget-visibility-nudge-B008722F
description: sess13 FIX-D (B008722F): dirent-resolved iget fail → PR-nudge creator publish + retry ×8. Root: mkdir-race loser saw dead shell + 2-gen-stale platter…
metadata:
  type: project
---

# sess13 FIX-D — fresh-inode cross-node visibility (the got=0/EUCLEAN family)

## PROVEN root (run_dlm_scaling_20260704T075050Z, 4/tcp)
- node3 lost the 4-way `mkdir -p /mnt/shared/.dlm_scaling` race:
  P127-EEXIST-LOSER winner_ino=8394204 dp_stale=1.
- Its iget(8394204): in-core shell = DEAD prior incarnation (mode=0,
  dlm_stale=1) → P4ST dangler (takes NEITHER reuse branch); platter = one
  MORE generation behind (live REG-FILE dinode 0x81a4 — the free never
  destaged); winner's dir existed only in its log. **di_gen IDENTICAL across
  all three incarnations (3281719562)** — gen guards are blind here (sess87
  same-gen family).
- Reload adopted the stale platter (P34D-RELOAD-FRESHSRC src=fua) → mode
  stays wrong → ENOENT ×2 → mkdir -p rc=1 → every op ENOENT → got=0.
- test2/test4 (later losers) recovered: their PR grants arrived AFTER the
  winner published → P74-GRANT have_mirror=1 prov=1 → mirror-apply fixed
  their shells. The winner's BAST→drain→iflush→release chain takes ~7ms
  (P-DIRIFLUSH disk_nx 0→1, P51-REL drain_ms=7). node3 was just EARLY and
  FIX-B declined (no cached buffer to invalidate) → zero retries.

## FIX-D (build B008722F18F9D08CE48E753)
- New `mxfs_dlm_iget_visibility_nudge(mp, ino)` (xfs_mxfs_dlm.c, after
  mxfs_dlm_iget_miss_reload): PR-acquire the ino's inode-DLM BY NUMBER
  (mxfs_v5_dlm_inode_lock(ctx,ino,MXFS_LOCK_PR)) → BASTs the creator into
  publish/iflush + provisions mirror → unlock → return 1. P13-VISNUDGE probe.
- xfs_lookup retry block: tries 3→8 (msleep i*10: ≤360ms total); on
  -ENOENT/-EFSCORRUPTED, try miss_reload first, else nudge, retry iget.
- Same block covers the dlm_fairness EUCLEAN (-117 foreign-content cluster)
  and drc round-dir -117 variants (all dirent-resolved iget failures).

## Same-session context
- FIX-C (entry-locks-before-AG-grants) at 14 suite iters: fence family 0/14.
- drc f1-dirent loss = SEPARATE mechanism (in-core committed adds dropped
  pre-destage; P49-STALEBASE=0, collision detector never fired for blk0, the
  three bins durably lack the 3 remote f1's while .md5 twins survived).
  Instrumented: P13-PLACE placement ledger (watch-gated) + P64-N1F1 extended
  with present2=node2_f1 tracer. Await next drc FAIL for the write-sequence.
- Harness: run.sh pulls /root/drc_* into artifacts (tar|base64); drc script
  snapshots dmesg at RDMISS; drc per-round create-phase snapshots existed
  since sess62 (drc_create_rN_rankR.dmesg) and are now pulled too;
  dlm_scaling.sh logs POSTMKDIR-INVISIBLE/FIRSTFAIL + parent dirdump;
  journald RuntimeMaxUse=400M per prep.
- KNOWN DEEPER ISSUES (unfixed, documented): (1) di_gen not advancing on
  realloc → all gen-based incarnation guards blind; (2) the P4ST dangler
  shell path; (3) inode free (mode→0) not destaged before chunk realloc.
  FIX-D sidesteps via retry+mirror; if faces persist, these are next.
