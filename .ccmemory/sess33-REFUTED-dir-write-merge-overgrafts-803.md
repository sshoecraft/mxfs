---
name: sess33-REFUTED-dir-write-merge-overgrafts-803
description: sess33: dir_write_merge=1 (write-chokepoint union graft) REFUTED — makes dir_reuse WORSE: round1 readdir=803/800 over-count every node, round2 readdi…
metadata:
  type: project
---

## sess33 — dir_write_merge=1 REFUTED (makes loss worse)

Tested the existing write-chokepoint union-graft `mxfs_dir3_data_writemerge` (pal/linux/xfs_buf.c:2215, gated `dir_write_merge`, default 0) as the fix for the proven clean-in-AIL stale-reflush loss. Build C0F7D69E, MA=`dir_write_merge=1`, 8/tcp dir_reuse.

RESULT iter1: round=1 readdir=**803/800** (OVER-count +3) on ALL 8 nodes; round=2 readdir=0 (test2/5), readdir=759 lookup_fail=58 (test3/7). The graft OVER-resurrects/duplicates dirents (the MERGE-NEEDED gate + name-dedup is insufficient against the rm+recreate churn — it grafts a stale prior-incarnation name back, and leaf hash goes inconsistent → lookup_fail). FAIL 0/8.

=> The union-merge-at-write approach is too dangerous (this is why it was default-off historically; matches sess21 offset-collision / sess26 dir_merge rc=-110 family). DO NOT enable dir_write_merge.

NEXT: the clean fix is to PREVENT the stale clean-BLI reflush, not patch its content. Release-side AIL-retire/stale of clean dir buffers at EX release (GPT-endorsed [[sess32-DECISIVE-A-vs-B-late-destage-toctou]], mirrors sess26 clean-ABA detach+stale [[sess26-FINAL-root-aba-buffer-stale-bli-fua-skip-and-exact-fix]]). [[sess33-PROVEN-clean-inAIL-stale-reflush-not-ghost]]
