---
name: ccloop-c7ee71c6-sess352-94-cleanskip-landed-0131
description: sess352: #94 SB counter clean-skip FULLY LANDED+GPT-reviewed+BUILT 0.13.1 sv F6C2522B7DBEDE27757C0AB — NOT deployed; next = prep_cluster + idle-fence…
metadata:
  type: project
---

# sess352 — #94 clean-skip implementation landed

Build: **0.13.1 sv F6C2522B7DBEDE27757C0AB** (clean make, my files warning-free).
NOT deployed. Cluster dirty from sess350 → prep_cluster first.

## Shape (sess351 rulings + sess352 GPT diff review, all items in)
- `mxfs_sb_counter_only_txn` (xfs_log_recover.c, after token parser): verdict
  codes 0..8 (0=OK, 1=token, 2=class, 3=status, 4=notsb, 5=framing,
  6=baseline-alloc, 7=content-mismatch, 8=empty). Every item: primary-SB
  LI_BUF, CLASS_SB + **ST_UNPROVEN only**, exact xfs_log_sb framing
  (ri_cnt==2, contig run bit0 of exactly ceil(sizeof(dsb)/128) chunks, no
  extra bits, region len in [sizeof(dsb), run bytes]), magic, masked memcmp
  (4 unmasked ranges; masked = icount/ifree/fdblocks/crc/lsn; frextents NOT).
- Baseline = replayer's own m_sb snapshot under m_sb_lock → xfs_sb_to_disk
  into kzalloc'd dsb, cached `l_mxfs_sb_baseline`, freed in xlog_dealloc_log.
  Single-threaded pass2 → single lazy call site OK.
- Classified ONCE in xlog_recover_items_pass2 pre-report; verdict passed into
  mxfs_report_replay_authority (new param) → TOKENSUM `sbclean=%d`; refusal
  notice `P227-FR-ATOMIC-SKIP sbreason=%d`; clean skip →
  `l_mxfs_sbclean_skips++` + P227-FR-SBCOUNTER-CLEANSKIP + return 0.
- Terminal predicate untouched (untagged_skips>0); TORN message
  untagged→unauthorized + sbclean count; success notice sbclean_skips=%u.
- Mount distrust: xfs_check_summary_counts adds `|| mp->m_mxfs_dlm` →
  unconditional AGF/AGI recompute on every cluster mount (DLM init precedes
  mountfs — verified xfs_super.c:3193 vs :3233).

## GPT review verdict (sess352 transcript)
Design sound; Q3 mount-distrust limit case CONFIRMED (no rebuild write, no
marker needed); Q4 publish-recovered with only clean skips CORRECT (recovered
marker prevents re-replay under a future different baseline). 4 required
items all implemented. Residual caveat: differing per-node quota state would
false-refuse (fail closed; rig has no quota). Recommended matrix (sector
sizes, quota combos, growfs-stays-refused, bitmap holes) — rig covers the
natural shapes; growfs/frextents refusal untested.

## Verification plan (next session)
1. prep_cluster, deploy, board baseline.
2. #94 closure: fence idle node → P227-FR-SBCOUNTER-CLEANSKIP, no TORN, no
   quarantine, remount OK. sbreason=5/7 in dmesg = false-refusal bug.
3. #92 races 6/7 (fixed choreography), then full board.
