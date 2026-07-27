---
name: ccloop-c7ee71c6-sess9-A-ROOT-drc-shape2-withdraw-tear-and-P110-crc
description: sess9 ROOT PROVEN (drc Shape-2 r13): P110 in-core read-completion CRC-fails dirty bnobt → t1 shutdown → withdraw releases grants pre-replay → torn di…
metadata:
  type: project
tags: [drc, dir_reuse, shape2, withdraw, foreign-replay, P110, P126, shutdown, sess9]
---

# sess9 (ccloop c7ee71c6) — drc Shape-2 ROOT CAUSE, full chain PROVEN from run 20260725T203759Z artifacts

## The failure (round=13, lookup_fail=3, missing node6_f1/2/3, all 15 live nodes + creator)
NOT a dir/DA-walk bug. Dirents resolved fine (readdir 128/128). The INODES (2097280-82, agno=1 agino 0x80-82)
read as FREE: P26-IGET-FAIL err=-2 after full retry chain (shell_reload/miss_reload/visibility_nudge ×8) exhausted.

## Proven event chain (all timestamps 20:39:xx, kernlogs + DRCph phase markers)
1. :37-:41 r12 creates (t6 got inos 2097280-82 — same inums EVERY round via free/realloc cycle).
   :43 t6 P-RELOAD-IDENTICAL: disk==incore gen=1330196801 live. r12 verify PASS.
2. :44 t1 starts r12 rm. Mid-rm across AGs (P82-REM agno 7,14,4,13,3,12...):
   - xfsaild pushes t1's dirty in-AIL AG1 bnobt (daddr 2093232) → P126-XFSAILD-SKIP-AGMETA
     (AG not held → "stale prior-tenure") → xfs_buf_stale'd a DIRTY buf.
   - rm's next read of that bnobt: P143-AGMETA-FLUSHREAD → P110-BIO-OVER-LOGGED undest=1 →
     "refusing DMA, completing read from in-core" → xfs_buf_ioend runs b_ops->verify_read on
     DIRTY in-core image whose CRC is stale-BY-DESIGN (XFS computes CRCs at write submit) →
     P15I-CRCFAIL err=-74 (content nr=2, mostly-zero tail is LEGIT for tiny bnobt; CRC field old)
     → xfs_trans_read_buf error → FORCE SHUTDOWN t1. P15I-MEDIUM showed platter magic VALID
     (real read would likely have succeeded).
3. t1 shutdown → mxfs_dlm_shutdown_withdraw → P-WITHDRAW-RELALL released 155 grants
   ("peers promote immediately") + heartbeat stop. NO slice replay (lease default 600000ms —
   dead-detect would fire ~10min later; run aborted at :52).
4. Torn durable state from t1's abandoned log: node6_f1-3 ifree DESTAGED (icluster mode=0
   gen=…+1 on platter) but dirent-removes + rest of rm UNDESTAGED (in CIL, abandoned).
   Dirent→freed-inode dangle, cluster-visible.
5. r13 (t1 dead but barriers pass — rm -rf/mkdir -p "succeed" on shutdown FS): t6's
   printf > node6_f1 opens EXISTING dirent+in-core file, O_TRUNC → EX acquire reload:
   disk gen=+1 mode=0 → P103-RELOAD-REUSE-ADOPT + P116-ZOMBIE-ADOPT (zombifies t6's live
   in-core inode; init_special_inode bogus i_mode) → SETSIZE-REVALIDATE-MISS clean -ESTALE ×2
   → create WROTE NOTHING (test's create wave doesn't check write errors!). Verify: everyone
   igets the freed inum → persistent lookup_fail=3. rank1 readdir=0/128 = its ls on shutdown FS.

## Defects (RULE 6 OPEN until fixed+verified)
- **D1a (P126, pal/linux/xfs_buf_item.c:608)**: predicate "AG not held ⇒ dirty AIL AG-meta is
  prior-tenure garbage" can destroy CIL-lagged legit content; and staling leaves a zombie the
  read path then trips on. Principled fix: compare platter LSN (bnobt header bb_lsn) vs BLI lsn
  before staling: platter newer ⇒ stale ok; platter older ⇒ our content is unwritten truth.
- **D1b (P110, pal/linux/xfs_buf.c:8526-8588)**: in-core read-completion runs verify_read on
  dirty content → guaranteed EFSBADCRC class. Fix: refresh CRC (content is authoritative,
  CRC is a write-time artifact) or skip verifier for this completion.
- **D2 (withdraw, dlm/v5_mount.c:1618 + dlm.c:2720)**: shutdown-withdraw wire-releases all
  grants immediately (sess10 72513a13, added to stop -ETIMEDOUT domino at 600s lease) →
  peers promote into torn unreplayed state. Foreign-slice replay (v0.5.0, works — CC 20/20 @98)
  only triggers on lease expiry (600s). Fix design:
  1. Withdraw = ACTIVE death declaration: stop hb + write WITHDRAWN stamp in own disklock
     heartbeat slot (+ TCP wire notify for sub-second) so peers run v5_lease_expire_cb NOW.
  2. Do NOT release grants; peers' expire path: fence → (elected) replay → publish
     replay-done (heartbeat field/seq) → THEN purge (grants flow). Torn set ⊆ held grants,
     so purge-after-replay barriers exactly the poisoned resources.
  3. Same purge-before-async-replay window exists in the HARD-death path
     (v5_lease_expire_cb purges then queues replay) — fix there too, verify vs CC.
  Edge: replayer dies mid-replay → keep foreign_dead_slots bit set until DONE; re-elect via
  original slot still dead+unrecovered; peers bound the gate (timeout + re-election).
- **Test gap**: drc create wave ignores write errors (printf ESTALE invisible) — add error
  check so create-time failures surface as the failing op, not as downstream lookup_fail.

## Key code landmarks
- P126: pal/linux/xfs_buf_item.c:608 (mxfs_buf_xfsaild_skip_agmeta_write). P60-SKIP-BMBT sibling :638.
- P110: pal/linux/xfs_buf.c:8526 (undest=mxfs_buf_is_undestaged: pinned || li_lsn > payload stamp).
- Withdraw: xfs_mxfs_dlm.c:21632 work fn → dlm/v5_mount.c:1618; release_all dlm/dlm.c:2738.
- Death pipeline: dlm/v5_mount.c:967 v5_lease_expire_cb (fence v5_pr_fence_dead_node → caw/disklock/dlm
  purge → beacon → election lowest-live-slot → dead_node_notify → xfs_mxfs_dlm.c:34146 sets bit,
  queues mxfs_dlm_foreign_replay_work_fn:34120 (flush → mxfs_xlog_recover_foreign_slice → flush)).
- Lease default: dlm/lease.h:58 = 600000ms. Heartbeat struct: dlm/disklock.c (512B sector, static assert).
- iget retry chain: xfs_inode.c:1154-1250.
- drc test: tests/suite/dir_reuse_coherency.sh (fail-fast, DRC_STREAM streams, /root snapshots).

## Verification plan
- D1: build; the P126+P110 combo needs the CIL-lag zombie — plain drc batches + watch P126/P110/P15I.
- D2: deterministic injection: xfs_io -x -c 'shutdown -f' (or GOINGDOWN ioctl) on one node mid-drc
  → expect prompt withdraw-death → replay-done → cluster continues coherent, no lookup_fail.
- Then drc@16 batches for Shape-1 (P60-RDVGG still 0-fired) + full rung re-runs at final srcver.

## Environment
- 0.11.101 (89303634BC49D202172AABD) deployed 16/tcp; cluster healthy at session start.
- Run artifacts: /tmp/run_dir_reuse_coherency_20260725T203759Z (kernlogs whole-boot: FILTER BY WINDOW;
  earlier PASS runs' events at 20:22/:28/:29/:37 are NOT this run).
