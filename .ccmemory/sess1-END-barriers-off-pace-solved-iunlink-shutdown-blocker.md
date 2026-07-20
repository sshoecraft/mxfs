---
name: sess1-END-barriers-off-pace-solved-iunlink-shutdown-blocker
description: sess1 END (build 1429D909): TCP per-op barriers OFF → 24 rounds at 9-12s/rd (pace SOLVED) BUT rank1 iunlink "unrecovered unlinked" shutdown r7. Fix t…
metadata:
  type: project
---

# sess1 END (ccloop a9a03929) — pace solved by barrier gating; one shutdown family left

READ WITH [[sess1-a9a03929-gen-aware-unlock-fix-wedge-fixed]] (the gen-aware unlock + dwork re-arm chain, run47 = 21 rounds 0 fails baseline, build `D03537C9`).

## HEAD = build `1429D90964E9C7928652E57` (in tree, deployed on cluster)
= D03537C9 + per-dirop durability barriers gated OFF on TCP:
- New modparam `mxfs_dirop_durable_tcp` (default 0) + helper `mxfs_dirop_durable_needed(mp)` (xfs_mxfs_dlm.c ~line 316, decl in xfs_mxfs_dlm.h).
- Gates INSIDE `mxfs_dlm_dir_durable_signal` (~18904) and `mxfs_dlm_dir_inode_durable` (~3723): early-return on TCP. CAW unchanged. Release-path drain (bast_process/inode_cluster_durable) untouched — only the per-create/unlink/rename barriers.

## run48 (this build): PACE SOLVED, ONE CORRECTNESS BLOCKER
- **ALL 24 rounds ran, 8-14s/round** (was 21-28s; budget needs ≤20). rm 10.6→4.8s, create-wave ~0.2-5s, verify ~5-6s. If correctness holds this build EASILY fits 480s.
- **BUT rank1 (t1) SHUTDOWN at t=179.9 (round-7 rm)**: `XFS: Found unrecovered unlinked inode 0xad in AG 0x6. Initiating recovery.` → `MX-INSTR remove dp=131 ip=12584877 nlink=0 xfs_droplink rc=-117` → `xfs_trans_cancel` dirty → shutdown → 17 cascade FAILs (ALL peer MAP_HOLE/EFSCORRUPTED errors start ≥180.2, AFTER the 179.94 shutdown = pure fallout; single primary root).
- Victim 12584877 = agino 0x7ad = the SAME inode the "unrecovered" recovery iget'd. Sequence: rm's unlink → xfs_iunlink insert walks AGI bucket 45 → hits stale on-disk unlinked-chain state referencing 0x7ad (prev incarnation's iunlink state not destaged — platter lags with barriers off) → xfs_iunlink_reload_next (xfs_inode.c:3358) iget UNTRUSTED → recovery mangles the LIVE reused inode's nlink to 0 → droplink EFSCORRUPTED → dirty cancel.
- `DLM inode lock failed: ino=X mode=5 rc=-35` (sess78 TOCTOU EX in xfs_inactive ~2945) fires on ~EVERY sync-inactivation in run47 AND run48 — pre-existing, the TOCTOU serialization is effectively INERT (proceeds unlocked). Not the regression, but the unlocked disk-check + lagging platter may also misjudge.
- Note: ifree per victim logs "P9-INSTR ifree DONE ... flushed" (cluster destaged per free) — the lagging piece is likely the AGI bucket heads / dinode next_unlinked chain.

## NEXT SESSION — fix the iunlink stale-read, keep barriers OFF
1. Find where P82-ADD probe lives (grep -rn "P82-ADD" xfs/ — NOT in xfs_inode.c literal; check xfs_mxfs_dlm.c / iunlink insert hook) to see what it logs (bucket head at add).
2. Instrument `xfs_iunlink_reload_next` (rare choke point): log prev_agino/next_agino, AGI buf state (pinned/in-AIL/ili_fields), whether cluster/AGI buf was FUA-fresh re-read. ALSO check guards: sess43 in-AIL AG-meta discard guard (BB54A138) + sess91 uncheckpointed-mods FUA guard (BD2A94BA) — is there a CIL-resident (logged-not-checkpointed) hole on the AGI FUA-reload path (sess90 family)?
3. Candidate fixes (in preference order): (a) targeted — iunlink reads must not adopt stale platter over same-node logged state (extend uncheckpointed-mods guard to AGI/iunlink path); (b) make xfs_iunlink_reload_next tolerate/heal the mxfs incarnation-reuse case; (c) fallback split — re-enable ONLY durable_signal's log_force(SYNC) per remove (not the dir-block bwrite) via a second knob; (d) full fallback: dirop_durable_tcp=1 → run47 behavior (21 rounds 0 fails, still 1-2 rounds short of 24).
4. Reproducibility unknown (fired once in run48). Rerun run49 same build to gauge rate; watchers + P7S/P7B/P6G probes all still in build.
5. Then: 8/tcp ×5 clean → 4/2/1 → full `./run.sh N tcp` N∈{1,2,4,8} → YES.

## Infra notes (fresh this session)
- clyde rebooted 08:17; restored via `scripts/lio_tcm_setup.sh setup` + `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass`. Runbook in [[sess1-a9a03929-gen-aware-unlock-fix-wedge-fixed]].
- Run invocation: `timeout -k 10 585 ./run.sh 8 tcp dir_reuse_coherency > out 2>&1` (never pipe — orphaned children hang the tool).
- ddwatch.sh (tests/, deploy via SCP to /root) now samples ALL D-state tasks.
- Scratchpad runs 43-48 under /tmp/claude-1000/-src-mxfs/348774c0-29cb-4b1d-9f9e-dfc093fbfe78/scratchpad/.
