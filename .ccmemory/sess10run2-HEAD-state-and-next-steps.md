---
name: sess10run2-HEAD-state-and-next-steps
description: sess10 HEAD: build 35DAB8EB w/ lastrel ledger; unarmed suite chain r8-r13 running. Flake inventory + all forensics; next = read chain results, discri…
metadata:
  type: project
---

# sess10 HEAD at relay boundary

## Current build 35DAB8EB (deployed by running chain) = D4C22548 + last-release ledger
- xfs_inode.h: i_mxfs_lastrel_ns/size/flag (flag 1=durable ran, 2=skipped by pr_release_fast clean gate) — stamped in mxfs_dlm_bast_process at the sd stage (xfs_mxfs_dlm.c ~10769).
- P-SFDIR-REVERT now prints lastrel_flag/age_ms/size → at the NEXT platter-lags-commit event, read: flag=2 ⇒ clean-skip gate wrongly skipped (fix: tighten gate for SF dirs); flag=1 small age ⇒ durable ran but platter still stale ⇒ flush→platter gap inside mxfs_inode_cluster_durable (fix: FUA readback verify+retry there); no-recent-lastrel ⇒ handoff happened without release (FIX-26v3 family).

## RUNNING at boundary: unarmed suite chain iters r8-r13
`for r in 8..13: MXFS_WATCH_ARM=0 scripts/suite_cycle_run.sh 4 tcp scratchpad/suite4_s10r$r.log` (~14 min each; scratchpad session 2eca429b). Each: fresh VM cycle, full 4/tcp, kernlogs archived to /tmp/suite_kernlogs_* + FAIL artifacts to /tmp/run_<test>_<runid>/ incl kernlog_testN.
READ THESE LOGS FIRST NEXT SESSION. grep FAIL + P-SFDIR-REVERT lastrel in artifacts.

## Session tally (all on instrumented builds, 4/tcp full suite)
17/17 ×4 (iters 2,4,6 + r1 had fence-only fail), fails: iter1 fence leak (5 durable leftovers, REAL), iter3 tds (my watch-leak perturbation), iter5 dlm_scaling quota-0 (REAL, SF loss) + tds window (P50-RD perturbation — since removed), iter7 dir_reuse r3 394/400 (REAL, 6 SF-era names durably absent, in-core==platter at verify — loss during create wave).
Standalone dlm_scaling ×6 w/ dir_relverify=1: 4 PASS + 2 rate-floor FAIL (rate face maybe relverify overhead; artifacts /tmp/run_dlm_scaling_20260703T2013*/2018*).

## Unified failure model (evidence-backed, per-face proof pending)
EX handoff outruns durable-to-PLATTER for the SF dinode (and once for block0 post-conversion in r8): next holder RMWs stale base, last-writer-wins erases peers' entries.
- dir_reuse iter7 r3: victims = each peer's f1..f2 (SF-era adds) — baked out at SF→block conversion from stale base.
- dlm_scaling iter5: node4 own mkdir dirent gone at first create; P-SFDIR-REVERT ×21-30/node incore=N disk=fua=N-1 (FUA=platter authority).
- fence iter1: 5 durable leftover names = lost/failed removes on SF hot dir.
- r8 r13 (archaeology, memory sess10run2-r8-forensics-*): block0 daddr 7872, t3 stale-serve→conversion→last-write 343.810.
- KEY parity fact: releases DO run bast_process (iter5 parent 12583063: ~26 P51-REL/node) and no DURABLE-FAIL lines ⇒ durable either skipped-by-gate or lands only in SCST write-cache.

## Instrumentation now in tree (build 35DAB8EB)
- mxfs_ino_watched()/watch_ino rescope of P9-LFREE/P13-LADD/P11-DATALOG/P2-EPOCHPLACE/P13-COLLIDE+P49/P28E/P10-RDBLK/P-DIRWR(+leaf owner, uncapped when watched); tests arm per-round (dir_reuse per-round stat, fence $HOT) gated MXFS_WATCH_ARM env; lib.sh finish() resets watch→1. UNARMED mode = watch_ino=999999999999.
- P10-DIRDUMP magic-lookup ('.mxfs_dirdump*' at xfs_lookup top, returns ENOENT) + P10-RDBLK; mxfs_dirblk_count_active/platter_active (xfs_dir2_readdir.c, protos in xfs_dir2_priv.h).
- P5D prints + plat_act + trans/comm; P50-RD +watched gate (platter read REMOVED — perturbs).
- run.sh: FAIL → kernlog_testN capture. suite_cycle_run.sh: cycle+suite+kernlog archive; MXFS_WATCH_ARM + optional test filter args.
- KNOWN QUIRK: kernlog_test1 empty-of-markers twice (iter7 dir_reuse, first ds fail) while 11MB+ present — investigate (journalctl -b 0 window? node1 clock?) before trusting t1 absence-of-evidence.

## Fix candidates (implement ONLY after lastrel discriminator)
(a) flag=2 case: exclude SF dirs (or any dir with ili_fields/AIL history this tenure) from pr_release_fast clean-skip.
(b) flag=1 case: mxfs_inode_cluster_durable: after submit+flush, SCSI-FUA readback the dinode; if di_size/count stale → resubmit loop (bounded); P13-SFPARENT-DURABLE-FAIL escalate.
(c) also consider: P5D honor-wait 50ms→backoff 600ms for trans!=NULL consumers (tds mv break).

## Ladder
4/tcp 3× consecutive clean → 8/tcp (boot test5-8) → 2/tcp → 1/tcp. Criteria marker NOT written.
