---
name: ccloop-c7ee71c6-sess306-P283-fix-verified-0.11.510-dup-invariants-ledgered
description: sess306: P283 audit defect FIXED+VERIFIED 0.11.510 sv F7FD86F (cas_noproof_v2==0 x32 over ~124k attempts, legacy ticked 4x = aliasing reclassified);…
metadata:
  type: project
---

# sess306 — P283 per-instance proof certificate: implemented, built, rig-verified

## What landed (0.11.510, sv F7FD86F154513313B4F84D9, make clean build)
Implementation of the sess305 RULE-5 ruling (Option A, per-instance tenure-bound proof cert):
- `struct mxfs_release_cert` gains `proved` (u8) + `rel_gen` (u32) — xfs_mxfs_dlm.h ~955
- `mxfs_relbar_close_or_defer`: `cert->proved=1` at BOTH PROVED exits (early ~14770, final ~14966); proof_failed exit leaves 0. Covers anchored AND noanchor arms (both pass &p282c; relbar_enforce default 1).
- `mxfs_iclus_disk_release`: proved=1 on clean settle+keyed proof (no longer gated on `ic` non-NULL); pre-CAS tripwire clears proved=0.
- Anchored CAS site stamps `p282c.rel_gen = p_rel_gen`.
- Emit path: new counter `mxfs_relcert_cas_noproof_v2` (cas_attempted && !proved); P283 print MOVED to the v2 condition (+relgen, "(per-instance)" suffix); legacy `cas_unproved` (shared-scalar != PROVED) counts SILENTLY as diagnostic.
- Dump: `cas_noproof_v2=` in P280-RELEASE-CERT-TOTAL; per-cert P280 print has `proved=`/`relgen=`.

## Verification (RULE 4 closure of the audit-defect arm)
3x `./run.sh 32 caw dir_reuse_coherency` on 0.11.510 — PASS 32/32 each (104/110/106s, budget 120s).
Fleet dump after 3 laps: **cas_noproof_v2=0 on ALL 32 nodes** over ~124k release attempts, while legacy cas_unproved ticked **4 times** (test9=1, test10=2, test17=1) — the concurrent-dup-release aliasing overlap recurred at the historical P283 rate and every instance was attested proved. The 2 P283 prints in test10 dmesg are pre-prep fossils (03:48/04:20, old format, module reloaded 04:48). This is the live A/B the ruling predicted: legacy audit false-alarms, v2 stays clean.
Note: cas_noticket == attempts everywhere (fua_disable=1 without target_cache_protected → NO_DOMAIN) — the known F2/step-7 config question, still owed.

## Ledger changes
- D-FOREIGN-REPLAY-UNGATED-IMAGES `next` += sess305-306 progress (v2 is THE steps 9-10 gate input); `updated` stamped sess306.
- NEW: **D-DUP-RELEASE-HANDOFF-INVARIANTS-UNVERIFIED** (high) — 7 ruling invariants for legal dup-concurrent releases unverified; invariant 4 literally violated today (loser relcert_finish writes ACTIVE over winner's RELEASING, xfs_mxfs_dlm.c ~15040, telemetry-only per grep). Ledger now 88 entries / 36 open.

## Ops notes
- `make clean` deletes tools/ binaries → `make tools` needed before prep_cluster (mkfs_mxfs missing = PREP FAIL).
- SSH to nodes: `P=$(tools/mxfs_secrets.sh passfile); tools/mxfs_sshpass.sh testN "$P" "cmd"` — bare wrapper w/ default /tmp/.mxfs_pass FAILED (stale 8-byte file, exit 5); always resolve via mxfs_secrets.sh.
- Cert-dump one-liner: `echo 1 > /sys/module/mxfs/parameters/release_cert_dump` then grep P280-RELEASE-CERT-TOTAL.

## Still owed
dlm.md awareness update (sess304), cas_noticket F2/step-7 config question, ccmemory compaction (236 unfolded), and the new dup-invariants defect's step 1.
