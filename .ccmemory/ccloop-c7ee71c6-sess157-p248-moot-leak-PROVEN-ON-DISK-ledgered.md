---
name: ccloop-c7ee71c6-sess157-p248-moot-leak-PROVEN-ON-DISK-ledgered
description: sess157: moot-leak PROVEN on disk + ledgered critical + GPT-approved fix LANDED as 0.11.456 (sv 4CA76BE55B7B45177024681), DEPLOYED 2/caw. Verify next.
metadata:
  type: project
---

# sess157 — moot leak proven on disk; fix landed 0.11.456 + deployed; verification is the next step

## PROVEN (RULE-4 closed) — D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK (ledgered critical, 30 open/18 critical)
Injected c1 departure on 0.11.455 (test1 K1=2, umount, no remount): P109 id=128 slot=39847 cas_rc=-108; P257 owed=1; P263 tenure=0/0/0/1/0/1; P267 retired=1; NO P6H/P259. Disk from test2 (1MB-scan; slot at 40960+idx*512 in scan file): **slot 39847 MXCW-LIVE gen=2 holders_ex=0x1 gm=5** while CAS-succeeded slots 24903/40155/49454 = TOMB. Control (no knob): 39847 TOMB holders_ex=0. PR nuance: P263 said PR+EX tenure, disk had only EX bit (PR cleared by up-convert) → fix lets image/CAS decide per mode. Full evidence in the ledger entry.

## GPT RULING (sess157, in transcript): one-predicate fix APPROVED as immediate correction
Required hardenings (both landed): (1) frozen+others → DEFER + P269 probe, never moot; (2) retraction-time provenance guard: refuse moot-strip of tenured mode in frozen world (P270). Follow-up (NOT landed, optional): explicit lifecycle-phase enum instead of inferred predicate. Verified cautions: P254 left>0 → fail latch → clean=false (wired, checked at ~12360); owe_residue publishes maximal mask (sess156); gen is u64 no-wrap.

## LANDED — 0.11.456, srcversion 4CA76BE55B7B45177024681, DEPLOYED test1+test2 (fresh mkfs, mounted, converged 2/caw)
- dlm/dlm_caw.c: new helper `lreq_world_frozen(ctx)` (~2196: ops_closed && release_all_done && lreq_finish_gen==stop_finish_gen; doc covers fail-latch window + ABA); lreq_plan tenure branch (~2270): !frozen→moot (unchanged), frozen+others→defer+P269-FROZEN-TENURE-ATTEMPTS+lreq_frozen_defer++, frozen+alone→PERMIT (holder stays true → drain CASes); lreq_owed_retract (~2398): moot-strip refused on tenured+frozen → P270-MOOT-RETRACT-REFUSED + lreq_owed_moot_refused++; proven holder strip logs P271-OWED-DISCHARGE (frozen-only, positive proof record); doc updates at holder_moot struct + retraction comment.
- dlm/dlm_caw.h: counters lreq_frozen_defer (~970), lreq_owed_moot_refused (~1005).
- tests/p248_inject.sh: parse() extracts p269/p270/p271; c1 asserts +P271≥1 +no-P269 +no-P270; c4 same + existing K5-consumed. c2/c3/c5/c6 unchanged (paths analyzed: c3 budget expires pre-plan; c2 terminal; c6 gen-mismatch keeps frozen=false→moots as before→P266/P248 asserts hold; c5 mid-run).
- VERSION 0.11.456.

## NEXT SESSION — verification sequence (rig is READY: fresh fs, 0.11.456 mounted both nodes)
1. `timeout 600 tests/p248_inject.sh` — expect ALL cases PASS incl. new c1/c4 P271 asserts. If c4 K5 unconsumed or P271 absent → fix defective, RULE-4 loop.
2. Injected-departure disk proof on 0.11.456: workload → K1=2 → umount test1 (NO remount) → get slot idx from P109 in test1 dmesg (fresh mkfs = new fsid → slot may differ from 39847!) → scan from test2 (dd bs=1M skip=64 count=34 iflag=direct → python3 struct at 40960+idx*512) → EXPECT MXDL-TOMB/zero holders_ex + P271 in dmesg + P267. Control run after (no knob) same expectation. Remount test1 after.
3. Fleet: ./run.sh 32 caw prep_cluster + teardown census (P248==0, P254/P259/P269/P270 silent, P263/P267/P271 sane) — tests/census_p.sh pattern from sess150.
4. Ledger disposition to FIXED AND VERIFIED only after 1-3 all pass; then continue board queue (D-INODE-CLUSTER-PUBLISH #2 next per state hook).
5. Memory compaction is DUE (~196 unfolded) — run compile-memories skill when a natural pause comes.

## Deferred (not blockers): lifecycle-phase enum hardening (GPT follow-up); docs/.md for dlm module per global CLAUDE.md after verification.
