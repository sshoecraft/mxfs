---
name: ccloop-c7ee71c6-sess155-p248-inject-c1-c6-PASS-c4-vacuity-question
description: sess155: p248_inject.sh WRITTEN+RAN. c1/c6 PASS. c4 FAIL non-vacuity only: K5 never consumed, NO P6H in c1 OR c4 — discharge never CAS'd. Disk truth…
metadata:
  type: project
---

# sess155 — p248_inject.sh written and running; c1+c6 PASS; c4 exposed an open question

## Done
- **tests/p248_inject.sh WRITTEN** (RULE 3; steps: `prep c1 c4 c6 c5 c3 c2`, no-arg = full seq `prep c1 c4 c6 c5 prep c3 prep c2`). Marker-delimited windows `P248TEST-$$ <case> BEGIN/PREUMOUNT/END` via /dev/kmsg; window fetched from /root/dmesg.stream (dmesg fallback); single-awk parse -> `eval` counts; per-case chk assertions. c3 deviates from sess154 recipe DELIBERATELY: arms K5=50 alongside K1=2+budget=1 because the drain loop checks deadline BEFORE first sweep but hands deadline INTO the sweep (hint-guided resolve could discharge in <1ms -> flaky). Umount syscall must succeed in every case incl c3 (P259 is a verdict, not a umount error).
- Fleet was found FULLY MOUNTED (32/32 on 0.11.454 sv 80380189DB5175E6A8CF74E from the 05:40Z rig run) — torn down all 32 (2 rounds; retry loop w/ 5x umount+rmmod+sleep5 needed for ~10 stragglers).
- **prep 2/caw with 0.11.455 OK** (24s), both nodes sv A559A52088F7FC1BF400138.
- **c1 PASS exactly as designed**: P257-RESIDUE owed=1 lost=0, P268 n=1, P263 (type=I id=128 tenure=0/0/0/0/0/1), P267 retired=1; zero P248/P266/P254/P259/P260. id=128 = ROOT dir inode (workload mkdir in /).
- **c6 PASS**: P266 gen=27/26 refusal, P248-ENT + agg entries=1, no P263/P267, clean departure, K4 consumed.
- **c4 FAIL on ONE assertion only** (probe set identical to c1, incl P263 tenure=0/0/0/1/0/1 PR+EX): `caw_inject_dow_casfail` readback = 1 — NEVER consumed.

## THE OPEN QUESTION (next session, FIRST)
NO P6H-ABORT-RECONCILE line in c1 OR c4 windows. dlm_caw.c ~3849: the drop_own_waiter CAS path prints P6H whenever do_h (about to clear a holder bit). Its absence + unconsumed K5 => in BOTH c1 and c4 the teardown owed discharge concluded WITHOUT ANY CAS — via `!do_w && !do_wx && !do_h -> rc=0 proven` (~3846), moot-plan retract (~3741 `lreq_plan` all-false), or terminal (magic/resource mismatch, ~3776/3797). Hypotheses:
- H1 bit already absent on disk at drain time (something cleared it earlier — eviction-era unlock? — while tenure record stayed live). Then retire is CORRECT and c4's K5-consumption expectation is wrong; K5 non-vacuity needs a different forcing recipe.
- H2 bit WAS on disk; plan/proven logic wrongly concluded absence -> clean departure with live bit left = NEW DEFECT worse than P248 (verdict false).
- H3 mode mapping: owed dispatch passes m from owed_holder_mask; ghp=holders_for_mode(cur,m); wrong/NL mode -> ghp NULL -> do_h false -> proven -> obligation retracted with EX bit still set = defect.
Decide by DISK EVIDENCE (RULE 4): read ino-128's CAW slot from the LUN after an injected c1-style departure. NO slot-dump tool exists (chk_mxfs dumps only heartbeat slots; check tools/caw_verify.c — it reads slots for transport verify, may be adaptable). Alternates: peer-visible probe from test2 (take EX on / after test1 departs; ghost bit would block/recover), or temporary instrumentation in drop_own_waiter printing image bits at teardown.

## Rig state at handoff
test1+test2 MOUNTED 2/caw 0.11.455 (post-c6 remount), all knobs zeroed, test3-32 unmounted+rmmod. Cases c5, (prep) c3, (prep) c2 NOT yet run — hold until c4 question resolved (c5 uses K5 and inherits the same question).

## Remaining bar (sess153 ruling)
deterministic 6 -> 3x `./run.sh 32 caw prep_cluster` fleet census (zero P248 agg+ENT, kept=0, P253/255/257-262 deltas zero, 32/32 clean departures, P268 consistent) -> ledger disposition -> docs (dlm/dlm_caw.md + awareness dlm.md, pal.md stale) -> memory compaction (COMPACTION DUE 194).
