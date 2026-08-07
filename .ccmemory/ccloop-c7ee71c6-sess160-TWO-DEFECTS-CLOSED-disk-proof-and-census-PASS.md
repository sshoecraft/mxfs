---
name: ccloop-c7ee71c6-sess160-TWO-DEFECTS-CLOSED-disk-proof-and-census-PASS
description: sess160: D-RELEASEALL-LREQ-RETIRE-MISSING + D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK both FIXED AND VERIFIED. Ledger 30->28 open. 0.11.457 unchanged.
metadata:
  type: project
---

# sess160 — disk proof + 4× 32-node census; two ledger closures

## Closed as FIXED AND VERIFIED (2026-08-07, full dispositions in OPEN_DEFECTS.json)
1. **D-RELEASEALL-LREQ-RETIRE-MISSING** (major, sess150) — bulk-release registry retire.
2. **D-TEARDOWN-DRAIN-MOOT-TENURED-HOLDER-LEAK** (critical, sess157) — the moot bug in the 0.11.455 fix.
Ledger: 28 open (17 critical). Build unchanged: 0.11.457 sv E44F37271ED23D708AFD84C, still deployed fleet-wide; all 32 nodes mounted at session end (cycle-4 prep).

## Evidence landed this session
- **tests/p248_disk_proof.sh PASS ×2**. Run 1 exposed an od quirk: repeated 16-byte lines collapse to `*`, shifting awk byte indices — pr mask decoded as `00*000...` which bash `0x$v & bit` silently evaluates as MULTIPLICATION (=0, always passes) and empty cw/cr vanish from the unquoted for-loop. Fixed: `od -A n -v` + strict per-mask validation (16 hex chars else DECODE FAULT rc=2). Run 2 (authoritative): owed slot MXCW-LIVE gen=6 ALL FIVE masks zero of departed node_slot 0; 3 control slots MXDL-TOMB; window P109 cas_rc=-108, P257 owed=1 lost=0, P268 n=1, P271×5 (mode5 tenure=1 = the leaked-EX case), P263 tenure=...0/1, P267 retired=1, P259=0. A/B vs sess157 baseline (0.11.455: holders_ex=0x1 leaked).
- **tests/p248_census.sh WRITTEN (RULE 3) + 4 cycles PASS on 32/caw**: kmsg marker → `./run.sh 32 caw prep_cluster` → single-pass multi-pattern awk per node (sess152 lesson honored). Preps 71s/117s/117s/57s, converge 12-13s. Cycles 2-4 = three full 32-node teardown windows, cycles 3-4 workload-bearing (per-node private dirs made FROM ONE NODE first — avoids 32-way shared-dir mkdir pace defect — then 32× parallel 5-file writes, p109=8/node at teardown). EVERY window ALL 32 nodes: agg/ent/kept=0, p253/254/255/257/258/259/260/261/262/266/269/270/272=0, p263/p267/p271=0 (consistent w/ zero residue), clean=1/node (cycles 2-4).
- **Natural B-fix observation** (ruling wanted this): test24 cycle 3 root-slot CAS cas_rc=-108 → ONE re-issue (P268 n=1) → converged clean. Benign cas_rc=-11 attempt-0 contention on ~1/3 nodes, P257=0 everywhere.

## Rig/tree state
- All 32 nodes mounted 32/caw on 0.11.457; fs freshly mkfsed by cycle-4 prep (clean, small cw_* litter only from nothing — last workload was pre-prep so fs is EMPTY).
- Tree: only tests/p248_disk_proof.sh (decode hardening) + tests/p248_census.sh (new) + OPEN_DEFECTS.json changed. NO module changes; no rebuild.

## Next session
1. Continue RULE-6 ledger top-down (28 open, 17 critical). State hook will list order; former #1 D-FOREIGN-REPLAY-UNGATED-IMAGES (ledger refreshed sess150), #2 D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (369 knob boards/soak), etc.
2. Deferred from sess159: lifecycle-phase enum hardening; docs/.md for dlm module (dlm_caw.c+v5_mount.c touched sess159, awareness nag may fire); memory compaction DUE (~200 unfolded — run compile-memories skill).
3. p248 family fully closed — do NOT reopen without new evidence; suite (p248_inject.sh 6 cases), disk proof, census scripts all in tests/ ready to rerun on any future regression.
