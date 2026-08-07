---
name: ccloop-c7ee71c6-sess35-coldread-live-capture-B3C-shipped
description: sess35: COLDREAD chain captured LIVE (P242→P239→P241, ino 58729920); consult-#3 tripwire rejected (0 true-staleness); B3+C shipped 299; FIX-A TOCTOU…
metadata:
  type: project
tags: [coldread, release-barrier, cluster-merge, provenance, sess35]
---

# sess35 (wrapper 17) — COLDREAD false-positive churn: live capture + fix set

## Classifier verdict (kills consult-#3 fatal tripwire)
17 P239 events on 297: **ZERO pcc>icc** (true-staleness class EMPTY — fatal tripwire at the authority gap is off the table), 11 icc>pcc (9 at dlm_mode=EX), 6 pcc==icc. False-positive churn class dominates → root it (done below).

## The live chain (test21, ino 58729920 = node21_f1, one lap, 74ms)
1. `P242-EPOCH-CHURN line=27664` (upgrade-into-EX site; the helper prints mode AFTER the assignment — mode=5 there does NOT mean already-EX). At re-acquire: `ds=gs=311, flush=7 dur=7 pend=9 fields=0x5(CORE|DEXT)` — **two txns committed while NOT holding EX** = post-release ioend conversions (`xfs_iomap_write_unwritten` via FIX-25 admit; P2G-LOGWHO proved callers).
2. +65ms `P239 ... ds=311 gs=312 gen==pgen pcc=2 icc=3 fields=0x0` — the epoch bump orphaned the provenance; merge condemned the freshly-staged flush 7→9 image. **gen==pgen = same incarnation** (not dead-shell).
3. +9ms `P241-BLIND-DISCHARGE dur=7->9 CLEAN DETACH` — ledger closed over merged-away bytes; in-core sole copy. Self-healed ONLY because workload kept writing (release drain later landed cc=4; P-RELOAD-IDENTICAL). The archived COLDREAD incident = the quiescent variant.

## The leak source (P220 companion capture, same lap)
`P220 pend=9 dur=5 flush=5 mode=0 epsrc` printed 0.4ms AFTER the conversions committed under dlm_state=BAST: **P236 gate TOCTOU** — gate evaluates, drain's own writeback generates conversions, terminal mode=NL+epoch++ store re-checks nothing. Post-NL RELFLUSH tail rescues pre-tail commits (observed flush 5→9 then unlock); post-tail commits leak into next tenure.

## Shipped (Gemini priority-1: C without B3 livelocks; B3 without C leaves loss)
- **299 B3**: merge mask protects slots with LIVE staged image under CURRENT tenure (`i_mxfs_pub_stage_epoch == i_dlm_epoch` && stage_mode EX && flush!=durable → curstage mask), verified per-slot vs coherent disk read (di_gen equal AND platter cc <= staged cc). P243-CURSTAGE-KEEP.
- **299 C**: P238 rollback extended outside RELFLUSH for cls=samegen-own (EX && gen==pgen && iversion>pcc && !ISTALE). 293-livelock class excluded by gen equality; B3 protects the re-stage next push.
- **298 instr**: P239 +gen/pgen/ds/gs/fields; P241 (MXFS_IF_CLMERGE_HIT bit 26, cleared at copy-in + P187 re-arm); P242 at all 6 ex_grant_seq bump sites.

## Open
- Engagement verification PENDING (1 lap: P239/P241/P238/P243 all zero — no condemnable overlap arose). Gemini A/B: fix26/27-style delays (xfsaild copy-in +100ms, ioend commit +50ms), negative arm = peer EX between tenures must NOT protect.
- **FIX-A queued (Gemini P2)**: in-flight-FIX-25-ioend counter + synchronous pend==durable re-check AT the terminal store (defer via existing obligation_only arm). Post-NL revert REJECTED (NL already observable). Note: mode=0 P239 events (leak pushed at NL before re-acquire) are NOT covered by C (EX-only) — FIX-A removes their source.
- rearm_unpublished churn site (28925): by-design fresh-incarnation bumps over the dead incarnation's pending free (dir 9666 reused every 17s; constant pend-flush=4 skew on that DIR — separate ledger-accounting question, dirs exempt from P236 gate).
