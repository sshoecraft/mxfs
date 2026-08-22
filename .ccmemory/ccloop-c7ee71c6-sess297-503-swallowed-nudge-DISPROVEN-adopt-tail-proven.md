---
name: ccloop-c7ee71c6-sess297-503-swallowed-nudge-DISPROVEN-adopt-tail-proven
description: sess297: .507 measured — swallowed-nudge DISPROVEN (wake=3 once/7417, miss=5); cost = adopt-path post-sighting tail med 1.8s on hot dir; fix B refuted
metadata:
  type: project
---

## sess297 — D-503 step-1 measurement run (0.11.507 fleet-wide)

Deployed .507 (sv F1E678C16F762EC785B1389) to all 32; `make tools` needed
first (make clean wipes tools/, prep fails otherwise).

### Run (20260815T012445Z and preceding chunks, 32/caw)
Accumulation: 20 cells PASS (precond, ag_strand_repair, dlm_* , scaling,
rsync_paired, sustained_load, fio*, cache/strong/mmap/posix, fence, zsl,
netpartition, responsive, kernel_health, lock_correctness).
Then: **crash_consistency PASS 82s/90s** (D-503 collapse did NOT recur);
**dir_reuse_coherency FAIL 0/32** — the ONE failed check is the pace
assertion: 7 rounds in 100s vs MIN_ROUNDS=8 (14.3s/round vs 12.5 needed).

### Measurements (evidence: session-297 scratchpad tkt_/exwin_/bp_/drcph_)
1. **P297-TKT n=7417: swallowed-nudge DISPROVEN.** wake=1 (nudge) 95%,
   wake=2 3%, wake=3 (oversleep past swallowed nudge) EXACTLY ONCE,
   miss>0 5 times. The nudge is delivered and wakes the nominee promptly.
2. **nom→adopt (slot-keyed via realms, nom slot= names nominee):**
   med 23ms, p90 414ms, p99 2.8s. Median handoff healthy; defect = tail.
3. **Slow (>1s) nom→grant: 287, ALL path=adopt, 272 on hot dir 1073804.**
   Where a TKT falls in [nom, adopt]: nom→sighting med 3ms;
   **sighting→adopt med 1801ms p90 2981ms**. The nominee SEES the ticket
   in ms then takes seconds to finish adopting. Decision-tree branch:
   claim/adopt contention — **fix B (nominee fast-retry ladder) REFUTED
   for this tail** (there is no sleep to shorten).
4. **P70-BP tenure decomposition (hot dir, dir_reuse window):** held med
   48ms, fo_ms med 1 (adoption setup NOT the cost), lo_ms med 11,
   tops=6/tenure, marginal ~10ms/op = structural CAW publish pace.
   NOT sess295's fixed-300ms MHT tenure picture.
5. **Round decomposition (mxfs-DRCph):** wrbar 2-6s, rank0 rm -rf 2-7s
   (fleet waits at barrier), create wave 1-4s, dc+verify ~3s. Medians
   near structural floor; the ~2s/round shortfall ≈ the tail stalls.

### Field semantics (hard-won, reuse)
- P291-EXWIN: yt/wex are HEX; slot= is nominee slot for nom/mint lines,
  self slot for adopt/promote/claim/cold/convert. realms=epoch-ms.
- P297-TKT fires ONCE per wait at first sighting — pairing to later
  noms of the same wait is invalid (143/287 slow events had no TKT in
  interval for this reason).
- P70-BP ENTRY: mode=3 sweep lines dominate (44k/47k); filter mode=5
  tops>=1 for EX tenure economics.

### Next (RULE 4 loop continues)
Hypothesis: the 1.8-3s sits between ticket sighting and adopt completion
in dlm_caw.c caw_wait_for_grant adopt arm (exwin_log "adopt" at ~:6212).
Read the path between the P297 site and the adopt log; find the seconds
(bounded backoff? gres wait? CAS storm with 31 claimers? drain?).
Instrument sub-steps if unclear. RULE-5 consult with THIS evidence before
any fix design. Then .508, redeploy, dir_reuse expecting >=8 rounds.
