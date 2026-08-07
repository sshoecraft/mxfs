---
name: ccloop-c7ee71c6-sess38-END4-325-full-green-board-9-open
description: sess38 END4 (true close): 0.11.325 FULL BOARD ALL GREEN @32/caw (2nd ever); dir_reuse x3 = 8/7/6 rounds (bimodal, OPEN); 9 OPEN; next = drain-pipelin…
metadata:
  type: project
---

# sess38 END4 — true final boundary

## 0.11.325 (9905C45A) — deployed, FULL BOARD ALL FUNCTIONAL TESTS GREEN @32/caw
Second all-green board (first was 322); this one carries: hb-starvation fix (per-slot disklock lock — D-RELABORT-SELFFENCE FIXED AND VERIFIED, 10→9), all sess38 protocol fixes (PR batch-claim, guard relax), and three standing tripwires (P-HB-SLOW, P83-UNL-RELOAD AGI canary, P139 tail census).
dir_reuse post-fix ×3: PASS(8 rounds,110s) / FAIL(7,112s) / FAIL(6,112s) — bimodality UNCHANGED (tail = EX-rotation × release-drain economics; the pace campaign's next lever is the drain-pipelining design, GPT-first; log_force_seq REVERTED v0.3.38 — do not retry).

## Note for next session (from END3): the multi-second P139-LOCKTOTAL events (retries=0, ea=0 — raw service inflation) may partly be device-queue convoys behind disklock's 63-read runtime scans (get_stale_slot_mask on v5_mount acquire/join paths). The 325 fix un-muteXed them but did NOT reduce their I/O volume. Measure how often that scan runs during dir_reuse waves (add a counter/log if needed) before designing the drain pipeline — cheaper win if the scans are frequent.

## 9 OPEN
Pace: D-DIR-REUSE-COHERENCY-32-FLAKY, D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE.
Authority: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (canary armed).
Other: D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED (rig-blocked columns).

## Session sess38 complete arc (memories: createint-verdict, batchclaim-322, END..END4, selffence-62s)
319 CREATEINT leak fixes → 320 default-off (measured net loss) → 321 tail census → 322 PR batch-claim + FIRST all-green board → grace A/B exposed AGI shutdown (ledgered, canary armed 323) → 324 hb probes → live 26.7s lockwait capture → 325 fix + closure + SECOND all-green board. One defect closed, two new found (one closed same-session, one canary-armed), zero regressions. Criteria NO.
