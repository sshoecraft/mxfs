---
name: ccloop-c7ee71c6-sess38-END2-324-deployed-three-tripwires
description: sess38 END2: cluster on 0.11.324 (2B93A613) — P-HB-SLOW hb-outage clocks added; smoke green; THREE standing tripwires (HB, AGI canary, P139); 10 OPEN…
metadata:
  type: project
---

# sess38 END2 — actual final boundary

Cluster: 32/caw on **0.11.324 (2B93A613)**, defaults, healthy; smoke (cache_coherency + dirent_durability) green; P-HB probes silent on healthy path as designed.

324 = 323 + disklock heartbeat cycle clocks (P-HB-SLOW: write_ms/lockwait_ms/age_since_last_ok_ms; P-HB-MONSLOW; failure log carries last-ok age). Unconditional, rare-fire.

## Standing tripwires in the deployed build (all unconditional)
1. P-HB-SLOW/-MONSLOW — the self-fence defect's outage anatomy (D-RELABORT-...).
2. P83-UNL-RELOAD — the AGI cross-node unlinked-recovery canary (D-AGI-UNLINKED-...).
3. P139-TAILCENSUS/-LOCKTOTAL — grant-wait tail anatomy (pace defects).
LESSON (repeated cost this session): capture fence/shutdown forensics IMMEDIATELY — the ring rotates within ~1 board of churn.

## 10 OPEN; next-session order (fullest detail in sess38 CLOSE + selffence-62s memories)
1. 324 needs a full board when convenient (delta vs 323 = hb probes only).
2. Self-fence RULE-4 step 2: run board-load mixes; on any P-HB-SLOW, the anatomy names the fix (monitor-out-of-mutex / hb REQ_PRIO / rig lease 15000 per code comment).
3. dir_reuse margin: release-drain pipelining design (GPT-first; log_force_seq REVERTED v0.3.38 — don't retry).
4. Authority family batch (incl. AGI canary watch).
5. D-DIRVIEW-NONCONVERGE, D-MATRIX-UNMEASURED, D-READDIR-PEER-CACHED-DIR-PACE.
