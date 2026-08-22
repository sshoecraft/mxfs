---
name: ccloop-c7ee71c6-sess174-BOARD-27of27-PASS-462-and-15-closure-RATIFIED
description: sess174: rig recovered from clyde reset; FULL BOARD 27/27 PASS 32/caw on 0.11.462; GPT RATIFIED #15 D-EX-GRANT-EPOCH closure. Ledger edit NOT YET DON…
metadata:
  type: project
---

# sess174 — 462 board-verified 27/27; #15 closure ratified; ledger edit PENDING

## Rig recovery (clyde's 08-07 hard reset had left everything down)
- All 32 VMs off → parallel `sudo virsh start`. scst.service failed since boot; **`scripts/rig.sh mpath 32` restored the whole condition-4 stack** (scst_setup dual portal .1/.2 + guest logins + multipathd) → 32/32 MPATH_OK. That one script is the full cold-start answer — no manual iscsiadm needed (my manual per-node login attempt was useless because host SCST was down, not the guests).
- `make clean` had wiped mxfs.ko AND tools → `make modules` reproduces srcversion F185ED4495CCC5DCEED0914 exactly (clean tree = deterministic srcversion); `make tools` needed before prep (mkfs_mxfs missing → PREP FAIL).
- prep_cluster 81s, converged 32/32 on 462.

## FULL BOARD on 0.11.462 @ 32/caw — 27/27 applicable PASS, all in budget
Run ids 20260810T041624Z..043143Z, 5 foreground chunks (<10min each). Highlights: crash_consistency 204/204 87s/90s; dir_reuse 86/86 106s/120s; dirent_durability 30 rounds durable_loss=0; fence_during_write 8/8; cache_coherency 654/654; zero_silent_loss 644/644. Only open_defects red (policy). This was the missing verification for the 461 edge-mint + 462 selftest stack.

## GPT ruling (this session): #15 D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID = FIXED AND VERIFIED in 0.11.462
No additional evidence required. Closure transaction MUST be atomic:
1. Rewrite #15: status FIXED AND VERIFIED in 0.11.462; closure line: "remaining cross-slot resource-lineage restart risk transferred to D-FOREIGN-REPLAY-UNGATED-IMAGES (#1), not claimed fixed by #15."
2. Wrap-policy text (Q4) into the entry/doc with THREE explicit caveats: (a) zero-skip prevents minting fail-closed 0 but does NOT preserve uniqueness after true 2^64 exhaustion (UINT64_MAX→1 can reuse); acceptance = exhaustion outside deployment lifetime (1M tenure-starts/s on one resource ≈ 584,542 yr; 10k/s ≈ 58.45M yr), NOT collision-free wrap; (b) state 2^64 wrap NOT empirically verified — handled by lifetime policy + injected boundary behavior; (c) caw_inject_gep_wrap is test-only, must never be an ordinary production control path.
3. COPY (not paraphrase) residual_note into #1 as "historical-record-lifetime" gate blocker, scope BROADENED beyond replay: "historical or delayed authority artifacts surviving a resource's release and later reacquisition from a different slot lineage, including replay records and any delayed live-path messages, queued work, cached capabilities, or other persistent consumers." #1's evaluator may not become authoritative until this is held. Live-path options to record: drain-before-rebind / independent lineage discriminator / explicit inclusion in #1 gate design.
4. Preserve #15↔#1 cross-links. Ledger open count 28→27.

## Evidence bundle for the #15 rewrite (cite in entry)
- Fix: caw_next_grant_epoch (dlm_caw.c:1102, +1 zero-skip), tombstone carry (~1273), single mint point caw_grant_epoch_update 5 sites (6253/7006/7868/8651/9921), edge-mint 0.11.461 (_orig removed), wrap knob 424.
- Verify: sess172 selftest basic (1..9 monotonic, 3 runs), wrap (prev=~0→t1=1), kill (t1=1699→~3473→virsh destroy mid-hold→rejoin→t1=3474 continuity); THIS session board 27/27.
- Consumer tuple audit: shadow evaluator xfs_log_recover.c:2370-2456 validates class+resource(daddr)+owner slot+incarnation+per-resource epoch; uncapable_match quarantine cites the defect ID.

## Next queue
1. Execute the atomic ledger transaction above (tests/criteria/OPEN_DEFECTS.json — edit only the two entries).
2. Then #1 D-FOREIGN-REPLAY next steps / severity order.
3. Compaction overdue (167+ unfolded) — run compile-memories.
