---
name: AAA-ccloop5d12-sess1-net2-progress
description: ccloop 5d123e7b: GATES 2+3 GREEN (0.11.2/.3). Step-4: sh_killpoints 74/74 GREEN after detached-creq + ack-routing fixes. Next: remaining 6 scenarios,…
metadata:
  type: project
---

# ccloop 5d123e7b — NET2 §11 state (sess1→2 relay)

## COMPLETE
1. **GATE 2 FULLY GREEN @0.11.2** (kernel smoke t1/t2 PASS 13s/60s,
   EAE6D695; linger lesson; NET2_ENQ_BATCH chunking; selftest driver).
2. **GATE 3 GREEN @0.11.3** (dlm_shared lift; CAW canaries 211/211 +
   5/5, 32s/120s pin, build 9D2672E5; MXFS_DEV=/dev/mapper/mpatha;
   `make tools` after make clean). Bookkeeping current for both.
3. **Step-4 lock plane**: engine files landed (net2_msg.h,
   net2_shard.{c,h}, net2_lock.{c,h}; harness-only, NOT Kbuild).
   Bring-up fixes: APPEND_ACK/leader-adopt use frame src (was
   req_slot — original hang); self-send loopback; BAST generalized to
   any blocked mode; FROM_WAITQ grant chains post_release_grants;
   async release op-thread in scenarios; PLUS detached-creq
   self-reaping logic in net2_lock.c (~836-1016) + extra traces
   (LAZY-CREATE/COMMIT-STALL/RXACK) landed at the relay boundary.
   **sh_killpoints NOW 74/74 PASS in 5s** (was 4×-ETIMEDOUT). Also
   green: sh_basic 19/19, sh_waiter_order 24/24, sh_leader_dead,
   sh_epoch_mid_op.

## NEXT (work queue)
1. Run remaining 6 scenarios individually (expect same-class bring-up
   bugs): sh_partitions, sh_reconfig, sh_recovery, sh_two_loss,
   sh_idempotent_failover, sh_xfer_no_vote.
   Repro tools: N2_DEBUG=1 env traces; KP_ONLY=n for kill points;
   `timeout N stdbuf -oL ./net2_harness run <scen>`.
2. Full `run shard` group ×3 seeds (0xF422 0xBEEF 0x1234) + rt where
   applicable + **ASan sweep** (see gate2_midcomms.sh for the ASan
   make invocation pattern).
3. Write tests/net2/gate4_shard.sh (RULE-0 header: provisional
   build + 900s, calibrate → pin; RESULT: line protocol; ×3 seeds +
   ASan section like gate2's script).
4. REMOVE the temporary N2DBG tracing from dlm/net2_shard.c +
   dlm/net2_lock.c (kernel build must stay clean; user too) before
   closing the gate — or convert to permanent gated stats if cheap.
   KP_ONLY in scen_shard.c may stay (harness-only).
5. Bookkeeping: [x]4, VERSION 0.11.4, CHANGELOG, docs/net2.md
   (deviations to document: release-validity = holder-bit rule;
   gen bump on every new-holder grant; dir_epoch++ on EX release
   interim policy; SH_FROZEN transition deferred to step-6 freeze
   wiring; lazy commit-watermark rationale), TIMEOUT_BUDGETS row.
6. Step 5: net2_membership/net2_epoch + disklock.h evict 28→25 +
   44B MEPOCH rec + chk_mxfs decode + gate5_mepoch.sh (prov
   build+120s) → 0.11.5 → STOP (step 6+ interactive) → DONE protocol
   per success.md (PENDING items recorded, not blocking).

## Standing
- COMMITS PENDING — no git ever. RULE 0 budget before every run.
- Cluster: t1/t2 formed 2/caw @0.11.3 (9D2672E5) mounted; t3..32
  running/unloaded; criteria.json.backup exists; CAW criteria intact.
- Budgets pinned so far: smoke 60s, gate3 120s, gate2 user 45s,
  full clean kernel build 525s (ref).
