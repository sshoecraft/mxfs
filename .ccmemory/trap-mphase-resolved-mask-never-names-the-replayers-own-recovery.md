---
name: trap-mphase-resolved-mask-never-names-the-replayers-own-recovery
description: TRAP: v5 mphase_resolved_mask is set only via P163-RECOVERED (monitor sees a slot reclaimed); the replayer never logs it for its own recovery.
metadata:
  type: feedback
---

**Trap (dlm/v5_mount.c, found 2026-10-09 on 0.90.113):** `ctx->mphase_resolved_mask` looks like "slots whose recovery is complete", but it is set ONLY by `v5_recovered_cb`, i.e. when this node's heartbeat monitor logs `P163-RECOVERED` (it saw a recovery-pending slot reclaimed by someone). A survivor that recovers the slot ITSELF as the replayer logs `P163-RECOVERY-COMPLETE` and never `P163-RECOVERED`, so its own recoveries never set the bit. It is the mount barrier's witness lineage (armed -> resolved), not a general recovery record.

**How it bit:** the 0.90.112 fix for D-REJOINER-IN-A-RECOVERED-SLOT-DECERTIFIES-THE-SURVIVORS-TAKEOVER keyed the bootstrap election's "pass over an unadmitted rejoiner in a slot this mount recovered" on that mask. On a 2-node pair the survivor is always the replayer, so the skip never applied; two clean A/B fix arms were luck, and a fix-on lap with the rejoiner's announce held 10 s deadlocked exactly like the control. `v5_bootstrap_ready` had the same blind spot: the rejoiner's new tenancy, beating but `live=0`, held the survivor out of the role (`P-BOOTSTRAP-NOT-READY ... resolved=0`).

**Do instead:** for "this mount recovered slot N", use `v5_recovered_here()` (`recovered_here_mask`, set at `P163-RECOVERY-COMPLETE`, voided while `dl->recovery_pending[N]`). Prove a predicate fires with a probe before trusting an A/B whose fix arms merely passed: the probe (`P-BOOTSTRAP-NOT-READY`, `bn=` on `P-TAUTH-TAKEOVER-DECERTIFIED`) is what exposed this.

**Reproducing the window deterministically:** `JOIN_ANNOUNCE_DELAY_MS=10000 tests/pve_pair_failover.sh withdraw-p0` (knob `dbg_join_announce_delay_ms`, one-shot, on the withdrawn host) holds the rejoiner between its heartbeat claim and its discovery announce. Holding the SURVIVOR's join instead (`dbg_join_flip_delay_ms`) is the wrong window: by then the rejoiner is in `active_nodes`, so `bn_in_view=1` and nothing deadlocks.
