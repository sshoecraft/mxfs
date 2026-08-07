---
name: ccloop-c7ee71c6-sess47-TAIL8-382-gate-shipped-gpt-ruling
description: sess47 END-2: 0.11.382 fleet = GPT-ruled non-destructive gate in coherent-reread (fossil clobber REFUSED at source, P-INOCL-REREAD-REFUSED); A-prime…
metadata:
  type: project
---

# 0.11.382 (B34F956E36A6CC745F5134A) — fleet state, sess47 true end

## Shipped: GPT immediate-safety patch (non-destructive gate)
mxfs_buf_coherent_reread_verify (pal/linux/xfs_buf.c): for multi-node inode-cluster buffers with ANY local unhomed state (DELWRI || pinned || bli-dirty || mxfs_buf_has_uncheckpointed_mods), the platter snapshot is NOT installed — current b_addr is re-verified and its verdict returned (dirty-unhomed image = previously-verified + own logged deltas; cold reads can't be dirty). P-INOCL-REREAD-REFUSED (ratelimited) names each refusal with flag detail. Outer CRC-retry backoff owns convergence. Core rule (GPT): "a raw shared-medium snapshot may refresh clean bytes but must never erase a locally committed, not-yet-home byte."
Deploy verification: reap repro CLEAN ×2 scenarios, matrix 9/9.

## GPT ruling digest (full text in transcript; key verdicts)
- PRIMARY fix = A-prime: typed ledger records for iunlink deltas {ino, gen/incarnation, ownership epoch, committed next_unlinked value, seq, retained until HOME completion} → merge overlays only PROVEN values, 4-byte graft + dinode CRC recompute + full verify, only when incarnation+epoch match. Counts (pend>flush) alone may only REFUSE, never graft.
- B (destage-first) = slow path via drop-lock/targeted-flush/reacquire/validate pattern (never AIL-push while holding bp; never manual DELWRI flag surgery). Timeout ≠ proof; on timeout leave image, fail upward.
- C rejected (shared-grain: stale local copy could clobber recovery/adoption/reuse-epoch updates).
- No re-logging from reread path; no generic precommit self-heal (only exact-ledger-proven transitions, loud).
- Idempotent carve-out: KEEP, but instrument unexplained live-path hits (persistent counter + health event) — post-fix they are the regression detector.

## Relay queue (updated)
1. Aged soak on 382 (producer rate was ~1/6 cycles): watch P-INOCL-REREAD-REFUSED (gate exercising = vector live and blocked), P53 pairs (should go to ZERO — the promotion signal for D-RSYNC-RENAME-361), plus standing watchlist. If P53 recurs with gate active → the refusal condition missed a state bit; ring + refine.
2. Implement A-prime (typed ledger) per ruling; then B slow path if refusals show verify-fail loops.
3. Finding B discriminator + AGI-stale + delwri tripwire remain armed (silent so far).
4. icluster campaign, FOREIGN-REPLAY, TCP arm (END memory).

Rig: 32/caw ship config on 382, 32/32 mounted, all green. Rings: test2 ×3, test9, test10, test32.
