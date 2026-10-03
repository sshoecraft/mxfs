---
name: trap-the-pr-worker-re-drives-a-fence-only-once-the-mount-is-live
description: TRAP (0.90.41): v5_fence_retry_worker_fn skips armed fence retries until ctx->mounted; code waiting on a fence INSIDE a mount must drive the retry it…
metadata:
  type: feedback
tags: [fencing, bootstrap, trap]
---

Observed 2026-10-02 (tests/evidence/20261002T215036Z_bsr_r2): a whole-cluster bootstrap's phase 3 waited on a PRECOMMAND fence attempt that `v5_pr_fence_prove` had armed for "retry=automatic". For 107 s the latch stayed armed and no P304-FENCE-RETRY appeared: `v5_fence_retry_worker_fn` (dlm/v5_mount.c) does `if (... || !ctx->mounted) continue;` before its retry loop, so during the mount itself nothing re-drives a standing attempt.

Also: when a retry certifies while `dead_node_notify_fn` is NULL (still inside the mount), `v5_fence_retry_one` hands the slot to the late-death dispatch (P567-FENCE-RETRY-DEFER). A slot a bootstrap term already owns must not be handed there.

Lesson: "retry=automatic" in a P238-FENCE-PENDING line means automatic only on a live mount. Any mount-time code that waits for a fence certificate drives `v5_fence_retry_one` itself when `fence_retry[slot].next_ms` is due. Also order phase-3 fences so a PRECOMMAND miss is deferred: another victim's PREEMPT may be what removes the registrant that refused it.
