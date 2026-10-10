---
name: compiled-caw-timeout-classifier-reach-durable-class-revocation-sweep-and-lease-bounded-waits
description: Assorted traps: CAW classifier needs 3x480s pause, revoking a durable class must grep the field not the classifier, lease-bounded waits take no timeo…
metadata:
  type: feedback
tags: [compiled, caw, dlm, timeouts, authority-lease, fence-kind, trap]
---

Three notes on one theme: a bound or a gate that looks like the single point of control is not, and the instrument has to be placed where the decision is actually made.

## Timeouts: measure the real number of attempts, and do not invent one

- [[trap-the-caw-timeout-classifier-runs-only-after-three-480s-attempts]] (0.89.92). On CAW, `MXFS_CAW_WAIT_HARDCAP_MS` (480 s) bounds ONE attempt; `mxfs_dlm_ilock_begin` makes three. The defect record claimed the classifier (P-LKWAIT-LIVE) is reached at PAUSE_MS > 480 s. Measured wrong: at a 540 s holder pause attempt 1 timed out at 480061 ms and attempt 2 was granted at 547 s, classifier never reached (caw0912_s2). Only at 1560 s did all three attempts time out and park the wait with P-LKWAIT-LIVE (caw0912_s3). A lap meant to exercise the post-budget classifier on CAW needs a pause past 3 x hardcap = 1440 s; TCP's equivalent is 3 x 60 x 1 s = 180 s. A lap that passes at 540 s measured the retry, not the classifier.

- [[technique-a-wait-whose-only-exits-are-the-event-and-the-lease-closing-itself-needs-no-timeout-constant]] (0.89.32, `mxfs_v5_dlm_lu_reset_barrier()` in `dlm/v5_mount.c`). The post-LU-reset barrier waits for a heartbeat issued after the reset (`last_ok_ms > reset_issued_ms`) and has exactly two exits: the beat landed, or `mxfs_disklock_authority_ok()` returned false because the lease closed itself at point of use. No timeout parameter, and none may be added: shorter than the lease refuses a node still holding authority; longer asserts liveness past the point peers may reassign the resource. The single-outstanding synchronous CAW heartbeat also means a fresh beat cannot land until the stranded one resolves, so observing it proves convergence with no drain or generation filter. Rule: when the awaited event renews a lease checked at use rather than by timer, the lease is the timeout. Measured in `tests/lu_reset_barrier.sh` s103b: held at 2523 ms healthy, held after 12598 ms with beat paused under the lease, refused after 28228 ms paused past it.

## Revocation: sweep the field, not the classifier

- [[trap-revoking-a-durable-class-misses-the-reader-that-reads-the-field-directly-instead-of-asking-the-classifier]] (s85). `mxfs_fence_durable_kind_supported` is the single classifier (0.89.17), but revoking fence kind 17 missed a reader in `dlm/v5_mount.c` (reached from `xfs/xfs_log.c`) that compared `desc.fence_kind == MXFS_FENCE_KIND_SINGLE_NODE_EXCLUSIVE` directly. It feeds `l_mxfs_untagged_authorized`, replay's widest permission, so an older build's durable kind-17 certificate would still unlock untagged replay. The direct comparison is camouflaged: grepping the enum name hits ~20 comments, the name table and help text, while compliant readers contain the classifier name. Sweep with `grep -rn "fence_kind ==\|cert_kind ==\|->fence_kind" --include=*.c .`; every hit is a decision made without the classifier. Same for any durable enum with a central interpreter (`stage`, `retire_basis`, `domain_kind`). A revocation is atomic across readers or it is not one, so the sweep completes before the change lands; the matrix arm that forges the class passes whether or not this reader was fixed because it exercises the claim gate, not the untagged-replay gate.

## Common failure mode

In all three the number or gate that was assumed (480 s, a chosen timeout constant, the classifier) was not the one in control. Count the attempts, find what actually bounds the wait, and grep the raw field.
