---
name: sess-tcp-double-grant-validation-also-unreliable
description: CRITICAL TRAP: the tcp_dlm_scaling double-grant is BOTH un-instrumentable AND un-validatable empirically — ANY timing change (instrumentation OR a fi…
metadata:
  type: project
---

## CRITICAL CONSTRAINT (supersedes the "validate empirically" guidance in
## [[sess-tcp-double-grant-instrumentation-impossible]] and [[sess-tcp-gen-token-fix-impl-notes]]):

The tcp_dlm_scaling DLM double-grant race window is sub-microsecond. PROVEN this session:
adding even a lock-free, no-printk event ring (a few struct-field writes under the already-held
table_rwlock) at the grant/release sites made it 6/6 PASS — i.e. a tiny TIMING perturbation
closes the race WITHOUT fixing the root.

=> THE TRAP: any code "fix" that adds instructions in the DLM lock acquire/grant/release path
will ALSO perturb timing and can produce 15-20/20 standalone PASSES as a pure TIMING ARTIFACT,
falsely reading as "fixed" while the root double-grant is untouched (it would resurface under any
future timing shift — different hardware, load, kernel version). So:
- You CANNOT trust a pass-rate improvement as proof a fix is correct.
- You CANNOT instrument to prove the mechanism (same perturbation, 6/6 pass — both printk P-LKT
  and the lock-free ring).

=> THE FIX MUST BE PROVEN CORRECT BY CONSTRUCTION (rigorous protocol reasoning), not by running
the test. Approach for the next session:
1. Reason out the EXACT message-ordering interleaving that lets the master grant EX to P while
   holder H still holds (H had NO release per P106). Enumerate every path that removes/supersedes
   a GRANTED entry: process_remote_request stale-removal (dlm.c ~2081-2134), local equiv
   (~890-911), conversion-blocked removals (~937-953, ~2162-2176), process_remote_release
   (~2386-2411), mxfs_dlm_unlock (~1264-1318), membership purge / fail_all_pending, and the
   -ETIMEDOUT retry's WAITING-entry remove+reinsert (~1108-1125). Find the one that can drop a
   live holder's entry given a plausible concurrent message/thread ordering.
2. Make the grant/request/release protocol PROVABLY maintain the invariant "at most one EX holder
   per resource cluster-wide" — e.g. a generation/fencing token (see impl notes) such that the
   master never supersedes a holder entry except on that holder's authenticated current-gen
   release, AND the holder never believes it holds after the master superseded it (BAST/grant-
   recall on supersede). The correctness argument, not the test, is the acceptance criterion.
3. A NON-timing-affecting observation IS still worth seeking: e.g. record events to a per-CPU
   ring via a SEPARATE already-running context, or use hardware tracing (Intel PT) / a post-hoc
   crash-dump of the lock table — but assume none will be easy.

NOTE: the -ETIMEDOUT retry ([[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]]) fixed the STALL by
adding a 6s wait+retry; that very retry is a prime suspect for creating the duplicate/late
in-flight messages that race the removal. Re-examine whether the retry can leave a stale WAITING
or re-request that, combined with a BAST/release, supersedes a live holder.
See [[sess-tcp-double-grant-mechanism-refinement]] [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]].
