---
name: sess15run-PRECISE-ROOT-8tcp-dlm-acquire-starvation-ino131-P36-retry-60s
description: sess15(ccloop) PRECISE ROOT: 8/tcp dir_reuse slowness+intermittent-fail = TCP-DLM acquire STARVATION on hot shared dir ino=131. P36-RETRY ~1s×60=60s;…
metadata:
  type: project
---

## sess15(ccloop) — PRECISE ROOT of 8/tcp dir_reuse (slowness + intermittent fail)

### THE ROOT (instrumented, RULE 4, proven via P36-RETRY dmesg)
8-node concurrent same-dir workload → **TCP-DLM acquire STARVATION on the hot shared dir inode (ino=131)** and on reused file inodes. Evidence (build 167ADFFF, fua_disable=1 run):
- `mxfs: P36-RETRY ino=131 type=1 mode=EX retries_left=59 (acquire timeout)` and `mode=PR ...` cascading on ALL nodes — the shared test dir's DLM acquire repeatedly times out (per-attempt ~1s) and retries.
- Retry interval ≈ **1s**, count = **60** (retries_left 60→0) ⇒ worst-case ~**60s** per stuck acquire. (The `MXFS_LOCK_ACQUIRE_WAIT_MS=6000` comments in dlm/dlm.c are STALE; observed re-fire is ~1s.)
- `ino=100665222 mode=PR retries_left=1 → "DLM inode lock failed: ino=... mode=3 rc=-110"` on test4+test6 — a PR acquire EXHAUSTED all 60 retries and FAILED (-110 ETIMEDOUT). This is where intermittent CORRECTNESS failures / barrier-timeouts come from too.

### How this produces the symptoms
- **Slowness**: per-round time varies 12s..74s. The slow rounds: ONE node's verify-phase PR acquire on ino=131 stalls in the P36-RETRY loop; the coord_barrier (drc_rN_vr) makes ALL 8 nodes report the same ~62s verify. (Round-3 verify=0.7s, round-2 verify=62s — same ops, the diff is whether someone hit the retry stall.) Native XFS ≈12s for the whole test; mxfs ≈630s = ~50× over ⇒ RULE 0 FAIL.
- **Intermittent shutdown/fail**: a PR/EX acquire that exhausts 60 retries → rc=-110 → trans_cancel/op-fail, plus the separate intermittent DABUF-hole (ABA stale-leaf, fmt=2 leaf dir blocks 1,2).

### Mechanism (TCP is reliable, so it's a LOGIC gap, not packet loss)
dlm/dlm.c: `pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS)` (line 964/1345). The outer mxfs_dlm_lock loop retries on -ETIMEDOUT and **re-fires the BAST** to "recover a lost grant/release msg" (comments at lines 509,963,1237,1344,1392). That the retry is NEEDED means the PRIMARY grant promotion / BAST collection has a gap under high contention: a holder releases but the waiter is NOT promptly promoted (promote_waiters / collect_grantee_bast_if_waiters at lines 528,569,663,700 stop at first incompatible waiter to avoid starvation — under 8-way EX/PR mix this leaves a waiter un-granted until its ~1s retry re-requests). 8 nodes all retrying ⇒ thrash on ino=131.

### What was TRIED & REFUTED this session
- `fua_disable=1`: did NOT fix slowness (rounds still 12-74s). ⇒ slowness is NOT FUA-read cost; it's the DLM acquire stall. (Earlier P15-DIRFUA "hot block daddr=120 re-read" is a real but SECONDARY effect, not the dominant cost.)
- Predecessor gen-coupling hypothesis: REFUTED (loaded_gen==dir_gen always).

### NEXT (the FIX target — RULE 4/5)
Make the DLM grant promotion reliable so a release immediately grants the waiting PR/EX without the ~1s..60s retry. Look at the RELEASE / convert / collect_grantee_bast path in dlm/dlm.c (promote_waiters ~569, collect_grantee_bast_if_waiters ~528, the BAST-collection after promote ~663-709) and the EX→PR downgrade at the create→verify transition. Hypothesis: under PR+EX mixed waiters, a released lock's waiters aren't all promoted/BAST'd in one pass, so the straggler waits for its own retry. Candidate: after every release/convert, re-run promote_waiters AND collect BASTs for ALL newly-grantable waiters (not stop-at-first). Verify ino=131 P36-RETRY count drops to ~0.
Also consider `inode_mht_ms` (EX min-hold) to batch and reduce handoff count.
Probe levers: nothing special — P36-RETRY is ALWAYS-ON. Reproduce: `MXFS_EXTRA_MODARGS=... MXFS_TEST_ENV='DRC_ROUNDS=8' ./run.sh 8 tcp dir_reuse_coherency` then `dmesg|grep P36-RETRY`.
CONFIRMED baseline: dir_reuse 8/tcp PASSES 8/8 at TEST_TIMEOUT=900 (correct, just slow). See [[sess15run-ROOT-8tcp-dir-reuse-is-SLOWNESS-hot-block-fua-restorm]].
