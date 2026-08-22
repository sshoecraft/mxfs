---
name: ccloop-c7ee71c6-sess312-GPT-ruling-step6-F1-option-c-dual-class-fault-coverage
description: sess312 RULE-5 ruling: step-6 F1 stays OPEN until (c) — INODE fault sites + persistent-failure policy defined/tested, knob-on .511 board, ICLUS fault…
metadata:
  type: project
---

# sess312 — RULE-5 ruling: step-6 F1 closure requires option (c)

GPT consult (sess312) on the sess311 blocked fault leg. Corrected input
evidence: icluster_dlm=1 HAS been board-green twice (0.11.290 sess33,
0.11.469 sess199 — full 27/27) — sess311's "never enabled" claim was
wrong; only the sess309 step-6 machinery has never run knob-on. The
46910 "MUST STAY 0" comment's two prerequisites (BAST fan-out, call-site
routing) both LANDED; sess46 note in xfs_super.c:3087-3104 says the
sess41 refusal was LIFTED (gated release publication + admission gate +
probe-based B6). Flipping the DEFAULT still requires MXFS_PROTO_GEN bump
— enabling per-rig via modargs does not.

## Ruling: (c) — both classes need deterministic fault coverage
1. ADD controlled fault sites to the INODE release path: proof failure,
   still-dirty, CAS interference before publication.
2. DEFINE the INODE persistent-failure policy: either bounded defer
   containment (implement+verify bound/pin/probe/shutdown like ICLUS) or
   documented indefinite fail-closed retry WITH a liveness mechanism.
   Do NOT infer the policy from whatever the code happens to do.
3. Qualify current build with icluster_dlm=1 + release_proof_enforce=1
   FULL board (27/27) — REQUIRED, not optional; .290/.469 don't qualify
   .511.
4. Run ICLUS fault legs: defer mode (P282 hits, episode resolution,
   cas_noproof_v2=0) and wedge mode (past 60s bound → P-ICLUS-WEDGE +
   pin + shutdown + NO publication); validate 300s total bound where
   practical.
5. Run INODE forced transient + persistent cases under production
   routing (icluster_dlm=0, enforce=1), cas_noproof_v2=0 hard gate.

INODE natural evidence (18 defers/19 tripwires resolved) = "transient
retry path naturally exercised", NOT "fault-verified".

## Plan ordering (sess312)
Read INODE defer path first (policy determination), design INODE fault
sites + any bound in ONE build, then a single knob-on prep serves items
3+4, then re-prep production config for item 5.
