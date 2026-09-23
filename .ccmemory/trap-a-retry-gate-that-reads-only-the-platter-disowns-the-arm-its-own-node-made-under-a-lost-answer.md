---
name: trap-a-retry-gate-that-reads-only-the-platter-disowns-the-arm-its-own-node-made-under-a-lost-answer
description: TRAP (s133c3/s138m/s141): a durable "may have run" arm cannot say whether the command was issued; the retry gate answered "ambiguous, not ours" from…
metadata:
  type: feedback
tags: [fencing, retry, scsipr, disklock, ambiguity, hang]
---

# A retry gate that reads only the platter disowns the arm its own node made under a lost answer

**What bit us.** Live-prover fault mode 3 (the arm CAS lands, the prover is told it failed) left the prover's own mount unresponsive: s133c3 ABORTed on a 20 s `mountpoint` stat and the node could not release the module 8 minutes later; s138m "PASSed" with the harness noting the stat did not answer in 5 s and `after settle: kind=NONE fence_term=1`.

**Mechanism (read, then confirmed by the fix's lap).** scsipr returns before issuing the PROUT when `arm_submit` reports failure, so the attempt is classified PRECOMMAND (`P238-FENCE-PENDING command_may_have_run=no`) and the retry latch is armed. The worker's `mxfs_disklock_recovery_fence_retryable()` re-reads the descriptor, sees `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN` (the arm DID land) and answers 0 — "ambiguous, needs reconciliation, not retry" — so the worker disarms. The proof-resume path only revisits slots whose in-memory record is `blocked`, which the PRECOMMAND classification never set. Net: FENCING + MAY_HAVE_RUN on the platter, no latch, no block, no fail-fast; waiters on the victim's grants hang forever.

**The category error.** The durable arm is written BEFORE the command so that a CRASH reads conservatively; it can only ever say "may have". Whether a command WAS issued under it is knowledge the writing incarnation has and the platter does not. A gate that consults only the platter must treat its own node's unissued arm as somebody else's ambiguity — and it did.

**Fix shape (0.89.63).** Per-slot in-memory witness in `struct mxfs_v5_dlm` — `fence_boundary[slot] = {victim, epoch, term}` — set in `v5_pr_fence_prove_locked` where every fence leg converges into `fres`, when `fres.phase == MAY_HAVE_SUBMITTED`. `retryable()` returns 2 for "ours and armed"; the worker re-drives when the witness does not match (`P304-FENCE-RETRY-ARMLANDED`; the idempotent arm step logs `P304-FENCE-ARM-STANDING`), disarms when it does. The same witness under the single-prover guard refuses a second command under an unresolved arm (`P238-FENCE-BOUNDARY-HELD`). Terms restart at 1 per new attempt on a slot, so the witness is keyed on all three fields, never on the term alone.

**Harness lesson.** The mode-3 assertions had been written to describe the hang ("nothing certified on an arm the prover believes it never made", "the key is STILL registered"). A harness that encodes the observed behaviour as the expected one passes on the defect. Mode 3 now requires the re-drive, a certificate that follows a completed command, and a served stat.
