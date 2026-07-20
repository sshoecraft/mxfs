# NET2 ccloop run — success criteria & authorizations

Task anchor for the ccloop run continuing DLM_PLAN.md v2 §11 from the
step-2 stop point. Read FIRST, every session:
`CLAUDE.md` (auto; RULES 0-5 bind) → `state.md` (exact stop point +
engine facts — do NOT re-derive them) → `DLM_IMPL_PLAN.md` (gate line +
step sections) → `docs/net2.md` (as-built engine description).
Handoff between loop sessions = the ccloop relay + a fresh `sessNN-*`
ccmemory per session (per feedback memory
`feedback-handoff-state-via-relay-and-ccmemory-never-claude-md`); update
`state.md` only ONCE at DONE (or at a hard blocker) as the bridge back
to interactive work.

## AUTHORIZATIONS (user-edited; the loop may not self-grant these)

Each line is a standing user decision. `APPROVED` = the loop acts on it
without asking again. `PENDING` = the loop must NOT do it; skip and
continue with whatever work remains authorized.

- CHECKPOINT-A-KBUILD: **APPROVED** — apply the exact Kbuild diff from
  state.md (dlm block += net2.o net2_link.o net2_overlay.o
  net2_midcomms.o net2_fault.o). First kernel compile of the net2
  engine; fix kernel-only issues as normal work.
- PORT-REGISTRY-7610: **APPROVED** — add `MXFS_PORT_NET2_LINK_BASE
  7610` to include/mxfs/mxfs_ports.h (NET2 link listen = base + slot,
  range 7610..7673; 7605 stays membership-only).
- DEPLOY-TEST1-TEST2: **APPROVED** — install the new mxfs.ko on
  test1+test2 ONLY (for the gate-2 smoke and gate-3 CAW sanity). The
  other 30 VMs stay on 0.10.120; criteria-met status must not be
  disturbed beyond these two nodes.
- STEP3-KBUILD-DLM-SHARED: **APPROVED** — at step 3, add dlm_shared.o
  to the same Kbuild block (the shared-code lift needs it).
- COMMITS: **PENDING** (user 2026-07-17: "i dont commit until its working") — do not run git at all unless this line says
  APPROVED (global CLAUDE.md git prohibition stands; if flipped, commit
  ALL outstanding changes incl. .ccmemory/ per the global rules).

If CHECKPOINT-A-KBUILD or DEPLOY-TEST1-TEST2 is PENDING: skip gates 2
(kernel part) and 3 entirely, leave their boxes as-is, and proceed to
steps 4 and 5 (both verify user-mode on clyde, no Kbuild, no VMs).

## SUCCESS CRITERIA (all must hold before writing DONE)

1. **Gate 2 fully green** (requires CHECKPOINT-A-KBUILD +
   DEPLOY-TEST1-TEST2): Kbuild diff applied; `make clean` then
   `make modules` clean; NEW srcversion recorded; a minimal in-kernel
   smoke driver (suggested: modparam-gated self-test in net2.c —
   creates a ctx, echoes reliable sends both ways between test1/test2,
   fault injection off, then tears down cleanly) passes 2-node;
   `gate2_midcomms.sh` user part re-run green; smoke budget written
   BEFORE the run (provisional: reset ~120 s + 60 s workload; calibrate
   → pin in tests/criteria/TIMEOUT_BUDGETS.md); DLM_IMPL_PLAN.md gate
   line [~]2 → [x]2; VERSION patch bump + CHANGELOG + docs/net2.md.
2. **Step 3 + gate 3 green** (requires STEP3-KBUILD-DLM-SHARED):
   `dlm/dlm_shared.{c,h}` pure move of resource_hash_raw/resource_equal
   (dlm.c:221/240) + lock_compat/is_compatible/recompute_granted_mode
   (dlm_caw.c:186/250/278) + EX/PW-popcount check — IDENTICAL bytes in
   the moved bodies, no signature changes; both builds green; gate 3 =
   `run.sh 2 caw posix_multi dlm_fairness` PASS on test1/test2 with
   manifest budgets (CAW behavior must be provably unchanged); [x]3;
   patch bump + bookkeeping.
3. **Step 4 + gate 4 green** (user-mode, no new authorizations):
   `dlm/net2_msg.h` (LE-packed lock-plane payloads with full §6 op
   identity), `dlm/net2_shard.{c,h}` (1024 shards, HRW top-3 configs,
   2-of-3 log commit, election, transfer, reconfigure, closed-set
   recovery barrier per §7.B), `dlm/net2_lock.{c,h}` (replicated waitq,
   effect-idempotent handlers + completed-op cache, PR fan-out + BAST,
   nonzero u64 gens). Gate 4 = harness §13.2 matrix
   (tests/net2/gate4_shard.sh): leader kill/partition at every commit
   point × partition patterns × ≥3 seeds; evidence asserts per
   DLM_IMPL_PLAN (single grant-capable leader per (E,term), commit_seq/
   gen high-waters never regress, transferring replicas never vote,
   waiter order preserved, total loss ⇒ barrier never empty-table).
   Budget written before first run (provisional build + 900 s) →
   calibrate → pin. ASan sweep clean. [x]4; patch bump + bookkeeping.
4. **Step 5 + gate 5 green** (user-mode; disklock.h evict 28→25 layout
   change is ALREADY approved with the plan): MEPOCH record + single-
   decree protocol + membership observers/SUSPECT machine per §7.C and
   the IMPL_PLAN step-5 section; persisted incarnation via the harness
   file-backed disklock image; `tools/chk_mxfs` learns MEPOCH decode.
   Gate 5 (tests/net2/gate5_mepoch.sh): bootstrap, join/leave,
   proposer-crash PREPARED adoption, voter-minority stall (visible
   freeze, no commit), whole-cluster restart adoption, excluded-node
   disk self-fence with zero network, exclusion-without-fence-proof
   NACK. Budget provisional build + 120 s → pin. [x]5; patch bump +
   bookkeeping.
5. **CAW stays green throughout** — any CAW regression at any point is
   stop-the-line: fix before proceeding (criteria-met status on
   0.10.120 must never be put at risk; only test1/test2 may run new
   builds, and cluster_reset.sh restores them).
6. **Every gate obeys RULE 0**: budget written BEFORE the first run
   (infra + native×2), timeout IS a failure, never widened to pass;
   actual walls recorded and budgets tightened in TIMEOUT_BUDGETS.md.
7. **Bookkeeping current at DONE**: VERSION/CHANGELOG per landed step,
   docs/net2.md maintained every step, DLM_IMPL_PLAN.md gate line
   accurate, per-session ccmemory written, state.md updated once at the
   end with the exact stopping point.

## HARD BOUNDARIES (loop must never cross)

- NEVER reboot/shutdown/sysrq clyde (RULE 2). VM destroy/start via
  virsh for test1..test32 is fine.
- No Makefile/Kbuild/mxfs_ports.h/deploy actions beyond the APPROVED
  lines above; anything else approval-shaped → leave PENDING, record
  in ccmemory, continue with authorized work.
- Do NOT proceed past step 5 (step 6+ touches fencing/PAL/scsipr and
  the seam — next interactive checkpoint). Write DONE instead.
- RULE 4 for every failure (hypothesis → instrument → measure; no
  code-reading guesses); RULE 5: escalate to GPT
  (mcp__ask_gpt__query, prompt only, never max_tokens) before any
  issue rolls into a second session without a proven diagnosis.
- Foreground waits, chunked ≤~5 min (no run_in_background polling);
  multi-line remote scripts via mxfs_sshpass.sh + `bash -s`;
  `make clean` before kernel-build gates + srcversion verify per node.
- Timeouts are performance assertions (RULE 0); 2× native XFS is the
  hard ceiling on anything with a native equivalent.

## DONE / STOP protocol

Write DONE to $CCLOOP_RESUME_FILE ONLY when criteria 1-7 hold for every
AUTHORIZED item (PENDING items are excluded from the bar but their
skipped state must be recorded in state.md + the final ccmemory).
If hard-blocked on something only the user can decide: do NOT write
DONE and do NOT idle-loop on it — record the blocker precisely
(ccmemory + state.md + final message), then continue with any remaining
authorized work; if none remains, say exactly that and stop.
