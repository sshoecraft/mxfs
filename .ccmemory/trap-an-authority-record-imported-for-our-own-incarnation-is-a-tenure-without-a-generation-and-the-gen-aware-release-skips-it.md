---
name: trap-an-authority-record-imported-for-our-own-incarnation-is-a-tenure-without-a-generation-and-the-gen-aware-release-skips-it
description: TRAP (sess616/617, D-0966): a ledger record of THIS node's own incarnation imported on a page takeover has grant_gen 0; the local shortcut adopted it…
metadata:
  type: feedback
---

# An imported record of our own incarnation has no generation, and every release that names tenures by generation skips it

## What happened (D-0966, 2/tcp, s616d → fixed 0.85.5, module 45B8EB0F812B0167A4CCF9E)
- A (survivor) became master of departed B's authority pages and imported an ACTIVE EX record for a directory inode **owned by A's own incarnation** (a release lost against the departing master). `dlm_import_holder` creates it GRANTED, `imported`, `grant_gen 0`.
- A reused the inode number; its local request hit the imported entry and the "already granted" shortcut in `dlm_lock` returned it as-is → the inode held EX on a table entry with generation 0.
- B rejoined, asked for the directory, BASTed A every 10 s. A's release pipeline (`mxfs_dlm_bast_process`, p_rel_gen == 0) read "no held tenure at release decision; DLM unlock skipped" (P6Z-REL-NOTHING ×42) for ever. B's listing sat in D state 300 s+ (P36-STACK, P73-WAITSTALL). Nothing shut down.

## The rule
- **Adopting an imported record IS starting a tenure.** Whoever turns an imported entry into a live local hold must mint the generation the release will later name (the remote re-affirm already did; the local shortcut did not). Fix: `P-TAUTH-ADOPT-LOCAL` in the shortcut; a record under our node id from a DIFFERENT incarnation is never adopted (`P-TAUTH-ADOPT-INC-MISMATCH`, waits for the purge).
- **A release arm that finds "nothing held" must check the mirror for a generation-less own entry** and adopt-and-release it (`mxfs_dlm_unlock_genless`, `P-REL-NOTHING-MIRROR-HELD`); otherwise the record is retirable by nobody.
- Diagnostic signature: `P-TAUTH-IMPORT-ACTIVE owner=<self>` on the new master, then `P-DIRBAST state=1 mode=5` / `P51-REL held_mode=5` followed by `P6Z-REL-NOTHING mode=0` every BAST period.

## Measurement notes
- The shape needs a within-mount sole survivor that took a real grant on a number the departed master had issued: the d0952 harness's probe directory (created+removed by A while B mastered it) supplied it in 3 of 4 laps (P-TAUTH-ADOPT-LOCAL=1); one lap (s617g) imported nothing and was clean but vacuous for this path — count the probe, not the verdict.
- The harness's cold-check block asserted zero P-SOLE-SURVIVOR over the whole lap; the sole arm fires one in phase 1 by design, so every clean sole lap read INCOHERENT (s617a-c) until the assertion was changed to "no more than the phase-1 event".
- The rejoined peer's mount still waits one BAST period (~10.3 s) for its root-directory EX behind the survivor's cached PR: filed as a pace record, not part of D-0966.
