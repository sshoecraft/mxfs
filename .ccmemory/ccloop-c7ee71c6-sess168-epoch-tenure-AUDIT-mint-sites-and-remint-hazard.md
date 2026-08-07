---
name: ccloop-c7ee71c6-sess168-epoch-tenure-AUDIT-mint-sites-and-remint-hazard
description: sess168: D-EX-GRANT-EPOCH ledger steps 1/2/4 ALREADY LANDED (sess108). Audit: 8 mint sites mapped; mid-tenure re-mint hazard found (PW→EX upgrade). R…
metadata:
  type: project
tags: [mxfs, sess168, epoch-tenure, ex-grant-epoch, audit, mint-sites]
---

# sess168 — D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID: code audit, ledger is STALE, consult owed

## The ledger's next field is STALE — steps 1/2/4 of 5 are ALREADY IMPLEMENTED (sess108, 0.11.438, on rig since ~sess110)
- Step 1 (+1 sequence): `caw_next_grant_epoch(prev)` at dlm/dlm_caw.c:1095 — `prev+1`, 0 skipped forever.
- Step 2 (tombstone carry): `caw_tombstone_slot` saves/restores ex_grant_epoch (~1209/1217); `caw_claim_inherit_epoch` (~1231) carries it across same-resource re-claims. Deliberately NOT cleared on is_free reset (monotonic across inode reuse).
- Step 4 (one mint point): `caw_grant_epoch_update(s, grantee_slot, mode)` (~1117) — explicit grantee since sess108; direct-handoff arm uses the same helper.
- REMAINING: step 3 (tuple-validation audit at consumers) and step 5 (wrap-boundary verification test exercising the cause). See sess108 note `ccloop-c7ee71c6-sess108-handoff-mint-LANDED-and-defects-table` for the blocker map (3=adopt-fill landed sess109, 5=AG-token threading landed sess110, 6→lreq campaign sess112-135, 8/9/10 partly open).

## Mint-site audit (complete inventory, this session)
`caw_grant_epoch_update` callers: 6176 (wait_for_grant self-promote — tenure start, correct), 6928 (claim — correct), 7789 (caw_lock_body compat-add/upgrade arm), 8571 (direct handoff — new grantee, correct), 9840 (convert-upgrade), 12977+13005 (in `mxfs_dlm_caw_flush_held_to_disk_orig`, marked `__maybe_unused` — VERIFY DEAD next session; if it has callers its "add our holder bit" arm re-mints on reassert = live hazard).
Holder-bit installs WITHOUT mint, all verified benign: 680/682 (corrupt-slot repair copies bits), 4029 (abort-reconcile CLEARS), 9775-9785 (convert-DOWNGRADE installs lower mode, no mint — CORRECT: EX→PW keeps the tenure, EX→PR ends it; minting there would strand same-tenure records).
Reaffirm/adopt paths do NOT mint (5902, 7334 mark reaffirm=1 and inherit) — correct.

## THE HAZARD FOUND (design question for RULE-5, blocks the #1 gate design)
`caw_grant_epoch_update` mints whenever the GRANTED mode is write-capable, NOT only when write authority STARTS. A same-node PW→EX upgrade (7789 or 9840 arm) re-mints MID-TENURE: journal records stamped under the pre-upgrade token then compare stale (`staleep`) against the manifest's current epoch. Under the future EQUALITY-gated foreign replay this REFUSES legitimately-durable same-tenure records = durability loss in the refuse direction. Mitigating fact: XFS layer currently never uses MXFS_LOCK_PW (grep: one comment only), so the only live write-capable mode is EX and EX→EX same-mode is filtered — hazard is latent, not exercised. Options to rule on: (a) mint only on not-write-capable→write-capable transition (tenure-start-only; makes token = tenure id exactly); (b) keep per-grant mint, gate replay on tenure RANGE not equality. (a) looks right; consult before touching.

## Step-5 verification design (to consult then build)
Wrap unreachable by driving (2^64). Inject boundary: existing fault-injection framework `caw_inject_take(&knob)` + `module_param_named(caw_inject_*)` at dlm/dlm_caw.c:389-461 is the natural vehicle — add e.g. `caw_inject_gep_wrap`: next mint treats prev as ~0ULL (one-shot), assert minted==1 not 0, grant_result status==MXFS_GAUTH_WRITE_EPOCH, P6H-HANDOFF gep= advances, consumers accept. Plus assert no-zero-mint fleet-wide over a board (grep P6H gep=0 → must be absent).

## Also this session (done, banked separately)
Adopted-arm shadow-eval sample MEASURED clean (see `ccloop-c7ee71c6-sess168-adopted-arm-MEASURED-purge-proven`); ledger #1 refreshed with the two-arm A/B. Cluster: all 32 mounted/formed on 0.11.460 (460F52B), BOARD-READY, do NOT re-prep.

## Compaction status
Background agent was compiling sess112-125 waiter-cancel cluster (20 notes) into `compiled-samenode-waiter-cancel-campaign`. VERIFY next session: does /src/mxfs/.ccmemory/compiled-samenode-waiter-cancel-campaign.md exist and cite all 20 slugs (grep each)? If missing/incomplete, redo per compile-memories skill. Backlog was 199 uncompiled.

## Next session
1. Verify compiled article landed (above). 2. Verify `mxfs_dlm_caw_flush_held_to_disk_orig` is dead (no callers) — if live, its re-mint is a real defect. 3. RULE-5 consult: mint policy (a/b above) + wrap-injection test design + staleep gate semantics, WITH the audit facts. 4. Implement per ruling, build, deploy, run the wrap test + a board. 5. Update ledger #15 next field (stale steps 1/2/4 → mark DONE sess108) after the consult confirms.
