---
name: ccloop-c7ee71c6-sess149-lreq-frontier-MAPPED-teardown-never-run-on-453
description: sess149: D-FOREIGN-REPLAY ledger next-field is STALE (ends sess98). True frontier: lifecycle landed thru 0.11.452; stop() NEVER run on deployed 453 —…
metadata:
  type: project
tags: [mxfs, sess149, lreq, lifecycle, teardown, verification, D-FOREIGN-REPLAY, stale-ledger]
---

# sess149 — campaign frontier mapped; the next concrete step is a teardown census

Session spent on state reconstruction (no code edits, no rig runs). Its product
is the corrected work queue, because the LEDGER IS STALE for the top entry.

## The stale-ledger finding

`defects.sh D-FOREIGN-REPLAY-UNGATED-IMAGES` \"next\" ends at sess98 (0.11.431,
\"begin_release/install unwired\"). WRONG — line-verified in the 0.11.453 tree:

- install IS wired: `mxfs_dlm_authority_install` at xfs_mxfs_dlm.c:26498/26540/30656
  with gen snapshots (sess99, 0.11.432). Verified on rig sess110.
- Blockers 1/2/7 (mint policy) sess108, blocker 3+B (adopt fill) sess109,
  blocker 5 sess110 — P241 st_unset GONE fleet-wide on 0.11.440 (sess110).
- Blocker 6 became the lreq campaign → sess111 ruling → sess112 landing →
  sess113 STOP-SHIP → sess118-129 blocker landings → sess130 lifecycle ruling →
  **sess131 landed steps 1-4 (0.11.448), sess132 D1 fix + escalation plumbing
  (0.11.449), sess134 D2/D3/D4/D6 state machine + fail-stop (0.11.451),
  sess135 create-unwind fix (0.11.452)**. My sess130-derived plan to \"land
  items 1-5\" was moot — deleted those tasks.
- STILL UNWIRED (grep-verified): `mxfs_inode_authority_begin_release_locked`
  (xfs_mxfs_dlm.c:955, __maybe_unused, zero callers) — the sess104 ruling calls
  the dead hook a real defect; the mode-lowering backstop in mxfs_dlmtr_rec is
  the only revoke. Nobody has resolved this against the sess104 \"centralized
  release-publication primitive\" requirement. Park it behind the lreq work.

## The actual frontier (sess134 NOT-DONE minus sess135's fix)

1. **stuck-notify chain dead-ends**: `mxfs_v5_dlm_set_dlm_stuck_notify`
   (v5_mount.c:5038) has NO caller; v5_owed_stuck_cb bails on NULL fn. The
   ruled force-shutdown request never reaches XFS. Wire = register at mount,
   handler QUEUES (runs in owed-worker context).
2. RULE-5 re-consult on the landed lifecycle shape (sess133 item 4).
3. **RIG VERIFICATION — the key gap**: 0.11.453 is deployed and the fleet is
   MOUNTED (sess148) but **stop() has never executed on this build** — the
   sess148 prep's teardown ran under the then-loaded 0.11.440 module; no
   unmount since. The teardown probes have NEVER fired on the new code.

## Next session: run the teardown census FIRST (measurement before code)

1. Baseline: `tests/census_p.sh 32 'dmesg | grep -cE \"P25[3589]-|P26[012]-\"'`
   (expect 0 — probes only exist in >=0.11.446 modules, loaded fresh sess148).
2. `./run.sh 32 caw prep_cluster` — teardown phase = 32 executions of the new
   stop(). Budget ~300s (sess148 actual 71s; per-node teardown timeout 100s).
3. Post-census the full probe set: P258-QUIESCE-STUCK/-LATE P259-DEPART-UNCLEAN
   P260-CAW-CTX-LEAKED P261-ESCALATE-UNDELIVERED P262-TEARDOWN-JOIN-STUCK/-LATE
   P253-OWED-STUCK P255-CAW-OPS-UNBALANCED. PASS = zero everywhere + MXFS_CLEAN.
   Any hit is real evidence — RULE 4 it before landing anything.
4. Then task #7 (stuck-notify wiring), then #8 (bundled GPT consult + board).

Tasks #6/#7/#8 in the task list carry the full step detail. Closure of
D-SAMENODE (#16) still additionally needs the sess113 debugfs exerciser —
boards cannot close it (reconcile arm = 0 entries on healthy boards, sess111).

## Also noted
- memory_list overflows the tool cap now (59KB); parse the saved JSON file it
  points to. COMPACTION DUE (188 unfolded) — worth running compile-memories
  when a session has slack.
- Cluster state: left mounted+converged 32/caw on 0.11.453 knob=3 (from
  sess148); the prep in step 2 above re-forms it, leaving it prepped again.
