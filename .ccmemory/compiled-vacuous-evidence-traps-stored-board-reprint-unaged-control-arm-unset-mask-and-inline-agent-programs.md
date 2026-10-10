---
name: compiled-vacuous-evidence-traps-stored-board-reprint-unaged-control-arm-unset-mask-and-inline-agent-programs
description: Assorted tail: evidence that looks green but is vacuous (stored board, unaged control arm, never-set mask) plus no inline sh -c in agent prompts.
metadata:
  type: feedback
tags: [compiled, trap, harness, evidence, drbd, delegation]
---

This is a `kind: assorted` group, the tail the clusterer could not fit to one topic. Three of the four notes share one theme: a result that reads as pass/green while the precondition for it never held. The fourth is a delegation rule.

## Evidence that is green but vacuous

**Stored board reprinted after a failed run.** `run.sh` prints the board from `data/criteria.json` after ANY exit, including a setup failure. In the 0.90.115 release gates, `tests/release_rig_gates.sh` graded boards from the log's `VERDICT:` line. Two configs (2/net/mesh/direct@g2 and 16/disk/caw/direct@g16) read "every criterion green" while `run.sh` had exited in 28 s with `ERROR: no pool LUN for [test1 test2]` and `=== rc=1 run.sh ...`. test2 was held off by the rig fence (libvirt hook, left behind by a failed drbd outage test). The green cells were a previous build's. See [[trap-run-sh-reprints-the-stored-board-after-a-failed-run-so-its-verdict-line-is-not-this-runs]].
- A board run counts only if its own `=== rc=0 run.sh <cfg> ...` line is present AND the verdict is green.
- Sanity-check log size: a real 31-row board log is about 11-12 KB, a setup failure about 4.5 KB.
- `tools/boards_stage_chain.sh` exits 0 whatever its boards found.
- After any failed DRBD rig test, check `virsh domstate` of both nodes and `tools/rig_fence_virsh.sh status <node>`. Release a fenced node with `rig_fence_virsh.sh release <node> <episode> <survivor>` only once the survivor has nothing to recover, then `scripts/drbd_rig.sh down`.

**Control arm on an unaged pair.** The physical-pair rejoin read stall (0.90.113: first read 69-95 s after `withdraw-p0`) reproduced 2/2 on a pair with many withdraw/rejoin laps behind it and 0/6 in an A/B run right after `scripts/pve_pair_update.sh` restarted both units, with the fix off as well as on. The deploy resets ledger and hand-off state: the rejoiner's swap lock fell to about 1 ms within 30 s on the fresh pair, versus 18-45 ms for 90 s+ on the aged one (census 3.7 pages/s vs about 20). Cause: the rejoiner's single hand-off worker activates the survivor's view-change FROZEN stream while the survivor's FREEZE_REQs wait behind it; the length grows with repeated rejoins. See [[trap-a-rejoin-read-stall-needs-an-aged-pair-so-a-control-arm-right-after-a-deploy-is-vacuous]].
- A control arm is evidence only if it shows the precondition: check `P-HRX-ASK-WAIT` / `P-TAUTH-PAGE-PARKED` counts in the arm's window, not just pass/fail.
- Age the pair with alternating `withdraw-p1 withdraw-p0` laps (4th lap stalled 69 s with the knob at 0), then run the treatment arm at once on the same aged state (5/5 passed, 0 asks waited >=1 s).
- `tests/pve_pair_failover.sh` used to collect step klogs before the verify, so a passing arm's reads were never in its evidence; it now collects again after the census, and a slow read leaves stacks via `tests/pve_read_stall_probe.sh`.
- Fix: 0.90.114 `handoff_rx_ask_first` in `dlm/v5_mount.c`.

**Predicate that is never set on the path under test.** `ctx->mphase_resolved_mask` in `dlm/v5_mount.c` looks like "slots whose recovery is complete" but is set ONLY by `v5_recovered_cb`, when this node's heartbeat monitor logs `P163-RECOVERED`. A survivor that recovers the slot itself as replayer logs `P163-RECOVERY-COMPLETE` and never `P163-RECOVERED`. The mask is the mount barrier's witness lineage, not a recovery record. The 0.90.112 fix for D-REJOINER-IN-A-RECOVERED-SLOT-DECERTIFIES-THE-SURVIVORS-TAKEOVER keyed its election skip on that mask; on a 2-node pair the survivor is always the replayer, so the skip never applied, two clean A/B fix arms were luck, and a fix-on lap with the rejoiner's announce held 10 s deadlocked like the control. `v5_bootstrap_ready` had the same blind spot (`P-BOOTSTRAP-NOT-READY ... resolved=0`). See [[trap-mphase-resolved-mask-never-names-the-replayers-own-recovery]].
- For "this mount recovered slot N" use `v5_recovered_here()` (`recovered_here_mask`, set at `P163-RECOVERY-COMPLETE`, voided while `dl->recovery_pending[N]`).
- Prove a predicate fires with a probe before trusting an A/B whose fix arms merely passed; `P-BOOTSTRAP-NOT-READY` and `bn=` on `P-TAUTH-TAKEOVER-DECERTIFIED` exposed this.
- Deterministic window: `JOIN_ANNOUNCE_DELAY_MS=10000 tests/pve_pair_failover.sh withdraw-p0` (knob `dbg_join_announce_delay_ms`, one-shot, on the withdrawn host) holds the rejoiner between heartbeat claim and discovery announce. Holding the SURVIVOR's join (`dbg_join_flip_delay_ms`) is the wrong window: the rejoiner is already in `active_nodes`, `bn_in_view=1`, nothing deadlocks.

Common rule across the three: a pass counts only when the run's own exit line, the arm's precondition counters, or a firing probe shows the thing under test actually happened.

## Delegation: no inline shell programs in agent prompts

User correction (2026-10-09, angry: "dont do this again", "run a script or something"): a grind agent asked to run `dlm_ledger_test` under CPU load copied the example from the prompt, `sh -c 'while :; do :; done' &` times 8 in a for-loop chain. The permission checker could not verify the `sh -c` program and stopped the unattended session on an approval prompt. Agents copy example commands verbatim, so the prompt text was the cause. Same class as `feedback-multi-step-shell-logic-goes-in-a-repo-script-never-an-inline-bash-c-program`, unapplied to the prompt itself. See [[feedback-never-put-an-inline-sh-c-program-in-a-delegated-agent-prompt]].
- Never write `sh -c`, `bash -c`, a busy-loop or a multi-command loop into an Agent prompt, even as an example. Write it as a script in `tests/` or `scripts/` first (`bash -n` it) and tell the agent to run that script with arguments.
- For CPU load use a repo script (or `stress-ng` if installed).
- If an agent is stopped mid-run, confirm any background load it started is gone (`ps -o pid,stat,cmd -C sh`, never pgrep or `ps -e`).
