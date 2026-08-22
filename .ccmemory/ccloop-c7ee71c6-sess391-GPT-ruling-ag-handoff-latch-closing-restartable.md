---
name: ccloop-c7ee71c6-sess391-GPT-ruling-ag-handoff-latch-closing-restartable
description: sess391 RULE-5 ruling (3rd on AG handoff/PACE-388): atomic zero-holder LATCH at last-holder unlock + explicit AG_CLOSING admission state at BAST + RE…
metadata:
  type: project
tags: [sess391, PACE-388, AG handoff, latch, GPT ruling, readopt, ULBP]
---

# sess391 RULE-5 ruling — AG handoff closure (re-ask of the sess390 consult that died)

Prompt = the sess390 constraint set (ledger D-RSYNC-LAP-PACE-AG-SHARING-388 next_step; L1-L5 shapes).

## Ruling (gpt-5.6-sol)
- Do NOT ship L1/L2 as written: blocking callers sleeping in wait_demote while holding ILOCK/dirty trans recreate arm-3 with a 3 s escape (protest publish) — not a sound handoff protocol.
- REJECT L3 (inline sync release in last-holder task: uncontrolled context, lock-order by accident). REJECT L4 (hi-prio worker/requeue: no admission guarantee, no bound).
- SHIP: **atomic zero-holder latch + explicit CLOSING admission state + RESTARTABLE unsafe callers + resource-free generation wait.**

### State machine (per AG, under pag_dlm_lock)
enum {AG_OPEN, AG_CLOSING (BAST accepted, draining admitted holders, NO new root admissions), AG_DEMOTING (cached grant detached, worker owns handoff)}. Fields: bast_gen, bast_received, close_deadline, post_bast_root_admits, close_admit_limit, demote_gen, completed_demote_gen.
- BAST receipt: bast_pending=true; bast_gen++; bast_received=now; admits=0; first version: state=AG_CLOSING immediately (no grace). If grace later: acquisition path itself must check deadline/cap under the lock and flip to CLOSING (never rely on worker/unlock only).
- Last-holder unlock (holders->0 && bast_pending && CLOSING): state=AG_DEMOTING; cached=false; demote_gen=bast_gen; bast_scheduled=true; epoch=0; queue worker. ONLY state change + queue inline — no drains inline. Exactly one worker owner per demote_gen; WARN_ON_ONCE(DEMOTING && !scheduled).
- Acquisition capability: NOWAIT (-EAGAIN in CLOSING/DEMOTING), CLEAN_WAIT (resource-free; sleeps for the generation, acquires fresh), RESTARTABLE (holds ILOCK/dirty trans: return internal RESTART_HANDOFF immediately — NOT -EAGAIN — caller unwinds (cancel/roll trans, drop ILOCKs), waits resource-free `completed_demote_gen >= observed_gen || cancelled(gen)`, restarts from the outer retry point; must NOT cycle trylock->blocking while holding deps), NESTED (only with an explicit admitted-operation token; holders>0 alone is NOT proof of nesting). Inode BAST worker pre-handoff flush uses RESTARTABLE too — no exemption.
- Worker post-latch: start from post-COMMIT drain/publication; do NOT run the Phase-1 AIL push with demoting set unless proven it cannot allocate/reacquire the AG; closed-world release path, assert any re-acquire attempt. Completion: state=OPEN, clear bast_pending ONLY for demote_gen (a newer BAST keeps it), completed_demote_gen=demote_gen, wake_up_all.
### Budget
Validate immediate closing first. If grace needed: time cap 20-25 ms from BAST rx AND root-admit cap 8 (whichever first) — NOT 32-128 re-adoptions (96-384 ms local preference). Count root admissions/tenures, not P12-READOPT. State the bound honestly: BAST->latch <= grace + drain of pre-closing holders + sched error; instrument max tenure duration.
### Acceptance
Per generation: BAST_RX->CLOSING, ->latch, latch->CAW unlock, BAST_RX->CAW unlock (p50/p95/p99/p99.9/MAX). Invariants: 0 cached 0->1 after latch (WARN_ON_ONCE), 0 root admits after CLOSING, 0 worker bail1-holders after latch, 0 AG reacquire from post-latch worker. Counts by call site: NOWAIT -EAGAIN, RESTARTABLE returns, resource-free waits, restarts, max restarts per op, CLEAN_WAIT callers holding ILOCK/trans (assert 0). Fairness: all 32 nodes complete, per-node wall min/med/p95/max + spread, completions at 60 s, per-AG CAW ownership intervals, longest no-grant interval. Safety: 0 RELFENCE-WEDGE, 0 noino wedges, 0 handoff-caused P86/protest, 0 3 s ILOCK-stage timeouts from a local handoff waiter, 0 stuck CLOSING/DEMOTING gens. Run longer than 3 laps; fault-inject a delayed worker after the latch (re-adoption must stay impossible).
