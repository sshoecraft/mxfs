---
name: ccloop-c7ee71c6-sess125-GPT-ruling-dir-tenure-batching-design
description: sess125 RULE-5 ruling on the dir-EX tenure batching fix: op-quantum ALONE is insufficient; measure deadline from BAST not GRANT; idle grace from last…
metadata:
  type: reference
tags: [gpt-ruling, dir-create-pace, mht, yield-quantum, design]
---

# sess125 RULE-5 ruling — directory EX tenure batching

Consulted after rooting the 22ms/create pace to the MHT adaptive floor
(`i_dlm_tenure_ops <= 1` -> clamp 300ms window to 15ms).
GPT ACCEPTED the diagnosis, REJECTED my fix as written.

## The causality gap (the core correction)

My proposal claimed "a true one-shot consumes 1 op and releases
immediately". **You cannot know it was a one-shot until you have waited
long enough to see that no second op is coming.** For a sequential
syscall stream (shell loop, single task) there is NO local kernel waiter
at the instant the first create unlocks. A pure op-quantum then has only
two bad choices: release now (one handoff per create — the present
defect) or hold until the budget fills (which may never happen).

**That inter-arrival grace is exactly what the MHT was trying to bridge.
Fix WHERE and HOW it is applied; do not eliminate it.**

## Required design (hybrid)

1. **Post-BAST op budget** — after a BAST arrives, admit at most N more
   local dir mutations. Charge the in-flight op against it.
2. **Idle grace measured from the LAST COMPLETED OP, not from EX grant.**
   This is the piece that lets a sequential syscall stream look like a
   burst without parking a genuine one-shot for 300ms.
3. **Hard deadline measured from BAST RECEIPT, not EX grant.** Semantics:
   "max EXTRA delay imposed on an already-waiting peer." At expiry enter
   must-yield: admit nothing new, demote at final active unlock.
4. **Adapt only from COMPLETED-TENURE outcomes.**

## DO NOT adapt at BAST arrival (would recreate the defect)

My "halve on BAST-with-allowance-unused" is wrong: the BAST always
arrives 22-75us after grant, so EVERY tenure has unused allowance at
BAST time -> everything halves to 1 forever. Same trap as the current
`tenure_ops<=1` classifier, one level up.

End-of-tenure signals to adapt from: budget exhausted w/ backlog
(increase); yielded idle w/ budget unused (decrease); deadline hit
(decrease); no BAST over real work (increase); **local re-request issued
immediately after a forced yield (strong evidence the yield was
premature)** — record when the next local request is ISSUED, not when
granted, since after 31 peers grant time no longer reflects inter-arrival.

## Sizing — N=512 is not needed

- N=4 -> ~800 handoffs (vs 3200); N=8 -> ~400. At ~20ms that is ~16s/~8s.
- 300ms is acceptable as an ABSOLUTE safety cap but too high as the
  normal contended quantum. Target **50-100ms post-BAST service**.
- Tail bound: T_owner <= L_target/(M-1) - H - S. At 32 nodes a 300ms cap
  permits a ~9-10s traversal of 31 owners; 50ms permits ~2s.
- N_max = min(N_abs, floor(T_service / C_ewma)); EWMA advisory only, the
  hard deadline is what actually bounds it.
- An op cap ALONE gives no time bound (an op can stall on log space, I/O,
  another metadata lock). Real bound: Q <= T_cap + longest in-flight op.
  The timer must set must-yield, never preempt an active critical section.

## Fairness prerequisite
The bound is real ONLY with queue discipline: no barging, no immediate
reacquire at the front after demotion, no conversion starvation, bounded
owner-failure recovery, and must-yield actually blocking new local entry.

## Cross-tenure state hazards
Treat as DISPOSABLE, generation-tagged perf hint — losing it may only
affect convergence, never correctness. Reset/bias-down on: reclaim or
eviction, inode number reuse / generation change, lock-resource
destroy+recreate, forced shutdown, cluster recovery / lockspace rejoin,
fencing of the previous owner, admin revoke, protocol-version or
mount-epoch change, unexpected steal. Tag delayed work with a
tenure/lock generation so stale work cannot demote a NEWER tenure; cancel
on reclaim. Decay history after long idle. Key per lock-resource
incarnation, not bare inode number.

## Format transitions (sf -> block -> leaf -> node)
Longer tenure is not inherently a correctness problem IF: every
transition is committed/recoverable before unlock, peers cannot observe
stale inode-core/fork/dir-buffer/LVB after handoff, the timer never
demotes mid-transition, and a time threshold alone never causes a lock
steal (stealing requires fencing). **Retain only the cached DLM grant
between ops — never an active XFS transaction, buffer lock, or local
ILOCK just to fill the quantum.** Test: every format boundary under
multi-node insertion; rename across two hot dirs; create/unlink
oscillation at format thresholds; ENOSPC/log-space pressure during
transition; owner crash at each transition; reclaim while idle-grace
work is armed.

## Is amortization the right lever? YES
One durable handoff per dirent cannot scale. Longer-term alternatives
(noted, not now): per-node subdirs, hash-sharded dirs, leaf-level dir
locking, designated dir owner + insert RPC, batched create API, cheaper
ownership publication. Fine-grained dir locking is a major redesign
(leaf splits, freespace index, rename, recovery); amortization is far
lower risk for this defect.
