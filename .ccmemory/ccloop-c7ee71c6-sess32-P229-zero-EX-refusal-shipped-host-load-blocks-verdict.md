---
name: ccloop-c7ee71c6-sess32-P229-zero-EX-refusal-shipped-host-load-blocks-verdict
description: P229 bypass measured ZERO firings (both healthy+failed boards) → EX refusal shipped 0.11.285 (inert here, closes latent hole). 285 dd FAIL 5/32 = HOS…
metadata:
  type: project
---

# sess32 close — P229 verdict, 0.11.285, and the host-load contamination

## P229/P230 probe results (0.11.284)
- `mxfs_dlm_ilock_try`'s preempt_count()>0 bypass arm: **ZERO firings** on
  the dirent_durability producer — on the healthy 65s lap AND on the failed
  board. The arm is dead code on this workload/kernel; it is NOT the
  recommit-window producer (that question returns to the admitted-holder
  commit timing — see the interlock design note).
- Structural hazard STANDS (source-proven): a hypothetical EX grant through
  that arm has no tenure/DEMOTING-gate/holder-count, and its paired
  ilock_end decrement (unconditional since P125) would eat a concurrent
  holder's count → P15 false-zero. 0.11.285 therefore REFUSES EX in that arm
  (nowait callers fall back to blocking xfs_ilock = full DLM path); PR keeps
  the bypass with the P230 log-under-bypass tripwire. Behaviorally invisible
  today (0 firings) — pure latent-hole closure.

## 0.11.285 validation BLOCKED BY EXTERNAL HOST LOAD — do not misread
285's first dd lap: FAIL 5/32 NO_TERMINAL_RECORD=27 @240s. NOT the change:
P229=0 on that very board (the changed code never ran), all sampled nodes
SYNC_OK, and clyde's loadavg was 16-23 driven by EXTERNAL processes
(Wow.exe 348% CPU + worldserver 91% + a 158% python3 — a game server on the
dev host). cache_coherency PASSed 27s in the same window (short criterion
slips between spikes); dd is the load-canary because its rounds fire on
WALL-CLOCK SLOTS — CPU-starved nodes miss their slot → NO_TERMINAL_RECORD.
Same regime as sess31's crash_consistency INFRA STALL and sess30's
"rig contention masquerades as regression" lesson.
A load-gated re-run (until loadavg<8, then one lap) was left running in the
background at session end; if it did not complete, session 15's FIRST move:
check loadavg, re-run `./run.sh 32 caw dirent_durability` on 0.11.285
(304E7F3D3CFC170D3EF5D5E, deployed all 32), expect PASS ~65s. If it FAILS
on a QUIET host, treat as a real 285 regression and bisect the EX-refusal
(knob-free change — revert = restore `return true` unconditionally).

## Version ladder this session (all deployed+validated except 285-pending)
272 mask-ON · 273 replay-containment+P224 · 274 adopted-slice · 275-278
relbar ledger probes · 279 enforce (off) · 280 enforce ON · 281 both arms ·
282 barrier (REVERTED — convoy) · 283 bounded trylock · 284 P229/P230
probes · 285 EX-refusal (validation pending host quiet).
