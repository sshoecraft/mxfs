<!-- sess488 RULE-5 ruling: D-0483 base half (lap 5 refusal arm) + fix half (lap 4 pre_wr=9) COMBINE under the declared rule; only the plain 32/caw board… -->
# sess488 GPT ruling on D-0483 closure evidence (2026-09-04 ~06:30Z)

Question: may the base half (lap 5 chain 138: base#1/base#2 each 1/32 hung with
470/460 P126 refusals after publication) and the fix half (lap 4 chain 136: fix
32/32, all after-publication counters 0, pre_wr=9/pre_iclus_wr=3 on 3 nodes)
be combined, given lap 5's fix leg had pre_wr=0 (G7: not a measurement) and
lap 4's base did not reproduce?

Rulings:
1. YES, they combine. The declared rule states separate predicates for BASE and
   FIX and never said "same lap"; both halves were produced after declaration on
   the same frozen modules/workload/harness. Adding a same-lap requirement now
   would be a retroactive criteria change. Each leg re-mkfs's anyway, so same-lap
   pairing would not give identical FS state.
2. No additional instrumented lap is required. Remaining item: the plain 32/caw
   board on the fixed build. If the harness is changed later to make the
   positive witness deterministic (teardown-specific witness: record deferred
   inactivation targets when producers stop, arm accounting before inodegc can
   drain them, record put_super consumed >=1 before publication; optionally a
   test barrier), that is a NEW declaration and base must reproduce again under it.
3. Lap 5's pre_wr=0 fix leg is non-qualifying but not void: it is supplementary
   liveness/safety data. "The workload left nothing to do" is too definite —
   pre_wr=0 cannot distinguish work-before-window / fix draining via an uncounted
   path / no work / incomplete instrumentation. Investigate the zero-witness
   behaviour before any harness redesign; it does not invalidate lap 4.

Next run: the plain 32/caw board (queued sess488 as chain 123 s488b on the
0.69.5 tree build, which carries the 0.69.3 fix plus probe-only 0.69.4/0.69.5
changes). If green, close D-0483 citing lap 5 base, lap 4 fix, and the board.
