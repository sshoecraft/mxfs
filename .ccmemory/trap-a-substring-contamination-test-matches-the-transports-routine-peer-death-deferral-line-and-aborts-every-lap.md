---
name: trap-a-substring-contamination-test-matches-the-transports-routine-peer-death-deferral-line-and-aborts-every-lap
description: TRAP (s70j→s71, 0.89.8): fence_crash_cuts counted 'self-fenc' in the prover's window; the TCP peer-death line 'deferring death ... EX frozen (self-fe…
metadata:
  type: feedback
tags: [harness, fence, contamination, substring, 2tcp]
---

# A substring contamination test that matches the transport's own routine line aborts every lap

**What happened (s70j, tests/fence_crash_cuts.sh):** the lap rejects itself as contaminated when a self-fence, a shutdown or a hold expiry sits between the crash-cut marker and the destroy. The self-fence count was `grep -c 'self-fenc\|SELF-FENCE\|hutting down filesystem'` over the prover's kernel window. On the TCP transport the prover prints, on EVERY peer death, `TCP peer N disconnected — deferring death 40000 ms (transient-flap tolerance); EX frozen (self-fence)` (dlm/v5_mount.c ~9603) — that is the prover freezing its own EX grants during the flap tolerance, not a self-fence. Cuts 1 and 2 both reached their marker cleanly (destroy 1-2 s after the marker, hold-expired 0) and both ABORTed on that one line.

**The real self-fence markers** are the module's own `P131-SELF-FENCE` (disklock.c, v5_mount.c, xfs_mxfs_dlm.c) and `P236-SELF-FENCE` (disklock.c). Fixed in 0.89.8: the count uses those and the shutdown text; both s70j windows count 0 under it.

**Lesson:** before a harness counts a word as a contamination or failure marker, grep the tree for every print that contains the word and confirm each one IS the event — a parenthetical in a routine line ("(self-fence)") is a substring too. Prefer the module's P-number markers, which name one event each, over English fragments. Same family as the substring-grep traps in compiled-rig-harness-measurement-traps.
