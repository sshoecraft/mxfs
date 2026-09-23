---
name: trap-chain-gate-already-done-starts-immediately-killed-harness-done-trap-cascades
description: TRAP (sess474): launching a chain gated on a log that ALREADY has DONE starts it instantly (collided with chain 105 = two preps, raced install_ko, bo…
metadata:
  type: feedback
---

# Chain-gate traps (sess474, 2026-09-02 17:58-18:02Z)

1. **Gate already DONE = immediate start.** Chain 116 was launched with GATE=chain108 s474b log at 17:58:44; s474b had printed DONE at 17:58:17, and chain 105 (gated on the same log) had started at 17:58:43. Two `run.sh 32 caw prep_cluster` ran concurrently; both harnesses ran install_ko into the same tree mxfs.ko within a second (chain 105 logged `modinfo: ERROR ... Invalid argument`, `sv=` empty, and its harness did NOT abort on the empty sv — a harness weakness to fix: install_ko must fail on sv mismatch/empty). Chain 105's prep then ran with the wrong module (0.64.26). RULE: `grep -q '^DONE' $GATE` BEFORE choosing a gate; if DONE, gate on the chain that is actually running/queued last instead.
2. **Killing a harness can open the next gate.** Chain 105's harness has a DONE-on-exit trap: `kill` -> `DONE 17:58:50` -> chain 111 started (prep rc=3 in 4 s = run-lock collision, then its arms rc=2, DONE) -> chain 104 started its prep. Cascade of invalid runs. When aborting a chain, IMMEDIATELY check whether the downstream waiter's gate opened and kill/relaunch it too; archive polluted logs (`mv ... .aborted_...`) — the relaunch appends to the same LOG name.
3. **Prep survives its parent's kill.** `timeout 300 ./run.sh 32 caw prep_cluster` is in its own process group (GNU timeout) — kill the `timeout` pid and the `run.sh` pid explicitly; then settle ~90-100 s (one prep wall) for ssh fan-out remnants before launching the next prep.
4. **A kill loop over /proc/*/cmdline matches ITS OWN shell** (the pattern text is in the command line): exclude `$$`/`$PPID` and `*shell-snapshots*` cmdlines, or the Bash call kills itself (exit 144).

Recovery used: kill 116/105/111/104 + preps, archive logs `*.aborted_s474_collision`, settle 90 s, relaunch 116 -> 105 -> 111 -> 104 gated in order (102/107/101/106/100 waiters untouched). Chain 104's launch env was only GATE (captured in tests/evidence/sess474_chain104_env.txt).
