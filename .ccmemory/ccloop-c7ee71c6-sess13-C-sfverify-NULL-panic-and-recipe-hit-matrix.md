---
name: ccloop-c7ee71c6-sess13-C-sfverify-NULL-panic-and-recipe-hit-matrix
description: sess13: D4 NEW — xfs_dir2_sf_verify NULL-deref PANIC in bast_process (serial log 09:03, test6); recipe hit matrix; test6+test12 dual crash ~14:35
metadata:
  type: project
tags: [panic, sf-verify, null-deref, 32-node, recipe, coherency, open]
---

# sess13-C: D4 sf_verify NULL panic + D3 recipe hit matrix

## D4 — kernel PANIC: xfs_dir2_sf_verify NULL-deref on BAST release (NEW defect thread)
Captured from test6-serial.log (panic at ~09:03 today, sess12 era, build .113/.114 family —
went UNNOTICED then: node was power-cycled by prep, journal non-persistent, serial unread):
```
RIP: xfs_dir2_sf_verify+0x26/0x300 [mxfs]   CR2: 0000000000000001
Code: <80> 7e 01 00 = cmpb $0x0,0x1(%rsi) with RSI=0  → SF fork if_data==NULL, size arg=6
mxfs_dlm_bast_work_fn → mxfs_dlm_bast_process+0xd71 → (near xfs_imap_to_bp) → xfs_dir2_sf_verify
P141-UNLK-EXCLR ino=10485896 (SF dir) printed at panic moment; P138-BAST ino=10485896 mid-print
Kernel panic - not syncing: Fatal exception
```
= the DOCUMENTED hazard (xfs_mxfs_dlm.c NEWARCH note: "reload momentarily cleared if_data while
a concurrent thread iterated sf entries — NULL deref") — the race still lives in the
bast_process release path (verify of an SF dir whose fork a concurrent reload/convert tore down).
TODAY ~14:35: test6 AND test12 both crashed+rebooted mid cache_coherency rv-verify (recipe
attempt 3) — membership 32→30, all other 30 nodes hung at coord barrier (NO_TERMINAL_RECORD=32),
cc processes still parked at rv-rename-done markers. No capture (serial logging dead since
09:03, journald non-persistent) — pattern-matched to the 09:03 panic. netconsole module IS
loaded on nodes — check/point it at clyde to capture the next one.
Fix direction: find the SF-verify call in bast_process's drain (likely mxfs_dlm_reload_inode/
dir-durable path); it runs without the lock that guards if_data teardown (ILOCK) or without a
NULL check; close the window at the proven site AFTER capturing one instrumented instance (or
fix directly — the NULL-deref mechanics are unambiguous from RIP+Code+CR2).

## D3 recipe hit matrix (fresh 32/caw prep each; recipe = wedge_load 120s → rm -rf tree → cc)
- 13:50 attempt 1 (dirwr OFF): FAIL 8 checks — cv phase, 4 writers' files invisible
  cluster-wide (nodes 6/8/21/28). Dir ino 39846016 daddr=41864552 fcnt=30 (2 names short).
- 14:1x attempt (dirwr=2): PASS ×2 — tracing likely perturbs the race (heisenbug) or 0.25 coin.
- 14:3x attempt 3 (dirwr OFF): test6+test12 PANIC (D4) → membership 30 → cluster-wide hang.
Plus lap-6 hit (13:25, residual storm churn): rv rename lost, ino 170 platter evidence (sess13-B).
Score: 3 catastrophic outcomes / 5 storm-primed runs — the churn recipe is a defect factory.
CLUSTER STATE at save: 30 nodes wedged at cc barrier (test procs alive), test6/test12 rebooted
unmounted. Needs cleanup: kill cc procs / full re-prep before next run.

## Immediate next steps
1. Capture next D4 panic: configure netconsole → clyde (or virsh console relog), OR read the
   bast_process SF-verify site and fix the NULL window directly (mechanics unambiguous).
2. D3: re-run recipe with ONLY P170-CLWR (no dirwr) until the ino-slot variant recurs; then
   P170-CLWR provenance names the stale-slot writer. For dir-block variant, arm dirwr=2 only
   AFTER a hit on the SAME boot (post-mortem provenance not possible — needs live) — or accept
   dirwr=1-level lighter tracing if a level exists.
3. The two variants (ino-slot clobber, dir-block lost-adds) + D4 panic all cluster around
   CONCURRENT SF/cluster RMW during release/reload with reused inos — likely one structural fix.
