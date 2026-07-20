---
name: AAA-ccloop46ef-sess2-PANIC-torn-publish-clobber-chain
description: sess2 DIAGNOSIS: 32/caw cache_coh+dlm_scaling 0/32 on 30E6BF7F = node PANIC mid-test → torn publish (P15-abort drains) → block re-alloc clobber. Seri…
metadata:
  type: project
---

## ccloop 46efd8b6 sess2 — RULE-4 PROVEN causal chain for the 30E6BF7F trio regression

### Result of trio @32 on 30E6BF7F (sliding 25ms grace)
- crash_consistency PASS 32/32 (grace preserves the batching win)
- cache_coherency 0/32, dlm_scaling 0/32 — NOT the sess1 strand (zero rc=-110, zero shutdowns, P15H strike-escalation works, 11-26 fires/node)

### PROVEN chain (run 20260710T021307Z, dirwr=1 ledger)
1. **test12 PANICKED mid-test** (prev boot FIRST ENTRY 02:18:08 = post-crash reboot; crash ~02:18:00-08 during rv-phase creates; network dead post-reboot → "no route"). Journal of crashed boot VACUUMED; pstore empty; no serial log (only test1-4 have it). Both failing runs had reboot casualties (run 014650Z: test9-16+32 returned empty marker sweeps = same pattern).
2. **Torn publish**: node12 built rv dir (ino 18874501) SF→block @ daddr 37678120 to 23 entries under batched tenures. P15-REL-ABORT path (120/node under grace) runs the Phase-2 drain (WRITES dir blocks to LUN) then aborts BEFORE mode=NL + RELFENCE → **block content lands on LUN mid-tenure, dinode (fmt/size/nextents) does NOT**. Crash mid-tenure leaves LUN: block=23 entries, dinode=SF-7.
3. **No foreign journal replay** of dead peer's slice (sess17 memory: designed, 3/6 edits done) → torn state persists.
4. **node7** (EX post-fence-out, 02:18:23.001) correctly reads dinode SF-7, adds its creates, SF→block conversion allocates the SAME daddr 37678120, writes 11-over-23 (P29-DATAWRITE ledger first line: N7 buf=11 disk=23 at 02:18:23.008395). 12 dirents wiped incl node1_before_1.
5. Cluster-wide: stale leaf entries → P21H-LEAFHOLE hv_in_leaf=2-3, dabuf-map holes at unmapped bnos → EFSCORRUPTED "Structure needs cleaning" on mv → rv checks fail everywhere → 0/32. LOOKUP paths trip !(HOLE_OK) at xfs_da_btree.c:2889; NODE-fmt (fmt=3) lookups have NO datascan-heal (only LEAF1 has rebuild: mxfs_dir_rebuild_leaf_from_data bails non-LEAF1).

### dlm_scaling 0/32 = DIFFERENT failure: rate/window floor miss ("ds nodeN rate>=floor"), no corruption. The 25ms grace taxes every single-op handoff. FIX DESIGN: gate grace on ops_in_tenure>=2 (dir_gen delta since grant); single-op tenures release immediately; crash_consistency batching bootstraps via holder-race abort (op2 arrives during ~6ms drain → P15 abort → tenure continues → ops>=2 → grace).

### NEXT STEPS (in order)
1. **Serial console capture on all 32 VMs** (sess24 recipe on test1-4: guest grub console=ttyS0 + libvirt serial <log file='/var/log/libvirt/qemu/testN-serial.log' append='on'>). Re-run cache_coherency@32 → catch the PANIC text. The panic is the primary defect.
2. Fix the panic.
3. TORN-PUBLISH hardening: P15-abort path publishes blocks without dinode — consider iflush-before-drain ordering or fence-at-abort so mid-tenure LUN state is dinode-consistent; AND/OR finish foreign replay (sess17).
4. dlm_scaling: ops>=2 grace gate (see design above).
5. Re-run trio; then dir_reuse@16/@32 (140*N budgets); then full ladder 1/2/4/8/16/32 on final build.

### Key artifacts
- Ledger: /tmp/claude-1000/-src-mxfs/eb86d5cb-4dfe-4534-aa32-12b1a65e25c0/scratchpad/ledger21/ (per-node P29/P-LEAFWRITE for ino 18874501; merged.txt sorted)
- Failed-run kernlogs (first run): /tmp/run_cache_coherency_20260710T014650Z/kernlog_test*
- rv dir run1: ino 14680196; run2: ino 18874501. P29 first line = the clobber.
- test25/26 ledger pulls timed out at 60s (big journals); test12 pull dead (no route pre-cycle). test12 now power-cycled clean.
- Build 30E6BF7F srcversion matches tree; params: caw_fair_handoff=1 (+dirwr=1 for ledger runs only).

### Cautions
- run.sh prep power-cycle escalation now PARALLEL (this session's edit, tested OK: 32-node all-dirty prep converged).
- Outer timeout for run.sh must cover prep(~360s w/ power-cycles)+converge(65s)+tests(300s each)+artifact collection(~180s under dirwr): use ≥1200s for one test, else exit 124 kills artifact copy (happened once; harvest from nodes directly then).
- journald on nodes rotates in ~85s under dirwr volume; harvest markers IMMEDIATELY post-run, filtered server-side.
