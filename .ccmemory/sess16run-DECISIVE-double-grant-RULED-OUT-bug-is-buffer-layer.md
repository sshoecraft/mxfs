---
name: sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer
description: sess16(ccloop) DECISIVE: master-table double-grant RULED OUT. Added always-on MX-DOUBLEGRANT auditor (dlm/dlm.c, build C1469F1E) that scans the maste…
metadata:
  type: project
---

## sess16 (ccloop) — DECISIVE: double-grant RULED OUT; bug is the buffer/reload layer

### Experiment
Added an always-on, clock-free master-side auditor `mxfs_dlm_audit_double_grant()` (dlm/dlm.c, build C1469F1E) that scans the resource's GRANTED holders in the master's lock table and logs MX-DOUBLEGRANT if any two different-owner holders are mode-incompatible (two EX, EX+PR, etc). Wired at all 3 local grant-commit points: new-grant (~1226), PR→EX upgrade (~1123), and promote_waiters post-release regrant (~626). The auditor runs on EVERY grant/promotion → thousands of times during the test.

### Result (DECISIVE)
dir_reuse 8/tcp mht=50 dirwr=0 (race manifests): FAILED 0/8 (loss reproduced, node1_f1/node5_f40) AND **MX-DOUBLEGRANT fired 0 times on ALL 8 nodes** (total_dg=0 everywhere).
→ The master grant table NEVER holds two incompatible EX/PR grants for ino=131. **The DLM serializes EX correctly.** The earlier P106 "pervasive overlap" [[sess16run-PIVOTAL-P106-overlapping-EX-grants-and-timing-race]] was an instrumentation artifact (P106-EXGRANT only logs slow-path acquires; holder-tracking was broken) — CONFIRMED bogus.

### What this PROVES (the search space is now small)
The dir_reuse lost-update is NOT a DLM serialization/double-grant bug. EX is granted serially: test4 fully acquires→writes→drains→releases, THEN test2 acquires. Yet test2's RMW base is STALE (writes count=77 after test4's durable 126). So a node acquires EX serially but its in-core dir buffer base is stale, and re-reading does not fix it. ALL refuted at dirwr=0: force_coherent, dir_postread_reread, b_mxfs_dir_epoch, dir_release_fua_write, dir_release_invalidate.

### Why even dir_release_invalidate failed despite serialized grants (the precise remaining gap)
dir_release_invalidate clears XBF_DONE on the released node's DATA blocks after the durable bwrite — but: (a) it may not cover LEAF/FREEINDEX blocks (the P21H leaf-hash hole is a LEAF-block issue; P34-LEAF-DRAIN showed leaf blocks UNCACHED at release → not flushed/invalidated); (b) the NEXT acquirer's reload/keep-guard may re-preserve a stale buffer; (c) GPT's REVOKING fence is needed so nothing re-dirties between drain and grant-drop. The stale base likely lives in the LEAF or freeindex block, OR in the inode's data-fork extent map (P32-NXSHRINK), which dir_release_invalidate doesn't touch.

### NEXT SESSION — implement GPT design parts 1+2 (now strongly justified)
[[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]: at EX release/handoff, under a REVOKING writer-fence (block new local dir ops, wait active txns, drain), invalidate ALL dir metadata buffers — DATA + LEAF + NODE + FREEINDEX — not just DATA blocks; AND the inode data-fork extent map (force reload on next acquire). The release-side invalidate must cover the leaf/freeindex blocks that P34-LEAF-DRAIN showed are UNCACHED (so cache them + flush + invalidate, or track their daddrs). Validate at dirwr=0/instr=0 (dirwr masks the race — a dirwr=2 run PASSED). Target: P-DIRWR daddr=120 count monotonic, dir_reuse 8/tcp PASS at mht=50, tcp_dlm ≤60s, 17/17, 1/2/4.

### Build C1469F1E = 42178C17 + MX-DOUBLEGRANT auditor (always-on, lightweight, KEEP as a permanent invariant check — it's a cheap table scan that proves serialization). New buffer logic still gated off at default. Criterion NOT met.</body>
