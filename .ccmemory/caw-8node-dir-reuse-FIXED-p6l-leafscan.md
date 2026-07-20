---
name: caw-8node-dir-reuse-FIXED-p6l-leafscan
description: RESOLVED: 8/caw dir_reuse_coherency PASSES on build 591A76FB (P6L ungated leaf scan fixes leaf-hash drops). 8/8 nodes, 0 fresh P-LEAFDROP. Remaining…
metadata:
  type: project
---

## 8/caw dir_reuse_coherency — FIXED (2026-07-06, ccloop 5bea4199)

The long-running 8/caw leaf-hash-hole blocker (see [[caw-8node-leafhash-hole-shutdown-diagnosis]])
is **RESOLVED** on build **591A76FB** (already in tree, built Jul 6 02:09).

### Proof
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 8 caw dir_reuse_coherency`
→ **PASS nodes_pass=8/8**. Test wall ~700s (well under 140*N=1120s budget).
During the run test1 dmesg showed **0 fresh `P-LEAFDROP.*bp=` events, 0 shutdown/BUG/Call-Trace**.
Confirms the sess6 "CORRECTION at relay" hunch: the ungated P6L leaf-range scan
(`mxfs_dir_coherent_leaf=1` in `mxfs_dir_refresh_stale_data_blocks`) DID fix the drops;
the earlier "fails every run" evidence was ring-redump contamination + a too-tight 900s wrapper.

### State of the caw ladder (criteria.json source of truth)
- 1/caw 17/17, 2/caw 17/17, 4/caw 17/17 (MIXED builds — need one-build rerun for marker).
- 8/caw now 15/17: +dir_reuse_coherency. Still MISSING at 8: **fault_netpartition, soak**.
- 16/caw, 32/caw: not yet attempted. Each runs the SAME 17 multi-node tests as 8.

### Final-ladder build blocker (soak dmesg-clean): TWO ungated dump_stack probes
soak.sh greps dmesg case-insensitively for `DPAT=...|BUG:|Oops|stuck for|call trace`. Any
`dump_stack()` ("Call Trace:") in a soak window = soak FAIL. Current build 591A76FB has:
- `pal/linux/xfs_buf.c:~4139` **P-LEAFDROP** pr_err + stack (dir_reuse canary).
- `xfs/xfs_mxfs_dlm.c:13520` **P-DIR-DELALLOC-TRIP** rate-limited(12) + dump_stack.
- (`xfs_mxfs_dlm.c:22672` P1-AGWAIT dump_stack is ALREADY gated behind mxfs_instr_enabled — OK.)
Plan for final build: gate those 2 dump_stacks behind mxfs_instr_enabled (keep pr_err counters
as canaries; their text has no DPAT keyword). BUT verify empirically first (RULE 4): run soak at
8/caw on 591A76FB and see if they actually fire before patching. Also known: mxfs_ili kmem-cache
"Objects remaining" BUG at rmmod (between-runs, likely outside soak's post-mark window).

### Harness facts
- `./run.sh N caw [tests...]` self-preps (teardown→mkfs→form→join→build-match assert→converge gate→run→record criteria.json). Nodes NFS-mount /src from 192.168.1.4; module deployed from /src/mxfs/mxfs.ko. Must pass MXFS_DEV=/dev/mapper/mpatha.
- dir_reuse 8/caw needs ~1300s wall (1120s internal budget); foreground Bash caps at 600s (tool default 120s — set timeout param). Launch bg + poll.
- Confirm result: `./showstat.sh 8 caw` or criteria.json runs["8/caw"].
