---
name: AAA-ccloopa864-sess5-HARDHANG-reproducible-spinlock-deadlock
description: sess5 MAJOR: reproducible HARD-HANG spinlock deadlock (test32 workload + test27 prep, SAME code site, offset 0x116553F from idle). New on build E5F76…
metadata:
  type: project
---

# sess5 — REPRODUCIBLE hard-hang spinlock deadlock at 32 nodes (blocks clean dir_reuse runs)

## The finding (RULE-4, forensic via QEMU monitor)
Two different nodes hard-hung with the IDENTICAL signature:
- **test32** — during dir_reuse WORKLOAD (run1 durable_caw=0+fair_handoff=1, ~r6).
- **test27** — during PREP/join (run3 default config, readiness check).
`virsh qemu-monitor-command <n> --hmp 'info registers -a'`: most vCPUs HALTED (HLT=1, idle RIP), **ONE vCPU busy-spinning** (HLT=0, RIP oscillating in an ~18-byte window, RFL flags changing). Signature = a CPU stuck in a tiny spin loop while all others idle = **spinlock held-and-never-released / corrupted lock** (no on-CPU holder → the lock will never free; classic use-after-free of a lock-bearing struct, fits inode/daddr REUSE churn). RCU stall from the infinite loop kills networking → SSH "No route to host" while virsh domstate=running.

**REPRODUCIBLE / SAME CODE SITE (proven):** idle→spin offset is IDENTICAL on both nodes = **0x116553F** (KASLR-invariant):
- test32: idle=0x9be6b751 spin=0x9cfd0c90 → 0x116553F
- test27: idle=0xa6a6b751 spin=0xa7bd0c90 → 0x116553F
Same low-order spin bits (…0c7e/0c90). NOT native_queued_spin_lock_slowpath (test1 kallsyms: nqsls=0xa6e60310, idle→nqsls offset ≠ 0x116553F). The spin site is ~18MB above the idle anchor — a fixed vmlinux/builtin code site. Spinning code is in vmlinux text (0xffffffffaX…), NOT mxfs.ko (which is at 0xffffffffc0e01000 module space) — but the LOCK is very likely an mxfs-owned lock mismanaged by mxfs.

## Attribution
- NOT infra: reproducible at a fixed code site across nodes.
- NOT fair_handoff-specific: test27 hung with DEFAULT config (no modargs).
- Likely NEW on build E5F760E6 (sess4 orphan fix) OR exposed by 32-node membership churn (heavy power-cycling). The orphan-escape region (xfs_mxfs_dlm.c 11921-11990) has NO spinlock itself (only mutates i_dlm_* fields), so the imbalance is elsewhere — probably a DLM/CAW slot lock (dlm_caw.c) freed+reused under dir_reuse churn.

## HOW TO CAPTURE THE CULPRIT (definitive — do this next hang)
Node is unreachable but virsh domstate=running. Get the spinning CPU's STACK (→ mxfs caller):
1. **inject NMI**: `virsh -c qemu:///system inject-nmi <node>` → kernel NMI handler dumps ALL CPU stacks to serial console `/var/log/libvirt/qemu/<node>-serial.log` (append='on', survives reboot). Read that file.
2. OR enable the hard-lockup watchdog BEFORE the run so it auto-prints: on each node `sysctl -w kernel.watchdog=1 kernel.nmi_watchdog=1 kernel.watchdog_thresh=10` (+ optional kernel.hardlockup_panic=1 to also panic-reboot). test32/test27 serial logs were EMPTY → watchdog was OFF by default → MUST enable it.
DO NOT power-cycle a hung node before capturing (lost test27's state that way).

## Impact / next
This hard-hang BLOCKS getting a clean dir_reuse@32 workload run (test27 died in prep; test32 died at r6 degrading the barrier). Must fix it (or at least identify it) before/alongside wedge #2. Plan: enable watchdog on all 32 → launch → read the lockup stack → find the mxfs lock bug → fix. Then wedge #2 (durable-signal AIL-flush soft-hang).
Also: run.sh convergence gate parallelized this sess (was serial 32-SSH, too slow at N=32 → false PREP FAIL on a converged cluster).
