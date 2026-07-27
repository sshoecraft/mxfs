---
name: physrig-campaign-COMPLETE-15of15-green
description: Physical QNAP campaign COMPLETE: suite 15/15 PASS on v0.11.76, dead-peer sysrq-b battery clean (survivor writes through death window, umount 0.42s, r…
metadata:
  type: project
tags: [physical-rig, campaign-complete, suite-green, dead-peer, v0.11.76]
---

# Physical-rig campaign — COMPLETE (2026-07-25, v0.11.76 = DAE09A36 on 6.17)

## Final battery results (all on pve1/pve2 + QNAP TS-453 Pro iSCSI, TCP DLM)
- Suite subset **15/15 PASS** via `MXFS_NODE_LIST=192.168.1.80,192.168.1.81 MXFS_PASS=/tmp/.proxmox_pass MXFS_DEV=/dev/sdb ./run.sh 2 tcp <tests>`: cache_coherency 534, strong_consistency, posix_multi 140, mmap, zero_silent_loss 44, dlm_fairness, rsync_paired, crash_consistency 104, fence_during_write, fault_netpartition, dlm_membership, scaling_curve, dlm_scaling, dir_reuse 142 (101s/120s), soak (31s, hits=0). fio tests EXCLUDED deliberately — .xfs_fio_baseline.json is VM-rig; phys baseline needed first.
- Results archived: **criteria.physrig-2tcp.json** (tree); criteria.json RESTORED to the VM board (backup was in scratchpad).
- **Dead-peer sysrq-b finale**: pve2 sysrq-b mid-activity → pve1: instant TCP-disconnect detect → 40s grace (EX frozen) → HB expiry 33s → slice recovery → dead declared @40s; survivor wrote through the whole window; post-death write OK; **umount 0.42s**; chk clean. pve2 POSTed back ~2min, modprobe'd installed v0.11.76, rejoined w/ gate 0ms, full cross-vis. AGI-wedge injection verified earlier same session.
- Racy-join (root #8) + deferred single→multi (root #7) re-verified on v0.11.76 fresh mkfs: settled 0ms, both seeds survive.

## Suite-on-phys mechanics (reuse next time)
- Nodes need the build installed as modprobe-able: cp /root/mxb/mxfs.ko /lib/modules/$(uname -r)/updates/ + depmod. **Stale dkms mxfs/0.11.40 in updates/dkms/ SHADOWED it — rm + depmod** (dkms metadata still says installed; a kernel update could resurrect 0.11.40 — deregister dkms properly someday).
- run.sh + prep_node.sh already handle foreign-kernel nodes (vermagic-detect → node-installed module as build ref). MXFS_DEV=/dev/sdb REQUIRED (default /dev/sda = pve SYSTEM DISK; mkfs refused on busy — close call).
- prep fresh = 36s on phys. Suite times ≈ VM board +0-3s each.

## "Would 2 pve9 VMs have found the same?" (user Q, answered w/ evidence)
- QNAP PR family: YES identically (target behavior; guest iSCSI hits same PR DB).
- D1a/D3/D5/D6: code is rig-independent, but VM journals show **0 log-error-52 hits ever** — LIO is conformant AND suite teardown umounts the HOLDER (test1) first, so the non-holder-under-live-reservation shape never occurs. My manual battery umounted non-holder first → surfaced it.
- D7: trigger (join while holder has unflushed root-EX) is rig-independent; suite prep never dirties between mounts → never trips. pve9 repro viable for fast iteration.

## Open (RULE 6) for next session
- **D7**: 4.7-20s joiner-side self-mastered pre-grant EX wait (samples 4676/4681/19765/20070ms). Request-ID+boottime stamps per GPT plan. Repro: mount n1, touch (no sync), mount n2 — P34-ACQ-SLOW fires.
- **D6**: clean-umount goodbye (survivor 40s stall; withdraw path P-WITHDRAW-RELALL exists for shutdown — wire clean path).
- **D4**: preempt hygiene (READ KEYS first; conflict classify; self-fence if own key gone).
- **D8**: periodic PR self-check + provisioning conformance probe; QNAP PR = advisory.
- Phys fio baseline never captured (fio_perf/vs_xfs skipped).
- Rig state: both nodes unmounted, v0.11.76 loaded+installed, LUN has suite-era FS + rejoin files, all slots released/clean except sysrq-b tenure remnants evicted.
