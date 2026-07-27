---
name: ccloop-c7ee71c6-sess1-d9-mount-abort-and-rig-fixes
description: Sess1: D9 fail-closed mount abort (v0.11.77) FIXED+VERIFIED; LIO /etc/target/pr missing broke PR OUT on VM rig; run.sh marker now rig-aware + live-ve…
metadata:
  type: project
tags: [d9, fail-closed, lio, aptpl, run.sh-marker, ccloop-c7ee71c6]
---

# ccloop c7ee71c6 sess1 — D9 + rig fixes (context: criteria "is it production ready?")

## D9 (v0.11.77, FIXED AND VERIFIED): DLM-init failure must fail the mount
`pal/linux/xfs_super.c` treated ANY `mxfs_v5_dlm_init` NULL as benign "continuing single-node" — so D2's PR-register abort (v0.11.75) aborted the DLM but the MOUNT PROCEEDED: both test nodes mounted the same LUN uncoordinated (observed during failed prep). Fix: envelope volume + DLM init failure → `xfs_alert` + `error = -ENOTCONN` + `goto out_filestream_unmount` (label safe at that point — zoned/reflink paths above use it). VERIFIED via `mxfs.dbg_pr_register_fail=1` one-shot: armed → mount(2) fails ENOTCONN, no crash in unwind; unarmed → mount OK. NOTE: state.md's claim that D2 was "VERIFIED: mount fails" on physrig was wrong — only the log line was verified; the mount continued single-node there too.

## LIO rig breakage (clyde): /etc/target/pr missing
PR OUT on the VM/tcp rig EXECUTED but completed CHECK CONDITION "NOT READY" ("SPC-3 PR: Could not update APTPL"; `filp_open(/etc/target/pr/aptpl_...) failed`). `/etc/target` existed but was EMPTY. Every PR OUT had side effects (PRgen bumped, keys changed) while reporting failure — pal retry x5 saw persistent failure → with D2+D9, cluster formation failed. `sudo mkdir -p /etc/target/pr` fixed it end-to-end (guest register rc=0). PR register historically ALWAYS failed silently on this rig (v0.11.73 proceeded unfenced). If PR fails again on VMs: check this dir first.

## run.sh marker validity fix
`.cluster_marker.json` matched a PHYSRIG-session marker for a VM invocation → 5 tests recorded PASS against the stale A9CE91EE module. Marker now records `node_list` and `marker_matches()` live-verifies each node's `/sys/module/mxfs/srcversion` + mountpoint (whitespace-squeezed). Old markers lack node_list → mismatch → forced prep. criteria.json's 2/tcp cell had held mislabeled phys data (soak ops≈910 = phys; VM ≈1500); overwritten by fresh VM runs.

## Old-build teardown hazard (dialloc-era A9CE91EE)
rmmod of that module left an `mxfs-worker` kthread running → instruction-fetch panic in unloaded text on test1 ("last unloaded: mxfs"), + test2 busy-inodes/slab-leak noise. v0.11.77+ teardowns observed clean (umount+rmmod fine, many prep cycles). If a CURRENT build ever repeats this family, it's a live defect — RULE 6.

## Board state after sess1 work
1/tcp + 2/tcp cells fully green FRESH on v0.11.77→78 (chunked runs; per-test budgets enforced). fio noise: fio_perf_vs_xfs 1-shot FAIL then healthy retry (seqW 212→712 MiB/s); fio_vs_xfs_baseline 68/70/70% worst under loadavg ~30 (Wow.exe+vLLM) — WATCH task #7: re-baseline in quiet window; not a credible regression (alternating weak metric, healthy samples per metric).
