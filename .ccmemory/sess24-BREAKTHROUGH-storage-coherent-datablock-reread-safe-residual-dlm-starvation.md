---
name: sess24-BREAKTHROUGH-storage-coherent-datablock-reread-safe-residual-dlm-starvation
description: sess24(ccloop): storage COHERENT -> data-block re-read SAFE -> postread leaf_only=0 kills both dir corruption faces; residual 8-node = DLM acquire st…
metadata:
  type: project
---

## sess24 (ccloop) — major progress on 8/tcp dir_reuse

### Key environment fact (decisive, ends a 20-session false assumption)
The shared LUN /dev/sda is qemu `<disk device='lun'><driver type='raw' cache='none'/><source dev='/dev/mxfs-shared'/><shareable/>`. So: **cache=none (O_DIRECT, no host page cache) + guest write_cache=write-through + shareable across all VMs = STORAGE IS COHERENT.** A completed+synced write from one node is immediately visible to another node's read. The recurring "torn-read = FUA reads the PLATTER which LAGS the target write-back cache" explanation (sess13/sess20, which forced `dir_postread_leaf_only=1`) is **WRONG** for this stack. Userspace tools/fua_verify SCSI CDB is rejected (INVALID FIELD 0x24) by qemu virtio-scsi but in-kernel REQ_FUA bios work.

### What this unblocks (PROVEN this session, fresh-boot runs)
`MXFS_EXTRA_MODARGS="dir_postread_reread=1 dir_postread_leaf_only=0"` (re-read BOTH leaf AND data dir blocks on stale grant_gen/epoch):
- DABUF-HOLE (stale leaf -> maps freed block) = **0** (was 60, shutdown).
- xfs_dir2_data_use_free corruption (stale/torn data-block RMW base, line 1740) = **0** (was the catastrophic shutdown at default).
So re-reading data blocks (now safe, storage coherent) eliminates the two dir-coherency corruption faces. Default keeper EF6000F0 has leaf_only=1 + postread_reread=0 → suffers BOTH.

### Residual 8-node blocker (NEW, clean): DLM acquire STARVATION
After the coherency faces are gone, the run dies differently: a node's dir-lock acquire on the hot shared dir **ino=131** retries 60× (P36-RETRY) and TIMES OUT after **184535 ms** → `DLM inode lock unrecoverable: rc=-110` → `xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE)` at xfs_mxfs_dlm.c:12394. Observed for mode=3 (PR, the cold-verify readdir) — a READER starved by the EX-writer storm. 8 nodes hammering one dir → EX ping-pong (grant_gen hit 52 in round 1, EX acquire 3.25s w/ retries) starves PR waiters indefinitely.

### Tension introduced by leaf_only=0
Re-reading data blocks adds synchronous FUA latency per stale block; under heavy handoff churn many blocks go stale each tenure → longer tenures → WORSE starvation. So leaf_only=0 alone trades corruption-shutdown for starvation-shutdown. Need to ALSO: (a) reduce churn (raise node-format dir MHT so each tenure batches more creates → fewer handoffs → fewer stale blocks), and/or (b) FAIR DLM grant queue (FIFO, anti-starvation) so a PR/EX waiter is never starved 184s, and (c) acquire-timeout should retry/yield, not force-shutdown (RULE 0: 184s is itself a fail).

### Flakiness methodology (IMPORTANT)
dir_reuse 8/tcp is ~50% on FRESH boot and ~always-fail on a 2nd consecutive run (no reboot) because the bdev buffer cache survives rmmod (peers read stale run-A pages after test1 re-mkfs). Added `blockdev --flushbufs $DEV` before mount in tests/setup/prep_node.sh (harmless hygiene; not the root). ALWAYS `virsh destroy+start test1..8` between trusted runs. Single-run PASS is NOT proof.

### Next
1. Make data+leaf postread re-read the default coherency path (validate 1/2/4 tcp unaffected).
2. Fix DLM dir-lock starvation: FIFO/fair grant + raise node-dir MHT to cut churn + don't shutdown on acquire timeout. See [[sess23-STATE-keeper-18064D1D-1and2-tcp-pass-8-is-lone-blocker]] [[sess50_lessons]] (defer_for_waiter writer-starvation fix) [[sess23-gpt5.5-grant-generation-coherency-design]].
</body>
