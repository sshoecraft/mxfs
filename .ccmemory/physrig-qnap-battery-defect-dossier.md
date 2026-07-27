---
name: physrig-qnap-battery-defect-dossier
description: Physical pve1/pve2+QNAP battery on v0.11.73: coherency fixes HOLD; 5 defects opened — PR-unfenced mount + eaten log EIO (critical), no slot release a…
metadata:
  type: project
tags: [physical-rig, qnap, scsi-pr, disklock, rule-6, defect-dossier, v0.11.73]
---

# Physical-rig battery (pve1 192.168.1.80 / pve2 192.168.1.81, QNAP TS-453 Pro iSCSI, TCP DLM) — v0.11.73

Build: 6.17.2-1-pve local /root/mxb on BOTH nodes, srcversion **8212BFC85564623890E5D79** (same tree as clyde's A9CE91EE 6.8 build). Creds: osimager secrets `proxmox/pve1|pve2` → `/tmp/.proxmox_pass` (clyde). QNAP LUN serial 393a5a6e = /dev/sdb both. QNAP **rejects READ(16)+FUA (asc=0x24)** → plain-bio fallback engages ("write-through backstore assumed").

## PASSED on physical (task 1-3 + wedge)
- mkfs 0.65s; chk clean. Formation + **racy-join reproducer**: settle gate "membership settled … after 250ms", deferred single→multi fired, both seeds survived (roots #7/#8 fixes HOLD on real iSCSI).
- 45s dual churn 938+508 ops errs=0, symmetric visibility. rc=-35 lines = designed B5 stale-incarnation guard (documented xfs_inode.c:3811-3849), soak DPAT does not match them.
- **AGI-wedge fix VERIFIED via scripts/agi_wedge_verify_inject.sh on pve1**: umount 2s post-shutdown, P-AGMETA-RECLAIM ×3 (agi/inobt/finobt), 0 drain-stuck.

## OPEN DEFECTS (RULE 6 — all with platter/dmesg evidence)
1. **PR-unfenced mount + eaten log write error (CRITICAL)**: TCP branch v5_mount.c:1009-1019 — scsipr register failure → destroy ctx → **proceed unfenced** (CAW branch aborts, line ~1161). Cycle2: pve2 REGISTER rejected w/ reservation conflict @2487.49 (PR gen never bumped: 0x77→0x79 = pve1's REGISTER+RESERVE only), pve2 ran whole tenure unregistered. Its **journal-slice write bounced** (sector 52920549 = slice 3 +2.5KB, flags 0x9800) → `XFS log I/O error -52` (EBADE) → **NO shutdown, error eaten** (journal writer = mxfs_pal_bdev_write_fua @ dlm/mount.c:5640). Cycle1 same shape (slice-1 write bounce @1717.7). Crash in that state = committed-txn loss.
2. **Teardown writes NO slot release**: mxfs_disklock_stop_heartbeat (disklock.c:736) stops thread only; platter keeps flags=ACTIVE forever (slots 0/1/2/3 all still ACTIVE post-clean-umounts). → every mount within lease window sees ghost "active foreign slots" → settle gate burns 15s cap (P-MEMB-SETTLE-TIMEOUT). Gate call passes threshold_ms=0 = snapshot-only, no liveness rescan (v5_mount.c:1124, disklock.c:1594).
3. **Clean peer umount = 40s survivor stall**: no goodbye msg; departure hits mxfs_tcp_death_grace_ms=40000 (v5_mount.c:80, sess45) — survivor umount 40.2s/39.5s with "lock request … retrying" spam; EX frozen window.
4. **~4.68s EX handoff constant**: P34-ACQ-SLOW dur_ms=4681/4676 (5ms apart!) joiner root-ino EX vs live holder; first-join 19765ms ≈ 15000+4700 composite. VM-class is ~130ms. Mechanism unknown (suspect periodic tick alignment).
5. **QNAP enforces PR intermittently (hardware qualification)**: unregistered pve2's disklock claim+heartbeats LANDED for 25s under active WE-RO (slot3 ts decode 2512.1s), only 4 conflicts/60s; enforcement probabilistic → PR fencing NOT trustworthy on this target. mxfs needs a PR-enforcement probe (like CAW/FUA probes) + fallback fencing + loud warn. (Enforcement probe pending as of writing.)

## Forensic gotchas (do not relearn)
- chk_mxfs "slot N: DIRTY/clean" = **journal slot table**, NOT disklock heartbeat records (heartbeat = disklock_offset 67117056 + slot*512, layout: magic MXLK, flags, node_id, fs_gen, ts_ms@+16). node_id is per-mount random; PR key = node_id.
- Raw O_DIRECT cross-node write/read of the LUN is coherent+fast (probe proven). tests/logs/ = 15.5G — exclude from any rsync.
- pve umount-order artifact: LAST umounter pays the 40s (its peer's departure), first umounter exits in ~0.2s.
- C1's "slot 2 revert to pre-mkfs ghost" = pve2's claim write likely bounced in an enforcement window while read-back was… (unresolved detail; superseded by cycle-2 clean repro of the bounce mechanism).

## Next
Enforcement probe (20 spaced unregistered writes under held WE-RO, count pass/bounce) → then fixes in severity order (1: abort-on-register-fail + log-error must shutdown or retry-with-proof; 2: FUA slot-clear in stop path + gate liveness window; 3: goodbye msg; 4: instrument handoff). Suite subset (task 5) + sysrq-b dead-peer finale pending. Battery scripts/state all on the nodes at /root/mxb.
