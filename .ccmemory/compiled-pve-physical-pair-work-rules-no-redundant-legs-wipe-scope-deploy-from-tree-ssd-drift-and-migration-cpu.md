---
name: compiled-pve-physical-pair-work-rules-no-redundant-legs-wipe-scope-deploy-from-tree-ssd-drift-and-migration-cpu
description: Physical PVE pair (pve1/pve2) rules: skip legs the A/B covered, wipe only the named host, FROM_TREE deploy, SSD drift confounds, migration CPU model.
metadata:
  type: feedback
tags: [compiled, pve, physical-pair, drbd, validation, destructive-ops, feedback]
---

Topic: working on the physical Proxmox pair pve1/pve2 (spare disks /dev/sdb, DRBD dual-primary, nested pairs pve9-3/4). Two are user corrections (behavior), three are traps that make results lie. All from the 2026-10-09 release work (0.90.111-0.90.115).

## User corrections

- **Do not queue a validation leg an earlier run already covered.** After 10+ VM build legs on the physical pair in one day, a further 50-minute leg was queued for the final build, although the fix was a runtime knob and two knob=1 legs had already exercised the identical code path (the final build differed only in the knob default and a log string). The user was angry. Before queuing any run, list what earlier runs (this session and prior transcripts) already exercised on the same path; run only what tests something new: the crash/takeover suite on the nested pair plus the gates scripts/release.sh actually enforces (README text check, tests/full_verify.sh STEPS=build,packages,platforms, tests/drbd_release_verify.sh, release-matrix boards). "Look at the transcripts" about testing means the assistant's own prior test runs, not the user's typed messages; launching an agent to extract user messages was the wrong reading. [[feedback-do-not-rerun-a-physical-pair-build-leg-the-ab-already-covered]]

- **A destructive disk request naming one host never extends to the other.** The user asked to wipe pve1's sdb (old OS install, inspected only there). The session wiped both hosts' sdb (wipefs -a + sgdisk --zap-all), destroying pve2's Intel RAID (isw) signature and partition table before the user had looked at it. Pair symmetry made "do both" feel implied; it was not. Wipe, format, mkfs, create-md, pvcreate and the like apply only to the named host's disk. For the symmetric host, report read-only (lsblk, wipefs -n, pvs) and ask first, even if the plan needs both. [[feedback-a-wipe-request-naming-one-hosts-disk-never-extends-to-the-other-host]]

## Traps

- **Spare SSDs (Kingston SVP100S, 2011-era SATA, no native FUA) stall ~1 s on flushes for minutes after heavy writes**, so back-to-back storage comparisons measure run order. Evidence: LVM-on-DRBD run first 7/7 builds in 1410-1635 s vs MXFS run after it 3/7 in 2730 s; vmio matrix's last run read 2-5x slower; the same MXFS test on a fresh fs read 26.9 MiB/s; a run 40 s after packer deleted VM images read 5x worse. Proof on the raw DRBD device with no filesystem (tests/pve_small_write_stall.sh, tests/pve_bio_census.py): stall fraction 69/58/47/37% across four identical passes, falling with time. The hypothesis that MXFS's 512 B register writes caused the stalls was DISPROVED by that run. Use scripts/pve_build_compare.sh (blkdiscard sdb on both hosts per leg, idle SETTLE_S, alternate legs mxfs lvm mxfs lvm so drift shows as same-storage legs disagreeing); compare p50/p90 and stall fraction, never the mean; keep the pair idle before measuring. [[trap-pve-spare-ssds-slow-for-minutes-after-heavy-writes-so-back-to-back-storage-comparisons-are-confounded]]

- **Live migration test guest needs a common CPU model and ssh, not guest-exec.** pve1 is a Xeon W3520 (Nehalem, no AES-NI/AVX), pve2 a Core i3-8100. A `cpu: host` guest completes RAM copy then the target QEMU dies ("Failed to set special registers: Invalid argument"); that is CPU mismatch, not storage/MXFS. Use `qm set <id> --cpu x86-64-v2` (default x86-64-v2-AES will not start on pve1); packer build VMs (alma9-X1/X2) are cpu: host so clones need the override. Build guests' qemu-ga refuses guest-exec; drive them over ssh as root with tools/mxfs_sshpass.sh. A writer told to stop never acknowledges a pause: the harness final check must wait for the writer's own exit marker. With these fixed, 6/6 migrations PASS data-wise, downtime 0.4-2.5 s. [[trap-pve-live-migration-test-guest-needs-a-common-cpu-model-and-ssh-not-guest-exec]]

- **PVE hosts do not mount clyde's /src, so scripts/pve_dkms_rebuild.sh exits 127** (no /src/mxfs on the physical pair 192.168.1.80/.81 or nested pair B 192.168.120.211/.212). The following `SKIP_INSTALL=1` update then silently reloads the OLD installed build (0.90.114) and reports success. Deploy a working-tree build with `FROM_TREE=1 scripts/pve_pair_update.sh` (~8 min on the physical pair; `CHECK=1` for a cold chk_mxfs), and always read back `/sys/module/mxfs/version` on both hosts. Host-built srcversion differs from clyde's (different kernel): compare the version string and the log's `installed=` srcversion. [[trap-pve-hosts-do-not-mount-clyde-src-so-dkms-rebuild-fails-use-pair-update-from-tree]]

## Common thread

Each failure was an unverified assumption carried across the pair: that a rerun adds information, that "the disk" means both disks, that a successful script run means the new build is loaded, that two timed runs on drifting hardware are comparable, that one CPU model fits both hosts.
