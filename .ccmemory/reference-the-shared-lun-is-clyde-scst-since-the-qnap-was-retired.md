---
name: reference-the-shared-lun-is-clyde-scst-since-the-qnap-was-retired
description: QNAP retired 2026-09-26. Rig test1/test2 use SCST :shared (scst-fio); each platform pair has its own isolated SCST target (scripts/scst_platform_targ…
metadata:
  type: reference
---

The QNAP TS-453 Pro was retired on 2026-09-26: its NFS export of /src and its iSCSI LUN (wwn-0x6e843b…) are gone for good. Anything still naming 192.168.1.4 or the 6e843b WWID is dead.

What replaced it:
- **/src** on clyde is a bind mount of /home/steve/src (fstab), exported over NFS to 192.168.120.0/24 as `192.168.120.1:/src`. VMs mount it on demand (rig.sh / caw_preflight do the mount); none has a persistent fstab entry.
- **Rig LUN (test1/test2)**: clyde's SCST target. Bring it up with `sudo bash scripts/scst_setup.sh setup` (vdisk_fileio `mxfs` over ~/disk.img, target iqn.2026-05.local.mxfs:shared, portal 192.168.120.1 only). Do NOT use scst.service (stale /etc/scst.conf). Then `sudo -E bash scripts/rig.sh direct 2` logs test1/test2 in, and `MXFS_FORCE_PREP=1 ./run.sh 2 cawd prep_cluster` needs NO MXFS_DEV (the cawd default by-path device is this LUN). Measured: prep 62 s, mounts announce transport=CAW.
- LUN identity: wwid `eui.3265343736643037`, vendor SCST_FIO, rig tag `scst-fio` (data/rigs.json).

**Each platform pair has its OWN target (since 2026-09-26)**, so the four platforms verify in parallel with each other and with rig laps: `scripts/scst_platform_targets.sh setup|status` creates, per `pair <p>=A,B` in the lab file, ~/disk-plat-<p>.img (sparse 64G) -> vdisk_fileio mxfs<p> -> iqn.2026-05.local.mxfs:plat-<p>, LUN 0 only in ini_group `pair` with the pair's two initiator names (no default LUN, so another initiator that logs in sees no disk), a node record for that target on each pair node, and ~/.config/mxfslab/lab.<p>. Run a round with `MXFS_LAB=~/.config/mxfslab/lab.<p> [TRANSPORT=caw] tests/packaged_round.sh <p> [version]`. The default lab file's storage line is the pve9 target.
Why the isolation: run.sh's cawd iSCSI restore does discovery + a bare `iscsiadm -m node --login`, which logs test1/test2 into EVERY target; and discovery on a RHEL node records every target with startup=automatic. This SCST build has no `allowed_initiator` attribute (add_target_attribute -> EINVAL), hence ini_groups.
SCST objects are runtime-only: after a clyde reboot run scst_setup.sh setup (rig) and scst_platform_targets.sh setup again.

Trap fixed at the same time: run.sh resolved the new rig tag through tools/mxfs_rig_tag.sh, which reads the OLD marker's `rig` first, so the SCST LUN was recorded as `qnap`. run.sh now sets MXFS_RIG_TAG_FRESH=1 at prep.

SCST keeps a dead initiator's PR registration (unlike the QNAP, which purged it ~34 s after a power cut), so the absent-key fence routes that were exercised on the QNAP are not reached here by a power cut alone.
