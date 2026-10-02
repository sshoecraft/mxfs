---
name: reference-the-shared-lun-is-clyde-scst-since-the-qnap-was-retired
description: QNAP retired 2026-09-26; /src is clyde NFS. LUN layout here is SUPERSEDED 2026-10-01 by the pool (reference-test-luns-come-from-the-pool-tools-lun-po…
metadata:
  type: reference
---

The QNAP TS-453 Pro was retired on 2026-09-26: its NFS export of /src and its iSCSI LUN (wwn-0x6e843b…) are gone for good. Anything still naming 192.168.1.4 or the 6e843b WWID is dead.

- **/src** on clyde is a bind mount of /home/steve/src (fstab), exported over NFS to 192.168.120.0/24 as `192.168.120.1:/src`. VMs mount it on demand; none has a persistent fstab entry.
- **LUNs: SUPERSEDED 2026-10-01.** The :shared (disk.img), per-group and per-platform targets and their scripts were deleted; every LUN is now borrowed from tools/lun_pool.sh. See reference-test-luns-come-from-the-pool-tools-lun-pool-sh.
- Still true: do NOT use scst.service (/etc/scst.conf was stale and is now deleted; SCST objects are runtime-only, re-create them with `tools/lun_pool.sh up` after a clyde reboot). This SCST build has no `allowed_initiator` attribute (add_target_attribute -> EINVAL), hence isolation by ini_groups with no default LUN. run.sh's iSCSI restore must log a node into its own target only: a discovery + bare login records every target, and a RHEL node logs into every discovered target at boot.
- SCST keeps a dead initiator's PR registration (unlike the QNAP, which purged it ~34 s after a power cut), so the absent-key fence routes that were exercised on the QNAP are not reached here by a power cut alone.
