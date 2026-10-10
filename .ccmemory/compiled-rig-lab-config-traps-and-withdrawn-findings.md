---
name: compiled-rig-lab-config-traps-and-withdrawn-findings
description: Assorted rig/lab traps: dnsmasq.d backups break DHCP; two retired findings (iSCSI 16MB window cost, rig_groups :shared LUN) and why they were retired.
metadata:
  type: feedback
tags: [compiled, rig, dnsmasq, iscsi, scst, lun-pool, withdrawn]
---

Topic group of three rig/lab notes: one live trap (dnsmasq config) and two notes retired on 2026-10-01 whose only surviving content is a caution about how the finding was reached.

## Live trap: dnsmasq loads every file in /etc/dnsmasq.d

[[trap-a-backup-file-inside-etc-dnsmasq-d-is-loaded-as-config-and-dnsmasq-refuses-to-start]] (0.90.39)

- `cp /etc/dnsmasq.d/lab.conf /etc/dnsmasq.d/lab.conf.backup`, edit, `dnsmasq --test` OK, `systemctl restart dnsmasq` FAILED: "illegal repeated keyword at line 3 of /etc/dnsmasq.d/lab.conf.backup". conf-dir reads every file in the directory, so the backup is a second copy of the config.
- The lab DHCP/DNS was down for 7 s until the backup moved to `/etc/dnsmasq.lab.conf.backup`. `dnsmasq --test` passed beforehand; it does not reliably catch this.
- Rule: back up dnsmasq config OUTSIDE `/etc/dnsmasq.d`.
- Why the edit was needed: platform nodes debian13-1/2 and alma9-1/2 had no dhcp-host reservation. debian13-1's lease moved .153 to .152 while the lab file still said .153, so every ssh by address failed; `tools/lun_pool.sh` read no initiator name and debian13's platform round reported "no pool LUN for its verification set" twice. All four nodes are now reserved in `/etc/dnsmasq.d/lab.conf` at the addresses the lab file uses. A missing reservation shows up downstream as a LUN-pool failure, not a network one.

## Withdrawn: "16 MB iSCSI TCP window costs a third of seqW"

[[trap-the-16mb-iscsi-tcp-window-tuning-costs-a-third-of-write-throughput-on-the-scst-pool-luns]] (withdrawn 2026-10-01)

- Claimed `scripts/tune_iscsi_tcp.sh`'s 16 MB window on test1-16 cut 4-node net/mesh/direct seqW to 1150-1864 MiB/s versus about 2000 at kernel defaults, on a "quiet host".
- Wrong: every sample ran while clyde carried the user's own workloads and other rig clusters on the same NVMe. An untuned g4 run an hour later read 1018 MiB/s, inside the "tuned" range.
- The tuning's effect on throughput is unmeasured. test1-16 were reset to kernel defaults (socket caps 212992, window 524288) so the rig is uniform with test17-28; that uniformity is a separate reason to leave them there.
- Replacement lesson: trap-a-throughput-yardstick-from-an-idle-host-grades-boards-that-ran-beside-other-clusters-and-the-users-load. A throughput comparison is invalid unless host load is controlled and recorded, and "quiet host" must be verified, not asserted.

## Superseded: whole-rig run after rig_groups setup finds no shared LUN

[[trap-a-whole-rig-run-after-rig-groups-setup-finds-no-shared-lun-run-rig-sh-first]] (superseded 2026-10-01)

- `scripts/rig_groups.sh` and the `:shared` target no longer exist. `run.sh` and `tests/board_4node_chain.sh` borrow pool LUNs via `tools/lun_pool.sh`, so no rewiring step is needed before a whole-rig run. See reference-test-luns-come-from-the-pool-tools-lun-pool-sh.
- Still true: binding a node to one target logs it out of every other, so whatever bound it last decides what it sees. The pool's alloc rebinding is now the only thing that does this.
