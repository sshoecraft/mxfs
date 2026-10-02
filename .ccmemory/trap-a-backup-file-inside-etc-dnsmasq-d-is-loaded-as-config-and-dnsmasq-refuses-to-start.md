---
name: trap-a-backup-file-inside-etc-dnsmasq-d-is-loaded-as-config-and-dnsmasq-refuses-to-start
description: TRAP (0.90.39): dnsmasq loads every file in /etc/dnsmasq.d; a lab.conf.backup there duplicated keywords and the lab DHCP failed to restart. Back up o…
metadata:
  type: feedback
---

Adding DHCP reservations on clyde: `cp /etc/dnsmasq.d/lab.conf /etc/dnsmasq.d/lab.conf.backup`, then edit, `dnsmasq --test` (OK), `systemctl restart dnsmasq` → FAILED: "illegal repeated keyword at line 3 of /etc/dnsmasq.d/lab.conf.backup". conf-dir reads every file in the directory, so the backup was a second copy of the config. The lab's DHCP/DNS was down until the backup moved to /etc/dnsmasq.lab.conf.backup (7 s, 2026-10-01 20:20:58-20:21:05 CDT). `dnsmasq --test` passed because it was run before... it does not catch this reliably either.

Back up dnsmasq config OUTSIDE /etc/dnsmasq.d.

Context: platform set nodes debian13-1/2 and alma9-1/2 had no dhcp-host reservation (they were the original verification pairs). debian13-1's lease moved .153 -> .152, the lab file still said .153, and every ssh by address failed: tools/lun_pool.sh read no initiator name and debian13's platform round got "no pool LUN for its verification set" twice. All four are reserved now in /etc/dnsmasq.d/lab.conf at the addresses the lab file uses.
