---
name: env-test1-dhcp-reservation-fix-sess29
description: sess29 INFRA FIX: test1/test2 IPs are DYNAMIC dnsmasq leases (range .100-.200), NOT static. Added dhcp-host reservations so test1=.186 test2=.182 reb…
metadata:
  type: reference
---

## sess29 (ccloop 8ddb16a2) — test1 unreachable-after-reboot root cause + permanent fix

### Symptom
After `virsh destroy+start test1`, test1 booted to a `test1 login:` prompt (kernel/getty fine) but was UNREACHABLE at 192.168.120.186 (no ping, no SSH). CPU ~14s idle. test2 was fine at .182.

### Root cause
The 192.168.120.x test network's DHCP is a **system dnsmasq** (pid bound to br0:67, NOT libvirt's default net which is 192.168.122/virbr0). Config: `/etc/dnsmasq.d/lab.conf` had only a **dynamic range** `dhcp-range=192.168.120.100,192.168.120.200,3h` and **NO reservations**. test1/test2 get DYNAMIC leases; "test1=.186" was just lease affinity. This boot test1's .186 lease was lost → it got .114 → harness (hardcodes .186) couldn't reach it. test1 netplan = `dhcp4: true` (50-cloud-init.yaml).

### PERMANENT FIX (applied sess29)
Added to `/etc/dnsmasq.d/lab.conf`:
```
dhcp-host=52:54:00:80:b0:04,192.168.120.186,test1
dhcp-host=52:54:00:f5:f5:3a,192.168.120.182,test2
```
(test1 MAC 52:54:00:80:b0:04 = vnet144; test2 MAC 52:54:00:f5:f5:3a = vnet142; both on br0=192.168.120.1.) Then `systemctl restart dnsmasq`. Verified: reboot test1 → DHCP gives .186 within 8s, SSH stable 6/6. **GOTCHA: never leave a `.bak` in /etc/dnsmasq.d/** — dnsmasq loads ALL files there (only ignores .dpkg-*), so a backup copy → "illegal repeated keyword" → dnsmasq fails to start. Put backups elsewhere (/root).

### Console recovery when a node is unreachable (reusable)
Wrote `scripts/vm_console_type.py <dom> --text '...' --enter` (and `--passfile`): types into the VGA console via `virsh send-key --codeset linux`. Login: `--pre-enter --text root --enter` then `--passfile /tmp/.mxfs_pass --enter`. See state with `virsh -c qemu:///system screenshot <dom> /tmp/x.png` then Read the PNG. Serial console (`virsh console`) is SILENT on these VMs — output goes to VGA (tty1), so screenshot is the way to see the screen. Also set `UseDNS no` in sshd if SSH is slow (reverse-DNS hang vs the .1 nameserver).
