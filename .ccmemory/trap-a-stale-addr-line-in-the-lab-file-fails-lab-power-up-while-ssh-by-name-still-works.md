---
name: trap-a-stale-addr-line-in-the-lab-file-fails-lab-power-up-while-ssh-by-name-still-works
description: TRAP (0.90.35): lab files pinned pve9-1/2 to .194/.138; DHCP moved them to .192/.137. lab_power up said NOT UP in 240 s while ssh by name worked.
metadata:
  type: feedback
---

`~/.config/mxfslab/lab*` carried `addr pve9-1=192.168.120.194 pve9-2=192.168.120.138` (from the two-node era). The guests' leases had moved to .192 and .137. `scripts/lab_power.sh up pve9` waits on `lab_addr <node>`, which prefers the lab file's `addr` over the resolver, so pve9-1 and pve9-2 were reported "NOT UP within 240 s" and the call exited 1. Meanwhile `tools/mxfs_sshpass.sh pve9-1 ...` by NAME answered at once, because DNS (`pve9-1.vm.localdomain`) had the current address. A power-managed chain (`tests/full_verify.sh POWER=1`, `tests/release_verify_chain.sh POWER=1`) would have failed at its first platform step.

**How to apply:** when a lab node is "not up" but reachable by name, compare `getent hosts <node>` and `ip neigh show dev br0 | grep -i <mac from virsh domiflist>` with `lab_addr <node>`. An `addr` entry is only needed for a node the resolver does not know: alma9-* and debian13-* have no DNS names here, pve9-* and ubuntu2404-* do. Drop entries the resolver covers rather than re-pinning them (lab_addr falls back to getent ahostsv4). Leave `lab.backup` alone.
