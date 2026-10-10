---
name: compiled-lab-rig-scheduling-clone-and-address-pin-traps
description: Lab/rig traps: DKMS install oversubscription at 8 nodes, virt-clone sharing the source's serial log path, stale lab-file addr pins.
metadata:
  type: feedback
tags: [compiled, rig, lab, libvirt, dkms, release]
---

Three traps in building and powering the multi-node lab rig, each a case of the rig's configuration silently disagreeing with the host or the resolver. The first is a scheduling error; the other two are stale or copied configuration.

## Host oversubscription: concurrent DKMS compiles
Source: [[trap-two-8-node-platform-sets-compiling-dkms-at-once-oversubscribe-clyde-and-overrun-the-install-budget]] (0.90.36).
- The packaged round's install step is a DKMS compile of the whole module on every guest. It is budgeted per guest at 45 core-minutes on a 4-vCPU guest, which is 660 s (`tests/packaged_round.sh`).
- `tests/full_verify.sh` (POWER=1) ran two platform sets per group. At 8 nodes, rhel9 and ubuntu2404 compiled together: 16 guests x 4 vCPUs = 64 vCPUs on clyde's 56 cores.
- Six of eight alma9 nodes were still in the %post DKMS build at 660 s (rc 124, `install_*.log` ends at "Running scriptlet"), and the round failed. At 4 nodes the same pairing is 32 vCPUs and installed in 426-527 s.
- Fix: one set per group at 8 nodes, `PLATFORM_GROUPS="pve9 debian13 rhel9 ubuntu2404"`.
- Do not widen INSTALL_S. The per-guest budget is right and the schedule oversubscribed the host. At any new node count, compute concurrent compile vCPUs (sets x nodes x 4) against `nproc` on clyde before choosing groups.

## virt-clone copies the source's serial log path
Source: [[trap-virt-clone-copies-the-sources-serial-log-path-so-no-clone-starts-while-the-source-runs]] (0.90.25).
- `scripts/lab_clone_node.sh test5 ubuntu2404-1 ... ubuntu2404-8` cloned the images, restarted test5, then died at the first clone's start with `Cannot open log file: '/var/log/libvirt/qemu/test5-serial.log': Device or resource busy`.
- The rig VM definitions carry `<log file='/var/log/libvirt/qemu/<name>-serial.log' append='on'/>` under both `<serial>` and `<console>`. `virt-clone` rewrites only name, UUID, MAC and disk, so every clone names the source's log file, which the running source holds open.
- It had never appeared because the osimager-built platform VMs (pve9-*, alma9-*, debian13-*) have a bare `<serial type='pty'>` with no log line, and every earlier clone was of one of those.
- Repair of clones already made: `virsh dumpxml --inactive <clone> | sed "s#<source>-serial.log#<clone>-serial.log#g" > file; virsh define file`. The images need nothing, since identity rewrite happens before first start.
- After any `virt-clone`, grep the clone's definition for the source's NAME. Anything still carrying it (log files, sockets, channel paths, nvram) is shared with the source and will either refuse to open or be written by both.

## Stale `addr` pins in the lab file
Source: [[trap-a-stale-addr-line-in-the-lab-file-fails-lab-power-up-while-ssh-by-name-still-works]] (0.90.35).
- `~/.config/mxfslab/lab*` still pinned `pve9-1=192.168.120.194 pve9-2=192.168.120.138` from the two-node era. DHCP had moved the guests to .192 and .137.
- `scripts/lab_power.sh up pve9` waits on `lab_addr <node>`, which prefers the lab file's `addr` over the resolver. It reported "NOT UP within 240 s" and exited 1, while `tools/mxfs_sshpass.sh pve9-1 ...` by name answered at once because DNS had the current address. A POWER=1 chain (`tests/full_verify.sh`, `tests/release_verify_chain.sh`) would have failed at its first platform step.
- Diagnosis when a node is "not up" but reachable by name: compare `getent hosts <node>` and `ip neigh show dev br0 | grep -i <mac from virsh domiflist>` with `lab_addr <node>`.
- An `addr` entry is needed only for a node the resolver does not know. Here alma9-* and debian13-* have no DNS names; pve9-* and ubuntu2404-* do. Delete entries the resolver covers instead of re-pinning them, because `lab_addr` falls back to `getent ahostsv4`. Leave `lab.backup` alone.
