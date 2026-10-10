---
name: technique-symbolize-a-hung-kvm-guests-cpu-from-the-qemu-monitor-with-the-kaslr-slide-from-idt-gate-0
description: TECHNIQUE: guest hung/panicked with no log: QEMU monitor RIP + stack, KASLR slide = IDT gate 0 handler - System.map asm_exc_divide_error; modules by…
metadata:
  type: reference
tags: [debugging, kvm, panic, kaslr, nested-pve]
---

When a rig VM (nested PVE pair) stops answering with no netconsole and kernel.sysrq too restricted for dumps:
1. `virsh domstats <dom> --vcpu --interface` twice: a vCPU whose time advances 1 s/s is spinning; rx pkts frozen = network dead.
2. `virsh qemu-monitor-command <dom> --hmp 'info registers'` a few times: RIP, RSP, RFL (IF bit), IDT base.
3. `--hmp 'x /2gx <IDT base>'`: gate 0's handler = low16 | (bits 48-63 << 16) | (high qword low32 << 32). slide = handler - System.map's asm_exc_divide_error (System.map from a healthy host on the same kernel, /boot/System.map-$(uname -r)).
4. `--hmp 'x /200gx <RSP>'` and symbolize every word in kernel text (subtract slide, bisect System.map). Words in 0xffffffffc0..: modules.
5. A module return address: copy the same build's .ko (DKMS on a sibling host; pull it as base64 over ssh), `objdump -d --disassemble=<fn>`, and match the address's low bits to the call's return offset in .text (mxfs .text on the hung host was 0xffffffffc0c00000; return c0e6b085 = .text+0x26b085 after mxfs_ioq_end_io's last call).
Used 2026-10-09: pve9-2 spun in delay_tsc under vpanic after BUG in bio_chain_endio. Then confirm with netconsole (tools/pve_netconsole.sh with PVE_PAIR_ALL listing the physical hosts first so nested ones get ports 6669/6670, PVE_NETCONSOLE_TO=192.168.120.1 PVE_NETCONSOLE_IF=br0, dmesg -n 8).
