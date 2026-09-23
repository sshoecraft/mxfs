---
name: technique-resolve-a-guest-oops-offset-by-disassembling-the-hosts-own-vmlinuz
description: TECHNIQUE (s166): guests run the same 6.8.0-101 kernel as clyde; extract-vmlinux + sudo System.map + objdump names which BUG_ON a RIP+off hit.
metadata:
  type: feedback
tags: [oops, disassembly, debugging, rig]
---

The test VMs and clyde all run 6.8.0-101-generic, so a guest oops `RIP: func+0xOFF` can be resolved on the host without debug symbols:

1. `sudo -n /src/linux/scripts/extract-vmlinux /boot/vmlinuz-6.8.0-101-generic > <scratchpad>/vmlinux` (stripped ELF, about 65 MB).
2. `sudo -n grep ' T func$' /boot/System.map-6.8.0-101-generic` gives the unrelocated address. The file is root-only.
3. `objdump -d --start-address=0x<addr> --stop-address=0x<addr+size>` and find `addr+OFF`. It is usually a `ud2` in the cold tail; follow the branch that jumps to it.

s166: `iput+0x1c5` resolved to the `ud2` reached from `testb $0x40,0xa8(%rdi)` at iput entry, i.e. `BUG_ON(inode->i_state & I_CLEAR)`: the caller released an already-evicted inode. That one fact turned "someone dropped an extra reference" into "the object was freed under the worker".

Guest pstore was empty and netconsole carries only console-level lines, so the ring history before a guest panic is not recoverable. Plan probes that print at console level, or reproduce on demand.
