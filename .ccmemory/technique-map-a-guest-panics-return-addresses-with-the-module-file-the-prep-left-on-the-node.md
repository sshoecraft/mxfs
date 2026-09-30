---
name: technique-map-a-guest-panics-return-addresses-with-the-module-file-the-prep-left-on-the-node
description: TECHNIQUE (0.90.29): /root/mxfs.ko.prep on a node is the build the fleet loaded; objdump -dr/-dl of it named the faulting kfree and the wrapper sleep.
metadata:
  type: feedback
tags: [panic, objdump, forensics, rig]
---

# Map a guest panic onto source with the module file the prep left behind

**Why:** the tree's `mxfs.ko` is rebuilt many times a day, so by the time a
panic is read the build that crashed is no longer in the tree.  A prep copies
the tree's module to `/root/mxfs.ko.prep` on every node, and that file stays
until the next prep.

**How (0.90.29, two defects named this way):**
1. `tools/mxfs_sshpass.sh test1 'cat /root/mxfs.ko.prep' > <scratch>/mxfs_<ver>.ko`;
   confirm with `modinfo -F srcversion` on the copy (modinfo on the node
   refuses a name that does not end in `.ko`).
2. A frame `sym+0xOFF/0xSIZE` is a RETURN address: the call is the one whose
   next instruction is at `+0xOFF`.  `objdump -dr --no-show-raw-insn
   --disassemble=<sym>` gives each call with its relocation (the real target);
   `objdump -dl` gives the source line.
3. A bare faulting address in freed module text: `.text` loads page aligned,
   so its low 12 bits equal the low 12 bits of the offset in the file.  Match
   them against the return addresses of the suspected function.
4. Unreliable (`?`) frames are stale stack words, also from earlier work items
   of the same kworker; only reliable frames order the calls.

**Results it gave:** the double free was the old merge base's `kfree` in
`mxfs_dir_sf_capture_base` (not the ring, not the read buffer); the unload
panic's address was the return from the thread wrapper's
`schedule_timeout_interruptible`.
