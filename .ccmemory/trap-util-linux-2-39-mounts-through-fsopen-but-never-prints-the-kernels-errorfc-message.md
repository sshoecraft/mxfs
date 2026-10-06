---
name: trap-util-linux-2-39-mounts-through-fsopen-but-never-prints-the-kernels-errorfc-message
description: TRAP (0.90.65): Ubuntu 24.04 mount(8) (util-linux 2.39.3) uses fsopen, so errorfc text goes to the fc log, not dmesg, and 2.39 never prints it.
metadata:
  type: feedback
tags: [mount, util-linux, errorfc, rig]
---

0.90.65 sends a refused mount's reason to mount(8) with `errorfc(fc, ...)` and EPERM. On the rig (Ubuntu 24.04, util-linux 2.39.3) mount(8) printed only "permission denied. dmesg(1) may have more information", and the errorfc text was NOT in dmesg either (the refusal line appears once, from mxfs_pal_log).

**Why:** `logfc()` (fs/fs_context.c) printk's only when the context has no log (classic mount(2)); an fsopen() context stores the message for read() on the context fd. util-linux 2.39 mounts through fsopen/fsconfig but does not read those messages; 2.40+ does (PVE 9 / Debian 13 ships 2.41: its earlier output "fsconfig() failed: Transport endpoint is not connected" shows the new-API path).

**How to apply:**
- Verify any errorfc/invalfc message on a host with util-linux >= 2.40 (the nested pve9 pair), never conclude it is broken from the rig's mount(8).
- Keep the reason also in the module's own kernel-log line: on 2.39 that is the only place an operator can find it.
