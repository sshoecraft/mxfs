---
name: compiled-rig-guest-instrument-capture-and-oops-resolution
description: Rig guest capture limits (console loglevel 1, 2-min journal), identifying control builds by sha256, resolving guest oops offsets on the host
metadata:
  type: feedback
tags: [compiled, rig, netconsole, journal, oops, instrument, srcversion]
---

# Getting an instrument line or an oops out of a rig guest

Four notes share one topic: what can be recovered from a rig guest after the fact, and how to tell which build produced it.

## Capture channels are narrower than they look

- **Netconsole is panic-only.** The first reading (0.90.29) was "the console passes KERN_ERR and above", from a `pr_warn` unload instrument that appeared in node journals but not in `tests/evidence/netconsole.log`. The re-measurement (0.90.37) corrected it. About 1,000 `pr_err` probe lines across test1-14 landed in each node's `dmesg`, and `netconsole.log` held none. On test3 `/proc/sys/kernel/printk` reads `1 4 1 1`, so console loglevel is 1 and only KERN_EMERG reaches the consoles. A panic or oops still arrives because it raises the console level. See [[trap-the-rig-panic-channel-carries-kern-err-and-above-so-a-pr-warn-instrument-line-never-reaches-it]].
  - A count of 0 in the channel for any non-panic tag is a capture limit, never evidence the line was absent.
  - Before relying on the channel, confirm one known occurrence of the line is in `netconsole.log`.
  - To make a line survive a guest panic, print it at the moment of the panic, or raise the console level on the nodes for that investigation only and restore it afterwards.
- **The node journal holds about two minutes of a loaded lap.** Journals held 78-82.5K kernel lines whatever `--since` asked for, which under multi-victim load is under two minutes. Lines printed at prep (module unload, mount, join) read 0 five minutes later. The followed logs `klog_<node>.txt.gz` start at T0, after prep, so they do not hold prep-time lines either. `journalctl -b` also hides everything before a victim's restart. See [[trap-a-rig-nodes-journal-keeps-two-minutes-under-load-so-a-prep-time-line-is-gone-before-the-lap-ends]].
  - Read prep-time lines within a minute of the prep.
  - When a journal read returns 0 for a tag, print the journal's first and last epoch beside the count. A first epoch later than the event makes the zero a capture failure.
- **Superseded advice.** The journal note and the control-build note both suggest printing at `pr_err` so the panic channel keeps the line. The 0.90.37 re-measurement shows `pr_err` does not reach netconsole. Collect from `dmesg` promptly, or print at panic time. Do not trust `pr_err` to reach the channel.
- **Guest pstore was empty**, so the ring history before a guest panic is not recoverable. Plan probes that print at console level, or reproduce on demand. See [[technique-resolve-a-guest-oops-offset-by-disassembling-the-hosts-own-vmlinuz]].

## Control builds: identify by sha256 and a printed line, not srcversion

A fix that adds a safety (here, module exit stopping unjoined threads) needs a control arm: the same test on a module without it. Compile the safety out behind an `#ifdef` and build `make modules KCFLAGS=-DMXFS_TEST_NO_THREAD_REAP` (`scripts/queue_build_module.sh` takes `MXFS_KCFLAGS=`). See [[technique-a-control-build-made-with-kcflags-keeps-the-srcversion-so-name-it-by-sha256-and-a-line-it-prints]].

- modpost's srcversion hashes source text, not compiler flags. The control and fix builds of 0.90.30 had the same srcversion (`7B9190EE705E969E04D0F5C`). Prep, harnesses and the cluster marker all identify a build by srcversion, so they cannot tell the arms apart.
- Make the control build print a line only it can print (`P-THREAD-REAP-DISABLED` at each unload), record the file's sha256 beside the flags, and keep each built module under `tests/evidence/modules/`. The next build overwrites the tree's file and the next prep overwrites the node's copy, and a panic's return addresses can only be read against the file that ran.
- A KCFLAGS change rebuilds every object (28 s), so the build after the control build is a full one too.
- Queue order: control build, prep, test, rig up, fix build, prep, test. Never leave the control build as the tree's `mxfs.ko`.
- Result: control arm with two unjoined threads took down 4 of 4 nodes, 8 faults, all `mxfs-worker`, every address ending in the low 12 bits of the wrapper's sleep return in that build (objdump of the kept file).

## Resolving a guest oops offset on the host

Guests and clyde run the same 6.8.0-101-generic, so `RIP: func+0xOFF` resolves without debug symbols:

1. `sudo -n /src/linux/scripts/extract-vmlinux /boot/vmlinuz-6.8.0-101-generic > <scratchpad>/vmlinux` (stripped ELF, about 65 MB).
2. `sudo -n grep ' T func$' /boot/System.map-6.8.0-101-generic` for the unrelocated address (the map is root-only).
3. `objdump -d --start-address=... --stop-address=...` and find `addr+OFF`, usually a `ud2` in the cold tail. Follow the branch that jumps to it.

Example: `iput+0x1c5` was `BUG_ON(inode->i_state & I_CLEAR)`, meaning the caller released an already-evicted inode, i.e. the object was freed under the worker. See [[technique-resolve-a-guest-oops-offset-by-disassembling-the-hosts-own-vmlinuz]].
