---
name: trap-virt-clone-copies-the-sources-serial-log-path-so-no-clone-starts-while-the-source-runs
description: TRAP (0.90.25): virt-clone of a rig VM keeps <log file='.../test5-serial.log'>; every clone fails to start: Cannot open log file ... busy.
metadata:
  type: feedback
tags: [lab, libvirt, clone, rig]
---

# virt-clone copies the source's serial log path

**What happened (0.90.25, growing the ubuntu2404 set to eight nodes).**
`scripts/lab_clone_node.sh test5 ubuntu2404-1 ... ubuntu2404-8` cloned and
rewrote all eight images, restarted test5, and then died at the first clone's
start:

    error: Cannot open log file: '/var/log/libvirt/qemu/test5-serial.log': Device or resource busy
    FATAL: ubuntu2404-1 did not start

The rig VMs' definitions carry `<log file='/var/log/libvirt/qemu/<name>-serial.log' append='on'/>`
under both `<serial>` and `<console>`. `virt-clone` copies the definition
verbatim apart from name, UUID, MAC and disk, so every clone named the
SOURCE's log file, which the running source holds open.

**Why it had never been seen:** the platform VMs osimager builds (pve9-*,
alma9-*, debian13-*) have a bare `<serial type='pty'>` with no log line, and
every earlier clone was of one of those.

**Fix for clones already made:** `virsh dumpxml --inactive <clone> | sed
"s#<source>-serial.log#<clone>-serial.log#g" > file; virsh define file`. The
images need nothing: identity rewrite happens before the first start.

**Rule of thumb:** after `virt-clone`, grep the clone's definition for the
source's NAME. Anything that still carries it (log files, sockets, channel
paths, nvram) is shared with the source and will either refuse to open or,
worse, be written by both.
