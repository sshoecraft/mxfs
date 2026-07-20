---
name: infra-sshpass-wrapper-flattens-args-no-complex-scripts
description: mxfs_sshpass.sh does CMD="$*" — multi-line/quoted remote scripts get mangled (sess2: sed -i became sed -ie, emptied /etc/default/grub on 17 nodes). U…
metadata:
  type: project
---

## tools/mxfs_sshpass.sh flattens the command with CMD="$*"

Passing a multi-line or quote-heavy script as the command argument gets re-tokenized (quoting layers: local shell → wrapper `$*` join → remote login shell). ccloop46ef sess2: an embedded `sed -i "s/.../"` arrived as `sed -ie ...` (backup-suffix e) and the /etc/default/grub on 17 nodes ended up mangled/emptied (originals preserved as /etc/default/grube, mtime kept).

**Rules:**
- Remote one-liners only: single command, no embedded double quotes if avoidable.
- For anything complex: build the file/script LOCALLY, push with the wrapper's SCP mode (`mxfs_sshpass.sh <host> <pf> SCP <src> <dst>`), then ssh `bash /path/script`.
- Repair recipe used: grub.fixed built from pristine + test1's params (GRUB_CMDLINE_LINUX_DEFAULT=" log_buf_len=16M console=ttyS0,115200 loglevel=3", GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 quiet"), scp to nodes, update-grub, verify grep console=ttyS0 /boot/grub/grub.cfg, power-cycle.

## Serial capture now LIVE on ALL 32 test VMs (sess2)
- Guest: console=ttyS0,115200 log_buf_len=16M loglevel=3 (all 32 verified via /proc/cmdline).
- Host: libvirt <serial><log file='/var/log/libvirt/qemu/testN-serial.log' append='on'/> (append=on survives virsh destroy/start prep power-cycles).
- Panics now land in /var/log/libvirt/qemu/testN-serial.log on clyde. scripts/setup_serial_capture.sh re-applies (idempotent) — but its fix_guest sed path is the one that mangled files; the grub side is now correct everywhere, so future runs only need the XML/no-op path.
