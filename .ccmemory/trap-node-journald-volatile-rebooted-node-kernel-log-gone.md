---
name: trap-node-journald-volatile-rebooted-node-kernel-log-gone
description: TRAP (sess433): test nodes' journald is VOLATILE (/run/log/journal; /var/log/journal files date from Jul 1) — a virsh-destroyed node's pre-crash kern…
metadata:
  type: feedback
---

# Node kernel logs do not survive a reboot

Measured sess433: on test1 after a virsh destroy, `journalctl --list-boots` shows boots -1/-2 from 2026-07-01 and boot 0 from the restart; `journalctl -k -b -1` for the pre-crash window returns 0 lines; `/var/log/journal/*` files have mtime Jul 1; the live journal is `/run/log/journal/.../system.journal`. So journald on the nodes is effectively volatile (Storage unset, /var journal not being written).

Rule for harnesses that power-cycle a node (lone_crash_replay, node_death_replay, tck): capture `dmesg`/journalctl on the victim INTO tests/evidence BEFORE the destroy, or derive the victim-side facts from the survivor's journal. A post-hoc `-b -1` sweep on the victim proves nothing.

Also: the dmesg ring on live nodes wraps within minutes under a board (see trap-dmesg-ring-wraps...).
