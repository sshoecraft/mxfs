---
name: trap-nothing-ever-listened-to-the-nodes-netconsole-so-every-guest-panic-was-discarded
description: TRAP (sess574): a node rebooted mid-mount with NO crash record anywhere — pstore empty, journald lost the boot, and nothing had ever listened on netc…
metadata:
  type: feedback
---

# TRAP: a guest panic on this rig left no record, because all four channels are silent by default

## What happened (sess574)

test1 rebooted while running `mount -t mxfs /dev/sda /mnt/shared`. Every place
a crash record could have been was empty:

| channel | what it said |
|---|---|
| `/sys/fs/pstore` | empty — and these guests may have **no pstore region at all**, so this can never hold anything |
| `/var/lib/systemd/pstore` | empty — systemd-pstore drained nothing at boot |
| `journalctl --list-boots` | three boots: two from **ten weeks earlier**, and the post-crash boot. The crashing boot is simply absent |
| `/var/log/libvirt/qemu/test1.log` | last entry is a `starting up` from eight hours before; **no** destroy/start near the crash |
| clyde's own `journalctl -k` | zero entries in the whole window |
| `.rig_halt` | not present |

So the only readable fact was `uptime` = "up 5 min".

## The two lessons

**1. An absent libvirt destroy/start event is a positive finding, not a
missing one.** It proves the reboot was initiated *inside* the guest — a panic
with `panic=N`, a triple fault, a guest-initiated reset — rather than by the
hypervisor or by the session. It does not tell you why.

**2. The nodes have always netconsoled to clyde and nobody was listening.**
Every node's boot log carries:

```
netpoll: netconsole: remote IPv4 address 192.168.120.1
netpoll: netconsole: remote port 6666
```

`ss -lunp | grep 6666` → nothing. Every datagram any guest has ever sent while
dying, for the entire history of this rig, was discarded by the host. A guest
panic and a guest that "just rebooted" have therefore been the *same
observation* in every session that has ever looked.

## The fix, and how to check it

`tools/netconsole_listen.sh start | stop | status | tail`. Run it whenever the
rig is doing anything that could kill a node. Documented in `docs/host-safety.md`.

Guest `console_loglevel` is **1**, so:
- ordinary probe output never reaches netconsole and the log cannot flood;
- a plain `echo x > /dev/kmsg` (level 4) will **not** appear — testing with one
  and seeing nothing is not a broken listener;
- a panic prints at `KERN_EMERG` and does arrive.

Verify end to end, because a listener that is running and receiving nothing
looks exactly like a healthy rig:

```
tools/netconsole_listen.sh start
tools/mxfs_sshpass.sh test2 "echo '<0>PROBE' > /dev/kmsg"
tools/netconsole_listen.sh tail 5
```
