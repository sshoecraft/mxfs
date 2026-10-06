---
name: trap-drbdadm-adjust-changes-ping-int-in-the-config-but-not-on-the-live-connection
description: TRAP (0.90.59): after `drbdadm adjust` set ping-int 3, drbdsetup show said 3 but the live meta socket kept 10 s; the next death test measured the old…
metadata:
  type: feedback
---

**What happened.** On the 2/net/mesh/drbd rig, `scripts/drbd_rig.sh reconfig` (writes the resource file, `drbdadm adjust`) added `ping-int 3;`. `drbdsetup show mxfs` on both nodes printed `ping-int 3;`. The self-death test that followed still detected the dead peer only at +10.8 s ("PingAck did not arrive in time"), which is one 10 s round plus the 0.5 s ping timeout: the old value.

**Why (read in /src/linux/drivers/block/drbd/drbd_receiver.c).** The meta socket's receive timeout, which is the idle interval before DRBD sends a ping, is set from `net_conf->ping_int` only when the connection is made (`msock.socket->sk->sk_rcvtimeo = nc->ping_int*HZ`, ~line 861) and again only after a PingAck arrives (`set_idle_timeout`, ~line 5875). A busy link exchanges no pings, so the old timeout stays in force for as long as I/O keeps flowing.

**Consequences for measurement.**
- A DRBD detection-time measurement right after `drbdadm adjust` measures the old ping-int. Re-establish the connection first (any fresh `drbdadm connect` / `up`, e.g. a rejoin), or let the link go idle for one old ping-int.
- Detection under traffic is up to 2 x ping-int + ping-timeout, not ping-int + ping-timeout: the first timeout is absorbed by "the data socket received something meanwhile" when the dead peer's last writes arrived after the receive began (measured 21.0 s at ping-int 10; 10.8 s when only one round was needed).
- A Proxmox host that boots and runs `drbdadm up` gets the configured value; only a live tune-up is affected.
