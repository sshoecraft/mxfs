---
name: trap-a-guest-console-timestamp-counts-from-its-last-reboot-so-place-it-by-intervals-not-by-creation-time
description: TRAP (0.90.58): VM 104's I/O errors at guest t=925 s were placed at 22:39 from VM creation; the VM had rebooted after install. Match intervals to hos…
metadata:
  type: feedback
---

**What happened:** a guest on MXFS-on-DRBD (physical PVE pair) showed `I/O error, dev vda` at guest kernel
time 925.449 s, then write failures at 928.461, 933.581, 939.213, 941.773 and an XFS shutdown.  A session placed
those at ~22:39 host time by adding 925 s to the VM's creation, found pve1's emulated compare-and-swap waiting on
the peer's ticket at 22:39:13/15, and built a whole load/lock-give-up hypothesis (plus a defect title, a rig
harness and an instrument plan) around that coincidence.

The console screenshot showed `alma9-5 login:` — the installer had finished and the VM had REBOOTED, so guest time
counted from that reboot.  The real failures were pve1's `P-RBLK-COVERS-DEAD-MASTER ino=138` refusals at
23:01:01.97, 04.98, 10.10, 15.74, 18.30 — intervals +3.01, +5.12, +5.63, +2.56 s, identical to the guest's to 10 ms —
four minutes after the peer died and the survivor's recovery was blocked.

**How to apply:**
- Never convert a guest console timestamp to host time from when the VM was created or started.  A guest's
  `[ t ]` is uptime since ITS last boot, and live migration keeps it.
- Instead match the SHAPE: the gaps between the guest's error batches against the gaps between candidate host
  lines (refusal probes, DRBD events) — a burst of N lines then +a, +b, +c s is a fingerprint.
- Map the image to its inode first (`stat -c %i` on the image path) so the host lines can be filtered by `ino=`.
- A coincidence in time with a "waiting" line (CAS waits, retries) is not a cause until an interval match or a
  returned error code ties them.
