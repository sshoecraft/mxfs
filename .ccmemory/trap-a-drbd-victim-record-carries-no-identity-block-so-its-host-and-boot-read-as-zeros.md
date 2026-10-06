---
name: trap-a-drbd-victim-record-carries-no-identity-block-so-its-host-and-boot-read-as-zeros
description: TRAP (0.90.62): DRBD mounts install no identity block (gated on ctx->pr_key), so a victim's host/boot UUIDs read all-zero; never compare them as "ano…
metadata:
  type: feedback
tags: [drbd, fencing, identity, trap]
---

**What bit:** designing fence kind 27 (DRBD pair death certificate), the victim binding compared the victim's host_uuid/boot_uuid with this host's. On DRBD those fields are ALL ZERO: the pair-outage test's survivor scan printed `P-BOOT-SCAN-NOIDENT slot=0 ... ident{magic=0x0 ver=0 key=0x0 gen=0}` for BOTH victims (tests/evidence/drbd_rig/20261006T094910Z-self-outage-test/sout_kernlog.test*). `memcmp(zeros, our_host_uuid) != 0` would have read every DRBD victim as "an incarnation of another host" — including one of this host's current boot.

**Why:** `mxfs_disklock_set_identity()` is called only under `if (ctx->pr_key)` (dlm/v5_mount.c ~18480 and ~19094); a DRBD mount registers no PR key, so its heartbeat records never carry an identity block. `v5_drbd_name_victims` fills the manifest's pr_key with a derived key (`v5_drbd_victim_key`), and `mxfs_disklock_mark_recovery_pending_ident` then installs that key with zero UUIDs, so `mxfs_disklock_victim_identity()` returns TRUE with zeros.

**How to apply:**
- On DRBD, treat an all-zero host or boot UUID as "not recorded", never as a value to compare.
- The bootstrap-owner record DOES carry real owner host/boot UUIDs (v5_bootstrap_run fills `id` from mxfs_host_identity), so a takeover's `who->host_uuid` is usable.
- What binds a DRBD victim without identity: MXFS mounts via get_tree_bdev (one superblock per block device per host), so no other MXFS incarnation of the device is alive on this host while a mount runs fill_super; DRBD holds its backing device exclusively; the resource has exactly two endpoints.
