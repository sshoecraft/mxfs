---
name: trap-a-slot-record-advancing-under-a-torn-down-fleet-is-a-foreign-host-with-a-stale-fstab-mount-on-the-shared-lun
description: TRAP (s62e→s67): the "node from the previous lap still heartbeating" behind the mkfs verify FAIL was serv (192.168.1.5), a lab host whose fstab mount…
metadata:
  type: feedback
tags: [rig, qnap, foreign-writer, prep, disklock, serv]
---

# A slot record that keeps advancing while every fleet node is torn down is a foreign host

## What happened
- s62e: `mkfs_mxfs` zero_region verify read 0x4b ('K' of MXLK) at the slot 2 sector and blamed the storage. s65/s66 attributed it to "a node from the previous lap still mounted" and closed the prep-ordering hole with a guard in `tests/setup/prep_fs.sh` (two platter dumps 3 s apart; refuse if any record's stamp advances).
- s67a: the guard fired on the very first fleet prep — `FS_PREP_FAIL: a node is still heartbeating into /dev/sda ... slot 2 node 1216714748 ts_ms 136074964->136078996` — with BOTH rig VMs torn down (mxfs unloaded, nothing mounted, uptime 16 min). The attribution to "a previous-lap node" had been an inference, never a measurement.

## How it was pinned
1. `ts_ms` on the record is `mxfs_pal_time_ms()` = `ktime_get_boottime_ns()/1e6` of the WRITER (`dlm/disklock.c` claim/heartbeat sites, `pal/linux/kern.c:2970`). 136,190,000 ms = 37.8 h: neither VM (16 min), so a kernel mxfs module on some other host up ~38 h.
2. `fs_gen=0 epoch=0 pr_key=0 boot=0 ident_magic=0` = a build older than the identity/provenance fields. The rig nodes silently skip such records (`hb_gen_foreign`: "pre-mkfs ghost"), so nothing in their journals names it.
3. The LUN is the QNAP iSCSI target (192.168.1.4, `iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772`, wwid in `data/rigs.json`); any LAN host logged into that target can write it. A scratch WE-AR reservation from test1 (`sg_persist --out --reserve --prout-type=8`) FROZE the stamp for 6 s and the clear released it: the QNAP enforces the reservation, so the foreign writer lands only in unreserved windows — which is exactly when mkfs runs (prep 3b clears PR first).
4. A ping sweep of 192.168.1.0/24 + `tools/mxfs_sshpass.sh <ip> "cut -d. -f1 /proc/uptime; lsmod|grep mxfs; grep mxfs /proc/mounts; iscsiadm -m session"` on every ssh-open host found **serv.localdomain 192.168.1.5** (reverse DNS says "unifi"): uptime 136597 s, Debian 5.10.0-45 with `/lib/modules/.../updates/dkms/mxfs.ko` (the physrig-era DKMS package), `/dev/sdb /mnt/shared mxfs dlm_transport=tcp` from `/etc/fstab` (`_netdev`), mounted 2026-09-17T18:46 CDT at boot, 48,027 mxfs kernel lines since, `heartbeat write failed: -52` (EBADE) bursts exactly in the cluster's reservation windows.
5. Fix applied on serv (s67): `umount /mnt/shared` (rc 0), `rmmod mxfs`, fstab line commented with a dated note, backup at `/etc/fstab.mxfs-disabled-2026-09-19`. Evidence: `tests/evidence/20260919T134608Z_foreign_writer_serv_s67/`.

## Lessons
- A stamp that advances under a torn-down fleet is NEVER "a node from the previous lap"; read the clock (boottime of the writer) and the identity fields, then sweep the LAN for the host. `tools/mxfs_whohas.sh` (new, s67) finds local holders of a file/device without the fuser/lsof mmap_lock walk.
- A foreign-generation ACTIVE record is invisible in the rig nodes' journals by design (`hb_gen_foreign` skips it with no log line) and `mxfs_disklock_claim_slot` treats it as CLAIMABLE with no liveness test — a live legacy writer sharing the LUN is a slot-collision hazard the module cannot see (filed s67).
- The QNAP LUN outlives every rig: a host provisioned during the physical campaign (pve1/pve2, serv) keeps its fstab/DKMS module and re-mounts at every boot. After any lab power event, dump the heartbeat table under a torn-down fleet before trusting a prep.
- `journalctl` over serv's full journal (since April) hung a 60 s ssh; use `journalctl -k -b` / `-u <unit>` with `timeout`.
