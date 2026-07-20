---
name: storage-backend-is-lio-fileio-not-scst
description: CORRECTION (sess9): test cluster shared LUN /dev/sda is clyde LIO fileio over /home/steve/disk.img via virtio-scsi (single-host, coherent), NOT SCST.…
metadata:
  type: project
---

## Storage backend reality (sess9, 2026-06-15) — corrects [[project_test_cluster_scst]]

Directly inspected on test1/test2 + clyde. The 2-node dlm=tcp test cluster shared LUN is:

- **`/dev/sda`** = SCSI INQUIRY `LIO-ORG / mxfs`, transport **virtio-scsi** (`/sys/.../virtio3/host0`), NOT iSCSI. It is clyde's **LIO `fileio` backstore** named `mxfs`, backed by the file **`/home/steve/disk.img`**, exposed to both VMs via virtio-scsi from the **same single LIO instance on the one host (clyde)**.
- LIO attribs on that backstore: `emulate_write_cache=0` (write-through, no write-back cache), `emulate_fua_write=1`, `emulate_fua_read=1`, `is_nonrot=0`.
- Consequence: both VMs read/write the SAME disk.img through clyde's **single host page cache** ⇒ the **storage layer is inherently coherent across both nodes**. Cross-node read staleness is therefore an **mxfs in-core (xfs_buf / inode) cache divergence**, NOT a storage/FUA/write-cache problem.
- `mxfs.fua_disable=1` is **harmless here** — plain reads still hit the one coherent page cache. Do NOT chase FUA/SCST/write-cache coherency as the root; it's a dead end on this backend. The CLAUDE.md "LIO drops FUA / O_SYNC-zero not durable" warnings do NOT apply to this fileio+virtio config.

## SCST memory is WRONG for current env
[[project_test_cluster_scst]] says "SCST iSCSI (not LIO) — CAW works." Current reality: **no SCST at all** (no /sys/kernel/scst_tgt); clyde runs **LIO** (`target_core_mod`, `iscsi_target_mod`, configfs `/sys/kernel/config/target`). Transport for mxfs is CAW-or-TCP over the virtio LUN; the criterion under test is **dlm=tcp**.

## QNAP iSCSI disabled on test nodes (sess9, user directive)
There was a stray QNAP iSCSI disk: `/dev/sdb` = `QNAP / iSCSI Storage`, session to `192.168.1.4:3260` IQN `iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772`, was `node.startup=automatic`. It was UNUSED by the mxfs harness (harness uses `/dev/sda`) but present at boot. Per user, disabled it on test1+test2: `--logout`, deleted node + sendtargets discovery records, `systemctl disable --now open-iscsi iscsid.socket iscsid`. Verified post-reboot (virsh destroy/start): only `sda`+`vda` present, "No active sessions". Persists (changes live on /dev/vda root). If a future session needs sdb back: re-enable iscsid + rediscover 192.168.1.4.
