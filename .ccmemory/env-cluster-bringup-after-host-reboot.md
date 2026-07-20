---
name: env-cluster-bringup-after-host-reboot
description: After clyde reboot/power-loss: rebuild LIO (/dev/mxfs-shared), restore /tmp/.mxfs_pass from /home/steve/.mxfs/pass, start test1/test2 VMs.
metadata:
  type: reference
---

After a host (clyde) reboot or power loss, the 2-node TCP test cluster needs 3 host-side things restored BEFORE any SSH/run works. Symptoms if skipped: VMs won't start ("Cannot access storage file /dev/mxfs-shared"); every `tools/mxfs_sshpass.sh` call HANGS/times out (rc=124/143) — looks like a node wedge but is really a missing password file.

1. **Rebuild the shared LUN (LIO tcm_loop):** `bash /src/mxfs/scripts/lio_tcm_setup.sh setup` → creates `/dev/mxfs-shared -> /dev/sda` (50G LIO-ORG fileio on /home/steve/disk.img). `status` shows "not loaded" when gone. (TCP transport uses LIO; CAW needs SCST.) Host root is nvme0n1p2, so /dev/sda being LIO is correct.

2. **Restore the SSH password file:** `cp /home/steve/.mxfs/pass /tmp/.mxfs_pass` (7 bytes, persistent copy survives reboot; the /tmp one does NOT). EVERY test/SSH helper hard-codes `/tmp/.mxfs_pass`; sshpass with a missing file silently fails auth → command hangs. THIS was the entire "test1 SSH hangs" red herring in sess12.

3. **Start VMs:** `for n in test1 test2; do virsh -c qemu:///system start $n; done`. If a VM boots but ARP stays FAILED (no network), `virsh -c qemu:///system destroy $n && virsh ... start $n`.

`/src` on clyde is itself an NFS mount from the NAS 192.168.1.4; nodes mount the same `192.168.1.4:/src`, so a local `make modules` propagates mxfs.ko to nodes with no extra copy step. NFS_SERVER for nodes = 192.168.1.4 (NOT clyde's 192.168.1.166).

Related: [[feedback-never-background-wait-poll]] — do node readiness checks in foreground; backgrounding a wait loop makes the ccloop Stop hook fire "background still running" forever.
