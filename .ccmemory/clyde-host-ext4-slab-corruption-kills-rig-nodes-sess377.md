---
name: clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377
description: sess377: clyde HOST kernel corrupts page-cache folio->private with iSCSI IQN text (3 oopses); kills VMs permanently. VM-clone recovery works with no…
metadata:
  type: project
tags: [infra, clyde, host, corruption, rig, rule2]
---

«CLYDE HOST KERNEL MEMORY CORRUPTION — NOT MXFS (sess377, 2026-08-19)»

## What is happening

clyde (6.8.0-101-generic) has taken THREE kernel oopses, all in the ext4/jbd2
page-cache path, on its own root filesystem:

- 19:27:00 general protection fault, non-canonical 0xa82f63a300000000 [#1]
  RIP: ext4_block_write_begin+0x32e  Comm: worker (a qemu io thread)
- 20:23:53 general protection fault, non-canonical 0x2e30312d34303032 [#2]
  RIP: jbd2_journal_grab_journal_head+0x10  Comm: kswapd0
  jbd2_journal_try_to_free_buffers <- ext4_release_folio <- filemap_release_folio
  <- shrink_folio_list <- evict_folios <- kswapd
- 20:24:06 Oops: 0002 NULL deref [#3]  RIP: jbd2_journal_grab_journal_head+0x29

THE SMOKING GUN IS OOPS #2. 0x2e30312d34303032 decodes little-endian to the
ASCII bytes "2004-10." — the middle of an iSCSI IQN
(iqn.2004-10.com.ubuntu:01:testN-mxfs-node). That value was in RDI, the
struct buffer_head * handed to jbd2_journal_grab_journal_head, which came from a
page-cache folio->private. A folio's private field held IQN string bytes.

A bit-flip cannot produce coherent ASCII. This is a wild write / page
use-after-free: an ext4 page-cache folio was reused by something that stores
iSCSI initiator-name text while ext4 still referenced it. The only things on
clyde writing IQN strings are the out-of-tree iscsi_scst / scst / scst_vdisk
modules. dmesg also shows "[last unloaded: scst(OE)]".

mxfs.ko IS loaded on clyde but is NOT implicated: refcnt=0, zero mxfs mounts on
clyde, and it is an OLD build (srcversion 5793DBE9279940C501229C0, vs the tree's
25057F6813DDAF1ECB477CF). It is doing nothing.

SMART on nvme0n1: PASSED. No MCE/EDAC entries. ext4 superblock state: clean
(but needs_recovery feature set — normal).

## Why this matters to the campaign (RULE 6 pollution risk)

clyde has ONE disk. lsblk: nvme0n1 1.8T -> p1 /boot/efi, p2 ext4 /. Everything
lives on that one ext4:
  - all 32 VM qcow2 disks under /home/steve/vms/qemu/testN/testN
  - THE SHARED MXFS LUN: /sys/kernel/scst_tgt/devices/mxfs/filename =
    /home/steve/disk.img (50GB), handler vdisk_fileio, o_direct=1, nv_cache=0,
    blocksize 512, threads_num 8.

So any host-side data-integrity failure can fabricate an "MXFS corruption"
defect. sess376 filed two free-space-btree corruption shutdowns on a freshly
mkfs'd fs with no fence and no refusal — those are now SUSPECT and must be
re-derived on a healthy host before they can be treated as MXFS defects.

## The failure mode it produces on the rig

Each oops leaves unkillable D-state tasks. Two nodes were lost this way:
  - test4: qemu main thread Z, 5 worker threads stuck D in
    ext4_buffered_write_iter+0x39 (inode_lock) on its qcow2. The GPF killed the
    lock holder mid-critical-section, so the inode rwsem is held forever. The
    libvirt domain is stuck "in shutdown"; `virsh destroy test4` returns rc=124.
    The 27.9GB file /home/steve/vms/qemu/test4/test4 can never be unlinked.
  - test5: killed when run.sh's prep power-cycled it; new qemu is Z with a
    vhost_task stuck D in exit_mmap -> __mmput.

`virsh destroy` on a HEALTHY node still works instantly (verified on test5
before the wedge), so this is per-inode, not a global libvirt/qemu problem.

## RECOVERY PROCEDURE — restores a lost node WITHOUT rebooting clyde (RULE 2)

This worked twice this session. Total ~3 minutes per node.

1. The wedged libvirt domain name is unusable forever. Use a new domain name
   (testNr) with a NEW disk file; keep the ORIGINAL MAC so DHCP hands back the
   same address and DNS resolves testN to it. (Node hostnames resolve via the
   network's DNS from the DHCP hostname — clyde's /etc/hosts has NO testN
   entries. An IP change is therefore harmless, verified: test4 came back on
   .159 instead of .158 and `getent hosts test4` followed it.)

2. If the dead node's OWN disk file is still readable (test5 case), just clone
   it — identity is already correct, no editing needed:
     sudo qemu-img convert -p -T none -t none -O qcow2 \
        /home/steve/vms/qemu/test5/test5 /home/steve/vms/qemu/test5r/test5r
   Use -T none -t none (O_DIRECT both ways). A plain `cp` of 6.5GB pushed
   kswapd hard and is what tripped oopses #2 and #3. 13s with O_DIRECT.

3. If it is not readable (test4 case), clone a LIVE node and rewrite identity:
   a. `ssh testX "sync; (sleep 1; systemctl poweroff -i) &"` — note ACPI
      `virsh shutdown` is IGNORED by these guests; poweroff from inside halts
      the guest but qemu stays "running", then `virsh destroy` completes
      instantly.
   b. clone the disk, `virsh start testX` to put the donor back immediately.
   c. sudo modprobe nbd max_part=8
      sudo qemu-nbd --connect=/dev/nbd0 -f qcow2 <clone>
      -> partitions appear; root is LVM: /dev/ubuntu-vg/ubuntu-lv
      sudo mount /dev/ubuntu-vg/ubuntu-lv /mnt/t4r
   d. Rewrite:
        /etc/hostname                 -> testN
        /etc/iscsi/initiatorname.iscsi-> InitiatorName=iqn.2004-10.com.ubuntu:01:testN-mxfs-node
        truncate -s 0 /etc/machine-id ; rm -f /var/lib/dbus/machine-id
        rm -f /etc/ssh/ssh_host_* then ssh-keygen -q -t {rsa,ecdsa,ed25519} -N ''
          -f <root>/etc/ssh/ssh_host_<type>_key
      cloud-init is DISABLED on these images (/etc/cloud/cloud-init.disabled),
      so nothing re-derives the hostname on boot. /etc/hosts inside the guest is
      empty. netplan is 50-cloud-init.yaml, eth0 dhcp4:true.
   e. umount; sudo vgchange -an ubuntu-vg; sudo qemu-nbd --disconnect /dev/nbd0
   f. Copy any live node's XML (they are 674-byte hand-written files at
      /home/steve/vms/qemu/testN/testN.xml), change <name>, <source file>, and
      add the dead node's <mac address> to the bridge interface. Note the
      stock XMLs have NO explicit mac; you must add one. virsh define; virsh start.

4. Node comes up in ~20s to ping.

## Status / what a human must do

clyde needs a MANUAL reset and an fsck of nvme0n1p2, plus an investigation of
iscsi_scst. Per RULE 2 no session may do this. Until then, every corruption-
family result from the rig must be corroborated against clyde's dmesg oops
count (`sudo dmesg -T | grep -cE '\[#[0-9]+\]'` — was 3 at end of sess377)
before it is entered in the RULE 6 ledger as an MXFS defect.

Disk pressure: / was 88% full at session start, 89% after the two clones
(206G free). The 27.9GB orphan /home/steve/vms/qemu/test4/test4 is
unreclaimable without a reboot.
