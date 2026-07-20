# MXFS Comprehensive Test Plan

## Overview

This document defines the complete test plan for MXFS — a portable clustered filesystem
that reads/writes XFS on-disk structures directly via libmxfs, with DLM-aware caching at
every layer. Tests cover build verification, single-node correctness, multi-node clustering,
fault tolerance, performance, stress, multi-OS compatibility, operations, and security.

MXFS_MAX_NODES = 64. All subsystems use static arrays sized to this limit.
Default ports: DLM TCP 7600, Discovery UDP 7601.
Discovery: UDP multicast 239.66.83.1 or broadcast.

---

## VM Configuration Matrix

### 1 VM — Single-node correctness

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 1 | 5.10 | Existing baseline node |

### 2 VMs — Basic cluster

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 1 | 5.10 | Low end of compat range |
| Ubuntu 24.04 | 1 | 6.8 | High end of compat range |

### 4 VMs — Core cluster

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 1 | 5.10 | Baseline |
| Debian 12 | 1 | 6.1 | LTS, bdev API change |
| Ubuntu 24.04 | 1 | 6.8 | Latest compat target |
| RHEL 9.7 | 1 | 5.14 | Enterprise ecosystem |

### 8 VMs — Extended cluster

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 2 | 5.10 | Baseline pair |
| Debian 12 | 1 | 6.1 | Mid-range LTS |
| Ubuntu 24.04 | 1 | 6.8 | High end |
| RHEL 9.7 | 1 | 5.14 | Red Hat |
| Alma 9.7 | 1 | 5.14 | RHEL rebuild |
| SLES 15.6 | 1 | 5.14 | SUSE enterprise |
| Ubuntu 22.04 | 1 | 5.15 | Another 5.x data point |

### 16 VMs — Full scale

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 3 | 5.10 | Baseline block |
| Debian 12 | 3 | 6.1 | 6.1 block |
| Ubuntu 24.04 | 2 | 6.8 | High-end pair |
| RHEL 9.7 | 2 | 5.14 | Enterprise pair |
| Alma 9.7 | 2 | 5.14 | RHEL rebuild pair |
| SLES 15.6 | 1 | 5.14 | SUSE |
| Ubuntu 22.04 | 1 | 5.15 | Mid-range |
| Rocky 9.7 | 1 | 5.14 | Third RHEL variant |
| Debian 13 | 1 | 6.12+ | Forward compat canary |

### 32 VMs — Maximum scale

| OS | Count | Kernel | Notes |
|----|-------|--------|-------|
| Debian 11 | 5 | 5.10 | Baseline block |
| Debian 12 | 5 | 6.1 | 6.1 block |
| Ubuntu 24.04 | 4 | 6.8 | High-end block |
| RHEL 9.7 | 4 | 5.14 | Enterprise block |
| Alma 9.7 | 3 | 5.14 | RHEL rebuild |
| SLES 15.6 | 2 | 5.14 | SUSE |
| Ubuntu 22.04 | 2 | 5.15 | Mid-range |
| Rocky 9.7 | 2 | 5.14 | RHEL variant |
| Debian 13 | 2 | 6.12+ | Forward compat |
| Alma 10.1 | 2 | 6.x | Latest Alma |
| OEL 9.7 | 1 | 5.14 (UEK) | Oracle UEK kernel |

---

## Test Infrastructure Requirements

**Shared storage**: iSCSI LUN on local dev machine (192.168.120.1, NVMe-backed), 50GB, XFS formatted.
All nodes must have iSCSI initiator configured and sessions active.

**Network**: All nodes on 192.168.120.0/24 subnet. UDP multicast must work across all nodes.

**Per-node requirements**:
- Kernel headers installed for the running kernel
- gcc, make, standard build tools
- iSCSI initiator (open-iscsi)
- fio, bonnie++, xfstests-dev (for performance/stress phases)
- /etc/mxfs/node.uuid (unique per node, 16-byte UUID)

**Deploy**: tools/mxfs_deploy.sh copies source and builds on each node.
SSH: tools/mxfs_ssh.exp with password from /tmp/.mxfs_pass.

**ESXi management**: Direct via SSH to 192.168.1.251, using vim-cmd and esxcli.

---

## PHASE 1: Build & Load Verification

### T-01-01: Compile on Debian 11 (kernel 5.10)

**Description**: Verify mxfs.ko compiles with zero warnings on 5.10 headers.
**Prerequisites**: Debian 11 node with kernel headers installed.
**Steps**:
1. `scp -r /home/steve/src/mxfs root@192.168.120.201:/root/`
2. `ssh root@192.168.120.201 "cd /root/mxfs && make kernel 2>&1"`
**Expected result**: Build succeeds, zero warnings, mxfs.ko produced.
**Failure indicators**: Compiler errors, undefined symbols, missing headers.
**Scale**: 1 VM.

### T-01-02: Compile on Debian 12 (kernel 6.1)

**Description**: Verify compilation on 6.1 — tests bdev API compat ifdefs.
**Prerequisites**: Debian 12 node with kernel headers.
**Steps**: Same as T-01-01 on Debian 12 node.
**Expected result**: Clean build.
**Failure indicators**: bdev_open_by_path / blkdev_get_by_path ifdef failures.
**Scale**: 4+ VMs.

### T-01-03: Compile on Ubuntu 24.04 (kernel 6.8)

**Description**: Verify compilation on 6.8 — tests mnt_idmap, latest bdev API.
**Prerequisites**: Ubuntu 24.04 node with linux-headers-$(uname -r).
**Steps**: Same as T-01-01 on Ubuntu node.
**Expected result**: Clean build.
**Failure indicators**: mnt_idmap compat, inode timestamp helpers.
**Scale**: 2+ VMs.

### T-01-04: Compile on RHEL 9.7 (kernel 5.14)

**Description**: Verify compilation on RHEL kernel with different kconfig.
**Prerequisites**: RHEL 9.7 node with kernel-devel installed.
**Steps**: Same as T-01-01 on RHEL node.
**Expected result**: Clean build.
**Failure indicators**: RHEL-specific kernel config missing symbols.
**Scale**: 4+ VMs.

### T-01-05: Compile on SLES 15.6 (kernel 5.14)

**Description**: Verify on SUSE with their kernel patches.
**Steps**: Same pattern, SLES node.
**Expected result**: Clean build.
**Scale**: 8+ VMs.

### T-01-06: Compile on Debian 13 (kernel 6.12+)

**Description**: Forward compatibility — kernel beyond our tested range.
**Steps**: Same pattern, Debian 13 node.
**Expected result**: Clean build or identified compat issues to fix.
**Scale**: 16+ VMs.

### T-01-07: Module load/unload cycle

**Description**: Load and unload mxfs.ko without crash or leak.
**Prerequisites**: Module compiled on target node.
**Steps**:
1. `insmod /root/mxfs/kernel/mxfs.ko`
2. `lsmod | grep mxfs`
3. `dmesg | tail -20`
4. `rmmod mxfs`
5. `dmesg | tail -10`
**Expected result**: Module loads, shows in lsmod, unloads cleanly. dmesg shows init/exit messages. No oops, no warnings.
**Failure indicators**: kernel oops, hung task, unable to unload.
**Scale**: All.

### T-01-08: Module info

**Description**: Verify module metadata is correct.
**Steps**:
1. `modinfo /root/mxfs/kernel/mxfs.ko`
**Expected result**: Shows description, author, license (GPL), version.
**Scale**: All.

### T-01-09: Repeated load/unload (50 cycles)

**Description**: Stress module init/exit for memory leaks.
**Steps**:
1. `for i in $(seq 1 50); do insmod /root/mxfs/kernel/mxfs.ko && rmmod mxfs; done`
2. `dmesg | grep -i "leak\|oops\|bug\|warning"`
3. Check /proc/meminfo for unexpected growth
**Expected result**: All 50 cycles complete, no leaks, no warnings.
**Failure indicators**: Increasing slab usage, kernel warnings.
**Scale**: All.

### T-01-10: Negative test — RHEL 8 (kernel 4.18) fails gracefully

**Description**: Kernel 4.18 is below our 5.10 compat floor.
**Steps**: Attempt build on RHEL 8 / CentOS 8 node.
**Expected result**: Compile error with clear message (missing API), not a silent miscompile.
**Scale**: N/A (one-off verification).

---

## PHASE 2: Single-Node Correctness

### T-02-01: Basic mount/unmount

**Description**: mkfs.xfs and mount -t mxfs on a single node.
**Prerequisites**: /dev/sdb available, module loaded.
**Steps**:
1. `mkfs.xfs -f /dev/sdb`
2. `mkdir -p /mnt/shared`
3. `mount -t mxfs /dev/sdb /mnt/shared`
4. `mount | grep mxfs`
5. `df -h /mnt/shared`
6. `umount /mnt/shared`
7. `dmesg | tail -30`
**Expected result**: Mount succeeds, df shows correct size (10GB), umount clean. dmesg shows subsystem init/shutdown messages.
**Failure indicators**: mount returns error, kernel oops, hung umount.
**Scale**: 1 VM.

### T-02-02: File create/read/write/stat/unlink

**Description**: Basic file lifecycle.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `echo "hello mxfs" > /mnt/shared/testfile`
3. `cat /mnt/shared/testfile`
4. `stat /mnt/shared/testfile`
5. `ls -la /mnt/shared/testfile`
6. `rm /mnt/shared/testfile`
7. `ls /mnt/shared/testfile 2>&1`
8. `umount /mnt/shared`
**Expected result**: File created, content reads back correctly, stat shows size=11, unlink removes file, ls after unlink shows "No such file".
**Failure indicators**: Wrong content, wrong size, unlink fails, stale entries.
**Scale**: 1 VM.

### T-02-03: Large file write/read

**Description**: Write and verify a 1GB file.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `dd if=/dev/urandom of=/mnt/shared/largefile bs=1M count=1024`
3. `md5sum /mnt/shared/largefile > /tmp/md5.txt`
4. `sync`
5. `echo 3 > /proc/sys/vm/drop_caches`
6. `md5sum /mnt/shared/largefile | diff - /tmp/md5.txt`
7. `ls -la /mnt/shared/largefile`
8. `rm /mnt/shared/largefile`
9. `umount /mnt/shared`
**Expected result**: dd completes, md5sum matches after cache drop, size is 1073741824.
**Failure indicators**: md5 mismatch (data corruption), dd fails mid-write, ENOSPC on 10GB device.
**Scale**: 1 VM.

### T-02-04: Directory operations

**Description**: mkdir, rmdir, nested directories, readdir.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `mkdir -p /mnt/shared/a/b/c/d/e`
3. `ls -la /mnt/shared/a/b/c/d/`
4. `touch /mnt/shared/a/b/c/d/e/file1`
5. `ls -laR /mnt/shared/a/`
6. `rm /mnt/shared/a/b/c/d/e/file1`
7. `rmdir /mnt/shared/a/b/c/d/e /mnt/shared/a/b/c/d /mnt/shared/a/b/c /mnt/shared/a/b /mnt/shared/a`
8. `ls /mnt/shared/`
9. `umount /mnt/shared`
**Expected result**: Nested dirs created, files listed correctly, cleanup succeeds.
**Failure indicators**: EEXIST on mkdir, ENOTEMPTY on rmdir, missing entries in readdir.
**Scale**: 1 VM.

### T-02-05: Many files — directory format transitions

**Description**: Create enough files to trigger all 4 XFS directory formats (shortform → block → leaf → node).
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `mkdir /mnt/shared/manyfiles`
3. `for i in $(seq 1 100000); do touch /mnt/shared/manyfiles/file_$i; done`
4. `ls /mnt/shared/manyfiles/ | wc -l`
5. `ls /mnt/shared/manyfiles/file_50000`
6. `rm -rf /mnt/shared/manyfiles`
7. `umount /mnt/shared`
**Expected result**: 100,000 files created, count is 100000, lookup of specific file works, removal succeeds.
Transitions: ~3 entries = shortform, ~10+ = block, ~100+ = leaf, ~10000+ = node/btree.
**Failure indicators**: Hang during creation (dir format transition bug), missing files in listing, ENOSPC.
**Scale**: 1 VM.

### T-02-06: Symlinks

**Description**: Create and read symbolic links.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `echo "target content" > /mnt/shared/realfile`
3. `ln -s realfile /mnt/shared/symlink`
4. `readlink /mnt/shared/symlink`
5. `cat /mnt/shared/symlink`
6. `ls -la /mnt/shared/symlink`
7. `rm /mnt/shared/symlink /mnt/shared/realfile`
8. `umount /mnt/shared`
**Expected result**: readlink returns "realfile", cat shows "target content", ls shows l permission type.
**Failure indicators**: readlink returns wrong target, dangling link not followed correctly.
**Scale**: 1 VM.

### T-02-07: Hard links

**Description**: Create hard links, verify nlink count, unlink behavior.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `echo "hardlink test" > /mnt/shared/original`
3. `ln /mnt/shared/original /mnt/shared/link1`
4. `ln /mnt/shared/original /mnt/shared/link2`
5. `stat /mnt/shared/original | grep Links`
6. `cat /mnt/shared/link1`
7. `rm /mnt/shared/original`
8. `cat /mnt/shared/link1`
9. `stat /mnt/shared/link1 | grep Links`
10. `rm /mnt/shared/link1 /mnt/shared/link2`
11. `umount /mnt/shared`
**Expected result**: nlink=3 after two links, content identical, removing original doesn't affect link1, nlink drops to 2 then 1.
**Failure indicators**: Wrong nlink count, data lost after unlinking original.
**Scale**: 1 VM.

### T-02-08: Rename — same directory

**Description**: Rename file within same directory.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `echo "rename test" > /mnt/shared/before`
3. `mv /mnt/shared/before /mnt/shared/after`
4. `cat /mnt/shared/after`
5. `ls /mnt/shared/before 2>&1`
6. `rm /mnt/shared/after`
7. `umount /mnt/shared`
**Expected result**: File renamed, content preserved, old name gone.
**Scale**: 1 VM.

### T-02-09: Rename — cross directory

**Description**: Move file between directories.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `mkdir /mnt/shared/dir1 /mnt/shared/dir2`
3. `echo "cross-dir" > /mnt/shared/dir1/file`
4. `mv /mnt/shared/dir1/file /mnt/shared/dir2/file`
5. `cat /mnt/shared/dir2/file`
6. `ls /mnt/shared/dir1/`
7. `rm -rf /mnt/shared/dir1 /mnt/shared/dir2`
8. `umount /mnt/shared`
**Expected result**: File appears in dir2, gone from dir1, content correct.
**Scale**: 1 VM.

### T-02-10: Permissions — chmod/chown

**Description**: Set and verify permission bits and ownership.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `touch /mnt/shared/permtest`
3. `chmod 0750 /mnt/shared/permtest`
4. `stat -c "%a" /mnt/shared/permtest`
5. `chown 1000:1000 /mnt/shared/permtest`
6. `stat -c "%u:%g" /mnt/shared/permtest`
7. `chmod 0000 /mnt/shared/permtest`
8. `cat /mnt/shared/permtest 2>&1` (as non-root, expect EACCES)
9. `rm /mnt/shared/permtest`
10. `umount /mnt/shared`
**Expected result**: chmod sets 750, chown sets 1000:1000, mode 0000 blocks read.
**Scale**: 1 VM.

### T-02-11: Sparse files

**Description**: Create a sparse file with holes, verify size vs blocks.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `dd if=/dev/zero of=/mnt/shared/sparse bs=1 count=1 seek=1073741823`
3. `ls -la /mnt/shared/sparse`
4. `du -h /mnt/shared/sparse`
5. `stat /mnt/shared/sparse`
6. `rm /mnt/shared/sparse`
7. `umount /mnt/shared`
**Expected result**: ls shows size ~1GB, du shows much less (only one block allocated). stat blocks << size/512.
**Failure indicators**: Full 1GB allocated (no sparse support), or read of hole returns non-zero.
**Scale**: 1 VM.

### T-02-12: Long filenames (255 bytes)

**Description**: Test maximum filename length.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `LONG=$(python3 -c "print('x'*255)")`
3. `touch "/mnt/shared/$LONG"`
4. `ls /mnt/shared/ | wc -c`
5. `rm "/mnt/shared/$LONG"`
6. `TOOLONG=$(python3 -c "print('x'*256)")`
7. `touch "/mnt/shared/$TOOLONG" 2>&1`
8. `umount /mnt/shared`
**Expected result**: 255-byte name succeeds, 256-byte returns ENAMETOOLONG.
**Scale**: 1 VM.

### T-02-13: Special characters in filenames

**Description**: Test filenames with spaces, unicode, special chars.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `touch "/mnt/shared/file with spaces"`
3. `touch "/mnt/shared/file-with-dashes"`
4. `touch "/mnt/shared/file.with.dots"`
5. `touch "/mnt/shared/UPPERCASE"`
6. `ls -la /mnt/shared/`
7. `rm "/mnt/shared/file with spaces" "/mnt/shared/file-with-dashes" "/mnt/shared/file.with.dots" "/mnt/shared/UPPERCASE"`
8. `umount /mnt/shared`
**Expected result**: All files created and listed correctly.
**Scale**: 1 VM.

### T-02-14: Truncate

**Description**: Truncate file to smaller and larger sizes.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `dd if=/dev/urandom of=/mnt/shared/trunc bs=1M count=10`
3. `truncate -s 5M /mnt/shared/trunc`
4. `stat -c "%s" /mnt/shared/trunc`
5. `truncate -s 20M /mnt/shared/trunc`
6. `stat -c "%s" /mnt/shared/trunc`
7. `truncate -s 0 /mnt/shared/trunc`
8. `stat -c "%s" /mnt/shared/trunc`
9. `rm /mnt/shared/trunc`
10. `umount /mnt/shared`
**Expected result**: Sizes are 5242880, 20971520, 0.
**Scale**: 1 VM.

### T-02-15: fsync

**Description**: Verify fsync commits data to disk.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `python3 -c "
import os
fd = os.open('/mnt/shared/fsync_test', os.O_WRONLY|os.O_CREAT|os.O_TRUNC)
os.write(fd, b'fsync data here')
os.fsync(fd)
os.close(fd)
"`
3. `cat /mnt/shared/fsync_test`
4. `rm /mnt/shared/fsync_test`
5. `umount /mnt/shared`
**Expected result**: Content reads back correctly after fsync.
**Scale**: 1 VM.

### T-02-16: statfs accuracy

**Description**: Verify df reports correct total/free space and inode counts.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `df -h /mnt/shared`
3. `df -i /mnt/shared`
4. `dd if=/dev/zero of=/mnt/shared/filltest bs=1M count=500`
5. `df -h /mnt/shared`
6. `rm /mnt/shared/filltest`
7. `df -h /mnt/shared`
8. `umount /mnt/shared`
**Expected result**: Total ~10GB, free decreases by ~500MB after dd, returns after rm.
**Failure indicators**: Total shows 0, free doesn't change, inode count wrong.
**Scale**: 1 VM.

### T-02-17: Append mode

**Description**: Multiple appends to same file, verify all data present.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `echo "line1" >> /mnt/shared/appendfile`
3. `echo "line2" >> /mnt/shared/appendfile`
4. `echo "line3" >> /mnt/shared/appendfile`
5. `wc -l /mnt/shared/appendfile`
6. `cat /mnt/shared/appendfile`
7. `rm /mnt/shared/appendfile`
8. `umount /mnt/shared`
**Expected result**: 3 lines, content is "line1\nline2\nline3\n".
**Scale**: 1 VM.

### T-02-18: Standard tools — cp, tar, rsync

**Description**: Verify standard POSIX tools work correctly.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `cp /etc/passwd /mnt/shared/passwd_copy`
3. `diff /etc/passwd /mnt/shared/passwd_copy`
4. `tar czf /mnt/shared/etc.tar.gz /etc/hostname /etc/fstab`
5. `tar tzf /mnt/shared/etc.tar.gz`
6. `mkdir /mnt/shared/rsync_dest`
7. `rsync -a /etc/cron.d/ /mnt/shared/rsync_dest/`
8. `ls /mnt/shared/rsync_dest/`
9. `rm -rf /mnt/shared/passwd_copy /mnt/shared/etc.tar.gz /mnt/shared/rsync_dest`
10. `umount /mnt/shared`
**Expected result**: cp produces identical copy, tar creates and lists, rsync copies.
**Scale**: 1 VM.

### T-02-19: Concurrent local processes

**Description**: Multiple processes doing I/O simultaneously on same node.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. Run 4 parallel dd processes to different files:
```
for i in 1 2 3 4; do
  dd if=/dev/urandom of=/mnt/shared/concurrent_$i bs=1M count=100 &
done
wait
```
3. `ls -la /mnt/shared/concurrent_*`
4. `md5sum /mnt/shared/concurrent_*`
5. `rm /mnt/shared/concurrent_*`
6. `umount /mnt/shared`
**Expected result**: All 4 files created, each 100MB, no corruption.
**Failure indicators**: Hang, kernel oops, file size wrong, mixed content.
**Scale**: 1 VM.

### T-02-20: Timestamps — atime/mtime/ctime

**Description**: Verify timestamp updates on file operations.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `touch /mnt/shared/tsfile`
3. `stat /mnt/shared/tsfile` (note mtime/ctime)
4. `sleep 2`
5. `echo "data" >> /mnt/shared/tsfile`
6. `stat /mnt/shared/tsfile` (mtime/ctime should have changed)
7. `sleep 2`
8. `chmod 0700 /mnt/shared/tsfile`
9. `stat /mnt/shared/tsfile` (ctime should have changed, mtime unchanged)
10. `rm /mnt/shared/tsfile`
11. `umount /mnt/shared`
**Expected result**: mtime updates on write, ctime updates on write and chmod, atime updates on read.
**Scale**: 1 VM.

### T-02-21: Deep directory nesting

**Description**: Create deeply nested directory tree (100+ levels).
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `python3 -c "
import os
path = '/mnt/shared'
for i in range(120):
    path = os.path.join(path, 'd')
    os.makedirs(path, exist_ok=True)
with open(os.path.join(path, 'deepfile'), 'w') as f:
    f.write('deep')
"`
3. `find /mnt/shared -name deepfile`
4. `rm -rf /mnt/shared/d`
5. `umount /mnt/shared`
**Expected result**: 120-deep dir tree created, file found at bottom, cleanup succeeds.
**Failure indicators**: ENAMETOOLONG (path too long), hang on deep recursion.
**Scale**: 1 VM.

### T-02-22: Empty file and zero-length I/O

**Description**: Edge cases with empty files.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `touch /mnt/shared/empty`
3. `stat -c "%s" /mnt/shared/empty`
4. `cat /mnt/shared/empty | wc -c`
5. `dd if=/dev/zero of=/mnt/shared/empty bs=1 count=0`
6. `stat -c "%s" /mnt/shared/empty`
7. `rm /mnt/shared/empty`
8. `umount /mnt/shared`
**Expected result**: Size is 0, cat outputs 0 bytes.
**Scale**: 1 VM.

---

## PHASE 3: Two-Node Cluster Correctness

### T-03-01: Simultaneous mount

**Description**: Two nodes mount the same device concurrently.
**Prerequisites**: Both nodes have iSCSI session to /dev/sdb, XFS formatted, module loaded.
**Steps**:
1. Node A: `mount -t mxfs /dev/sdb /mnt/shared`
2. Node B: `mount -t mxfs /dev/sdb /mnt/shared`
3. Both: `mount | grep mxfs`
4. Both: `dmesg | tail -30`
**Expected result**: Both mounts succeed. dmesg on each shows discovery found the other node, TCP peer connected, leases active.
**Failure indicators**: Mount hangs, discovery doesn't find peer, TCP connection fails.
**Scale**: 2 VMs.

### T-03-02: Discovery verification

**Description**: Verify UDP multicast discovery finds both nodes.
**Steps**:
1. Both nodes mounted.
2. `dmesg | grep -i "discovery.*found\|peer.*connect"`
3. Check that each node's dmesg shows the other node's IP and node_id.
**Expected result**: Each node logged discovering the other. TCP connection established.
**Failure indicators**: "no peers found", multicast not received.
**Scale**: 2 VMs.

### T-03-03: Cross-node file visibility

**Description**: File created on node A immediately visible on node B.
**Steps**:
1. Node A: `echo "from node A" > /mnt/shared/cross_test`
2. Node B: `cat /mnt/shared/cross_test`
3. Node B: `ls -la /mnt/shared/cross_test`
**Expected result**: Node B reads "from node A", stat shows correct size.
**Failure indicators**: ENOENT on node B (stale dir cache), wrong content (stale data).
**Scale**: 2 VMs.

### T-03-04: Cross-node read after write

**Description**: A writes data, B reads it — verify DLM cache coherency.
**Steps**:
1. Node A: `dd if=/dev/urandom of=/mnt/shared/coherency bs=1M count=10`
2. Node A: `md5sum /mnt/shared/coherency`
3. Node B: `md5sum /mnt/shared/coherency`
**Expected result**: md5sums match between nodes.
**Failure indicators**: md5 mismatch — data cache not invalidated on BAST.
**Scale**: 2 VMs.

### T-03-05: Both nodes write different files simultaneously

**Description**: Concurrent non-conflicting writes from both nodes.
**Steps**:
1. Node A: `dd if=/dev/urandom of=/mnt/shared/fileA bs=1M count=50 &`
2. Node B: `dd if=/dev/urandom of=/mnt/shared/fileB bs=1M count=50 &`
3. Wait for both to complete.
4. Node A: `ls -la /mnt/shared/fileA /mnt/shared/fileB`
5. Node B: `ls -la /mnt/shared/fileA /mnt/shared/fileB`
**Expected result**: Both files 50MB, visible on both nodes.
**Scale**: 2 VMs.

### T-03-06: DLM lock contention — EX vs EX

**Description**: Both nodes try to write same file — verify BAST fires and lock handoff works.
**Steps**:
1. Node A: `dd if=/dev/urandom of=/mnt/shared/contention bs=4K count=1000 conv=fsync &`
2. Node B (immediately): `dd if=/dev/urandom of=/mnt/shared/contention bs=4K count=1000 conv=fsync &`
3. Wait for both to complete.
4. `dmesg | grep -i "bast\|lock.*grant\|lock.*queue"` on both nodes.
**Expected result**: Both dd complete (possibly serialized). dmesg shows BAST callbacks firing, lock grants/releases. No deadlock.
**Failure indicators**: Deadlock (one dd hangs forever), kernel oops, data corruption.
**Scale**: 2 VMs.

### T-03-07: Cross-node directory operations

**Description**: A creates files and dirs, B lists and removes them.
**Steps**:
1. Node A: `mkdir /mnt/shared/crossdir && touch /mnt/shared/crossdir/f1 /mnt/shared/crossdir/f2`
2. Node B: `ls /mnt/shared/crossdir/`
3. Node B: `rm /mnt/shared/crossdir/f1`
4. Node A: `ls /mnt/shared/crossdir/`
5. Node A: `rm /mnt/shared/crossdir/f2 && rmdir /mnt/shared/crossdir`
**Expected result**: B sees f1 and f2, after B removes f1, A sees only f2.
**Failure indicators**: Stale directory listing, ENOENT on existing file.
**Scale**: 2 VMs.

### T-03-08: Cross-node rename

**Description**: Node A creates file, node B renames it.
**Steps**:
1. Node A: `echo "rename me" > /mnt/shared/before_rename`
2. Node B: `mv /mnt/shared/before_rename /mnt/shared/after_rename`
3. Node A: `cat /mnt/shared/after_rename`
4. Node A: `ls /mnt/shared/before_rename 2>&1`
**Expected result**: Content preserved, old name gone on both nodes.
**Scale**: 2 VMs.

### T-03-09: Cross-node hard link

**Description**: Node A creates file, node B creates hard link to it.
**Steps**:
1. Node A: `echo "link me" > /mnt/shared/linkfile`
2. Node B: `ln /mnt/shared/linkfile /mnt/shared/linkfile2`
3. Node A: `stat -c "%h" /mnt/shared/linkfile`
4. Node B: `cat /mnt/shared/linkfile2`
**Expected result**: nlink=2, content correct via both names.
**Scale**: 2 VMs.

### T-03-10: Cache coherency — inode attributes

**Description**: A modifies inode attributes, B sees updates.
**Steps**:
1. Node A: `touch /mnt/shared/attrtest`
2. Node B: `stat -c "%a %u %s" /mnt/shared/attrtest`
3. Node A: `chmod 0700 /mnt/shared/attrtest`
4. Node B: `stat -c "%a" /mnt/shared/attrtest`
5. Node A: `echo "grow" >> /mnt/shared/attrtest`
6. Node B: `stat -c "%s" /mnt/shared/attrtest`
**Expected result**: B sees 700 after chmod, sees increased size after write.
**Failure indicators**: B sees stale permissions or stale size.
**Scale**: 2 VMs.

### T-03-11: Simultaneous readdir (PR lock)

**Description**: Both nodes readdir same directory concurrently — should not block (PR is shared).
**Steps**:
1. Create 1000 files in /mnt/shared/prtest/
2. Node A: `time ls /mnt/shared/prtest/ | wc -l &`
3. Node B: `time ls /mnt/shared/prtest/ | wc -l &`
4. Wait for both.
**Expected result**: Both complete quickly (PR lock is compatible with PR), both show 1000.
**Failure indicators**: One node blocks waiting for the other (lock mode bug).
**Scale**: 2 VMs.

---

## PHASE 4: Multi-Node Cluster (4/8/16/32 nodes)

### T-04-01: All N nodes mount concurrently

**Description**: All nodes in the cluster mount the shared device.
**Steps**:
1. On each node: `mount -t mxfs /dev/sdb /mnt/shared`
2. On each node: `dmesg | grep -c "peer.*connect"`
**Expected result**: All N mounts succeed. Each node shows N-1 peer connections in dmesg.
**Failure indicators**: Mount timeout, discovery incomplete, missing peer connections.
**Scale**: 4/8/16/32.

### T-04-02: TCP mesh verification

**Description**: Verify full TCP mesh — N*(N-1)/2 connections total.
**Steps**:
1. On each node: `ss -tn | grep 7600 | wc -l`
2. Sum across all nodes, divide by 2 (each connection shows on both ends).
**Expected result**: 4 nodes = 6 connections. 8 = 28. 16 = 120. 32 = 496.
**Failure indicators**: Missing connections, connection refused errors.
**Scale**: 4/8/16/32.

### T-04-03: Concurrent file creation — all nodes

**Description**: Every node creates files simultaneously in same directory.
**Steps**:
1. On each node i: `for j in $(seq 1 100); do touch /mnt/shared/node${i}_file${j}; done &`
2. Wait for all nodes.
3. On any node: `ls /mnt/shared/ | wc -l`
**Expected result**: 4 nodes × 100 = 400 files (or N × 100). All visible on all nodes.
**Failure indicators**: Missing files, duplicate inode numbers, EEXIST on unique names.
**Scale**: 4/8/16/32.

### T-04-04: Concurrent mkdir — all nodes

**Description**: All nodes create directories in same parent simultaneously.
**Steps**:
1. Each node i: `for j in $(seq 1 50); do mkdir /mnt/shared/dir_${i}_${j}; done &`
2. Wait.
3. Any node: `ls -d /mnt/shared/dir_* | wc -l`
**Expected result**: N × 50 directories. All visible everywhere.
**Scale**: 4/8/16/32.

### T-04-05: AG affinity verification

**Description**: Verify nodes allocate from preferred AGs (node_slot % ag_count).
**Steps**:
1. Each node creates 1000 files.
2. Use xfs_db to check which AGs contain the inodes: `xfs_db -r /dev/sdb -c "agi 0" -c "p freecount"` (repeat for each AG).
3. Compare AG usage patterns.
**Expected result**: Inodes concentrated in different AGs per node. Not all in AG 0.
**Failure indicators**: All inodes in same AG (affinity not working).
**Scale**: 4/8/16/32.

### T-04-06: Sequential consistency

**Description**: Ordered operations from one node are seen in order by others.
**Steps**:
1. Node A: `for i in $(seq 1 100); do echo "entry $i" >> /mnt/shared/seqfile; done`
2. Node B: `wc -l /mnt/shared/seqfile`
3. Node B: `head -5 /mnt/shared/seqfile`
4. Node B: `tail -5 /mnt/shared/seqfile`
**Expected result**: 100 lines, ordered entry 1 through entry 100.
**Scale**: 4/8/16/32.

### T-04-07: Mixed-OS cluster — wire protocol compatibility

**Description**: Nodes with different kernel versions exchange DLM messages.
**Steps**:
1. 4-node config: Debian 11 (5.10) + Debian 12 (6.1) + Ubuntu 24.04 (6.8) + RHEL 9.7 (5.14).
2. All mount, create files, read each other's files.
3. Verify cross-node operations work regardless of kernel version.
**Expected result**: All operations succeed. DLM wire protocol is identical regardless of kernel.
**Failure indicators**: Message parsing errors, lock grants fail cross-version.
**Scale**: 4+ with mixed OS.

### T-04-08: Scale — 32-node concurrent I/O

**Description**: All 32 nodes doing I/O simultaneously.
**Steps**:
1. Each node: `fio --name=test --filename=/mnt/shared/fio_node${i} --size=100M --bs=64K --rw=randrw --runtime=60 --time_based &`
2. Wait 60 seconds.
3. Check all nodes completed without error.
4. Check dmesg on all nodes for oops/warnings.
**Expected result**: All 32 fio instances complete, no kernel warnings.
**Failure indicators**: Hung fio, kernel oops, lock timeout, node disconnection.
**Scale**: 32.

---

## PHASE 5: Fault Tolerance & Recovery

### T-05-01: Node crash — lease expiry detection

**Description**: Power off a VM, verify surviving nodes detect it via lease timeout.
**Prerequisites**: 4-node cluster, all mounted and active.
**Steps**:
1. Note which node we'll kill (e.g., node 203).
2. Via ESXi: `ssh root@192.168.1.251 "vim-cmd vmsvc/power.off 159"`
3. Wait 15-20 seconds (lease timeout).
4. On surviving nodes: `dmesg | grep -i "lease.*expir\|node.*dead\|fencing"`
**Expected result**: After lease timeout (~15s), surviving nodes log lease expiry for dead node, trigger fencing sequence (SCSI PR preempt, disklock purge, DLM purge).
**Failure indicators**: Surviving nodes hang, no lease expiry detected, fencing not triggered.
**Scale**: 4/8/16/32.

### T-05-02: SCSI PR fencing — dead node preempted

**Description**: Verify SCSI PR key of dead node is removed.
**Steps**:
1. Kill a node (T-05-01).
2. After fencing completes, on surviving node check PR keys.
3. Verify dead node's key is no longer registered.
**Expected result**: Dead node's PR key preempted, only surviving nodes registered.
**Scale**: 4+.

### T-05-03: DLM purge — dead node locks released

**Description**: Locks held by dead node are released, unblocking other nodes.
**Steps**:
1. Node A: Start a long write (holds EX lock).
2. Kill node A mid-write.
3. Node B: Attempt to write same file.
**Expected result**: After lease expiry and DLM purge (~15-20s), node B's write proceeds.
**Failure indicators**: Node B blocked forever (deadlock — lock not purged).
**Scale**: 4+.

### T-05-04: Graceful leave and rejoin

**Description**: Node unmounts cleanly, others continue. Node remounts and rejoins.
**Steps**:
1. 4-node cluster active.
2. Node D: `umount /mnt/shared`
3. Nodes A/B/C: continue I/O, verify no disruption.
4. Node D: `mount -t mxfs /dev/sdb /mnt/shared`
5. Node D: `ls /mnt/shared/` — sees files created while it was away.
**Expected result**: Unmount triggers clean disconnect (no fencing). Remount rediscovers peers and rejoins.
**Failure indicators**: Fencing triggered on clean umount, remount can't find peers.
**Scale**: 4/8/16/32.

### T-05-05: Network partition — iptables

**Description**: Simulate network partition by dropping traffic to one node.
**Steps**:
1. 4-node cluster.
2. On node C: `iptables -A INPUT -s 192.168.120.0/24 -j DROP && iptables -A OUTPUT -d 192.168.120.0/24 -j DROP`
3. Wait 20 seconds.
4. On nodes A/B/D: `dmesg | grep -i "lease.*expir\|node.*dead"`
5. On node C: `dmesg` (should show it can't reach peers).
6. Clean up: On node C: `iptables -F`
**Expected result**: Nodes A/B/D detect C as dead via lease timeout. C is fenced.
**Failure indicators**: No detection, split-brain (both sides continue writing).
**Scale**: 4+.

### T-05-06: Cascading failure — kill 2 of 4

**Description**: Two nodes die, remaining two continue.
**Steps**:
1. 4-node cluster.
2. Kill nodes C and D simultaneously via ESXi.
3. Wait for fencing on A and B.
4. A and B: continue I/O.
**Expected result**: A and B survive, fence both dead nodes, continue operating.
**Scale**: 4+.

### T-05-07: All-but-one failure

**Description**: Kill all nodes except one — last node still functions.
**Steps**:
1. 4-node cluster.
2. Kill B, C, D.
3. Wait for fencing on A.
4. A: create files, read files, stat.
**Expected result**: A detects all three peers dead, fences them, continues as single-node cluster.
**Scale**: 4+.

### T-05-08: Recovery under load

**Description**: Kill a node while other nodes are actively doing I/O.
**Steps**:
1. All 4 nodes running fio.
2. Kill node C mid-I/O.
3. Wait for fencing.
4. Verify remaining nodes' fio continues without error.
**Expected result**: Temporary pause during fencing, then I/O resumes.
**Failure indicators**: Other nodes' fio fails, kernel oops, data corruption.
**Scale**: 4+.

### T-05-09: Rapid rejoin — 50 mount/unmount cycles

**Description**: Stress the join/leave path.
**Steps**:
1. Nodes A/B/C mounted, stable.
2. Node D: `for i in $(seq 1 50); do mount -t mxfs /dev/sdb /mnt/shared && sleep 2 && umount /mnt/shared && sleep 1; done`
3. Check dmesg on all nodes.
**Expected result**: All 50 cycles complete. No leaks, no warnings, no hung mounts.
**Failure indicators**: Mount hangs, discovery fails, TCP connection leak.
**Scale**: 4+.

### T-05-10: Power failure simulation

**Description**: Kill VM mid-write, restart, verify FS integrity.
**Steps**:
1. Node A writing large file: `dd if=/dev/urandom of=/mnt/shared/bigwrite bs=1M count=500 &`
2. After ~2 seconds, kill VM: `ssh root@192.168.1.251 "vim-cmd vmsvc/power.off <vmid>"`
3. Wait for other nodes to fence dead node.
4. Power VM back on: `ssh root@192.168.1.251 "vim-cmd vmsvc/power.on <vmid>"`
5. On recovered node: `xfs_repair -n /dev/sdb` (check mode, no modifications).
6. Node remounts: `mount -t mxfs /dev/sdb /mnt/shared`
**Expected result**: xfs_repair finds no corruption (or only correctable issues), mount succeeds.
**Failure indicators**: Unrecoverable corruption, mount fails.
**Scale**: 4+.

### T-05-11: iSCSI session drop

**Description**: Simulate storage path failure on one node.
**Steps**:
1. 4-node cluster active.
2. Node C: `iscsiadm -m node --logout`
3. Observe behavior on all nodes.
4. Node C: `iscsiadm -m node --login`
**Expected result**: Node C loses access to /dev/sdb, I/O errors trigger unmount or error state. Other nodes fence C.
**Scale**: 4+.

---

## PHASE 6: Performance Benchmarking

All performance tests should be run and recorded for comparison across scale tiers.
Baseline comparison: raw XFS (mount -t xfs) on same device, single node.

### T-06-01: Sequential write throughput — single node

**Description**: Measure peak sequential write MB/s.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `dd if=/dev/zero of=/mnt/shared/seqwrite bs=1M count=2048 oflag=direct 2>&1 | tail -1`
3. Record MB/s.
4. Baseline: `mount -t xfs /dev/sdb /mnt/shared && dd if=/dev/zero of=/mnt/shared/seqwrite bs=1M count=2048 oflag=direct 2>&1 | tail -1`
**Expected result**: Record throughput. Compare to XFS baseline. Overhead should be < 20%.
**Scale**: 1 VM.

### T-06-02: Sequential read throughput — single node

**Description**: Measure peak sequential read MB/s.
**Steps**:
1. Create 2GB file.
2. `echo 3 > /proc/sys/vm/drop_caches`
3. `dd if=/mnt/shared/seqwrite of=/dev/null bs=1M 2>&1 | tail -1`
**Expected result**: Record throughput.
**Scale**: 1 VM.

### T-06-03: Random I/O — fio profiles

**Description**: Standard fio benchmarks at various block sizes.
**Steps**:
1. Create fio job file /tmp/mxfs_fio.ini:
```
[global]
directory=/mnt/shared
ioengine=psync
direct=0
size=256M
runtime=60
time_based=1
group_reporting=1

[randread-4k]
rw=randread
bs=4k
numjobs=4

[randwrite-4k]
rw=randwrite
bs=4k
numjobs=4

[randread-64k]
rw=randread
bs=64k
numjobs=4

[seqwrite-1m]
rw=write
bs=1M
numjobs=1
```
2. `fio /tmp/mxfs_fio.ini`
3. Record IOPS and bandwidth for each job.
**Scale**: 1/2/4/8/16/32.

### T-06-04: Metadata performance — file create rate

**Description**: Measure file creation rate (files/sec).
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `time (for i in $(seq 1 10000); do touch /mnt/shared/meta_$i; done)`
3. Calculate files/sec.
4. `time (rm /mnt/shared/meta_*)`
5. Baseline: same on raw XFS.
**Expected result**: Record create rate and delete rate. Compare to XFS.
**Scale**: 1/2/4.

### T-06-05: Cross-node operation latency

**Description**: Time for node B to see a file created by node A.
**Steps**:
1. Node A: creates file, records timestamp.
2. Node B: polls for file, records when it appears.
3. Measure delta.
```
# Node A:
python3 -c "
import time, os
t = time.monotonic()
open('/mnt/shared/lattest', 'w').close()
print(f'created at {t}')
"
# Node B:
python3 -c "
import time, os
while True:
    if os.path.exists('/mnt/shared/lattest'):
        print(f'visible at {time.monotonic()}')
        break
    time.sleep(0.001)
"
```
**Expected result**: Latency < 100ms typical (DLM lock + network round trip).
**Scale**: 2+.

### T-06-06: Lock contention throughput curve

**Description**: Measure throughput as contention increases (1 to N nodes on same file).
**Steps**:
1. Single node: `fio --name=solo --filename=/mnt/shared/contention --size=100M --bs=4k --rw=randwrite --runtime=30 --time_based`
2. 2 nodes: same fio on both, same file.
3. 4 nodes: same.
4. 8, 16, 32 nodes: same.
5. Plot IOPS at each node count.
**Expected result**: Throughput decreases as contention increases. Should degrade gracefully, not cliff.
**Scale**: 1/2/4/8/16/32.

### T-06-07: bonnie++

**Description**: Full bonnie++ benchmark suite.
**Steps**:
1. `bonnie++ -d /mnt/shared -s 2G -u root`
2. Record all metrics (sequential write, rewrite, read, random create, etc.).
**Scale**: 1 VM.

### T-06-08: Directory readdir performance scaling

**Description**: Measure readdir time as directory grows.
**Steps**:
1. Create directories with 100, 1000, 10000, 100000 entries.
2. Time `ls -f <dir> | wc -l` for each.
3. Plot time vs entry count.
**Expected result**: Linear or sub-linear growth. No exponential blowup.
**Scale**: 1 VM.

### T-06-09: Network traffic measurement

**Description**: Measure DLM message rate and bandwidth during load.
**Steps**:
1. On one node: `tcpdump -i eth0 port 7600 -w /tmp/dlm_traffic.pcap &`
2. Run 60 seconds of fio across cluster.
3. `tcpdump -r /tmp/dlm_traffic.pcap | wc -l` (message count).
4. `ls -la /tmp/dlm_traffic.pcap` (total bytes).
**Expected result**: Record messages/sec and MB/sec of DLM traffic.
**Scale**: 4/8/16/32.

### T-06-10: Memory usage under load

**Description**: Track kernel memory during sustained I/O.
**Steps**:
1. Before load: `cat /proc/meminfo | grep -E "Slab|SReclaimable|SUnreclaim"`
2. Run fio for 5 minutes.
3. After load: same meminfo check.
4. After unmount: same check.
**Expected result**: Slab usage increases during I/O, decreases after unmount. No persistent growth.
**Failure indicators**: Slab grows continuously (memory leak).
**Scale**: All.

---

## PHASE 7: Stress & Edge Cases

### T-07-01: fsx — File System eXerciser

**Description**: Random read/write/truncate/mapread for extended period.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `fsx -N 100000 -l 10485760 /mnt/shared/fsx_test`
3. Or if fsx not available: use xfstests fsx equivalent.
**Expected result**: 100,000 operations complete with no miscompares.
**Failure indicators**: "READ VERIFY FAILED" or "DATA MISMATCH" from fsx.
**Scale**: 1 VM, then 2+ VMs (separate fsx files).

### T-07-02: xfstests — generic suite

**Description**: Standard filesystem compliance test suite.
**Steps**:
1. Configure xfstests:
```
export TEST_DEV=/dev/sdb
export TEST_DIR=/mnt/shared
export FSTYP=mxfs
```
2. `./check -g generic/quick`
3. `./check -g generic/auto`
4. Record pass/fail/skip counts.
**Expected result**: Majority of generic tests pass. Known incompatibilities documented.
**Failure indicators**: Test failures indicating POSIX non-compliance.
**Scale**: 1 VM.

### T-07-03: Fill filesystem to 100%

**Description**: Fill device completely, verify ENOSPC handling.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `dd if=/dev/zero of=/mnt/shared/fillme bs=1M || true`
3. Check error: should be ENOSPC.
4. `df /mnt/shared` — should show 0 or near-0 free.
5. `rm /mnt/shared/fillme`
6. `df /mnt/shared` — free space returns.
7. `touch /mnt/shared/after_fill` — should succeed.
8. Cleanup.
**Expected result**: ENOSPC returned cleanly, no hang, no corruption. Space recovered after delete.
**Failure indicators**: Kernel oops, hang, space not reclaimed.
**Scale**: 1 VM, then 2+ VMs.

### T-07-04: Create/delete storm — multi-node

**Description**: Rapid create and unlink of files from all nodes simultaneously.
**Steps**:
1. On each of N nodes:
```
for i in $(seq 1 5000); do
    touch /mnt/shared/storm_${HOSTNAME}_$i
    rm -f /mnt/shared/storm_${HOSTNAME}_$i
done &
```
2. Wait for all.
3. `ls /mnt/shared/storm_* 2>&1`
**Expected result**: All complete, no leftover files, no errors.
**Failure indicators**: ENOENT races (acceptable if handled), kernel warnings, leftover files.
**Scale**: 4/8/16/32.

### T-07-05: Rename storm — multi-node

**Description**: Rapid renames from all nodes.
**Steps**:
1. Create 1000 files.
2. Each node: rename different subsets rapidly.
3. Verify final state is consistent.
**Expected result**: No lost files, no duplicate names, consistent directory.
**Scale**: 4+.

### T-07-06: Rapid mount/unmount — 100 cycles

**Description**: Stress mount/unmount path for leaks.
**Steps**:
1. `for i in $(seq 1 100); do mount -t mxfs /dev/sdb /mnt/shared && umount /mnt/shared; done`
2. Check dmesg for warnings.
3. Check /proc/meminfo for slab growth.
**Expected result**: All 100 cycles complete. No slab growth. No kernel warnings.
**Scale**: 1 VM.

### T-07-07: 24-hour sustained load

**Description**: Long-haul stability test.
**Steps**:
1. 4-node cluster.
2. Each node:
```
fio --name=sustain --filename=/mnt/shared/fio_node${i} \
    --size=1G --bs=64K --rw=randrw --runtime=86400 --time_based \
    --verify=md5 --verify_backlog=1024 &
```
3. Monitor dmesg every hour.
4. Check /proc/meminfo every hour.
**Expected result**: 24 hours with zero verification failures, no kernel warnings, stable memory.
**Failure indicators**: fio verify failure (corruption), hung task, memory leak.
**Scale**: 4/8.

### T-07-08: 72-hour sustained load at 32 nodes

**Description**: Extended long-haul at maximum scale.
**Steps**: Same as T-07-07 but 32 nodes for 72 hours.
**Expected result**: 72 hours clean. This is the "ship it" test.
**Scale**: 32.

### T-07-09: Clock skew

**Description**: Nodes with different system times.
**Steps**:
1. Node A: `date -s "+5 minutes"`
2. Node B: `date -s "-5 minutes"`
3. Both mounted, do I/O.
4. Verify leases still work (they use monotonic time internally, not wall clock).
5. Reset clocks: `ntpdate -s pool.ntp.org` or `timedatectl set-ntp true`
**Expected result**: Leases unaffected (monotonic), filesystem operations work.
**Failure indicators**: False lease expiry (using wall clock instead of monotonic).
**Scale**: 2+.

### T-07-10: Memory pressure — cgroups

**Description**: Limit kernel memory to force cache eviction.
**Steps**:
1. Create cgroup with 128MB memory limit.
2. Run I/O workload in that cgroup.
3. Monitor for OOM kills, cache eviction behavior.
**Expected result**: Cache evicts LRU entries, I/O continues at reduced cache hit rate.
**Failure indicators**: OOM kill of kernel threads, hang.
**Scale**: 1 VM.

### T-07-11: Thundering herd

**Description**: N nodes blocked on same EX lock, holder releases — verify orderly grant.
**Steps**:
1. Node A: open file for write, hold open (blocking EX lock).
2. Nodes B, C, D (and more): attempt to write same file (blocked).
3. Node A: close file (releases lock).
4. Verify each blocked node gets the lock in sequence.
**Expected result**: Each node eventually gets the lock, no starvation, no deadlock.
**Failure indicators**: One node never gets the lock (starvation), all nodes get it simultaneously (lock bug).
**Scale**: 4/8/16.

### T-07-12: Maximum directory entries

**Description**: Push directory to 1M entries.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `mkdir /mnt/shared/bigdir`
3. `python3 -c "
import os
for i in range(1000000):
    open(f'/mnt/shared/bigdir/f{i:07d}', 'w').close()
    if i % 10000 == 0:
        print(f'{i} files created')
"`
4. `ls /mnt/shared/bigdir/ | wc -l`
5. `ls /mnt/shared/bigdir/f0500000`
6. `rm -rf /mnt/shared/bigdir`
**Expected result**: 1M files created (if disk space allows), lookup works, cleanup succeeds.
This tests all 4 XFS directory format transitions: shortform → block → leaf → node/btree.
**Scale**: 1 VM.

---

## PHASE 8: Multi-OS Compatibility

### T-08-01: Build verification matrix

**Description**: Compile on every distro in the VM configuration matrix.
**Steps**: Run `make kernel` on each distro/kernel combination.
**Expected result**: Clean build on all supported kernels (5.10, 5.14, 5.15, 6.1, 6.8). Debian 13 (6.12+) may need compat fixes.
**Scale**: All distros.

### T-08-02: Mixed cluster — correctness

**Description**: Different kernel versions in same cluster perform cross-node I/O.
**Steps**:
1. 4-node mixed cluster: Debian 11 + Debian 12 + Ubuntu 24.04 + RHEL 9.7.
2. Each node creates 100 files.
3. Each node reads files created by every other node.
4. md5sum verification.
**Expected result**: All files readable across all kernel versions, md5 matches.
**Failure indicators**: DLM message format mismatch, byte order issues.
**Scale**: 4+.

### T-08-03: On-disk format compatibility

**Description**: Files written by one kernel version are readable by another.
**Steps**:
1. Node with 5.10 kernel writes a file.
2. Node with 6.8 kernel reads it.
3. Reverse: 6.8 writes, 5.10 reads.
4. Verify content matches.
**Expected result**: XFS on-disk format is kernel-version-independent. All reads correct.
**Scale**: 4+.

### T-08-04: Security module interaction

**Description**: Verify MXFS works with SELinux (RHEL/Alma) and AppArmor (Ubuntu).
**Steps**:
1. RHEL node with SELinux enforcing: mount and do I/O.
2. Ubuntu node with AppArmor enabled: mount and do I/O.
3. Debian node with neither: mount and do I/O.
**Expected result**: All work. Security modules don't block mxfs operations.
**Failure indicators**: SELinux AVC denials, AppArmor DENIED messages.
**Scale**: 4+ mixed.

---

## PHASE 9: Operational Testing

### T-09-01: dmesg log quality

**Description**: Verify kernel log messages are clean and informative.
**Steps**:
1. Mount, do I/O, unmount.
2. `dmesg | grep mxfs`
3. Review: no debug spam at default log level, errors are clear, subsystem init/shutdown logged.
**Expected result**: Clean log output at INFO level. No debug messages unless enabled.
**Scale**: All.

### T-09-02: Invalid mount options

**Description**: Mount with bad options, verify clean error.
**Steps**:
1. `mount -t mxfs -o port=abc /dev/sdb /mnt/shared 2>&1`
2. `mount -t mxfs -o bogus_option /dev/sdb /mnt/shared 2>&1`
3. `mount -t mxfs /dev/nonexistent /mnt/shared 2>&1`
**Expected result**: Clear error messages, no crash, no kernel warning.
**Scale**: 1 VM.

### T-09-03: Graceful shutdown with active I/O

**Description**: umount while writes are in progress.
**Steps**:
1. Start background writes: `dd if=/dev/urandom of=/mnt/shared/bgwrite bs=1M count=1000 &`
2. `umount /mnt/shared`
3. Observe: does umount wait for dd to finish, or does it fail with EBUSY?
**Expected result**: umount returns EBUSY while file is open. After dd completes, umount succeeds.
**Scale**: 1 VM.

### T-09-04: Force unmount

**Description**: umount -f behavior.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `exec 3>/mnt/shared/openfile`
3. `umount -f /mnt/shared`
4. `dmesg | tail -20`
**Expected result**: Force unmount succeeds (or returns clear error). No kernel oops.
**Scale**: 1 VM.

### T-09-05: rmmod with active mount

**Description**: Attempt to unload module while filesystem is mounted.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `rmmod mxfs 2>&1`
**Expected result**: Returns "ERROR: Module mxfs is in use". Module stays loaded.
**Scale**: 1 VM.

### T-09-06: df and stat -f output

**Description**: Verify filesystem reporting tools work.
**Steps**:
1. `mount -t mxfs /dev/sdb /mnt/shared`
2. `df -Th /mnt/shared`
3. `stat -f /mnt/shared`
**Expected result**: df shows type "mxfs", correct size. stat -f shows valid block counts.
**Scale**: 1 VM.

---

## PHASE 10: Security Testing

### T-10-01: Cross-node permission enforcement

**Description**: Permissions set on one node are enforced on another.
**Steps**:
1. Node A (as root): `touch /mnt/shared/secfile && chmod 0600 /mnt/shared/secfile && chown 1000:1000 /mnt/shared/secfile`
2. Node B (as uid 1001): `cat /mnt/shared/secfile 2>&1`
3. Node B (as uid 1000): `cat /mnt/shared/secfile 2>&1`
**Expected result**: uid 1001 gets EACCES, uid 1000 succeeds.
**Scale**: 2+.

### T-10-02: UID/GID consistency

**Description**: Same UID on different nodes represents same owner.
**Steps**:
1. Node A: create file owned by uid 1000.
2. Node B: stat the file, verify uid is 1000.
3. If uid 1000 exists on both nodes, both can access appropriately.
**Expected result**: UID/GID stored on disk, same values seen by all nodes.
**Scale**: 2+.

### T-10-03: Non-root mount

**Description**: Unprivileged user cannot mount mxfs.
**Steps**:
1. As non-root user: `mount -t mxfs /dev/sdb /mnt/shared 2>&1`
**Expected result**: Permission denied (requires CAP_SYS_ADMIN for raw block device).
**Scale**: 1 VM.

### T-10-04: Sticky bit cross-node

**Description**: Sticky bit on directory prevents cross-user deletion.
**Steps**:
1. Node A: `mkdir /mnt/shared/sticky && chmod 1777 /mnt/shared/sticky`
2. Node A (as uid 1000): `touch /mnt/shared/sticky/myfile`
3. Node B (as uid 1001): `rm /mnt/shared/sticky/myfile 2>&1`
**Expected result**: uid 1001 gets EPERM (sticky bit prevents deletion of other user's files).
**Scale**: 2+.

### T-10-05: SCSI PR key uniqueness

**Description**: Verify no PR key collisions across 32 nodes.
**Steps**:
1. All 32 nodes mounted.
2. Read SCSI PR keys from device.
3. Verify all 32 keys are unique.
**Expected result**: 32 unique keys (derived from unique node UUIDs via FNV-1a).
**Failure indicators**: Duplicate keys (hash collision — astronomically unlikely with 64-bit keys and 32 nodes, but verify).
**Scale**: 32.

---

## Test Execution Order

1. **Phase 1** (Build) — must pass before anything else.
2. **Phase 2** (Single-node) — correctness foundation.
3. **Phase 3** (Two-node) — basic clustering.
4. **Phase 4** (Multi-node 4) — cluster at small scale with existing VMs.
5. **Phase 5** (Fault tolerance) — with 4 nodes.
6. **Phase 6** (Performance) — baseline numbers at 1/2/4 nodes.
7. **Phase 8** (Multi-OS) — build verification on new distros as VMs come online.
8. **Phase 4** (Multi-node 8/16/32) — scale testing as VMs are added.
9. **Phase 7** (Stress) — extended duration tests.
10. **Phase 9** (Operational) — can run anytime.
11. **Phase 10** (Security) — can run anytime after Phase 3.

## Pass Criteria

- **Alpha**: Phase 1-3 pass (build, single-node, two-node).
- **Beta**: Phase 1-6 pass (add multi-node, fault tolerance, performance baselined).
- **RC**: Phase 1-8 pass (add stress, multi-OS).
- **Release**: All phases pass including 72-hour sustained load at 32 nodes.
