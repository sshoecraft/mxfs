---
name: infra-src-is-qnap-nfs-do-not-touch-exports
description: /src is QNAP NFS (192.168.1.4:/src); VMs mount it directly. NEVER touch clyde /etc/exports/prep NFS IP. If module missing, just rebuild mxfs.ko.
metadata:
  type: reference
---

## The /src NFS rig (user directive, sess72 run14d — said sharply twice)

`/src` on BOTH clyde and every test VM is an **NFS mount from the QNAP at
`192.168.1.4:/src`** (clyde: vers=3 soft,timeo=100; nodes: vers=4.1 hard). It is
the SHARED source tree — clyde and all 16 VMs see the same files. The VMs mount
it **directly from the QNAP**; they can reach 192.168.1.4 (routed via the libvirt
bridge clyde=192.168.120.1). This is intentional and is the test rig.

**DO NOT:**
- touch clyde's `/etc/exports` or run `exportfs` — clyde does NOT serve `/src`
  (it's a re-mount of the QNAP; exporting it needs fsid= and is pointless/wrong).
- repoint `tools/prep_tcm_node_scst.sh` NFS_SERVER away from `192.168.1.4` — it is correct.
- try to "fix" NFS by exporting from clyde or using 192.168.120.1. The QNAP is the server.

**If a node reports `Module not found at /src/mxfs/mxfs.ko`:** the cause is simply
that `mxfs.ko` is not built (clean tree). FIX = `cd /src/mxfs && make modules`
on clyde (writes mxfs.ko into the QNAP /src, visible to all nodes). Nothing else.
Note: clyde's QNAP mount is `soft` so `modinfo mxfs.ko` can return stale cached
srcversion for a file that was later cleaned — verify with `ls -la mxfs.ko`.

Other storage: SCST iSCSI target on clyde serves the real shared cluster LUN as
`/dev/sda` (vendor SCST_FIO) to the VMs — that is separate from the QNAP /src NFS
and is the device mxfs actually runs on. sdb=QNAP block dev (a session-71 tangent,
ignore). See [[test-cluster-scst-stack]].
</body>
