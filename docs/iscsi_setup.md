# MXFS Shared-Storage Requirements & iSCSI/SAN Setup

**Audience:** operators deploying MXFS on a real shared LUN (iSCSI, FC, or
NVMe-oF). This is the "what the storage has to provide, and how to prove it
before you trust data to it" guide.

MXFS is a shared-LUN clustered filesystem: every node opens the **same** block
device read/write at the same time. Correctness depends on the storage target
providing a few SCSI behaviours that ordinary single-initiator setups never
exercise. If those behaviours are missing or faked, MXFS cannot coordinate the
nodes and you will get silent corruption. **Read this before formatting a LUN.**

---

## 1. Pick a transport: CAW (default) vs TCP DLM

MXFS coordinates nodes with a distributed lock manager (DLM) that runs over one
of two transports:

| Transport | How locks travel | What the LUN must support | Node-to-node network |
|---|---|---|---|
| **CAW** (default) | In-band, on the shared disk itself, via SCSI **COMPARE AND WRITE** | CAW (0x89) + Persistent Reservations + durable writes | Not required for locking |
| **TCP DLM** (fallback) | Out-of-band, over TCP between nodes | Only a plain shared block device | Required (low-latency LAN) |

- **CAW is the primary, recommended transport.** It needs no separate lock
  network — the lock state lives on the LUN — and it scales past the point where
  TCP DLM's per-node coordination cost dominates (>16 nodes).
- **TCP DLM is the fallback** for storage that does *not* honour SCSI CAW/PR
  (see §2). It works over any shared block device but requires a fast, reliable
  node-to-node network and has a lower node-count ceiling.

**Transport selection rules** (also in the module):

1. **Joining an existing cluster:** you get whatever transport the existing
   peers use. No choice — a joining node conforms.
2. **Forming a new cluster:** MXFS probes CAW first; if the probe fails it falls
   back to TCP DLM.
3. **Override** `mxfs.force_transport=1` (force TCP) applies **only** when
   forming a new cluster. Once membership exists, transport is fixed.

If you know your target can't do CAW reliably, form the cluster with
`insmod mxfs.ko force_transport=1` on the first node.

---

## 2. CAW transport — hard storage requirements

To use the default CAW transport, the shared LUN **must** provide all of the
following. Verify each with the tools in §4 **before** running `mkfs_mxfs`.

### 2.1 SCSI COMPARE AND WRITE (opcode 0x89), honoured atomically
This is the compare-and-swap primitive the on-disk DLM is built on. The target
must:
- **Advertise** it — `sg_opcodes <dev>` lists `COMPARE AND WRITE`.
- **Execute it atomically and durably** — a successful CAW must have actually
  persisted the new data, and a losing CAW must return **MISCOMPARE** (sense
  key `0x0E`), not a false success.

> ⚠️ **Targets that *fake* CAW are the #1 cause of silent corruption.** Some
> targets accept opcode 0x89 and return success **without** doing an atomic
> compare-and-swap (they report CAS-success without persisting). MXFS then
> believes it holds a lock it does not hold, and two nodes scribble the same
> blocks. Advertising CAW is **not** proof — you must run the cross-node
> `caw_verify` check in §4.2.

### 2.2 SCSI Persistent Reservations (PR) — for fencing
MXFS fences dead/partitioned nodes with SCSI-3 PR. The cluster uses
**type 5 — WRITE EXCLUSIVE, REGISTRANTS ONLY**: every live initiator registers a
key; a write from an unregistered nexus returns **RESERVATION CONFLICT (0x18)**.
The target must implement PR **per I-T nexus** (each initiator session is one
registrant). Targets that ignore PR cannot fence, so a partitioned node can
corrupt the FS.

### 2.3 Durable writes — no volatile target-side write cache
MXFS's coherency protocol releases a lock only after the data is on stable
media; a peer then reads it back. If the target buffers writes in a volatile
cache that a peer's read can miss, coherency breaks. Configure the backstore for
**write-through**, i.e. **disable the volatile write cache**:
- SCST `vdisk_fileio`: `write_through 1`, `nv_cache 0`.
- LIO fileio/iblock: `emulate_write_cache=0`.

### 2.4 FUA reads must reach media
MXFS issues **SCSI READ(16) with the FUA bit** to force-refresh metadata after a
peer writes. Some targets **silently drop the FUA bit** and serve a stale
per-initiator read cache — a peer's fresh write is then invisible. MXFS has an
internal workaround (`_XBF_FUA_FRESH` gating via a PAL SCSI READ(16) passthrough)
but it only helps if the target actually re-reads media on FUA. Prove it with
`fua_verify` (§4.3).

---

## 3. Which targets work

| Target | CAW usable? | Notes |
|---|---|---|
| **SCST** (`vdisk_fileio`, `write_through`) | ✅ Yes | Implements CAW (0x89) + PR natively. Recommended CAW target. |
| **LIO** (`fileio`/`iblock`, kernel target / `targetcli`) | ❌ No — CAW **faked** | Reports CAS-success without an atomic persist. **Use TCP DLM** (`force_transport=1`), not CAW, on LIO. |
| Vendor SAN arrays (FC / iSCSI / NVMe-oF) | ⚠️ Verify | Many enterprise arrays honour CAW+PR (VMware VAAI ATS uses the same 0x89 primitive), but you **must** run §4 to confirm before trusting it. |

**Rule of thumb:** never assume — a target either passes the §4 cross-node
`caw_verify`/`fua_verify` checks or you run TCP DLM instead.

---

## 4. Verify the LUN before you trust it

Run these from two (or more) nodes that all see the same LUN, **before**
`mkfs_mxfs`. Build the checkers with `make tools` (`tools/caw_verify`,
`tools/fua_verify`).

### 4.1 Does the target advertise CAW?
```bash
sg_opcodes /dev/sdX | grep -i "compare and write"   # must print a line
```
A read-only probe — safe on a reserved LUN (does not trip PR).

### 4.2 Cross-node CAW proof (the one that matters)
`caw_verify` issues a real SCSI COMPARE AND WRITE (0x89) with FUA and checks
that a losing CAW gets MISCOMPARE while a winning one persists across nodes:
```bash
# node A — write a known pattern at LBA 2048 (512-byte units)
tools/caw_verify write /dev/sdX 2048 aa
# node B — read it back; must see 0xaa (proves A's CAW reached media)
tools/caw_verify read  /dev/sdX 2048 aa
```
If node B does **not** see the pattern, or a concurrent CAW returns success on
both nodes instead of one MISCOMPARE, **CAW is faked/broken → do not use CAW**;
switch to TCP DLM.

### 4.3 Cross-node FUA-read proof
```bash
# node A
tools/fua_verify write /dev/sdX 4096 5a
# node B — FUA read must return 0x5a, not a stale cached value
tools/fua_verify read  /dev/sdX 4096
```
A stale result means the target serves a per-initiator read cache that ignores
FUA — coherency will be unreliable.

---

## 5. Per-node (initiator) tuning — REQUIRED

### 5.1 Widen the SCSI command timeout
The Linux default SCSI command timeout is **30 s**. Under concurrent load a
strictly-serialized SCSI command (a CAW, or `mkfs`'s WRITE SAME slot-table zero)
can legitimately take longer than that while the target drains its queue. If the
initiator's error handler fires first it escalates
`ABORT_TASK → LUN_RESET → I-T nexus loss`, which on some targets **permanently
wedges the shared LUN for every node** (leaked cleanup threads that never
release the device). Widen the per-device timeout on **every** node:

```bash
echo 180 > /sys/block/sdX/device/timeout
```

Make it persistent with a udev rule so it survives reboots, e.g.:
```
# /etc/udev/rules.d/99-mxfs-scsi-timeout.rules
ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sd*", \
  ATTR{device/timeout}="180"
```

This does **not** mask a slow filesystem — a genuinely slow workload still fails
its own time budget. It only stops a transient transport stall from turning into
an unrecoverable wedge.

### 5.2 Unique node identity
Each node must have a unique cluster slot (disklock slot 0..63). Two live nodes
on the same slot corrupt the LUN. Give each node a distinct hostname/slot; do not
clone a node's identity.

---

## 6. Reference SCST target config (CAW-capable)

A minimal SCST `vdisk_fileio` export of one shared backing file. One iSCSI
**target per initiator** so each node gets its own I-T nexus (= one PR
registrant). `/etc/scst.conf`:

```
HANDLER vdisk_fileio {
    DEVICE shared {
        filename /path/to/shared-lun.img   # or a real block device
        write_through 1                     # durable writes (§2.3)
        nv_cache 0                          # no volatile cache
    }
}

TARGET_DRIVER iscsi {
    enabled 1
    # one target per node — repeat per initiator, each mapping LUN 0 -> shared
    TARGET iqn.2026-05.example.mxfs:node1 { enabled 1; rel_tgt_id 1; LUN 0 shared }
    TARGET iqn.2026-05.example.mxfs:node2 { enabled 1; rel_tgt_id 2; LUN 0 shared }
    # ...one per node...
}
```

Apply with `scstadmin -config /etc/scst.conf`, then log each node's initiator
into its target and confirm the guest sees a SCSI disk that passes §4.

> **Operational note (SCST + heavy concurrent CAW):** SCST executes CAW and
> WRITE SAME as strictly-serialized commands (block device → drain outstanding →
> execute). Under very high concurrent-CAW load the drain can exceed the
> initiator timeout — which is exactly why §5.1 (180 s timeout) is mandatory.
> Keep initiators patched and the timeout widened.

---

## 7. Format and mount

Once §4 passes on all nodes:

```bash
tools/mkfs_mxfs /dev/sdX            # format (writes the MXFS envelope + XFS region)
mount -t mxfs /dev/sdX /mnt/shared  # on every node
```

Use **MXFS's own tools** to inspect an MXFS device — `tools/chk_mxfs -v` for
fsck+geometry, `tools/resize_mxfs` to grow. Do **not** use `xfs_db`/`xfs_info`/
`xfs_repair`: MXFS wraps the XFS region in an on-disk envelope (a slot table +
journal slice precede the XFS superblock), so stock XFS tools read the wrong
sectors and return empty/garbage.

---

## 8. Quick checklist

- [ ] Chosen transport: CAW (needs §2) or TCP DLM (`force_transport=1`, needs a fast node network).
- [ ] `sg_opcodes` shows COMPARE AND WRITE (CAW only).
- [ ] `caw_verify` passes cross-node (CAW only) — **not faked**.
- [ ] `fua_verify` passes cross-node — no stale read cache.
- [ ] Target write cache disabled (`write_through`/`nv_cache 0`/`emulate_write_cache=0`).
- [ ] PR (type 5) implemented per nexus (CAW fencing).
- [ ] SCSI command timeout = 180 s on every node (udev rule).
- [ ] Every node has a unique slot/identity.
- [ ] `mkfs_mxfs` then `mount -t mxfs` on all nodes; inspect only with `chk_mxfs`.

---

## Related docs
- `docs/dlm-protocol.md` — DLM transport internals (CAW + TCP).
- `docs/architecture.md` — overall MXFS design.
- `docs/test_infra_lio_tcm.md` — the project's LIO/tcm_loop **test** rig (TCP DLM
  testing; LIO fakes CAW, so it is not a CAW reference).
- `SCST_PROBLEM.md` — deep dive on the SCST serialization/wedge behaviour behind §5.1/§6.
