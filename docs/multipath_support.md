# MXFS on dm-multipath — kernel support (v0.6.0)

## What this covers

Running mxfs mounted on a whole-LUN `dm-multipath` device
(`mount -t mxfs /dev/mapper/mpathX /mnt/shared`) with the CAW DLM
transport — the enterprise-SAN deployment (any FC or iSCSI SAN with ≥2
paths and multipathd).  The storage substrate (raw CAW + PR through
dm-multipath) was characterised green in
`docs/condition4_multipath_scope.md`; this document covers the mxfs
KERNEL work that makes the filesystem itself run there, plus the test
rig.  Runtime rig: `scripts/mpath_up.sh {up|status|down} N` (synthetic
2-path: SCST on two br0 portals, each guest logs into both).

## The problem

Three PAL operations are SCSI passthrough CDBs and need a
`struct scsi_device`:

| Op | CDB | User |
|---|---|---|
| COMPARE AND WRITE | 0x89 | `dlm/dlm_caw.c` slot CAS (the CAW DLM) |
| READ(16)+FUA | 0x88 | coherent cross-node metadata rereads |
| WRITE(16)+FUA | 0x8A | surgical pre-release persistence |

On a plain SCSI disk the gendisk's device-model parent IS the
scsi_device.  A dm device has no SCSI parent, and since the 5.16 block
layer removed `scsi_request` there is no way to carry a CDB through a
dm request queue (dm forwards userspace SG_IO ioctls to one path
itself, but offers no in-kernel equivalent).  Before v0.6.0 the CAW
path returned `-EOPNOTSUPP` on dm (no CAW transport at all) and the
FUA-read path permanently latched its plain-bio fallback.

SCSI Persistent Reservations are NOT affected: mxfs uses the kernel
`pr_ops` interface and dm-multipath implements it, replicating
register/reserve/preempt to every path (verified live: one key listed
once per I_T nexus).  Normal FS I/O (bios) rides the dm queue as usual.

## The design: backing-device resolution by content identity

`pal/linux/kern.c :: mxfs_bdev_to_sdev()`:

1. Gendisk parent is a scsi_device → use it (unchanged fast path).
2. Otherwise read the MXFS on-disk super sector (LBA 0 — written only
   by mkfs, immutable while mounted, contains magic + per-mkfs UUID)
   through the stacked device via plain bio, then scan every SCSI disk
   (`scsi_host_lookup` 0..4095 + `shost_for_each_device`, exported
   APIs only — dm's table internals are not exported) and READ(16) its
   LBA 0: the disk that reads back the identical sector is a path to
   the same LUN.  Any path qualifies — CAW/PR semantics are
   target-side, per-LUN.
3. Cache the referenced sdev per stacked-device `dev_t`
   (`mxfs_sdev_cache`, 4 entries, spinlock).  A cached path that goes
   offline is dropped and re-resolved — control-plane failover.
   Negative results are cached 5s (a virtio-blk mount must not rescan
   per call).  All references released in `exit_xfs_fs` via
   `mxfs_pal_sdev_cache_release()`.

Requirement: the stack must map sector 0 → LUN LBA 0 (whole-LUN
dm-multipath).  A partition / dm-linear slice fails the content match
and cleanly reports "no passthrough" instead of writing mistranslated
LBAs.  (The direct-sd path has the same whole-disk assumption — the
passthrough LBA math adds `base_offset` to a device-relative sector.)

## UNIT ATTENTION retry

The first command down a (re)selected path routinely reports UA
(e.g. 0x29 power-on/reset) instead of executing.  CAW and WRITE-FUA
now reissue on `sense_key == UNIT_ATTENTION` (bounded, 5 tries,
2<<n ms backoff — mirrors `tools/caw_verify --retry-ua`); READ-FUA's
pre-existing generic retry already covered it.  Reissuing a CAW after
UA is safe: UA means the command did not run.

## CAW DLM changes that multipath testing surfaced (transport-level)

These are not dm-specific — they are CAW-transport gaps exposed by the
first FS-level CAW matrix runs (the June-era CAW work predated the
TCP-era coherency pipeline):

1. **Slot-carried dir handoff epoch** (`dlm/dlm_caw.h` slot fields
   `dir_epoch` + `last_ex_slot`, carved from the reserved pad).  The
   sess64 handoff-epoch design — what tells a re-acquiring node "a
   peer held EX since your cached base; adopt the on-disk image" —
   lived only in the TCP master.  On CAW the acquirer now bumps
   `dir_epoch` inside the same grant CAS whenever `last_ex_slot` names
   a different node; every grant records {epoch, handoff} in
   `ctx->grant_meta` (direct-mapped, like `slot_hints`), served to the
   XFS layer via `mxfs_dlm_caw_grant_dir_epoch/_handoff()` through the
   existing `mxfs_v5_dlm_inode_dir_epoch/_grant_handoff()` calls.
   Slot reclamation (last holder unlocks) can RESTART the counter, so
   on CAW the XFS adopt gate compares `!=` (and stamps by assignment);
   TCP keeps its monotonic `>` (`mxfs_v5_dlm_transport_caw()` selects).
   Without this: peer-created dirents invisible after barriers
   (posix_multi), stale-base dir RMW writebacks (P49-STALEBASE) and
   write-verifier shutdowns (P56-INCORE-DIFF) under dir_reuse.
2. **Membership beacon on CAW** (`v5_membership_beacon_caw`): the
   `MXFS-MEMBERSHIP active_count` line the harness convergence gate
   greps was emitted by the TCP engine only; CAW now emits it from the
   lease view on discovery-join and lease-expiry.
3. **FIX-20 phantom-reconcile escalation gated to TCP**: CAW BAST
   hints are multicast and re-sent ~100ms by every blocked waiter, so
   every NON-holder receives them too; escalating "repeated no-mirror
   BAST" into a serialized release made every bystander CAS the very
   slot the real contenders were negotiating (~1550 phantom releases
   in one 4-node dir_reuse run).  On CAW the `held==0` disk read that
   precedes the escalation is already ground truth — nothing to
   reconcile.
4. **`caw_lock` wait-path `granted_mode`**: the waiter-promote path
   returned success without setting `*granted_mode` (callers saw
   uninitialized stack — 1462 bogus P52-PARTIAL-GRANT warns per run).
5. **Unlock-vs-regrant race closure** (v0.6.2) — the 4-node dirent-loss
   family (mmap node4.bin / cv node3.txt / rv after_8 / uv 115-of-120,
   moving between tests run-to-run).  Genesis, µs-proven: a bast_process
   unlock's CAS retry loop raced a concurrent LOCAL slow-path re-acquire
   (P106-EXREL :264909 → P106-EXGRANT :265003 → on_disk_held=0 1.6ms
   later) — the release's -EAGAIN re-read saw the freshly re-granted bit
   and cleared it, leaving in-core CACHED-EX with the disk released.  The
   node then free-ran creates with zero cluster serialization while the
   real EX moved on: `dirland=1` completion tracing caught t1 and t4
   interleaving writes of ONE dir block for ~60ms, each climbing its own
   dirent-count ladder.  Closure (both directions, on the grant-meta
   table): (a) `releasing` flag set for the unlock's lifetime — the
   acquire's ALREADY-HELD shortcut (the only no-CAS grant) waits it out
   and re-probes; (b) `grant_seq` bumped by every grant-meta store — the
   unlock aborts its retry loop when it advances (any CAS-based local
   re-grant miscompares the unlock first, so the abort check always runs
   before a stale clear).  An aborted unlock leaves an inverse phantom
   (in-core NL, disk held) which P135-ORPHAN-RELEASE already self-heals.
   The sess51 `dir_ex_revalidate=1` defense (slow-path re-acquire per
   published dir EX-modify) reduced the failure ~100%→~20% but cannot
   close the no-CAS window; the v0.6.2 closure targets the genesis.
6. **Tombstone epoch continuity** (v0.6.1): a fully-released slot
   becomes a tombstone, and the old tombstone write zeroed the body —
   the only carrier of `dir_epoch`/`last_ex_slot` across an idle gap
   (all holders release, resource claimed again later).  The first
   cross-node grant after every idle gap then looked handoff-free
   (epoch restarted at 0, `last_ex_slot=NONE`) and the adopt gate
   never fired, so a stale cached dir survived exactly when handoffs
   are least observable.  `caw_tombstone_slot()` now preserves
   {resource, dir_epoch, last_ex_slot} through all three tombstone
   writers (unlock, release-all, dead-node purge);
   `caw_claim_inherit_epoch()` re-adopts them when a claim recycles a
   tombstone of the SAME resource (a different resource still gets a
   fresh epoch, and pre-mkfs ghosts fail the volume match).  The
   claim-empty grant now reports `handoff` from
   `caw_grant_epoch_update()` instead of a hardcoded false.  A
   repaired corrupt slot advances the epoch and drops `last_ex_slot`
   (unknown EX history ⇒ force every holder to reload).

## Test-rig notes (harness)

- `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw` — run.sh forwards
  MXFS_DEV to prep and to every test (all scripts already honored it).
- `tests/setup/prep_fs.sh` clears stale PR (register-ignore + clear)
  before mkfs: a hard node reboot leaves the LUN reserved (WE-RO) by a
  dead nexus and every unregistered write fails EBADE ("Invalid
  exchange").
- `tests/setup/prep_node.sh` resolves `/dev/mapper/*` symlinks
  (`readlink -f`) and widens the SCSI command timeout on the dm
  device's `slaves/*` paths.
- SCST multi-value attributes render as `allowed_portal`,
  `allowed_portal1`, … — glob when checking (scripts/mpath_up.sh).

## Verification state

See `criteria.json` (`./showstat.sh N caw`) — the matrix ladder
1/2/4/8/16/32 nodes is tracked there; `.ccmemory/`
`caw-multipath-matrix-progress` holds the session log.
