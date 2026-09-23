# The offline checker, the block device's page cache, and local exclusion

Design-consult ruling (Astra, 0.89.6) on the last three buffered readers of
the shared device in the userspace tools: chk_mxfs's main check descriptor,
and the silent non-direct fallbacks in mkfs_mxfs and resize_mxfs.  The
question brought: whether an invalidation of the device's cached pages at
open is correct and sufficient for the checker, whether the whole checker
must move to aligned direct I/O, and whether the format and resize tools
should warn or refuse when they cannot open the device direct.

## The mechanism the ruling is about

The kernel module writes the LUN with bios.  Those never touch the block
device inode's page cache.  A buffered read from userspace populates that
cache once, and the kernel drops it only at the device's LAST close.  So on
a node where any opener still holds the device — its own mxfs mount above
all — a buffered reader is fed the first image it (or any earlier buffered
reader) cached, for as long as the device stays open.  On a node that has
unmounted and holds nothing else, the same read looks live, which is why
the tools "worked" in every unmounted-node run.

## What an invalidation at open does and does not give

- `BLKFLSBUF` synchronises the device and drops its clean, unpinned cached
  pages.  An open reference by another process does not pin those pages, so
  the leftovers a completed buffered reader left ARE dropped even while the
  module holds the device.  That is the ordinary case measured on the rig
  and it is what the checker's invalidation fixes.
- It is not a certificate that every page is gone: pages that are locked,
  dirty, under writeback or mapped survive, and the ioctl does not report
  them.  It is not coherence afterwards either: a block the checker reads
  is cached from then on, and a peer's later write to that block is
  invisible to a re-read within the same run.  On a quiescent device that
  window contains nothing; on a live one no checker design closes it.
- It needs `CAP_SYS_ADMIN` and fails with `EACCES` as readily as `EPERM`.
  On a block device a failure is an abort of the whole check: a read-only
  checker that cannot say what it read can still print a false corruption
  report.  A regular-file image has no such cache to drop.
- It can cause writes on a read-only descriptor: dirty pages some OTHER
  buffered writer left are written back, and if the module's bios have
  since superseded those bytes the writeback overwrites newer platter
  contents.  That is a pre-existing mixed-I/O violation the flush would
  expose, not create; the project has no buffered writer of the shared
  device, and a stale page a buffered READER left is clean and cannot do
  this.
- `posix_fadvise(DONTNEED)` is advisory, unchecked, and not a substitute.

## The checker's contract

The check is an offline check.  A node whose own module holds the device is
not offline, and a check run there is not made valid by dropping the cache
first: the answer is a refusal, not a verdict read through that mount.  So
the main descriptor is opened `O_EXCL`, which the kernel refuses with
`EBUSY` while an exclusive holder (a mount, a mount in progress) has the
device on this node.  This is LOCAL exclusion only.  A peer's mount is not
visible to it, and "no heartbeat advanced while I sampled" is not
exclusion either: a node may be stalled, a mount may start after the
sample, writes may be in flight.  Cluster quiescence remains the caller's
obligation, and a harness that checks the platter from one node while the
other is mounted is checking a moving target and must say so in its own
assertions.

A full aligned direct-I/O layer under the checker's read and write wrappers
would make the cache-bypass unconditional, but its write side is a
read-modify-write of enclosing aligned units that can lose a concurrent
neighbour's bytes, so it is only correct under the same offline contract —
it does not turn the checker into an online one.  Not done at 0.89.6; the
invalidation plus exclusion covers the measured class.

## mkfs and resize: no buffered fallback on a block device

`O_SYNC` is not `O_DIRECT`: it changes when a write is durable, not what a
read returns.  A format verified through a buffered descriptor verifies the
page cache's copy of the bytes; a resize planned from a buffered read of
the geometry is planned against a different filesystem than the one on the
platter.  A warning would be ignored by the next harness or operator.  So
on a block device the direct open either succeeds or the tool stops, and
the fallback exists only for a regular-file image whose filesystem has no
direct I/O, recognised by the open's own error (`EINVAL`, `EOPNOTSUPP`) and
announced.  A failed direct open does not prove the target is a file:
permissions, resource limits and a vanished device fail it too, and they
are reported as what they are.  Resize's DISCOVERY read was buffered as
well, and fixing only the write reopen cannot undo a decision already made
from stale metadata — both descriptors are direct now.

## Still true whatever the descriptor's flags

- Direct I/O bypasses this node's page cache, not the target's volatile
  cache, and it is not a snapshot: one read racing a peer's write can see
  old bytes, new bytes or a mix across sectors.  A live heartbeat or ledger
  reader needs its own stamp/checksum discipline; equal bytes on two reads
  is not a consistency proof.
- Alignment is the LOGICAL sector size (`BLKSSZGET`), not the physical one,
  and a 512-byte read of a slot on a 4Kn LUN is not made valid by a
  4096-aligned buffer — read the enclosing unit and extract.
- Persistence is a separate question: `O_DIRECT` implies none; `O_SYNC`,
  flush and FUA handling do.
