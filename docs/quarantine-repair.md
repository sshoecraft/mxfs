# Accepting a refused slice: the offline quarantine repair

`chk_mxfs --accept-quarantine-loss SLOT --confirm DIGEST --archive-to PATH`

A terminal replay refusal is permanent by design.  The refused slice's committed
transactions were never applied and cannot be applied safely, so the slot that
names them stays unclaimable and every gate keeps refusing it.  The only way
back that preserves the filesystem is the operator ACCEPTING that those
transactions are lost.  This document is the design of that operation; the
rulings it implements are `docs/rulings/quarantine-slot-repair-design.md` and
`docs/rulings/2-archive-magic-slice-reinit.md`, and where this design departs
from them it says so and why.

## The two shapes a refusal takes on the platter

- **GUARD**: an ordinary recovery (a survivor's foreign replay, or a bootstrap
  replaying a victim slice it did not adopt) refused the slice.  The victim's
  slot holds a `RECOVERY_GUARD` record whose descriptor is `QUARANTINED` and
  whose outcome record is the verdict.
- **ADOPTED**: a whole-cluster bootstrap owner adopted victim slot K as its own
  log (`docs/whole-cluster-restart.md` §6.5 shape B) and K's FULL replay was
  refused.  K's sector holds the ADOPTER's `ACTIVE|BOOTSTRAP_PENDING` record;
  the verdict is the bootstrap record itself — `REFUSED`, reason
  `TERMINAL_SLICE`, `refused_slot` K — and its escrow, `K_REPLAY_REFUSED`, which
  carries the victim's destroyed descriptor, certificate, tuple and manifest
  pointer byte for byte.

The repair accepts either shape directly.  For ADOPTED it does NOT first turn
K back into a guard: that would need a userspace tool to forge a kernel verdict
(a QUARANTINED descriptor and an outcome record the kernel never wrote, with a
reason code that does not exist), and it would leave the adopter's retained
identity explained by no record.  The escrow already is the durable verdict.

`chk_mxfs --show-quarantine` prints both shapes and their VERDICT DIGEST: for
ADOPTED the digest binds the volume uuid, K, K's sector and the whole bootstrap
record.  Read it after the last node has unmounted — an unmount re-stamps a
guard's owner fields, which changes the digest.

`chk_mxfs --clear-bootstrap` refuses a term whose escrow is
`K_CLAIMED`, `K_REPLAY_OK` or `K_REPLAY_REFUSED` while K still holds the
adopter's record.  Clearing it used to zero the escrow and leave K's sector
naming the adopter, so the next term judged the VICTIM's slice against the
adopter's (empty) grants and refused every transaction — measured: term 15
refused 2 of 395, term 16 refused all 395.  For `K_REPLAY_REFUSED` the refusal
names `--accept-quarantine-loss K`.

## The order, each step durable before the next

| step | what | volume changed |
|---|---|---|
| 1 | validate and display the verdict; `--confirm` must quote its digest (GUARD: volume uuid + slot + sector; ADOPTED: that and the bootstrap record) | no |
| 2 | exclusion: O_EXCL, no heartbeat advancing across 10 s, and the device half (SCSI: no PR registrant; DRBD: see below) | no |
| 3 | every other slot settled: EMPTY (a clean release), zero, or a bare sweep guard; anything else is named and refuses | no |
| — | transport: the slot's feature block must validate and show TCP (see "CAW") | no |
| lock | the ADMISSION LOCK (below), then step 2 and 3 again under it | bootstrap record, journal |
| 4 | archive OFF the volume, on storage proven disjoint: the verdict, the sector(s) verbatim, and the whole slice as `PATH.slice`; fsync, reopen, re-verify | no (off-volume) |
| forecast | the repair passes of step 7 with every write suppressed | no |
| 5 | LOSS_ACCEPTED in the journal: the point of no return | journal |
| 6 | the slice's lifecycle record to ZEROING, then every byte of the slice overwritten, flushed and read back zero | slice, lifecycle record |
| 7 | two repair passes and one check-only pass over the WHOLE filesystem; the last must be clean | metadata |
| 9 | the slot's sector, still byte-identical to the archived one, to a zero record; then the bootstrap record to IDLE (term carried forward) | slot, bootstrap record |

There is no step 8 record of its own: CHECK_COMPLETE is the journal phase
written after step 7's clean pass, carrying the passes' counts.

Every exclusion-dependent step (5, 6, 7, 9) re-proves the device half first.

## The admission lock and the repair journal

The ruling asks for a durable maintenance owner that keeps every node out for
the whole repair.  Checking exclusion once at the start does not: a node could
mount during the slice reset.  The lock is the bootstrap record in state
`REFUSED`, which every mount refuses before it registers anything
(`v5_bootstrap_peek`), whatever the reason — no kernel change.  An IDLE or
RECOVERY_COMPLETE record becomes `REFUSED` with reason `OPERATOR_REPAIR` (6),
owner `0xFFFFFFFF`, owner nonce = the run's nonce, host/boot = the running
host's machine-id and boot_id.  A record the kernel already REFUSED over the
same slot is the lock as it stands.  A CLAIMED/SEALED/RECOVERING term belongs
to its owner and refuses the repair.

The ruling placed the repair phase "in the still-guarded source descriptor".
The guard sector has no free bytes — header, descriptor, outcome, manifest
pointer, obligation record, identity, provenance, membership epoch and feature
block fill all 512, each crc-bound to the victim — so the phase lives in the
REPAIR JOURNAL instead: sector 56 of the bootstrap region (sector 57 keeps the
record as the repair found it).  The kernel never reads sectors 51-63, and mkfs
zeroes them.  What the ruling's placement served still holds: the guard (or the
adopter's record) is not touched until step 9, and from LOSS_ACCEPTED on the
lock stays until the repair finishes.

After any crash the volume is in one of: the original refusal (nothing taken);
locked with nothing lost (a re-run resumes, `--clear-bootstrap` may hand the
lock back); locked past LOSS_ACCEPTED (only a re-run that finishes may release
it — `--clear-bootstrap` refuses); finished.  A re-run resumes only for the
same slot and the same verdict digest, and re-verifies the archive.

## Step 6: the canonical empty log

The kernel's own slice initialisation is the lifecycle record
(`MXFS_FORMAT_F_SLIFE`): a claimant finding a slice INIT_REQUIRED or ZEROING
zeroes the whole payload through the FUA path, reads it back and persists READY
before it mounts the log (`mxfs_slife_claim_init`), and a foreign recovery
skips such a slice as holding no record.  The repair writes ZEROING FIRST, so
from that moment nothing can trust or replay the slice, then overwrites and
reads back every byte itself, so the invariant "no pre-repair sector of the
slice can take part in discovering a log record" holds before the slot is
released, not only after the next claim.  The next claimant re-zeroes it
through the kernel and marks it READY: the empty log is made by the same code
that makes every other one, never hand-constructed headers.

## Step 7: what a discarded slice leaves, and the repair

Log recovery makes metadata consistent by replaying whole checkpoints.  A
discarded slice cannot be replayed, and before the victim died AIL writeback may
have put some of its checkpoints' buffers home and not others.  So the image
the discard leaves is, object by object, as of some committed checkpoint — a
MIX across objects.  The classes, and what covers each:

| left behind | checked by | repaired |
|---|---|---|
| a fork naming a block the free-space btrees call free | `Inode fork ownership` (new) | yes: the AG's BNO/CNT leaves rebuilt without fork-owned blocks, AGF freeblks/longest from the result |
| a fork naming a block inside an inode chunk, or two forks one block | `Inode fork ownership` | no: the repair stops, the slot stays quarantined |
| a name for an inode the inobt calls free, an inode no name reaches, a wrong link count | `Directory entries` | no |
| inode chunk blocks free in BNO | `Chunk/free-space aliasing` | no |
| AGF counters disagreeing with their trees | free-space walk | yes (existing) |
| superblock icount/ifree/fdblocks | summary | yes: fdblocks is now Σ(freeblks + flcount + btreeblks), the kernel's own formula; it used to be the BNO sum, low by every AGFL |
| blocks allocated in BNO that no fork names (a free that reached the fork but not the tree) | not checked | not needed: a leak loses space, never data |

The fork pass is new and it is the one that matters: the checker called the
first reproduced image "filesystem clean" while 51 blocks of AG 5 were named by
inode data forks and free in the BNO btree, so the allocator could hand them out
again over live files the moment the quarantine's AG fence was lifted.  The
repair gives the blocks to the forks — what `xfs_repair` does when it rebuilds
free space from the blocks it found in use; the files keep their data.

The repair is deliberately narrow: both free-space trees of the AG must be one
leaf before and after, and the free map must equal the AGF's count (a tree not
read whole cannot be rewritten from what was read).  Anything outside the
repaired classes fails the FORECAST — the passes run with writes suppressed
before LOSS_ACCEPTED, on the very image step 7 will see, because discarding the
slice changes no home metadata — and the repair stops with nothing lost and the
lock handed back.

The domain is the whole filesystem: until a proof that a quarantine's AG mask
is closed over every effect of the discarded transactions exists, every accepted
quarantine is FSWIDE (the ruling).

## DRBD exclusion

`/dev/drbdN` has no SCSI target, so the PR half cannot be asked.  A replica's
only writers are this host (O_EXCL proves it) and the peer, over the replication
link.  `/proc/drbd` must show this replica Primary and the peer either Secondary
or the link down (StandAlone, WFConnection, ...): a peer write cannot reach the
replica then, and a peer that reconnects and is promoted is caught by the
recheck before the next destructive step, while the admission lock keeps its
mount out.  A DRBD 9 `/proc/drbd` (no per-minor state) refuses.

## CAW

On the TCP transport a vanished incarnation's authority-ledger pages become
takeover-eligible once its sector is a zero record (the settled-owner rule,
`mxfs_disklock_incarnations_settled`), so releasing the slot settles them.  On
CAW the victim's grants sit in the on-disk lock table and stay frozen under the
quarantine; this repair does not purge them, so it refuses a slot whose record
does not validate as TCP.  Releasing a CAW quarantine needs that purge first.

## Still open

- CAW lock-table purge of the accepted incarnation (above).
- A bootstrap term that refused one victim while other sealed victims are still
  unreplayed: step 3 refuses on their guards, and the term cannot be cleared
  without judging K against the adopter, so neither side can move.  Likewise a
  term refused elsewhere after adopting K (`K_CLAIMED`/`K_REPLAY_OK`).
- SCSI: two repair runs on two hosts at once both see "no registrant"; the lock
  write is not a compare-and-write from userspace.
- Multi-level free-space trees in an AG that needs the fork repair.
- The ruling's crash matrix (every durable transition, torn writes) and the
  on-volume archive ledger in slots 32..63 (the archive here is off-volume only).
