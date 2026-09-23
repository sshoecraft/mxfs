# The single-to-multi join transition

What happens on a mount when its first peer appears, why it is shaped the way
it is, and what is still open. The code is `mxfs_dlm_join_prepare` /
`mxfs_dlm_join_commit` (`xfs/xfs_mxfs_dlm.c`), the join worker in
`dlm/v5_mount.c` (`v5_join_queue`, `v5_join_worker_fn`, `v5_join_transition`)
and the membership-settle gate in `dlm/dlm.c` (`dlm_membership_settling`,
`dlm_view_pending_live`, the gate at the top of `mxfs_dlm_lock`).

## The problem the transition exists for

Until 0.87.16 a mount that had never had a peer ran no inode ownership
protocol: the inode-lock entry bypassed the DLM (`mxfs_v5_dlm_never_multi`,
0.83.3), `i_dlm_mode` stayed NL, inode-cluster and directory-block writes were
whole-buffer writes, and file data sat in the page cache until writeback.
Nothing at any DLM master represented what such a mount held dirty.

0.87.16 removed that state (`docs/sole-survivor-sweep.md`): a lone mount
takes real inode grants from the master (itself) exactly as its AG grants
have been real since 0.41.0, because the replayer of its slice after a death
needs the grant behind every inode-owned image it logged. So the incumbent's
inode ownership IS represented at the master when its first peer appears, and
the newcomer's conflicting acquire revokes it through the ordinary BAST
drain, as it does a sole survivor's. What the transition still provides is
the rest of this section: file data in the page cache and cached views that
were populated on the non-FUA single-node read path are still unrepresented,
and the freeze below is what makes them durable and dropped before the
two-node view is installed. The cached-view walk retains every grant, AG and
inode, by design (0.41.0: surrendering a grant while journal records bearing
its token can still require replay would make them `staleep` to a replayer).

Before 0.87.16, the moment a peer could take a grant on the same numbers,
that state was unrepresented ownership:

- the master has no record of it, so the peer's acquire raises no BAST and
  reads the platter's older image;
- whichever side flushes last reverts the other, or the incumbent's image is
  refused by a multi-node write rule (a logged directory dinode at NL without
  a release token is never published) and never lands;
- for a shortform directory the incumbent's own next access re-acquires under
  a grant and a reload merge re-applies the delta, and for a block directory
  the whole in-core block is relogged — which is why every reproduction that
  let the incumbent touch its objects again after the flip measured nothing.

## The invariant

Before the newcomer can use shared state under a grant, every modification
the incumbent made without a grant is durable on the platter, its cached
views are dropped, and no further modification without a grant can occur.
Two halves enforce it, one on each node.

### Incumbent: freeze-ordered prepare, view installed under the freeze

On its first sight of a peer the incumbent queues the sighting to a join
worker and returns; the discovery (lease UDP) and TCP-accept threads keep
serving liveness and lock traffic. The worker:

1. `mxfs_dlm_join_prepare`: on a born superblock, `freeze_super` with the
   kernel holder. New writers and page faults block, `sync_filesystem`
   writes back every dirty page, `xfs_fs_freeze` quiesces the log (force,
   AIL push to empty, cover). Then the cached-view walk drops AG-meta and
   inode-cluster views and marks every clean, unlocked, unpinned other block
   (directory data/leaf/node, bmbt, symlink) for a re-read; readers may
   still hold buffer locks, so the walk repeats briefly. Returns 0 with the
   freeze HELD.
2. Registers the peer in the lease, adds/connects it on the mesh, refreshes
   the view (`mxfs_dlm_update_active_nodes`: lock-table purge, epoch
   advance, membership callback → the sticky `ever_multi` bit).
3. `mxfs_dlm_join_commit`: thaw.

After the thaw every modification takes a real grant. The peer is
registered only after prepare succeeded, so no other path (a death, a
recovery completion, a reconnect) can install or beacon a view that includes
it earlier.

A prepare that does not succeed leaves nothing frozen and nothing installed;
the worker retries. This replaces a bounded set of destage rounds that raced
the node's own workload and, when they lost, force-shut the filesystem down —
a join preparation that has not finished is not a corruption, and the
shutdown was the data loss it claimed to prevent (measured: every unsynced
byte on the incumbent).

A mount still in progress (the newcomer's side of every join, and a peer
sighted before the XFS layer wired its callbacks) keeps the unfrozen destage
rounds: it has modified nothing of the user's, and a freeze would block on
`s_umount` for the whole mount while the incumbent waited on its beacon.

### Newcomer: admission on positive readiness, not on a timer

The lease beacon carries `{count, view-hash}`, and the incumbent's hash
changes only when it installs its view — after prepare. The settle gate at
the top of `mxfs_dlm_lock` therefore holds EVERY acquiring mode (PR as well
as EX; a shared read served before the incumbent's drain is a stale base for
the EX that follows it, and nothing can correct it) until every member's
beacon received after the local view change carries the local view.

The gate is fail-closed. The wall-clock window still opens the gate over a
member that has not beaconed at all (the lease declares a silent peer dead,
which is a new view), but not over a member whose beacons are arriving with
a different view: that member is alive and has not admitted this membership.
An acquire whose bounded wait expires in that state is refused with `EAGAIN`
rather than served.

## What it does not cover, and the long-term shape

- Dentries cached before the transition are not revalidated by it; the
  cluster dentry revalidation applies as for any other node.
- The grant-serving side does not itself refuse a request while its own
  view is settling; ordering rests on the requester's gate plus the beacon
  carrying only an installed view.
- The transition still manufactures ownership after the fact. The design
  consult's long-term recommendation is to remove the never-multi bypass
  altogether: a lone node takes grants from itself as master, exactly as a
  sole survivor does since 0.83.3, so dirty state always has a represented
  owner, a first join is the rejoin path, and none of the above is needed.
  Two conditions must hold before that ships: master handoff at the
  membership change must incorporate existing holders before granting a
  conflicting request (a protocol invariant, not a timing expectation), and
  land-before-release must include file data (the BAST drain writes log and
  AIL, and ordinary file payload is not journaled).

## How it is measured

`tests/d0959_first_join_peermod.sh`: the incumbent adds round-robin over 96
objects (32 block directories, 32 shortform directories, 32 files) and stops
within milliseconds of its membership line; the newcomer reads every object
cold, modifies each, syncs; both leave and each remounts cold. The verdict is
per object. Expected on a correct transition: no shutdown, no loss, the
newcomer's first cold read complete, `P-JOIN-FREEZE` → invalidation complete
→ `P-JOIN-INSTALLED` → `P-JOIN-THAW` on the incumbent, and a
`P-D7-SETTLEGATE ... confirmed=1` on whichever node installed its view second.
