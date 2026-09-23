# The sole-survivor guard class

A guard that asks "am I the only node right now" switches itself off at exactly
the moment a departed peer's residue is on the platter and nobody is left to
publish it. There are 77 such guards in this tree. This document is the class,
the queue that tracks it, and the criterion for closing it.

The predicate to reach for is `mxfs_v5_dlm_sole_survivor()`, not
`mxfs_v5_dlm_is_single_node()`. The difference is the whole subject.

## The predicate, and why the obvious one is wrong

`mxfs_v5_dlm_is_single_node()` answers **"is this mount single-node right
now"**. `mxfs_v5_dlm_sole_survivor()` answers **"has this volume had another
node during this mount, and is it alone now"** (`ever_multi && single_node`,
`dlm/v5_mount.c:17360`).

Many guards ask the first when the question they need answered is the second,
because *that* is what decides whether anybody else can still hold a view of
the metadata in hand. Every such guard switches itself off at the moment a
departed peer's residue is on the platter and nobody is left to publish it.

**Measured, `tools/sole_survivor_audit.py` (new, sess574):**

```
77 guards that skip work, out of 394 is_single_node() references
10 references to sole_survivor()
```

Run `tools/sole_survivor_audit.py` for the grouped list by file+function,
`--inverted` for the `!is_single_node()` sites, `--csv` to diff two revisions.
The 394-vs-10 figure quoted in earlier sessions counted every reference,
including instrumentation; **77 is the number of guards that actually skip
work**, and it is the one to work against.

`mxfs_v5_dlm_sole_survivor()` (`dlm/v5_mount.c:17360`) exists *precisely*
because **"the single-node fast paths must keep honouring the invalidations the
departed peer left behind."**

**Generalisable:** any `is_single_node()` test on a durable, on-disk-visible
decision is suspect. The safe predicate for anything that outlives the moment is
`sole_survivor()`.

## There is no third predicate: the ownership protocol has no membership exemption (0.87.16)

A guard of the shape "skip this work if single-node" has NO correct spelling
when the work is an ownership, freshness or publication decision. Every mount
with a DLM takes real grants from the master — itself, when it is alone —
whatever its membership history.

0.83.3 introduced `mxfs_v5_dlm_never_multi()` (`is_single_node && !ever_multi`,
the complement of "multi now, or a sole survivor") as the one state allowed to
modify and publish an inode without a grant, on the argument that such a
mount's caches hold nothing but its own images and no successor writer can
exist for anything it logs. That argument covers live coherency only. After a
death the replayer of the victim's slice — a survivor, or the same node's next
incarnation — is the successor writer for everything the victim logged, and
the replay authorizes each inode-owned image (directory block, bmap-btree
block, remote symlink or attribute block) only against the durable grant the
owning inode held when the image was captured. A never-multi mount's inodes
had no DLM mode, no authority state and no grant, so every such image shipped
`AUTH_NOT_HELD`; the replay refused the whole transaction and quarantined its
AGs (s53f: a lone mount's mkdir + 40 creates + fsync, killed within a second;
AG 0 quarantined cluster-wide, root lookups EIO, the fsynced files unreachable).
Proven by instrument before the change (`tests/lone_dir_block_authority.sh`,
s54a/s54b): 45 non-durable captures of the directory's block on the lone
mount at authority NONE / DLM mode NL, zero with a peer mounted. The AG path
had no such exemption since 0.41.0, which is why the same transaction's six AG
images were VALID.

0.87.16 therefore removed the predicate and every site keyed on it (the table
below now describes what runs on EVERY mount). The 2026-09-18 design consult's
corrected invariant: being alone permits omitting coordination with live
peers; it does not permit omitting the durable authority a future incarnation
or foreign replayer needs. A local `UNPUBLISHED_EX` tenure remains what a new
inode gets on create (the deferred-publish list is the accepted cost model —
no eager publish-on-create); it is not authority for logging a block outside
the inode core, which is why a directory publishes at its first EX modify and a
metadata-owning file before its first out-of-core image, on a lone mount
exactly as with a peer.

Why 0.83.3 chose a predicate and not "take the partial path for a sole survivor" (the
first D-0955 fix, measured and withdrawn in sess583): the multi-node
publication filter in `mxfs_submit_partial_inode_write()` refuses a logged
directory at NL without the release-drain token. Under multi-node that is
right — NL means released to a successor, and the BAST drain sets the token.
Under the single-node bypass `mxfs_dlm_ilock_begin` takes no lock and sets no
mode, the new-inode grants (`grant_local_new`, `rearm_unpublished`) are gated
off, and no BAST ever fires. So a sole survivor on the filter alone had every
logged directory at NL with no token, and none of them could reach the
platter: its freshly created directory was dropped, then poisoned ESTALE by
the next reload (799 of 800 creates failed), and its root directory only
landed because the A/B harness alternated with the pre-fix whole write.

The design-consult ruling (sess583): the partial-write filter, the grant paths
and the release drain are one protocol; enabling the filter without the grants
is not "the multi-node path". A sole survivor therefore runs the ordinary
protocol against a master that is itself — and since 0.87.16 so does a mount
that has never had a peer. The sites that were keyed on `never_multi` and now
run unconditionally:

| site | decision |
|---|---|
| `mxfs_dlm_ilock_begin` bypass / `mxfs_dlm_ilock_end` gate | take and release real grants |
| `xfs_iget_cache_miss` (`grant_local_new`) / `mxfs_dlm_rearm_unpublished` | new incarnation gets local unpublished EX |
| `xfs_iget_cache_miss/hit` stale-shell reloads | freshness of a recycled number |
| `mxfs_dlm_publish_dirs_work` / `mxfs_dlm_publish_inode` | publish so a rejoining peer BASTs |
| `mxfs_submit_partial_inode_write` / `mxfs_dino_clobber_probe` (via `sole_survivor`) | mask un-logged no-tenure slots; measure |

Peer-signalling shortcuts stay on `is_single_node()`: the heartbeat-ring notes
(`note_inode_freed`, `note_dir_modified`), the CAW dir barrier, the
leaf-before-dinode flush, the open-bits publish. They have nobody to signal,
and a rejoining peer reads cold.

One thing the same ruling names as owed by the class, not by D-0955: the
remaining `is_single_node` guards in the census below still need classifying
as peer-signalling (allowed) or ownership (not allowed). The other hazard it
named — a never-multi mount receiving its first peer with dirty NL images no
join barrier drains — no longer exists: the incumbent holds real grants, which
the join transition retains by design (`docs/join-transition.md`) and a
newcomer's conflicting acquire revokes through the ordinary BAST drain.

## History of this class

- **D-0904** closed it on *one* call site (`FIXED AND VERIFIED`). The rest were
  never swept.
- **D-0949** (sess573) found another: the inode-chunk keep guard. It had
  deleted **187 chunks in a single lap** — essentially every chunk a
  12000-file workload carved — and had never printed a line, because its only
  probe sat inside a branch requiring not-multi-node while itself requiring
  multi-node. Fixed in 0.75.125.

## The census and the work queue

| thing | what it is |
|---|---|
| `tools/sole_survivor_audit.py` | the census + the gate + the classifier |
| `tests/criteria/sole_survivor_sites.json` | the reviewed inventory — a WORK QUEUE, not a tally |
| `tests/tooling/guard_census.sh` | board row; red when a guard appears the inventory does not account for |

```sh
tools/sole_survivor_audit.py                    # grouped report
tools/sole_survivor_audit.py --csv              # file,line,function,shape
tools/sole_survivor_audit.py --check            # the gate (exit 1 on a new site)
tools/sole_survivor_audit.py --baseline         # re-record, PRESERVING classes
tools/sole_survivor_audit.py \
    --classify 'file::func' durable 'the reason'  # repeatable; writes + exits
```

### State at end of sess574

**75 sites tracked, 77 live guards. Classified 8; 67 unclassified.**
`durable` 4 · `recovery` 1 · `instrument` 2 · `epoch` 1.

## The four classes

The axis is **not** performance vs correctness. It is *what fact makes the
skipped work unnecessary, and what stops that fact changing mid-operation.*

- **`epoch`** — transient coordination, elidable **only while an exclusion
  against peer admission is HELD for the whole operation**. A bare "am I alone"
  boolean is a TOCTOU observation and does not qualify.
- **`durable`** — the skipped work leaves state a future or rejoining peer can
  observe (publication, allocation/reuse validation, write masking,
  invalidation obligations, ownership). Maintain regardless of membership, or
  convert explicitly before admitting a peer.
- **`recovery`** — depends on the **departed peer's disposition** (clean
  handoff / unfenced / fenced-but-unrecovered / recovered per-AG), not on
  member count. Often scope-specific: recovering one peer or one AG proves
  nothing about the rest.
- **`instrument`** — a probe. Skipping costs measurement, not correctness — but
  record it anyway: an unreachable probe is exactly how D-0949 stayed invisible
  for the life of the project.

## D-0949 — the inode-chunk keep guard

sess573, tree 0.75.123. Filed as
`D-INODE-CHUNK-KEEP-GUARD-OFF-FOR-SOLE-SURVIVOR-PROBE-UNREACHABLE-0949`.

`xfs_difree_inobt` normally (upstream) deletes a fully-free inode chunk and
returns its blocks to the AG free pool. MXFS **keeps** the chunk in multi-node
mode, because otherwise a directory can reallocate those blocks and write dir
data over an inode cluster. The guard's own comment names the consequence:

> dir data is written over the inode cluster -> the cluster fails its verifier
> on the next read (imap_to_bp rc=-5 EIO) / dialloc sees inobt incoherent
> (-117) -> forced FS shutdown

The guard tests `mxfs_v5_dlm_is_single_node()`. That is **dynamic membership**,
not configuration — `dlm/v5_mount.c:17317` says so itself: *"Single-node again
after multi-node membership is a legitimate, durable state: the sole survivor
of a peer's death (or of a peer's departure)."*

So on a 2-node cluster, from peer death until rejoin, the guard is off.

### Two corrections to D-0948 established here, both without a rig run

1. **The `XDD3` was not a stale cache read.** `mxfs_buf_coherent_reread_verify()`
   (`pal/linux/xfs_buf.c`) re-reads via `mxfs_pal_scsi_read_fua_bdev` (SCSI
   READ(16)+FUA) whenever `mxfs_fua_disable` is off — the default. The eight
   retries logged `P-DIRCRC-RETRY-FAIL ... durable, not transient`. The medium
   really holds dir metadata at that block. (This killed my own first
   hypothesis, that the "coherent" plain read was serving stale bytes.)
2. **`chk_mxfs` clean never supported "the block belonged to the chunk."**
   `tools/chk_mxfs.c` has **no** block-ownership map and no cross-tree
   duplicate detection: check 5 validates the free-space btrees against
   themselves, check 6 the inode btrees against themselves, never against each
   other. Its verdict is *silent* on this class, not evidence against it.

### What was added

- `chk_mxfs` cross-tree audit: bitmap of inobt chunk blocks (honouring
  holemask) AND bitmap of BNO free extents; a block in an allocated chunk must
  never also be free. Offline, no race to catch, runnable on the LUN after any
  lap. Prints `Chunk/free-space aliasing . OK/ERRORS`.
- `P103-CHUNKFREE` made reachable, carrying `sole=0/1`, plus an unbudgeted
  `P103-CHUNKFREE-SOLE` alert.
- `P949` in `mxfs_dbg_disk_di_read_coherent`: on a no-magic home, FUA re-read
  the same LBA and classify — `PLAIN-STALE` / `HOME-FOREIGN` (non-zero
  foreign metadata, unbudgeted, with bytes) / `HOME-EMPTY`.

**The decider is cheap:** if `P103-CHUNKFREE-SOLE` never fires on a death lap,
D-0949 is disproved and D-0948 needs another root.

## The three candidates instrumented in 0.75.126

#### 1. `mxfs_submit_partial_inode_write()` — `pal/linux/xfs_buf.c`
The cross-node false-sharing protection: omits the sectors of in-core inodes
this node released to a peer, because a cached image of a slot we no longer own
is stale prior-tenure and whole-writing the cluster reverts the peer's durable
inode (the function's own comment names BUG1 file / BUG2 dir). It also carries
`P218-CLUSTER-AUTHORITY`, the **always-on** detector for writes carrying slots
this node neither logged nor holds. A single `is_single_node()` test at the top
disables the protection *and* makes the detector unreachable in the same
breath.
- knob `partial_iwrite_sole=1` → sole survivor enters the function, detector runs.
- Read `P218-CLUSTER-AUTHORITY ... no_write_tenure= gen_mismatch= no_incore= -> WHOLE|PARTIAL`.

#### 2. `mxfs_dialloc_two_phase()` — `xfs/libxfs/xfs_ialloc.c`
The D-0351/D-0946 containment: reads a picked inode's platter home before
anything is dirtied and refuses a number whose home carries a live dinode.
Gated the same way — and at the same instant `mxfs_ag_inode_owned()`
(`xfs_ialloc.c:3502`) returns true for **every** AG, so the survivor starts
picking numbers out of the departed peer's AGs it has just stopped checking.
- probe `P951-VALIDATE-OFF-SOLE` counts the unvalidated path (capped 40).
- knob `dialloc_validate_sole=1` keeps the validator running for a sole survivor.

#### 3. The publication guards — `xfs/xfs_mxfs_dlm.c`
`MXFS_SOLE_SKIP_NOTE()` (macro in `xfs/xfs_mxfs_dlm.h`) prints
`P952-SOLE-SKIP site=<name>` at hit 1, 100 and 10000 per site. Placed on seven
publication/durability guards: `publish_inode`, `publish_dirs_work`,
`rearm_unpublished`, `note_inode_freed`, `dir_durable_signal`,
`iflush_force_bmbt_durable`, `iclus_publish_open_bits`.

`mxfs_dlm_publish_inode()` is the sharpest of these. Its job is to give a newly
created inode a real on-disk DLM slot, and its own comment says why: without
one, *"a peer acquires the empty slot cleanly, never BASTs"* — so the survivor
never drains or flushes and the peer reads stale. A sole survivor skips it, and
in a 2-node cluster the peer **comes back**.

## How to measure all three in one lap

`tests/d0946_disklive_knob_vs_aging.sh` gained an opt-in sole-survivor
pre-phase:

```sh
MXFS_D0946_SOLE=umount MXFS_D0946_KNOB=partial_iwrite_sole \
  tests/d0946_disklive_knob_vs_aging.sh <label> 8 400 tight
```

It ages both nodes, removes the peer (`umount` = clean, `death` = virsh
destroy), **waits for `P-SOLE-SURVIVOR` to actually be observed rather than
assuming the transition**, refuses to run if it never fires, then alternates the
named knob in place across rounds on the survivor and restores the peer at the
end. Per-round it counts `P951=`, `P218=`/`PASS*=`, `P952=`/`P952SITES=`
alongside the existing D-0946 counters, each windowed to that round's own kmsg
marker.

## Traps already hit in this tooling — do not re-introduce

1. **Instrumenting a guard removed it from the census.** A probe line between
   the test and its `return` defeated a next-line-only scan; the count fell
   **77 → 70** the instant seven guards were instrumented. A safety census that
   shrinks when you look at something is worse than none. The scan now steps
   over probe/comment lines and stops at a closing brace or any real work.
   **If this number ever drops, suspect the census before believing the tree.**
2. **Converting a guard removed it from the queue.** Rewriting a site into a
   nested decision (or deleting the membership test) drops it out of the census,
   and a live-only inventory silently discards the classification *and the
   reasoning*. The two best-understood sites — `mxfs_submit_partial_inode_write`
   and `mxfs_dialloc_two_phase` — left the census the moment they were touched.
   Converted sites are now retained with `guards: 0`, class and note intact.
3. **Keys are `(file, function)`, never line.** A line-keyed baseline fails on
   unrelated edits and gets switched off within a week — which is how the two
   previous closures ended up unenforced.

## Rules for using the queue

- **Re-baselining to clear a red is the same act as widening a timeout to make
  a test pass.** Classify the new site first.
- The gate **fails closed**: missing inventory, missing tool, or missing
  `python3` is a FAILURE. An absent inventory is not an empty one.
- Passing means every guard is **known**, not that any guard is **safe**.
- `--classify` checks the site exists *in the tree* (file present, function name
  present), not merely in the census, so a converted site can still be
  classified — but a typo is still refused.

## Closure criterion for the class

Per the ruling: **all sites classified AND the ambiguous predicate removed** —
not individual bug fixes. Until then no guard conditioned on
`sole_survivor()` may be described as covering the class, only the
within-mount case. The within-mount case is the whole case for that
predicate: every consumer protects in-core state of the current mount or a
departed peer's not-yet-landed free, none of which outlives a quiesce, and
the one durable consequence (chunk deletion) is unconditional on a clustered
volume (`docs/rulings/sole-survivor-predicate-class.md`, the D-0956
resolution).

## Rig facts measured alongside this work

- 12000 empty files into a fresh dir, chunks already carved: **85.5 s**.
- The same 12000 files on a filesystem that had to **carve 187 chunks**: still
  running at **400 s**. Chunk carving dominates create cost by roughly 1.7 s
  per chunk — relevant to D-0349 and to any create-heavy harness budget.
- 500 files: 11.16 s; 2000 files: 11.07 s. The first ~11 s is fixed cost, not
  per-file.
