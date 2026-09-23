# Foreign replay — inode-item ordering across incarnations

Ledger: `D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408`
(sess408 root, sess409 fix 0.26.5/0.26.6).

## The rule foreign replay uses

Upstream XFS skips an inode-item image at recovery when the on-disk
`di_lsn` is newer than the transaction being replayed.  MXFS per-node log
slices have independent LSN spaces, so for a *foreign* slice (a survivor
replaying a dead node's slice) `xfs_inode_item_recover.c` replaces that test
with a node-independent one:

    disk di_changecount >= logged di_changecount  ->  SKIP (disk same-or-newer)
    else                                           ->  APPLY

Sound only if `di_changecount` is monotonic per inode NUMBER across every
node and every incarnation.  Every modifier reads-current-then-increments
under the DLM, so it was monotonic within an incarnation.

## The defect (sess408, proven with P77-FRINODE)

`xfs_inode_init()` restarted `di_changecount` at 1 for every allocation
(`inode_set_iversion(inode, 1)`), and the v5 iget(CREATE) path never read
the old dinode.  The freed core on the platter keeps the previous
incarnation's (higher) count.  Replaying a dead node's slice in LSN order:

    ino=46137473 disk_cc=0 log_cc=7 APPLY      (incarnation A's images)
    ino=46137473 disk_cc=7 log_cc=2 SKIP       (incarnation B's creation, later in the slice)

B's inobt/AGI/unlinked-bucket BUFFER images (a different replay rule)
applied; B's core did not: platter = inobt-allocated, bucket-linked, mode-0
core.  8 of 29 clean-unmount chk runs that day showed it; the slot's next
mount re-drives that bucket into a freed core.

Design-consult ruling (sess408): option A — continue the count across
incarnations from a *fresh* read of the freed core — is the minimal sound
fix; using `di_gen` as an order (option B) is unsound (gen is identity, not
order); inode-chunk free+reinit would reset the ordering domain but is
already impossible in multi-node mode (`xfs_ialloc.c` sess54
INODE-CHUNK-KEEP).

## The fix (0.26.5, sess409 completed it)

* `struct xfs_inode.i_mxfs_prev_changecount` — the freed core's count.
* `xfs_icache.c: mxfs_iget_create_prev_changecount(mp, pag, tp, ip)` — on a
  multi-node mount, at iget(CREATE), read the cluster buffer and take
  `dip->di_changecount`.  Called from BOTH reincarnation paths:
  - `xfs_iget_cache_miss` v3 CREATE branch (shell not in core), and
  - `xfs_iget_recycle` for a CREATE that recycles an in-core reclaimable
    shell — the DOMINANT path under churn (same node frees and re-allocates
    the agino while the shell is still cached).  sess408 landed only the
    cache-miss half; sess409 added the recycle half.  There the value is
    `max(platter read, in-core i_version)`: the in-core `i_version`
    (preserved by `xfs_reinit_inode`) is this node's last value for the
    previous incarnation; the platter read covers a peer having
    reincarnated+freed the number while the shell sat idle (no DLM is held
    on an idle shell, so no BAST reached us).
* `xfs_inode_init`: `inode_set_iversion(inode, prev + 1)`.
* `xfs_iget_cache_hit` / `xfs_iget_recycle` now take `tp` (the read must
  go through `xfs_imap_to_bp(tp)` so a cluster buffer already joined to the
  ICREATE transaction is found, not dead-locked on).

Live proof (lap2, tests/evidence/sess409_cc/lap2/p77.txt):
`ino=16777347 disk_cc=1539 log_cc=1546 disk_gen=2632946196 log_gen=2777566480 APPLY`
— a different incarnation with a HIGHER count than the platter's freed core.

### Freshness of the read

The last writer of a free core is the node that freed it; it drained the
cluster buffer before releasing its AG grant (Invariant #1), so the platter
is current but OUR cached copy may predate it.  The helper follows the
sess38/sess91 cache-miss discipline: stale a clean cached cluster copy so
`xfs_imap_to_bp` re-reads it FUA-fresh; keep it when it carries this node's
uncheckpointed co-resident modifications (`mxfs_buf_has_uncheckpointed_mods`
— then our copy is authoritative).  The `xfs_buf_incore` lock is TRYLOCK:
the cluster buffer of a chunk this very transaction just ICREATE'd is held
by `tp` (zeroed cores, count 0) and a blocking lock would self-deadlock; a
buffer locked by anyone else is read as cached and counted.

### Pace (budget) — AG-tenure stamp (0.26.6)

Re-reading the cluster on EVERY create cost +18% on the tmpfile-churn median
(lap2 21.2 s vs sess408 17.9 s for 2000 iterations).  A free core can only
change on the platter under a PEER's AG EX tenure, and a peer gets one only
after we yield our grant — which opens a new `pag->ag_dlm_tenure_id` when
we next acquire (sess123).  So a cluster buffer fresh-read under the CURRENT
tenure stays fresh for the rest of it: the helper stamps `bp->b_tenure_id`
at the fresh read (unused on inode-cluster buffers otherwise — AG-meta
stamps at modify, dir/bmbt blocks stamp `i_mxfs_ex_grant_seq`) and skips
the stale when the cached copy already carries the current tenure.

Lock discipline (0.26.7, from the sess409 GPT review of the stamp): the
ICREATE case is detected with `xfs_trans_buf_item_match(tp, ...)` (made
non-static in `xfs_trans_buf.c`, declared in `xfs_trans.h`) and read as is;
every other cached copy is taken with a BLOCKING `xfs_buf_incore` — the
earlier TRYLOCK-fail "read as cached" fallback could have returned a
prior-tenure copy while xfsaild held the buffer for write.  Lock order AGI
(held by tp since dialloc) → cluster buffer is the same as `xfs_ifree`'s and
the sess38/recycle reads'.

A/B knob (0.26.8): `mxfs.ccprev_enable` (default 1).  0 restores the
restart-at-1 behaviour for instrumented cost attribution ONLY — it re-opens the
defect; never run a correctness campaign with it off.

Counters (in the periodic `mxfs DLM cache:` stats line and `FUA-COUNT`):
`ccprev` (helper calls), `ccprev_tenure_hit` (re-read skipped),
`ccprev_nostale` (locked by tp/xfsaild, read as cached, not stamped).
lap3 (0.26.6): single-owner AG node test9 `ccprev=2001 tenure_hit=1992`;
shared-AG nodes test1/test2 `tenure_hit=0` — every create there already
re-acquires the AG (tenure++), so the read is one per acquire, i.e. the
pre-existing shared-AG create-pace shape (D-32NODE-SHARED-DIR-CREATE-PACE,
D-TMPFILE-CHURN-the budget rule-PERF-400), not a new cost class.

## Oracles

* `tools/chk_mxfs -v`: ERROR on an unlinked-bucket member whose core is
  FREE (mode 0) [sess408], and ERROR `P-ALLOC-FREE-CORE` on any
  inobt-allocated inode whose core is FREE [sess409] — dialloc+init and
  ifree are each ONE transaction, so after a clean unmount either shape is a
  half-applied creation.
* `P77-FRINODE` (instr=1) now carries `disk_mode log_mode disk_gen log_gen`;
  `tests/tmpfile_churn_kill.sh` captures it to `$OUT/p77.txt` and reports
  apply/skip totals plus `skip_alloc_over_free_diffgen` (reported, not a
  FAIL: post-fix that shape can still be a dead node's OLD image of an
  incarnation a peer has since freed again).

## Closure (sess409, 0.26.9 sv 8F59A85088DBA6459479F55)

Third reincarnation entry added (CREATE cache-hit on a VFS-live shell, the
P-CR63 reset-for-create rescue path).  Verified: instr=1 kill laps show
reincarnation images APPLY with `disk_gen != log_gen` and `log_cc > disk_cc`;
10 clean-unmount chk runs with 0 bucket->free-core / 0 P-ALLOC-FREE-CORE
(8 of 29 on 0.26.4); rman matrix 9/9; board 26/27 (the FAIL is D-401,
A/B-dispositioned with `ccprev_enable`); no measurable pace cost (churn,
rsync_paired, crash_consistency A/B all equal within noise).  Ledger entry
closed FIXED AND VERIFIED.

## Residual hazard (GPT, sess408)

Inode-item and buffer-item verdicts of one transaction can still diverge in
other shapes (an old inobt/bucket image applied while the matching inode
image is correctly skipped because a newer incarnation is on disk).  Not
observed; instrument/assert transaction-level compatibility if chk ever
shows it.

## The mirror shape: buffer images (sess459, D-0517)

Ledger: `D-ICLUS-RELMARK-POSTMARK-CRASH-ALLOC-FREE-CORE-UNLINKED-DANGLING-0517`
(root sess459, fix 0.61.4).  The divergence above DID happen, in the other
direction: the inode image applied, the buffer images did not.

The buffer-item path (`pal/linux/xfs_buf_item_recover.c
xlog_recover_buf_commit_pass2`) had kept upstream's stamp test unchanged:

    lsn = xlog_recover_get_buf_lsn(mp, bp, buf_f);   /* bb_lsn / agi_lsn / agf_lsn / dir lsn / sb_lsn */
    if (lsn && lsn != -1 && XFS_LSN_CMP(lsn, current_lsn) >= 0)  ->  SKIP

On a shared disk the stamp is the LAST WRITER'S slice LSN.  Chain 80 lap 2
(`tests/evidence/sess456_d0517lab_s456b/lap2/`): victim test3 (slot 6) died
holding AG 6 right after freeing ino 25165953; the AG 6 AGI/inobt/finobt on
the platter carried 0x100001183, written by the previous holder (slot 31),
while slice 6's two admitted transactions were 0x100000e48 and 0x100000e4c.
All six AG images were token verdict APPLY and still skipped; after the
replay test1 read the inobt root still stamped 0x100001183 (a replayed buffer
is restamped with the transaction LSN by `xlog_recover_validate_buf_type`).
The inode item, changecount-gated, applied the free's core (mode 0).  Result:
inobt says allocated, unlinked bucket 6 points at the inode, core is FREE —
chk's `P-ALLOC-FREE-CORE` line, which reads as "creation half-applied" but
is the FREE half-lost.  Inode-cluster (DINODE magic) buffers never hit the
test (`recover_immediately`), which is why the sess456 P-FR-DINO-BUF probe
could not fire.

### The rule now (0.61.4)

The authority token is the node-independent gate for buffer images, the
same role `di_changecount` plays for inode images.  An image reaches pass 2
only with verdict APPLY (REDUNDANT_CLEAN and refused images are dropped in
the item loop); APPLY for class AG or INODE means the victim HELD that
resource at death — the fence-time manifest says so, the live CAW slot still
carries the victim's bit with unchanged lineage (P-RMAN live check; a
mismatch aborts the attempt), and the dead slot is zeroed only after
P163-RECOVERY-COMPLETE.  So no successor tenure can have written the block
after the transaction; within the victim's own slice replay is in LSN order
from the tail, so re-applying an image the victim had already flushed is
idempotent.  Hence:

    untrusted replay && ri_mxfs_verdict == APPLY && ri_mxfs_class in {AG, INODE}
        -> the stamp does not veto; apply (counted: buflsn_overrides,
           P-FR-BUF-LSN verdict=OVERRIDE-APPLY)
    everything else (SB class, untagged, trusted/standalone recovery)
        -> upstream test unchanged (counted: buflsn_skips, verdict=SKIP)

design-consult ruling (`docs/rulings/d0517-buf-lsn-skip-bypass-stop-ship-6-items.md`)
fixed the shape: never bypass on "untrusted" or "clustered" alone, never for
SB/dquot/RT, keep every non-LSN validation, and route every dirty clustered
slice through authority admission.  The PASS-1 own-stamp reclaim does not
(it replays a dirty own slice as a trusted log): ledger
`D-OWN-SLICE-PASS1-RECLAIM-REPLAY-CROSS-SLICE-LSN-VETO-0521`.

## The third shape: no replay at all — a logged image dropped from the cluster write (D-0957)

Ledger: `D-INOBT-ALLOCATED-INODE-WITH-A-FREE-CORE-ON-A-QUIESCED-FILESYSTEM-CREATION-HALF-APPLIED-0957`
(observed sess574 on 0.75.128, cause established sess583, removed by 0.83.3,
adjudicated sess615).

`P-ALLOC-FREE-CORE` does not need a dead node.  The same on-disk state — inobt
allocated, dinode still the chunk-initialisation image (mode 0, changecount 0,
the carve's random generation) — is produced on a single live node whenever
its inode-cluster write drops the slot of a directory it has just created and
nothing re-flushes it:

1. `mxfs_submit_partial_inode_write` (`pal/linux/xfs_buf.c`) refuses a LOGGED
   directory slot whose in-core `i_dlm_mode` is NL and which carries no
   release-drain token (`P56-NL-LOGGED-DIR-SKIP`).  Under the multi-node
   protocol that is right: NL means the grant went to a successor and the
   drain already landed our change.
2. With `mxfs.pub_skip_rearm=0` (the default) the buffer completion then
   completes the inode log item as if its bytes had landed — the item leaves
   the AIL, the in-core inode is clean, and no flush will look at it again.
   The inobt/AGI buffer items of the same create land normally.
3. A later whole-buffer write of the same cluster can still land the copied-in
   image (co-resident flush after a knob flip), which is why an A/B lap
   strands fewer directories than it has knob=1 rounds.

The state that put a freshly created directory at NL with no token was the
sole survivor running the partial-write filter WITHOUT taking DLM grants:
the single-node lock bypass set no mode, the new-inode grants were gated off,
and no BAST could ever set the token.  That configuration was the
`partial_iwrite_sole` knob arm on 0.75.128 (s574iwr: the first directory in
AG 4 was a knob=1 round's) and the withdrawn first D-0955 fix on 0.83.2 (s583c:
`P34H-INCARN-POISON ino=8463296 disk_mode=0`, 799 of 800 creates failed).
0.83.3 removed it for a survivor: the bypass was keyed on
`mxfs_v5_dlm_never_multi()`, so a survivor took real grants and its logged
directories were EX-held at flush. 0.87.16 removed the bypass altogether: a
mount that has never had a peer takes the same real grants, because its
logged directory blocks and bmap-btree blocks otherwise ship `AUTH_NOT_HELD`
and a replay after its death refuses the whole transaction
(`docs/sole-survivor-sweep.md`).

What remains true of the current tree, by construction rather than by
observation: a `P56-NL-LOGGED-DIR-SKIP` is lossless only while the release
drain lands every committed change before the grant leaves.  If that drain
invariant is ever broken, the dropped change is lost silently under
`pub_skip_rearm=0`; the sibling stale-stage path fails closed instead
(`P224-UNLANDED-STALE-FATAL`).  The oracle for both is the same cold check.

### Oracles

- `foreign replay of slot N complete (sbclean_skips= buflsn_skips= buflsn_overrides=)`:
  `buflsn_skips` must be 0 for APPLY images; `buflsn_overrides > 0` proves the
  path was exercised.
- `P-FR-BUF-LSN blkno= len= magic= blft= txn_lsn= disk_lsn= verdict=SKIP|OVERRIDE-APPLY tokverdict= class=`
  per decision (cap 4000/boot).
- `chk_mxfs` after the fleet unmount: 0 `P-ALLOC-FREE-CORE`, 0 bucket->free-core.

## The fourth shape: the replayed dinode never leaves the survivor (D-0976)

Ledger: `D-RECOVERY-REPLAYED-DINODE-DROPPED-BY-CLUSTER-WRITE-AUTHORITY-MASK-0976`
(root and fix 0.87.8).

The inode item applies (changecount gate APPLY), the buffer items apply, and
the platter still ends up torn — because the survivor's write of the patched
inode cluster is itself filtered.  Every inode-cluster write on a clustered
mount goes through `mxfs_submit_partial_inode_write` (`pal/linux/xfs_buf.c`),
the authority mask that publishes only slots this node logged this round or
holds with a write grant.  A slot a recovery patched is neither: no inode log
item of this node's is attached and no in-core inode exists.  The mask drops
it as an un-owned passenger; with the rest of the cluster free it refuses the
whole write with no I/O and completes the buffer as landed, so the home flush
milestone reports success.  The victim's leaves and AG images land; its
dinodes do not.  Measured: a file killed mid-growth read back after rejoin
with a dinode 13000 extents behind its own leaves and shut the node down.
Earlier death laps never met it because their files had landed before the
kill, so every inode item was skipped as already on disk.

### The rule now (0.87.8)

The recovery is the authority for the slots it patches: the dead node held
them at death (token verdict APPLY), its grants stay frozen until
`P163-RECOVERY-COMPLETE`, so no successor image can exist.  That entitlement
is recorded on the buffer, per slot (`b_mxfs_recov_slots`, `xfs_buf.h`):

- set by the inode-item replay at the dinode it applied, by the inode-buffer
  replay at every unlinked pointer it copied, and by the icreate replay for
  every slot of a cluster it initialised (so a later inode item of the same
  recovery cannot turn that write partial and drop the initialised free
  slots) — for a foreign, adopted or own-slice recovery alike;
- honoured by the partial writer before any other rule: a set slot is
  written, never masked, never refused (`P218-RECOV-OWNED`); a nonzero mask
  that still computes an empty I/O fails the write (`P218-RECOV-REFUSED`),
  it never completes as success;
- cleared when a write of the buffer completes (any submitter — a
  co-resident flush by this node discharges it too) and when a stale buffer
  is reused; a failed recovery write stales the buffer as before.

The baseline hazard (design consult, sess46): a foreign replay reads the
cluster through the survivor's cache, whose copy of the dead node's slot can
predate that node's last durable flush, and an image patches only the logged
fields.  So the first patch of a slot in a recovery first copies that one
slot in from a cache-bypassing platter read (`mxfs_recov_slot_refresh`):
once per slot per recovery (a slot the recovery already owns carries its own
in-order baseline), never for a slot this node has in core (its own history;
a later flush of that inode overrides the patch), and a read failure fails
the replay.  `recov_slots_own=0` is the same-build control.

### Oracles

- `P218-RECOV-OWNED daddr= slots=` on every cluster write that carried
  recovery-owned slots; `P218-WRITE-REFUSED` and `P218-RECOV-REFUSED` must
  not appear in a recovery.
- `P77-FRINODE <foreign|adopted> ino= txn_lsn= disk_cc= log_cc= disk_nx= log_nx= ... verdict=`
  per inode item of an untrusted replay (budgeted; unbounded under `instr`).
- `P-BMBT-OVERCOUNT ... blk_lsn= loaded= if_nextents= platter_nx= platter_cc= platter_di_lsn=`
  at the extent-read overcount that shuts a node down: the platter fields
  say whether the dinode lags the leaves on disk.
- `tests/recov_bmbt_reuse.sh` ends with the cold `chk_mxfs` (both nodes
  unmounted): 0 `P-ALLOC-FREE-CORE`, verdict clean.
