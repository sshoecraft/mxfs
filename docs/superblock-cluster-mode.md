# Superblock mutations in cluster mode

Ledger: `D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE-0133` (critical).
Code: `xfs/xfs_mxfs_dlm.c` `mxfs_sb_mutation_refuse()`, prototype in
`xfs/xfs_mount.h`.  Landed 0.29.2 (sess419).  Test:
`tests/d0133_sb_mutation_gate.sh`.

## The hazard

Every node keeps its own private in-core `m_sb`, and `xfs_log_sb()`
serialises that ENTIRE structure over the one shared superblock sector.
The routine lazy-counter sync at log cover / unmount / `xfs_log_worker`
is such a log.  So any node's persistent non-counter change (a feature
bit, geometry, label, quota flags, stripe alignment) is durably REVERTED
by the next peer that merely covers its log from a stale copy — proven
for ATTRBIT in sess353 (#94 root).  Single-node XFS never had this
problem because there was only ever one `m_sb`.

## The containment (sess353 GPT ruling, item 4)

FORBID every runtime non-counter superblock mutation on a cluster mount,
rejecting BEFORE `m_sb` is modified.  `mxfs_sb_mutation_refuse(mp, what)`
returns 0 on a non-cluster mount and, when `mp->m_mxfs_dlm` is active,
logs `MXFS P-SB-MUTATION-REFUSED what=<site> n=<count>` and returns
`-EOPNOTSUPP`.  Operators perform these changes OFFLINE with all nodes
unmounted (`tools/resize_mxfs`, `tools/chk_mxfs`).

Gated producers (the complete runtime set, enumerated sess419 from every
caller of `xfs_log_sb` / `xfs_sync_sb` / `xfs_sync_sb_buf` /
`xfs_sb_to_disk`):

| site | what | effect on a cluster mount |
|---|---|---|
| `xfs_growfs_data` (`xfs_fsops.c`) | `growfs_data` | ioctl fails EOPNOTSUPP before `m_growlock` |
| `xfs_growfs_log` | `growfs_log` | same |
| `xfs_ioc_setlabel` (`pal/linux/xfs_ioctl.c`) | `setlabel` | FS_IOC_SETFSLABEL fails, `sb_fname` untouched |
| `xfs_add_incompat_log_feature` (`xfs_mount.c`) | `add_incompat_log_feature` | LARP / exchange-range callers fail EOPNOTSUPP before the primary bwrite |
| `xfs_clear_incompat_log_features` | `clear_incompat_log_features` | returns false; bits stay as found (harmless) |
| `xfs_mountfs` quota branch | `quota mount option` | `-o uquota/gquota/pquota` mount REFUSED before `xfs_qm_newmount` |
| `xfs_mountfs` reset branch | `reset_sbqflags` | mount refused if the SB carries stale ACCT flags (clear offline) |
| `xfs_qm_scall_quotaon` / `quotaoff` | `quotaon` / `quotaoff` | defence in depth (unreachable once the mount gate holds) |
| `xfs_update_alignment` | `dalign mount option` | `-o sunit/swidth` that would rewrite `sb_unit/sb_width` refused |
| `xfs_mountfs` features2 mismatch | `features2 mismatch repair` | mount refused (repair offline) |
| `xfs_mountfs` NLINKBIT add | `NLINKBIT add` | mount refused (mkfs_mxfs presets the bit) |
| `xfs_mountfs` `m_update_sb` sync | `mount-time sb update` | backstop for any future `m_update_sb` source |
| `xfs_remount_rw` | `remount-rw sb update` | deferred update refused on ro→rw |

Reachability on the SHIPPED `mxfs.ko` (Kbuild excludes the XFS ioctl
surface — `xfs_stubs.c` answers ENOTTY to everything but GOINGDOWN — the
quota subsystem (`CONFIG_XFS_QUOTA` undefined; `-o uquota` fails at option
parse) and DEBUG-only LARP): the only producer a live cluster can reach
from userspace is the `sunit/swidth` mount option, which the gate turns
into a refused mount.  The growfs / setlabel / log-incompat / quota gates
are defence in depth for the day those surfaces are compiled in.
`pal/linux/xfs_ioctl.c` and `xfs/xfs_qm_syscalls.c` are not built at all;
their gates are kept so the file is correct if it ever is.

Unreachable on a cluster volume and therefore ungated (documented, not
forgotten): `xfs_bmap_add_attrfork` / `xfs_inode_init` `xfs_add_attr`
(mount refuses `!xfs_has_attr` since 0.13.3), `xfs_sbversion_add_attr2`
and PROJID32 (`mkfs_mxfs` presets `FEATURES2 = LAZYSBCOUNT|ATTR2|PROJID32|CRC`),
online repair `xrep_*` (scrub is not built into `mxfs.ko`, see `Kbuild`).

Still ALLOWED, by design: the counter-only syncs (`xfs_log_cover`,
`xfs_log_worker`, `xfs_log_quiesce`'s counter path, unmount) — these are
what the #94 clean-skip replay classifier tolerates, and the sess44 clamp
inside `xfs_log_sb` keeps a per-node counter divergence from tripping the
write verifier.

## What this is not

It is containment, not coordination.  A future protocol that lets a
cluster grow or relabel online must cover this SAME producer set (a
coordinated mutation that a peer's counter sync can still revert is no
better than an uncoordinated one) — the natural shape is a single-writer
SB epoch carried in the DLM with every node re-reading the sector under
the epoch before its own whole-SB log.

## 0.64.26 (sess474) — the counter arm: quiesce recompute summed stale per-AG summaries

Chain 115 s473c (0.64.23, only test1/test2 active, clean 32-node unmount) left
`sb_icount=1856` against an inobt total of 2048 (exactly three 64-inode
chunks) and `sb_ifree=187` vs 397; s473b left the mkfs snapshot 64/61.
Mechanism (code): `xfs_log_quiesce`'s recompute (`P30-QUIESCE-RECOUNT`,
sess30) calls `xfs_initialize_perag_data`, which summed
`pag->pagi_count/pagi_freecount/pagf_*`.  Those summaries are rebuilt only on
the FIRST header read and on a fresh AG-DLM tenure; for an AG this node never
acquires they keep their mount-time values forever, while the AGF/AGI buffers
themselves are FUA-refreshed on every read (`mxfs_ag_meta_invalidate_stale`).
So the last node to cover the log wrote a sum that missed every chunk a peer
allocated after this node's mount.

Change: in cluster mode `xfs_initialize_perag_data` sums the fresh AGF/AGI
buffer contents and prints `P-SB-RECOUNT-STALE agno=… pag[…] buf[…]` for every
per-AG summary that disagreed (the measurement of the mechanism).
`xfs_log_quiesce` prints `P-SB-SYNC-PRE` (this node's in-core counters beside
the DURABLE primary-SB counters read at the coherence point via
`mxfs_sb_read_counters_coherent`), `P-SB-SYNC-WRITE` (what its cover logs) and
`P-SB-SYNC-POST` (durable counters after the cover) — the design-consult (sess474)
instrumentation for the remaining hypothesis H2: two nodes quiescing
concurrently, one recomputing before the other's AG headers are durable and
its whole-sector SB write landing last.  Harness:
`tests/sess474_chain116_d0133_sb_recount.sh` (timestamped fleet unmount =
`P-UNMOUNT-ORDER`, every node's probe lines, chk).

### 0.64.28 — the fix (design-consult design A+)

Chain 116 (0.64.26, two laps) proved both halves: the 30 idle nodes' recompute
read their OWN cached mount-time AG headers (summary == cached buffer, so the
0.64.26 buffer-sum change was inert) and summed the mkfs snapshot 64/61, and
three of them (`P-SB-SYNC-PRE` durable=128, `P-SB-SYNC-WRITE` 64) wrote it
over the workers' 128/125 because the 32 parallel unmounts race their
whole-sector SB writes.  Fix: `xfs_log_quiesce` (after its AIL push + buftarg
wait) takes `mxfs_sb_summary_lock` — a cluster EX grant on the
geometry-reserved unallocatable key `((agcount+1+65) << (agblklog+inopblog)) | 1`
(slot 65: beyond every per-node pw-selftest key and the shared samenode key) —
recomputes via `mxfs_sb_summary_recount_uncached` (every AGF/AGI read with
`xfs_buf_read_uncached`, magic/crc/seqno verified by hand, old counters kept on
any failure), covers the log, waits for the buftarg and flushes the device
cache, re-reads the durable sector (`P-SB-SYNC-POST`), then unlocks
(`P-SB-SUMMARY-LOCK` / `P-SB-RECOUNT-DONE mode=uncached-coherent` /
`P-SB-SUMMARY-UNLOCK`).  The last serialized writer is the last node out and
its sums are terminal.  Lock order: the quiesce task holds no inode/AG grant;
never acquire the summary key inside a metadata transaction.

### 0.64.29 / 0.64.30 (sess475) — the lock was inert; the section moves into put_super and SEALS the mount

Chain 116 s474e (0.64.28, three laps × 32 nodes) printed `P-SB-SUMMARY-LOCK
rc=-19` on every node: `xfs_fs_put_super` (`pal/linux/xfs_super.c`) purges the
ICLUSTER objects, force-releases the AG grants, NULLs `m_mxfs_dlm` and runs the
v5 shutdown BEFORE `xfs_unmountfs` → `xfs_log_clean` → `xfs_log_quiesce`, so
the in-quiesce lock could never be granted.  The laps still ended with chk 0
and a 512-byte SB byte-compare (`tests/mxfs_sb_bytecmp.sh`) clean outside
icount/ifree/fdblocks/crc/lsn — the uncached recount alone was enough for
those orderings, which is not the serialization the ruling requires.

Design-consult ruling (ccmemory `ccloop-c7ee71c6-sess475-GPT-ruling-d0133-lock-inert-
put-super-teardown-shape9-hardened`): the section must run while the DLM is
alive, every log-capable producer must be stopped before it, and after its
unlock NOTHING may write the SB sector — a late dirtying must REFUSE the clean
departure rather than write unlocked ("read the durable counters right before
an unlocked write" is a read/write race and was rejected).

The landed shape:

1. `mxfs_sb_summary_final_sync` (put_super, after `mxfs_defer_reap_destroy` —
   the reap worker re-drives inactivation — and the destage-kick cancel,
   before `m_mxfs_dlm = NULL`): `xfs_inodegc_flush`, `xfs_blockgc_stop`, the
   summary EX lock (its CAW `ex_grant_epoch` is printed on every probe as the
   fleet ORDERING WITNESS — clocks cannot prove non-overlap, grant numbers
   can), `xfs_log_quiesce` with `m_mxfs_sb_lock_held` set, unlock, SEAL.
2. `mxfs_sb_summary_cover` (`xfs/xfs_log.c`, the clustered quiesce path):
   `P-SB-SYNC-PRE` → uncached recount → `P-SB-SYNC-WRITE` → cover → buftarg
   wait + device flush → durable re-read `P-SB-SYNC-POST` (a mismatch against
   what we logged is `P-SB-SYNC-POST-MISMATCH`, an intruding writer).  Fails
   closed: a lock or recount failure covers NOTHING (`P-SB-SUMMARY-LOCK-FAIL`,
   `P-SB-RECOUNT-FAIL`).  Freeze / remount-ro reach it with the DLM alive and
   take the lock here.
3. The seal (`m_mxfs_sb_sealed`): `xfs_trans_alloc` (`P-SB-SEAL-TRANS`),
   `xfs_log_sb` (`P-SB-SEAL-SYNCSB`) and every SB-sector submission
   (`P-SB-WRITE-SUBMIT … sealed=1`, `pal/linux/xfs_buf.c`) after it are
   counted.  `mxfs_sb_summary_sealed_quiesce` — the quiesce `xfs_unmountfs`
   runs later — writes nothing when the log is still covered and the counters
   are zero (`P-SB-SEAL-OK`); otherwise `P-SB-LATE-DIRTY-COVER`,
   `XFS_SICK_FS_COUNTERS` (the unmount record is withheld) and
   `m_mxfs_sb_late_dirty`, which the slot-release predicate honours: the
   departure is DIRTY (`P-SB-SEAL-DIRTY-DEPARTURE`), the slot stays ACTIVE and
   the peers recover the slice.
4. `P-SB-WRITE-SUBMIT slot= seq= epoch= locked= sealed= image[…]` is printed
   for EVERY clustered SB-sector write at the submission chokepoint — the
   terminal-writer proof and the D-0536 measurement (below).

Knobs (default off, never in production): `dbg_sb_pause_point=1..4` +
`dbg_sb_pause_ms` park the critical section (after lock / after recount /
after cover / after POST) for the adversarial-waiter and holder-failure arms;
`dbg_sb_late_dirty=1` logs the root inode after the seal (the departure must
go DIRTY).  Harness: `tests/sess475_chain116_d0133_sb_seal.sh`.

**D-0536 (filed sess475):** the runtime covers — `xfs_log_worker` every
`xfssyncd_centisecs`, `xfs_log_quiesce`'s incompat-clear sync, growfs/quota/
feature-bit `xfs_log_sb` callers — still write the whole SB sector from the
node's PRIVATE lazy counters outside the lock.  The all-nodes-clean-unmount
case stays terminal-correct (each node's last write is its locked one, after
its own worker was cancelled) and a clustered mount always recounts at mount,
but the summary lock must never be described as exclusive against all SB
writers until those covers join the protocol (or stop publishing private
counters).  The section "Still ALLOWED, by design" above is therefore no
longer the last word on the counter syncs.

### 0.64.33 (sess476) — D-0537: the summary key had no holder the DLM could see

Chain 116 v2 (0.64.30, `tests/evidence/sess475_chain116_d0133_s475a.log`) passed
its three normal laps and both adversarial laps (Y's grant epoch = X's + 1 only
after X's UNLOCK line, Y's umount wall 20.3 s = X's hold), but the
holder-failure lap granted Y (test5) epoch 2 in **255 ms** while X (test4) was
parked inside its critical section at epoch 1 for a 60 s hold, two seconds
before X was destroyed.  Root (code): `mxfs_sb_summary_key` is a raw
inode-class CAW grant with **no in-core inode**, so a peer's BAST for it takes
`__mxfs_dlm_bast_notify`'s "inode not in cache — release the orphan lock" arm
and `mxfs_dlm_noino_bast_work_fn` unlocks the grant from under put_super after
its drain fence.  The 0.64.30 verdicts ("32 distinct epochs") witness the order
of *grants*, not exclusion of the critical sections.  Filed as
`D-SB-SUMMARY-LOCK-RELEASED-BY-NOINO-BAST-UNDER-LIVE-HOLDER-0537`.

The fix: `m_mxfs_sb_lock_held` (raised **before** the granting CAS now, so the
grant-to-mark window is closed) names the live holder; a BAST for the key while
it is set prints `P-SB-SUMMARY-BAST ... held=1 action=REFUSED-live-holder` and
returns without queuing the release — the peer keeps waiting on its own
bounded CAW poll.  Knob `sb_summary_bast_refuse` (default 1; 0 = measure only,
the instrumented proof lap: `action=RELEASE-under-live-holder`).  Harness: the
holderfail arm runs once per `HF_KNOBS` value and captures X's mark-bounded
ring before the destroy (`holderfail<knob>_test4_predestroy.txt`).

The late-dirty arm's harness assertion was wrong on chain 116 v2 (it matched
the `P304-RETIRE-QUIESCED ... release stamp may proceed` line, which prints on
every departure) — the filesystem had refused the clean departure correctly
(`P-SB-LATE-DIRTY-COVER`, `P277-SLOT-RETAINED-UNMOUNT-DIRTY`, `P302` key
retained, a peer's `P163` 71 s later).  On 0.64.33 the arm then WEDGED: the
injected `xfs_ilock(root)` after the seal could not re-drive a dead demote
instance on the root once put_super's teardown bast-arm sweep had closed the
gate (`P-DEMWAIT-REDRIVE ino=128` -> `P6S-ARM-REFUSED ... teardown` every 3 s).
0.64.36 takes the knob at put_super entry (`mxfs_sb_late_dirty_prearm`) and
pre-warms the root's EX before the sweep, so the post-seal injection is a
local acquire.
