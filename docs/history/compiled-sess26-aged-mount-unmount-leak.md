<!-- sess26: aged-mount cache_coherency degradation root-caused+fixed (demoter self-exemption), unmount inode-leak narrowed, 3 measurement techniques disp… -->
# sess26: aged-mount coherency degradation + unmount inode-leak investigation

Two entangled defects worked in the same session, v0.11.222-225, 16-32/caw:
D-MOUNT-DEGRADES-WITH-USE / D-DIRENT-INODE-TYPE-MISMATCH (cache_coherency/
strong_consistency/posix_multi fail only on an aged mount) and
D-UNMOUNT-BUSY-INODES (an inode survives to module unload with icount=1).
Three measurement techniques were tried and two were disproven before the
real root cause of the coherency degradation was found and fixed; the
unmount leak stayed open with attribution narrowed to a specific class of
bastq deferred-release sites.

## Repro recipe for the aged-mount failure

[[aged-mount-coherency-repro-recipe]]: on ONE mount, without re-prepping, run
~12x `dirent_durability` @32/caw plus 2-3 full correctness boards
(cache_coherency, strong_consistency, posix_multi, mmap_coherency,
zero_silent_loss, dlm_fairness, dlm_membership, dir_reuse_coherency,
crash_consistency). Then `cache_coherency` fails identically on all 32 nodes
(`checks=654 passed=653 failed=1`, one specific check wrong cluster-wide, not
a per-node flake) and `strong_consistency` fails 17/32. A fresh prep on the
same build passes both clean minutes later. Single-node runs on the same aged
mount pass — the failure needs 32-way concurrency. This paired
aged-vs-fresh comparison is what made the defect tractable at all.

## Two measurement techniques that produced confident wrong answers

[[unmount-leak-global-refcount-balance-cannot-work]]: to attribute the
unmount leak, instrumented a per-inode grab/release balance
(`i_mxfs_tgrabs`/`i_mxfs_tputs`, P205-REFBAL) on the theory that
`net == icount` would name the leaking grabber. First cut only counted
MXFS's own tracked chokepoints and read `tgrabs=61 tputs=1 net=60` against
`icount=1` — confidently wrong, because MXFS releases via `xfs_irele()` not
`iput()`, so the release side was nearly uninstrumented. Second cut added
both chokepoints symmetrically and still landed `tgrabs=161 tputs=83 net=78`
against `icount=1` — off by 77, because VFS-side references (`dput`->`iput`,
`evict`, `d_splice_alias`'s own error-path `iput`) never pass either
chokepoint. Conclusion: a global balance is unsound in principle, not
uncalibrated — Linux gives no reverse map from a refcount to its holder, so
no filesystem-confined counting scheme can attribute one surviving
reference. Keep the probe only for its honest third verdict, `UNEXPLAINED
(VFS igrab/iput outside both chokepoints)`. Three catches in five 16/caw
cycles converged on: all DIRECTORY inodes, icount=1, dentries=0, hashed=1,
lru_linked=1, dlm_mode=PR, no bast/dwork/bwork pending, demoter=0 — a lookup
reference with no dentry ever holding it.

[[differential-invalid-when-loser-is-rank1]]: `dd_loss_differential.sh`
diffs per-token kernel-probe counts between a losing node and its 31 peers;
valid for an ordinary-peer loser (it found the real P6-MIDTENURE lead for
D-SILENT-MKDIR-LOSS that way). Two `dirent_durability` 240s/240s truncations
landed on test1 = rank 1, and the differential showed test1 elevated
20x-158x on P1-AGWAIT, P128-INACT-DEFER, P-DIRFLUSH etc. — read at the time
as "the probes name the backlog." A control run
(`rank1_straggler_probe.sh` on a fresh-prep PASSING run) showed the SAME
elevation on every one of those probes purely from rank1's coordinator role,
with zero discriminating power for the failure. Rule: loser-vs-peers is only
valid for an ordinary peer; when the loser is rank 1, the only valid
comparison is rank1-failing vs rank1-passing (same node, same role,
different run). Before trusting any differential row, check whether the
loser differs from peers in ROLE as well as outcome — role skew here reached
x158 and would swamp any real signal.

## A methodology note that explains why the differentials misled

[[probe-counts-are-per-module-load-and-capped]]: MXFS probes are
`atomic_inc_return(&n) <= CAP` — per-module-load, monotonic, silent forever
once capped until the next module reload. Comparing node vs node WITHIN one
run is valid (same module age everywhere); comparing early-run vs late-run
on ONE mount is not (measures cap exhaustion, not behavior). This is exactly
what corrupted an early rank1 pass/fail diff: seven probes read exactly
their documented caps (P170-CLWR=800, P25-INSTR=600, ...) on the passing
(fresh-module) side and 0 on the failing (cap-exhausted) side — a pure
saturation artifact. Fix when a cross-run compare is unavoidable: match
ORDINAL position after a fresh prep (fail at iteration k -> fresh prep -> run
k iterations again -> diff at k), or get the failure to occur on the first
run after a prep so any fresh-prep pass is a like-for-like control. Related
trap: `pr_warn_ratelimited` probes read near-zero regardless of true
frequency — check which macro a probe uses before reasoning about its count.

## Telling a genuine coherency/durability loss from harness noise

[[dirent-durability-failure-mode-discriminator]]: `durable_loss=8` appears
in both a genuine loss and a straggler-timeout artifact — the discriminators
are `late_ok` and the wall, not the loss count. Genuine: wall ~116-124s
(normal), `late_ok` 4-21 (reconciliation ran), 1/32 nodes failing. Artifact:
wall 240s/240s (hit budget), `late_ok=0` (cut off before reconciliation
could run), 31/32 failing + `NO_TERMINAL_RECORD`. The artifact's cause was
residual cluster state from a harness an outer `timeout` had killed
mid-iteration; a token differential on it showed the straggler node
elevated across MANY unrelated probes at once (flush, AG-wait,
inactivation-defer together) rather than a narrow path — that shotgun
pattern itself is the tell for a stuck node, not a coherency bug. Rule:
after killing any harness mid-run, `MXFS_FORCE_PREP=1 ./run.sh N caw
prep_cluster` before trusting the next red.

## Root cause found and fixed: demoter predicate lost its self-exemption

[[demoter-predicate-self-exemption-invariant]]: `mxfs_foreign_demoter()`
in `xfs/xfs_mxfs_dlm.c` answers "is another task draining this inode, so
should I defer?" and MUST return false whenever `current` owns any claim
slot, checked BEFORE looking at whether some other slot is occupied. The
original one-slot form (`ip->i_dlm_demoter && !mxfs_is_demoter(ip)`)
self-exempts correctly because `mxfs_is_demoter()` covers both slots. The
sess26 generalization to two slots, `(d1 && d1 != current) || (d2 && d2 !=
current)`, diverges in exactly one state — slot 1 foreign, slot 2 == me —
where it wrongly says "defer," causing a live release drain to abandon its
own reload because a peer drain exists on the same inode (measured 30-152
times per 32-node run, an ordinary state). Cost: cache_coherency FAIL 0/32
(timed out at budget — looks exactly like a wedged-node infra fault, was
not), strong_consistency FAIL 25/32, posix_multi FAIL 1/32. Corrected form
checks self-ownership of either slot first and returns false immediately,
then falls through to the general occupied-check — this also fixes a real
blindness in the original one-slot spelling (reads false when slot 1 was
released while slot 2 still drains, reachable since the two drains don't
finish in claim order). Fixed: cache_coherency 32/32 654/654 in 26s,
strong_consistency 32/32, posix_multi 32/32 80/80. This fix resolved the
D-MOUNT-DEGRADES-WITH-USE / D-DIRENT-INODE-TYPE-MISMATCH family; it does
NOT explain the separate unmount inode leak below.

## Unmount leak: elimination and live hypothesis at session end

`docs/history/docs/history/compiled-sess26-aged-mount-unmount-leak.md`: reproduced 3/5 cycles at 16/caw,
one node per catch. Eliminated by probe counts on the leaking node in the
leak window: P142-BWORK-LASTREF, P142-DWORK-LASTREF (both variants — sess25
had checked only one), P60-BWFN-BADREF, P124-DWFN-BADREF, P134-ILEND-FREEING,
P204-CANCEL-ARMED-REF, P-DBLRECLAIM, P72/74/76-DEMOTER-* all read 0.
Eliminated by source verification: `xfs_lookup` releases on every internal
path; `d_splice_alias` consumes its reference on every path (including
MXFS's non-upstream habit of passing `ERR_PTR` into it); `xfs_lookup` has
only 3 callers, all safe; `mxfs_dlm_bast_work_fn`'s one early return is the
already-measured-0 P142-BWORK path; the shared PR-demote arm helper pairs
igrab/irele correctly on every branch. Live hypothesis at session end:
`P203-LEVEL`'s attribution is only sound under LIFO release order and is
likely misattributing the grab to `xfs_lookup`; two independent fields
(`iget_caller`, and `LEVEL[3]`/`LEVEL[4]` in later captures) instead name
**`mxfs_dlm_bast_notify+0x71`** as owning the un-released grab, with
`bast_pending=0 bwork_pending=0 dwork_pending=0 dwork_timer=0 demoter=0` —
the work that owns the reference is neither queued nor running. Since
`i_dlm_bastq_src` has 21 assignment sites and captures show src 1 (already
audited, correct, xfs_mxfs_dlm.c:27113), 9, and 14 — the next step is
auditing src=9 (16613, 16866) and src=14 (13867, 17816). Do not rebuild a
global refcount balance to chase this — see
[[unmount-leak-global-refcount-balance-cannot-work]] above.

## Generalizable lesson

Three separate instruments this session produced a confident wrong answer
before being sanity-checked against a known invariant: the global refcount
balance (`net == icount` failed by 77 on the first capture), the rank1
loser-vs-peers differential (elevated 20x-158x on a healthy control run),
and the raw pass/fail probe-count diff (seven probes landed exactly on
their documented caps). Sanity-check any new counter against a known
invariant before reading a verdict off it.
