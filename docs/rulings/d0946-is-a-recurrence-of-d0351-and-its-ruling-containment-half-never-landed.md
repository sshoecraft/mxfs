<!-- sess571: D-0946 reproduces D-0351's chain line-for-line on 0.75.114/115 though D-0351 is FIXED AND VERIFIED; the ruling's pre-dialloc containment was… -->
# D-0946 is D-0351 coming back, and half the ruling was never built

## The match

D-0351 (`D-IFREE-DINODE-NEVER-PUBLISHED-INOBT-FREE-VISIBLE-PEER-DOUBLE-ALLOC-
SHUTDOWN-0351`, status **FIXED AND VERIFIED**) records this chain:

    P150-ALLOC-FIN picks <ino> (inobt free)
    -> P-CR63-SHELL dead shell (peer-freed)
    -> P-RECYCLE-GATE disk_mode=040755 disk_gen=3586970507
    -> P-CR63-DEFER-DISKLIVE
    -> P-CREATE-ERR1 err=-117
    -> P-CR62 verdict=DISK-LIVE=>double-alloc(inobt-stale)
    -> P-CR3-CANCEL error=-117 trans_dirty=1
    -> Internal error xfs_trans_cancel -> shutdown -> P-SESSION-POISON -> fenced

Every probe fired in that order, three times, on 0.75.114 and 0.75.115, always
ino 132, always a **peer-freed** dead shell, always `incore_gen == disk_gen + 1`.
Evidence: `20260910T064106Z_agshut_s573fixl3`, `..._064524Z_agshut_s573fixl6`,
`..._072208Z_agshut_s575fixl7`. Rate: 3 in 16 death laps on an un-re-prepped fs.

D-0351's stated root — *"the FREE-PUBLISH invariant is unenforced: nothing
guarantees the free dinode is durable before the inobt free becomes visible to a
peer under a new AG grant"* — still holds on the current build.

**Ledger handling:** D-0946 is the live record (current evidence, next steps).
D-0351 is annotated, not reopened, so one defect is not counted twice — but its
disposition must not be read as covering the create path.

## The half that was never built

The sess427 RULE-5 ruling on D-0351 specified a fix AND containment:
*"validate the platter dinode BEFORE dialloc dirties the transaction."*

**Verified absent.** In `xfs/xfs_inode.c`, between `mxfs_quar_gate_locked(dp,
"create")` (~2882) and `xfs_dialloc` (~2890) there is no platter read of any
kind. The only `mxfs_dbg_disk_di_mode` call in `xfs_create` is the **post-error**
probe at 3184 that prints P-CR62 after the transaction is already dirty.

That is exactly why a correctly-caught divergence costs the whole filesystem.
The fail-safe is right to refuse — handing out an inode the platter says is live
would be strictly worse — but it fires too late to fail cleanly.

`mxfs_quar_gate_locked`'s own comment at 2878-2881 already names that spot:
*"the transaction is still clean here — xfs_dialloc below is what dirties it —
so this is the last point a refused acquire can be turned into a clean
failure."* The containment belongs there.

## Why this is the cheap next move

Landing containment is **independent** of finding the durability root:
- testable alone — the shutdown becomes an ordinary `open(2)` error and the node
  stays in the cluster;
- would have turned all three observed occurrences into non-events;
- does not weaken the check. **Never "fix" the fail-safe itself** — relaxing
  P-CR62 converts a caught divergence into a silent double-allocation.

## Caution carried forward

`verdict=DISK-LIVE=>double-alloc(inobt-stale)` is a **label**, not a
measurement: `xfs_inode.c:3194-3196` picks one of three fixed strings purely on
the di_mode it just read. Nothing there reads the inobt. "The inobt is stale"
and "the dinode free never landed" fit every observed fact and have opposite
fixes. Discriminate offline with `tools/chk_mxfs -v` on the LUN, comparing the
platter inobt free bits for AG 0 startino=128 off=4 against the dinode.
