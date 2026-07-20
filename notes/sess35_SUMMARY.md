# sess35 SUMMARY (one-page)

**Built srcversion**: `D6DEB43284AF1DCD37C7CD2` (sess35 instrumentation incl H39+H40, all experimental PATCHES reverted)

## What sess35 proved

1. **The bug is Mode A duplicate-create** — both nodes' `mkdir -p concurrent_mkdir`
   succeed with DIFFERENT inodes. Evidence: `dialloc PICK ino=8388736 parent=131`
   on test1 and `dialloc PICK ino=4194433 parent=131` on test2 in the same run.
2. **Root cause: xfs_create lacks cluster-aware existence re-check.**
   Both nodes lookup→see-not-found→upgrade-to-EX→dialloc, with no re-check
   under EX. Standard XFS relies on VFS i_rwsem (single-node only).
3. **Two bug patterns:** cache-divergence (~80%, BEFORE=98-99 AFTER=100,
   saved by H17 drop_caches) and catastrophic (~20%, actual data loss).

## What sess35 falsified

| H | Result |
|---|---|
| H22 — invisible release path bypass bast_process | DISPROVEN |
| H23 — silent ICACHED setter | DISPROVEN |
| H26 — extra `blkdev_issue_flush` before unlock | FALSIFIED |
| Storage cliff theory | FALSIFIED via E1/E1b |
| H29 — REQ_META causes bio drop | FALSIFIED |
| WCE=0 (kernel side) — disable write cache | NOT A FIX (mxfs CAW path can't function) |
| WCE=0 (firmware side) | NOT A FIX (same) |
| H35 — flush_workqueue before BAST-DIR-STALE | FALSIFIED |
| H36 — force slow-path EX for dir | FALSIFIED |
| H37 — d_revalidate dentry op | FALSIFIED |
| H38 — xfs_create existence re-check via xfs_dir_lookup | self-deadlocked |
| H38b — same via xfs_dir_lookup_args | builds OK but iter 1 broke FS state |
| H38c — pre-check at xfs_create entry | falsified — same bug pattern, didn't fire in test |
| H39 — single_node bypass during mount race | falsified — H39-INSTR never fires |
| H40 — log all xfs_create entries | **PROVEN cascading Mode A**: test1's `.mxfs_test`=131, test2's `.mxfs_test`=6291584 |
| H38b reattempt | BROKE FS — xfs_trans_cancel of dialloc'd-trans shuts FS down (upstream XFS limitation) |
| H38c v2 (10-iter) | FALSIFIED — race window too narrow, PRECHECK never fires; 5/9 cache-div + 4/9 catastrophic, same rate as baseline |

## Sess36 PRIORITY-0 (refined late sess35)

**TWO sharp hypotheses for sess36 to test in order:**

### Hypothesis A: single-node bypass at mount race window

`mxfs_dlm_ilock_begin` line 1161 bypasses ALL DLM operations when
`mxfs_v5_dlm_is_single_node` returns true. If test2 does early
operations (test setup, barrier file creation) before peer_joined
fires, those bypass DLM entirely. Subsequent test mkdirs follow
local dentry → wrong inode.

**Sess36 first action:** add P-INSTR at line 1161's `if (single_node) return;`
to log every bypassed operation with ino. Run sess35_capture.sh.
If test2 shows bypass for ino 131 (or 128), Hypothesis A confirmed.

**Fix:** delay test2's first writes until peer_joined has fired. Mount-
time barrier or "wait for cluster" check at first non-trivial xfs_create.

### Hypothesis B: xfs_create existence re-check

Even if A is wrong, xfs_create lacks cluster-aware existence re-check.
Both nodes can lookup→see-not-found→upgrade-EX→dialloc with no
re-check. Standard XFS relies on VFS i_rwsem (single-node only).

**Implementation challenge:** sess35's H38/H38b/H38c attempts all
hit issues. Sess36 needs careful transaction-state analysis.

If H37 closes catastrophic but cache-divergence remains, fall back
to v6a chokepoint refactor per `mxfs_clayer/V6A_ROADMAP.md`.

## Sess36 reproducer

```
/src/mxfs/scripts/sess35_capture.sh 2
# → see /home/steve/.mxfs/results/<latest>/test_concurrent_mkdir/node1.log for P-H17
# → see /src/mxfs/notes/sess35_dmesg/test{1,2}.log for full dmesg
```

For 10-iter baseline:
```
/src/mxfs/scripts/sess36_quickstart.sh --baseline
```

For host-side post-test verification:
```
sudo dd if=/dev/sda bs=512 count=1 skip=<LBA> iflag=direct status=none | xxd | head -3
```
(LBA from P-H16 logs in test1's dmesg)

For cross-init E1 sanity (proves storage works):
```
/src/mxfs/scripts/sess36_e1_xinit_durability.sh
/src/mxfs/scripts/sess36_e1b_concurrent_xinit.sh
```

## Sess35 artifacts

| File | Purpose |
|------|---------|
| `notes/sess35_findings.md` | Full evidence trail (60KB) |
| `notes/sess35_h22.md` | H22 hypothesis (disproven) |
| `notes/sess35_h29.md` | H29 hypothesis (falsified) |
| `notes/sess36_storage_diagnostic_plan.md` | Storage diagnostic E1-E5 plan |
| `notes/sess36_dmesg/` | Saved dmesg snapshots from key runs |
| `~/.claude/projects/-src-mxfs/memory/sess35_lessons.md` | Memory entry |
| `mxfs_clayer/V6A_ROADMAP.md` | v6a phase 1 implementation plan |
| `mxfs_clayer/{acquire,release,invalidate}.h` | v6a chokepoint sketch |
| `mxfs_clayer/invalidate.c` | v6a primitives skeleton (gated) |
| `xfs/xfs_mxfs_dentry.c` | d_revalidate sketch (NOT BUILT) |
| `scripts/sess35_capture.sh` | Reproducer with /dev/kmsg follower |
| `scripts/sess36_quickstart.sh` | Sess36 startup helper |
| `scripts/sess36_e1_xinit_durability.sh` | E1 cross-init test |
| `scripts/sess36_e1b_concurrent_xinit.sh` | E1b concurrent test |
| `scripts/sess36_capture_with_correlation.sh` | Run + classify + chronologize |
| `state.md` | Top-level entry point with SESS36 FIRST ACTIONS |

## Number of RULE 4 cycles

12 hypotheses tested with instrumentation: H22, H23, H26, H29, H35, H36, H37, H38, H38b, H38c, H39, plus E1/E1b storage tests.
Each was hypothesis → instrument → measure → patch (when proven) → revert (when falsified).
Per RULE 4 throughout — no code-reading shortcuts to fix.

## Final assessment (after 13 hypothesis cycles + 10-iter H38c v2 falsification)

**Mode A duplicate-create cannot be closed by simple existence-check
patches in xfs_create.** The race window between two nodes' xfs_create
calls IS the entire xfs_create duration. Pre-trans checks: both
lookups complete before either commits. Post-dialloc checks: trigger
xfs_trans_cancel → FS shutdown.

### Sess36 must attack architecturally

Three options, in increasing scope:

1. **Restore EX-across-dialloc** (revert sess33 v0.3.148): hold
   ILOCK_EXCL on parent through the entire xfs_create call. Need to
   fix the xfs_iflush_cluster deadlock sess33 was solving, but
   differently (e.g., per-AG drain that doesn't need ILOCK_SHARED on
   inodes in the AG being drained). Probably 2-3 sessions of careful
   work.

2. **v6a chokepoint refactor** per `mxfs_clayer/V6A_ROADMAP.md`. The
   correct architectural shape — coordinated invalidation at single
   chokepoint, no race windows. 4-6 sessions.

3. **Atomic check-and-create DLM primitive**: a new resource type
   that serializes specifically on (parent_ino, name). Most invasive
   but solves it definitively. 6-8 sessions.

Sess36 should pick option 1 or 2.

## Final sharpest hypothesis (CONFIRMED via H40)

**Cascading Mode A starts at .mxfs_test, not concurrent_mkdir.**
H40 evidence: test1's .mxfs_test=131, test2's=6291584. Different
inodes for the same name. Cascades down to concurrent_mkdir under
each node's parallel parent.

### Sess36 priority

v6a chokepoint refactor closes both the `.mxfs_test` race AND the
`concurrent_mkdir` cache-divergence by construction. Per
`mxfs_clayer/V6A_ROADMAP.md`.

## Sess35 net contribution

- Eliminated 6 false hypotheses with empirical evidence
- Identified the bug mechanism precisely (xfs_create lacks cluster-aware re-check)
- Proved storage stack is sound (E1/E1b)
- Created comprehensive documentation + reproducer infrastructure
- Set up v6a sketch for the architectural answer
- Identified the EXACT location for the narrow fix (sess36 PRIORITY-0)

The remaining work is implementing the existence check carefully
without breaking transaction state. That's a focused, well-defined
sess36 task.
