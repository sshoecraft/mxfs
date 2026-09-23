---
name: technique-a-capture-must-cross-a-validity-boundary-in-the-parent-shell-before-any-count-becomes-a-verdict
description: TECHNIQUE (D-A-TEST-HARNESS, 0.87.17): rsx + capture_require (tests/lib/rig.sh) — status observed, stderr kept, shape asserted as a parent-shell stat…
metadata:
  type: feedback
tags: [harness, capture, verdict, rig.sh, D-A-TEST-HARNESS]
---

# A capture crosses a validity boundary in the parent shell before any count becomes a verdict

**The class.** `rs() { timeout N $SSH host cmd 2>/dev/null | filt; }` discards remote stderr and
returns filt's status. A remote failure (tool on an unmounted NFS share, device from another rig,
python exception, timeout) leaves an empty or partial capture; `grep -c` reads 0; ck/ckge prints a
verdict about MXFS. Hit again in sess54 (s54j/s54k): a probe that had answered a minute earlier ran
on a node a previous lap had rebooted without /src, printed nothing, and the harness printed
`home_before=?` and ran on to a verdict; in the peer arm the node-prep script was unreachable and
every recovery assertion FAILed about the filesystem.

**The contract (consult 2026-09-18, docs/harness-capture-contract.md).** Before a measurement
feeds an assertion: status acceptable (remote, ssh 255, sshpass, the caller's timeout — observed
by the acquirer, not filt), the tool's anchored structure present, and the capture belongs to this
invocation. Otherwise ABORT (2), never FAIL/VACUOUS/PASS. A validated capture may count zero.

**Traps met while building it.**
- An `exit 2` inside `$(...)` ends the substitution, not the harness; the assertion still runs.
  The validator is a STATEMENT (`capture_require file shape what`), never a counting helper.
- A per-call counter kept in the parent is lost when the acquirer runs inside `$(...)` (a
  subshell): every call named the same stderr file and overwrote it. Name per-call files with
  mktemp, not a counter.
- Do not merge remote stderr into stdout class-wide: 122 sites in 37 harnesses parse the helper's
  last line, and error text can contain any string a loose grep recognizes (`refus`, `FAIL`).
  Keep stderr in its own file and name it from the ABORT.
- A remote `grep -c` with zero matches exits 1; a status record on that would break the parse.
  The caller states an expected non-zero (`|| true`); the wrapper cannot know.
- filefrag's summary line counts only physically discontiguous runs; count `filefrag -v` rows.
  xfs_bmap/xfs_io cannot read an MXFS extent map (the XFS ioctl file is not compiled).
- A verdict grep for `refus` matched the fence protocol's own "refusing the claim" stage lines
  and `mismatch` matched `inc_mismatch=0`; assert the image-refusal probes (P227-FR-ATOMIC-SKIP,
  P241-RECOV-TERMINAL, P240-QUAR) and `P227-TOKENSUM wskip=0`.
- `make clean` removes tools/mkfs_mxfs and tools/chk_mxfs; the fleet prep then aborts. `make tools`
  after a clean module build.
- A fleet prep with MXFS_NODE_LIST of two nodes and N=1 is refused; and run.sh refuses a 1-node
  test on a fleet prepped for 2 until `./run.sh 1 tcp` preps it.
