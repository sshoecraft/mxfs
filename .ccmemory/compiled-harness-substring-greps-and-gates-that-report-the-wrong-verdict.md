---
name: compiled-harness-substring-greps-and-gates-that-report-the-wrong-verdict
description: Harness verdict traps: substring/word greps, wrong-polarity probe gates, unanchored fields, presence-vs-usability checks, and ruling escape clauses.
metadata:
  type: feedback
tags: [compiled, harness, substring-grep, measurement-integrity, vacuity-gate]
---

# Harness greps and gates that answer a different question than the one asked

Seven traps, one shape: a test asks "did event X happen?" but implements "does the text X appear somewhere?" (or counts a sibling, a stale format, or a presence that is not usability). Most fail silently in the direction of good news or of a null result that reads as "defect did not reproduce".

## Word/substring matches that hit the wrong line

- **Wait loop on `grep -q PENDING`.** A board's totals line contained "0 PENDING", so the loop never saw absence, spun its full 420 s and exited 124 on a finished board. The retired `showstat.sh` is gone and `tools/criteria.py` omits absent statuses, but a bare word test is still wrong (the word also shows in `pending` output and `measured` text). Assert on a parsed number: count rows by the status column, e.g. `grep -cE '^[0-9]+ +\| [^|]+\| PENDING '`. Better, do not wait on a board; run `run.sh` in the foreground with its own per-row budgets. [[trap-grep-q-PENDING-matches-the-summary-lines-own-zero-pending]]
- **`grep -o 'mount_rc=[0-9]*'` matches inside `umount_rc=0`**, which the harness prints first; with `head -1` every lap read `mount_rc=0`. In `tests/d0944_death_rejoin_ab.sh` this turned "control 5 of 7 FAILED, fix 8 of 8 clean" into "control 4/6 ok, fix 6/6 ok". Second occurrence of that exact mis-summary. Anchor to the owning line (`sed -n 's/.*REJOIN mount_rc=\([0-9]*\).*/\1/p'`), prefer the node's own evidence file, and cross-check the driver's verdict against the harness's own `ck`/FAIL line at least once. Kernel-side probes (`ATOMIC-SKIP`, `P227-FR-TORN-UNPUBLISHED`) come from the survivor's dmesg, not harness stdout. [[trap-bare-mount-rc-grep-matches-inside-umount-rc-and-reports-every-lap-as-success]]
- **Contamination test counting `self-fenc`.** `fence_crash_cuts.sh` aborted every TCP lap because the routine peer-death line "deferring death 40000 ms ...; EX frozen (self-fence)" (dlm/v5_mount.c) contains the word. Fixed in 0.89.8 by counting the module's own `P131-SELF-FENCE` / `P236-SELF-FENCE` plus the shutdown text. Before counting a word as a failure marker, grep the tree for every print containing it and confirm each one is the event; prefer P-number markers over English fragments. [[trap-a-substring-contamination-test-matches-the-transports-routine-peer-death-deferral-line-and-aborts-every-lap]]

## Gates with the wrong polarity, format coverage or precondition

- **Vacuity gate counted the no-event probe.** `authtail_mount_unwind.sh` required a foreign replay but counted `P163-RECOVERED` (dlm/disklock.c, the NO-REPLAY completion). The replay path prints `P163-RECOVERY-COMPLETE` and `foreign replay of slot N complete` (xfs/xfs_log.c). Four laps read VACUOUS while their journals showed the replay; three release-gate records depended on it. "The string exists in the tree" does not validate a probe; read the source line to see which branch prints it, and prefer the subsystem's own sentence over a prefix-sharing tag. A harness that keeps returning VACUOUS on a path with independent evidence it ran is a harness bug until the raw journal is checked against the gate predicate. [[trap-a-vacuity-gate-can-count-the-probe-that-fires-only-when-the-thing-it-requires-did-not-happen]]
- **Gate table keyed on `RESULT:`.** 17 of 19 "no verdict" logs were passing laps in older shapes: `=== <harness> <label>: fails=0 wall=Ns ===`, `VERDICT PASS`. Also 25 of 150 capture-gate dirs are chunk runs whose dir name lacks the harness name; match on `<harness>_fault.log` / `<harness>_ok.log`. The gate itself reads only `^RESULT`, so its one-line summary of an older-format lap is also "no RESULT". Classify by all verdict shapes; "no line matched" means read the tail, never a category. [[trap-a-gate-table-keyed-on-the-result-token-misreads-the-older-fails0-and-verdict-pass-lines-as-no-verdict]]
- **Presence is not usability.** A shut-down (self-fenced) fs stays in `/proc/mounts` and returns EIO; `tests/d0949_sole_survivor_chunkfree.sh` ran against it, got zero counters and printed `VACUOUS` instead of a precondition failure. Probe usability (`mkdir -p $MNT/.probe.$$ && rmdir ...`) and `exit 2`. A `touch` at a mountpoint with nothing mounted writes to the root fs. [[trap-a-mount-in-proc-mounts-is-not-a-working-mount-and-two-shell-counter-bugs]]
  - `cnt() { grep -ac ... || echo 0; }` returns `"0\n0"` because `grep -c` prints 0 and exits 1. Use `c=$(grep -ac ... | head -1); echo "${c:-0}"`.
  - `df -i --output=itotal` is rejected, and without `-i` itotal is `maxicount`, not `sb_icount` (25991808 before and after 12000 creates). Use `tools/chk_mxfs -v <dev>` (`Superblock icount:`, `Total inodes (inobt sum):`; works mounted). Prefer kernel-maintained counters over budgeted probes (`P133-ICLUSTER-SYNCINIT` prints only the first 20 per load), but verify the counter means what the verdict assumes.

## Not a grep, same discipline

- **A ruling's escape clause may already be closed.** `docs/rulings/fence-crash-matrix-cuts.md` allows omitting in-flight entries as crash laps "once pending I/O has drained before a successor acts". `dlm/scsipr.c`, in the comment sizing `mxfs_lu_reset_converge_ms`, says that would be "the pre-reset drain the design ruling rejected". No drain exists to measure, so the live-prover faults must be injected (`mxfs.pr_fence_submit_inject`, 0.89.55). When an exemption is conditional on a property, grep the subsystem for the property's name first: a rejected design is not a property that might happen to hold, and the decision can sit in an unrelated timeout comment. [[trap-a-rulings-escape-clause-can-be-closed-by-a-design-decision-recorded-only-in-a-comment-on-an-unrelated-timeout]]

## Checklist

1. Assert on a parsed number or an anchored field, never on a word the all-clear text may also contain.
2. For each marker, enumerate every print site containing it and confirm which branch emits it.
3. Gate on usability of the precondition; exit non-zero (precondition failure), never emit a null measurement.
4. Enumerate every verdict format before tabulating; unmatched means read the tail.
5. Cross-check a driver's summary against the harness's own FAIL lines and the raw node evidence at least once.
